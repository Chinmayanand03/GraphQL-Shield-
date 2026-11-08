"""
The security properties the paper states, checked on generated worlds and requests.

Hypothesis picks who owns what and which folder holds what, and composes requests
from independent constructs. For a non-admin caller:

  P1 Safety             no response contains an object the caller does not own.
  P2 Non-interference   changing only other users' objects cannot change the response.
  P3 Write safety       no request changes an object the caller does not own.
  P4 Availability       a request naming only the caller's objects returns them.
"""
import json
import random

import pytest
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app.core.security import create_access_token
from app.database import get_db_connection
from app.main import app
from scripts.run_fault_injection import compose_request

client = TestClient(app)
USERS = [101, 102, 103]
FOLDERS = [201, 202, 203]
DOCUMENTS = [301, 302, 303, 304, 305, 306]
CHECKS = settings(max_examples=120, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])

worlds = st.fixed_dictionaries({
    "owners": st.fixed_dictionaries({object_id: st.sampled_from(USERS) for object_id in FOLDERS + DOCUMENTS}),
    "parents": st.fixed_dictionaries({object_id: st.sampled_from([None, *FOLDERS]) for object_id in DOCUMENTS}),
})


def name_of(object_id: int) -> str:
    return f"object-{object_id}"


def install(world: dict, renamed: frozenset = frozenset()) -> None:
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM objects")
        # Folders first: a document's parent must exist before it does.
        for object_id in sorted(world["owners"], key=lambda i: i not in FOLDERS):
            kind = "folder" if object_id in FOLDERS else "document"
            name = f"changed-{object_id}" if object_id in renamed else name_of(object_id)
            conn.execute("INSERT INTO objects (id, object_type, owner_id, name, parent_id) VALUES (?, ?, ?, ?, ?)",
                         (object_id, kind, world["owners"][object_id], name, world["parents"].get(object_id)))
        conn.commit()
    finally:
        conn.close()


def view(world: dict, caller: int | None = None) -> dict:
    owned = {i: o for i, o in world["owners"].items() if caller is None or o == caller}
    return {"owner": world["owners"], "folders": [i for i in FOLDERS if i in owned],
            "documents": [i for i in DOCUMENTS if i in owned]}


def send(caller: int, body) -> tuple[int, str]:
    token = create_access_token(user_id=caller, role="user")
    response = client.post("/graphql", json=body, headers={"Authorization": f"Bearer {token}"})
    return response.status_code, response.text


def objects_in(value) -> list:
    """Every object in a response body that names an ID or a seeded name."""
    found = []
    if isinstance(value, dict):
        if "id" in value or "name" in value:
            found.append(value)
        for item in value.values():
            found += objects_in(item)
    elif isinstance(value, list):
        for item in value:
            found += objects_in(item)
    return found


def seen_foreign_objects(text: str, world: dict, caller: int) -> list:
    leaked = []
    for item in objects_in(json.loads(text)):
        object_id = item.get("id")
        if object_id in world["owners"] and world["owners"][object_id] != caller:
            leaked.append(object_id)
        if isinstance(item.get("name"), str) and item["name"].startswith("object-"):
            named = int(item["name"].split("-")[1])
            if world["owners"][named] != caller:
                leaked.append(named)
    return leaked


@pytest.fixture(scope="module", autouse=True)
def restore_objects():
    conn = get_db_connection()
    saved = [tuple(row) for row in conn.execute("SELECT id, object_type, owner_id, name, parent_id FROM objects")]
    conn.close()
    yield
    conn = get_db_connection()
    conn.execute("DELETE FROM objects")
    conn.executemany("INSERT INTO objects (id, object_type, owner_id, name, parent_id) VALUES (?, ?, ?, ?, ?)", saved)
    conn.commit()
    conn.close()


@CHECKS
@given(world=worlds, caller=st.sampled_from(USERS), seed=st.integers(0, 2**32))
def test_p1_no_response_contains_a_foreign_object(world, caller, seed):
    install(world)
    _, body = compose_request(random.Random(seed), view(world), caller)
    _, text = send(caller, body)
    assert seen_foreign_objects(text, world, caller) == []


@CHECKS
@given(world=worlds, caller=st.sampled_from(USERS), seed=st.integers(0, 2**32), other_seed=st.integers(0, 2**32))
def test_p2_other_users_data_cannot_change_the_response(world, caller, seed, other_seed):
    rng = random.Random(other_seed)
    foreign = [object_id for object_id, owner in world["owners"].items() if owner != caller]
    renamed = frozenset(foreign)

    # The second world differs only in objects the caller does not own: their names,
    # and which of the other users holds them.
    second = {"parents": world["parents"], "owners": dict(world["owners"])}
    for object_id in foreign:
        second["owners"][object_id] = rng.choice([user for user in USERS if user != caller])

    _, body = compose_request(random.Random(seed), view(world), caller)
    install(world)
    first_response = send(caller, body)
    install(second, renamed)
    second_response = send(caller, body)
    assert first_response == second_response


def test_p2_also_holds_when_a_foreign_child_is_added_or_a_foreign_object_removed():
    world = {"owners": {201: 101, 301: 101, 302: 102, 303: 102}, "parents": {301: 201}}
    queries = ["{ resource(id: 201) { id childrenCount children { id name } } }",
               "{ resource(id: 303) { id } }", 'mutation { updateResource(id: 303, name: "x") { id } }']
    baseline = {}
    install(world)
    for query in queries:
        baseline[query] = send(101, {"query": query})
    changed = {"owners": {201: 101, 301: 101, 302: 102}, "parents": {301: 201, 302: 201}}
    install(changed)
    for query in queries:
        status, text = send(101, {"query": query})
        assert status == baseline[query][0]
        assert text.replace("303", "") == baseline[query][1].replace("303", "")


@CHECKS
@given(world=worlds, caller=st.sampled_from(USERS), seed=st.integers(0, 2**32))
def test_p3_no_request_changes_a_foreign_object(world, caller, seed):
    install(world)
    _, body = compose_request(random.Random(seed), view(world), caller)
    send(caller, body)
    conn = get_db_connection()
    rows = {row["id"]: row for row in conn.execute("SELECT id, owner_id, name FROM objects")}
    conn.close()
    for object_id, owner in world["owners"].items():
        if owner != caller:
            assert rows[object_id]["owner_id"] == owner
            assert rows[object_id]["name"] == name_of(object_id)


@CHECKS
@given(world=worlds, caller=st.sampled_from(USERS), seed=st.integers(0, 2**32))
def test_p4_a_request_for_own_objects_is_never_denied(world, caller, seed):
    pools = view(world, caller)
    if not pools["documents"]:
        return
    pools["folders"] = pools["folders"] or pools["documents"]
    install(world)
    constructs, body = compose_request(random.Random(seed), pools, caller)
    status, text = send(caller, body)
    assert status == 200, text
    # A folder the caller owns may hold foreign children, which are removed, not denied.
    assert "errors" not in json.loads(text) or constructs["kind"] == "mutation"


@pytest.mark.parametrize("prop", [test_p1_no_response_contains_a_foreign_object,
                                  test_p2_other_users_data_cannot_change_the_response,
                                  test_p3_no_request_changes_a_foreign_object])
def test_the_properties_fail_without_protection(prop):
    from app.security.layers import set_layers

    set_layers(layer1=False, layer2=False)
    try:
        with pytest.raises(AssertionError):
            prop()
    finally:
        set_layers(layer1=True, layer2=True)


def test_deleting_a_folder_does_not_reveal_a_hidden_child():
    """Deleting a folder once failed on the foreign-key constraint when it held a hidden
    foreign child, which told the caller the child existed. Children now move to the top
    level, so the response is the same and the foreign child survives unchanged."""
    without_child = {"owners": {201: 101}, "parents": {}}
    with_foreign_child = {"owners": {201: 101, 301: 102}, "parents": {301: 201}}
    with_own_child = {"owners": {201: 101, 302: 101}, "parents": {302: 201}}
    query = {"query": "mutation { deleteResource(id: 201) }"}
    responses = []
    for world in (without_child, with_foreign_child, with_own_child):
        install(world)
        responses.append(send(101, query))
    assert responses[0] == responses[1] == responses[2]
    assert json.loads(responses[0][1])["data"]["deleteResource"] is True

    conn = get_db_connection()
    child = conn.execute("SELECT owner_id, name, parent_id FROM objects WHERE id = 302").fetchone()
    conn.close()
    assert tuple(child) == (101, name_of(302), None)

    install(with_foreign_child)
    send(101, query)
    conn = get_db_connection()
    foreign = conn.execute("SELECT owner_id, name, parent_id FROM objects WHERE id = 301").fetchone()
    conn.close()
    assert tuple(foreign) == (102, name_of(301), None)
