"""
Channels besides the returned objects that could reveal a foreign object: denial
responses that tell a foreign ID from a missing one, computed fields, and fields
typed as an interface or union.
"""
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from graphql import build_schema, graphql_sync

from app.core.security import create_access_token
from app.database import get_db_connection
from app.main import app
from app.seed import add_shared_folder_scenario
from app.security.object_extractor import normalize_query
from app.security.runtime_object_guard import OwnershipMiddleware
from app.security.shield_config import ShieldConfig, default_config, lint_config

client = TestClient(app)


def headers(user_id=101, role="user"):
    return {"Authorization": f"Bearer {create_access_token(user_id=user_id, role=role)}"}


@pytest.mark.parametrize("template", [
    "{{ resource(id: {id}) {{ id }} }}",
    "{{ user(id: {id}) {{ id }} }}",
    'mutation {{ updateResource(id: {id}, name: "x") {{ id }} }}',
    "mutation {{ deleteResource(id: {id}) }}",
])
def test_foreign_and_missing_objects_get_the_same_response(template):
    foreign = client.post("/graphql", json={"query": template.format(id=102)}, headers=headers())
    missing = client.post("/graphql", json={"query": template.format(id=99999)}, headers=headers())
    assert foreign.status_code == missing.status_code == 403
    foreign_body = foreign.json()["detail"]
    missing_body = missing.json()["detail"]
    assert foreign_body.pop("object_id") == 102 and missing_body.pop("object_id") == 99999
    assert foreign_body == missing_body
    assert foreign_body["reason"] == "ACCESS_DENIED"


def test_exact_reason_stays_in_the_audit_log():
    client.post("/graphql", json={"query": "{ resource(id: 103) { id } }"}, headers=headers())
    conn = get_db_connection()
    row = conn.execute("SELECT reason FROM audit_logs WHERE object_id = 103 ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    assert row["reason"] == "OWNERSHIP_MISMATCH"


@pytest.mark.parametrize("object_id", [102, 99999])
def test_explainer_reveals_no_owner_to_a_user(object_id):
    response = client.post("/api/v1/taint-explain", json={"query": f"{{ resource(id: {object_id}) {{ id }} }}"},
                           headers=headers())
    item = response.json()["objects"][0]
    assert item["owner_id"] is None
    assert item["authorization"]["reason"] == "ACCESS_DENIED"
    assert item["authorization"]["risk_level"] is None


def test_explainer_still_shows_an_admin_the_reason():
    response = client.post("/api/v1/taint-explain", json={"query": "{ resource(id: 999999) { id } }"},
                           headers=headers(104, "admin"))
    assert response.json()["objects"][0]["authorization"]["reason"] == "OBJECT_NOT_FOUND"


def test_child_count_excludes_foreign_children():
    add_shared_folder_scenario()
    query = "{ resource(id: 201) { childrenCount children { id } } }"
    owner = client.post("/graphql", json={"query": query}, headers=headers()).json()["data"]["resource"]
    assert owner["childrenCount"] == len(owner["children"])
    assert 204 not in [child["id"] for child in owner["children"]]
    admin = client.post("/graphql", json={"query": query}, headers=headers(104, "admin")).json()["data"]["resource"]
    assert admin["childrenCount"] == owner["childrenCount"] + 1


SDL = """
interface Node { id: ID! }
type Note implements Node { id: ID! body: String! }
type Tag implements Node { id: ID! label: String! }
type Folder { id: ID! ownerId: ID! }
union Hit = Note | Tag
type Query {
  node(id: ID!): Node
  nodes: [Node!]!
  search: [Hit!]!
}
"""

NOTES = {1: {"__typename": "Note", "id": 1, "body": "mine", "owner": 1},
         2: {"__typename": "Note", "id": 2, "body": "secret", "owner": 2}}
TAG = {"__typename": "Tag", "id": 9, "label": "public"}
schema = build_schema(SDL)
schema.query_type.fields["node"].resolve = lambda _, info, id: NOTES.get(int(id))
schema.query_type.fields["nodes"].resolve = lambda _, info: [*NOTES.values(), TAG]
schema.query_type.fields["search"].resolve = lambda _, info: [*NOTES.values(), TAG]
schema.get_type("Node").resolve_type = lambda value, *_: value["__typename"]
schema.get_type("Hit").resolve_type = lambda value, *_: value["__typename"]

CONFIG = ShieldConfig(schema=lambda: schema, owned_types={"Note": "Note"},
                      owner_lookup=lambda key, object_id: NOTES.get(int(object_id), {}).get("owner"))


def run(query):
    request = SimpleNamespace(url=SimpleNamespace(path="/graphql"),
                              state=SimpleNamespace(current_user={"user_id": 1, "role": "user"}))
    return graphql_sync(schema, query, context_value={"request": request}, middleware=[OwnershipMiddleware(CONFIG)])


def test_foreign_object_behind_an_interface_is_denied():
    assert run('{ node(id: "2") { ... on Note { body } } }').data["node"] is None
    assert run('{ node(id: "1") { ... on Note { body } } }').data["node"]["body"] == "mine"


@pytest.mark.parametrize("field", ["nodes", "search"])
def test_abstract_lists_are_filtered_by_concrete_type(field):
    result = run(f"{{ {field} {{ ... on Note {{ id }} ... on Tag {{ label }} }} }}")
    assert result.data[field] == [{"id": "1"}, {"label": "public"}]


def test_layer1_reads_the_type_from_a_global_id_on_an_interface_field():
    config = ShieldConfig(schema=lambda: schema, owned_types={"Note": "Note"}, owner_lookup=lambda *_: None,
                          decode_id=lambda value: tuple(value.split(":")))
    objects = normalize_query('{ node(id: "Note:2") { id } }', config=config)["objects"]
    assert objects == [{"type": "Note", "id": 2, "path": "node"}]


def test_principals_and_ids_need_not_be_numeric():
    notes = {"a-1": {"id": "a-1", "owner": "alice"}, "b-2": {"id": "b-2", "owner": "bob"}}
    text_schema = build_schema("type Note { id: ID! } type Query { note(id: ID!): Note notes: [Note!]! }")
    text_schema.query_type.fields["note"].resolve = lambda _, info, id: notes.get(id)
    text_schema.query_type.fields["notes"].resolve = lambda _, info: list(notes.values())
    config = ShieldConfig(schema=lambda: text_schema, owned_types={"Note": "Note"},
                          owner_lookup=lambda _, object_id: notes.get(object_id, {}).get("owner"))
    request = SimpleNamespace(url=SimpleNamespace(path="/graphql"),
                              state=SimpleNamespace(current_user={"user_id": "alice", "role": "user"}))

    def run(query):
        return graphql_sync(text_schema, query, context_value={"request": request},
                            middleware=[OwnershipMiddleware(config)]).data

    assert run('{ note(id: "a-1") { id } }') == {"note": {"id": "a-1"}}
    assert run('{ note(id: "b-2") { id } }') == {"note": None}
    assert run("{ notes { id } }") == {"notes": [{"id": "a-1"}]}


def test_lint_is_clean_on_the_demo_configuration():
    assert lint_config(default_config()) == []


def test_lint_reports_an_owned_type_left_out():
    findings = lint_config(ShieldConfig(schema=lambda: schema, owned_types={"Note": "Note"}, owner_lookup=lambda *_: None))
    assert {"kind": "possible_unowned_type", "type": "Folder", "field": "ownerId"} in findings


def test_lint_reports_an_undeclared_aggregate():
    config = default_config()
    lenient = ShieldConfig(schema=config.schema, owned_types=config.owned_types, owner_lookup=config.owner_lookup,
                           mutation_targets=config.mutation_targets)
    assert {"kind": "undeclared_aggregate", "type": "ResourceType", "field": "childrenCount"} in lint_config(lenient)


def test_a_listed_query_checks_owners_once_and_audits_in_one_transaction(monkeypatch):
    from app.security import ownership, runtime_object_guard

    add_shared_folder_scenario()
    single_lookups, audit_batches = [], []
    real_log = runtime_object_guard.log_decisions
    monkeypatch.setattr(runtime_object_guard, "get_object_owner",
                        lambda *args: single_lookups.append(args) or ownership.get_object_owner(*args))
    monkeypatch.setattr(runtime_object_guard, "log_decisions",
                        lambda rows: audit_batches.append(len(rows)) or real_log(rows))
    response = client.post("/graphql", json={"query": "{ resource(id: 201) { children { id } } }"}, headers=headers())
    ids = [child["id"] for child in response.json()["data"]["resource"]["children"]]
    assert ids == [202, 203]
    assert [args for args in single_lookups if args[1] in (202, 203, 204)] == []
    assert audit_batches == [3]


def _without(config, owned_type):
    from dataclasses import replace

    return replace(config, owned_types={k: v for k, v in config.owned_types.items() if k != owned_type})


@pytest.mark.parametrize("owned_type", ["ResourceType", "UserType"])
def test_lint_reports_each_demo_owned_type_when_removed(owned_type):
    findings = lint_config(_without(default_config(), owned_type))
    assert owned_type in {f["type"] for f in findings if f["kind"] == "possible_unowned_type"}


@pytest.mark.parametrize("owned_type", ["Patient", "Record", "Prescription"])
def test_lint_reports_each_clinic_owned_type_when_removed(owned_type):
    from app.clinic.api import CLINIC_CONFIG

    findings = lint_config(_without(CLINIC_CONFIG, owned_type))
    assert owned_type in {f["type"] for f in findings if f["kind"] == "possible_unowned_type"}


def test_layer2_checks_a_missing_lookup_like_a_found_one():
    """With Layer 1 off, a lookup that finds nothing still goes through the owner lookup,
    policy and audit, so it costs the same as a foreign object (no timing channel)."""
    from app.security.layers import set_layers

    set_layers(layer1=False, layer2=True)
    try:
        response = client.post("/graphql", json={"query": "{ resource(id: 987654) { id } }"}, headers=headers())
    finally:
        set_layers(layer1=True, layer2=True)
    assert response.json()["data"]["resource"] is None
    conn = get_db_connection()
    row = conn.execute("SELECT reason, layer FROM audit_logs WHERE object_id = 987654 ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    assert (row["reason"], row["layer"]) == ("OBJECT_NOT_FOUND", "L2")


LOOKUP_SDL = """
type Invoice { id: ID! holder: ID! total: Int! }
type Product { id: ID! title: String! }
type Ticket { id: ID! belongsTo: ID! }
type Query { invoice(id: ID!): Invoice product(id: ID!): Product ticket(id: ID!): Ticket }
"""


def _lookup_findings(**extra):
    lookup_schema = build_schema(LOOKUP_SDL)
    config = ShieldConfig(schema=lambda: lookup_schema, owned_types={}, owner_lookup=lambda *_: None, **extra)
    return lint_config(config)


def test_lint_finds_an_owned_type_whose_owner_field_has_an_unusual_name():
    # "holder" matches no owner-like name; the lookup by ID still gives Invoice away.
    assert {"kind": "unowned_id_lookup", "type": "Invoice", "field": "Query.invoice"} in _lookup_findings()


def test_lint_knows_more_owner_field_names():
    assert {"kind": "possible_unowned_type", "type": "Ticket", "field": "belongsTo"} in _lookup_findings()


def test_lint_is_quiet_about_types_declared_public():
    findings = _lookup_findings(public_types=frozenset({"Product"}))
    assert all(f["type"] != "Product" for f in findings)
    assert any(f["type"] == "Product" for f in _lookup_findings())
