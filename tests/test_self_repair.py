"""
Self-repairing configuration: Layer 2's evidence of what Layer 1 missed becomes a
configuration repair, verified by replaying recorded requests offline, and applied
only by an administrator.
"""
import pytest
from fastapi.testclient import TestClient

from app.clinic.data import to_global_id
from app.core.security import create_access_token
from app.database import get_db_connection
from app.main import app
from app.security import repair
from app.security.shield_config import REGISTRY, default_config

client = TestClient(app)
default_config()


def token(user_id=101, role="user"):
    return {"Authorization": f"Bearer {create_access_token(user_id=user_id, role=role)}"}


ADMIN = token(104, "admin")


def gql(query, user=101, path="/graphql", variables=None):
    body = {"query": query, **({"variables": variables} if variables else {})}
    role = "admin" if user == 104 else "user"
    return client.post(path, json=body, headers=token(user, role))


@pytest.fixture(autouse=True)
def clean_configs():
    for name in ("demo", "clinic"):
        repair.restore(name)
    conn = get_db_connection()
    conn.execute("DELETE FROM config_repairs")
    conn.commit()
    conn.close()
    yield
    for name in ("demo", "clinic"):
        repair.restore(name)


def suggestions(name):
    return repair.analyse(REGISTRY[name])


def verified(name):
    return [r for r in suggestions(name)["repairs"] if r["verification"]["verified"]]


def apply(name, item):
    return client.post("/api/v1/security/repairs/apply", headers=ADMIN,
                       json={"config": name, "kind": item["kind"], "payload": item["payload"]})


# ------------------------------------------------------------------ the three repairs

def test_a_wrong_id_argument_name_is_found_and_repaired():
    repair.inject_fault("demo", "wrong_id_argument_name")
    assert gql("{ resource(id: 102) { id name } }").json()["data"]["resource"] is None  # only Layer 2 stopped it
    gql("{ resource(id: 101) { id name } }")
    gap = repair.GAPS["demo"][0]
    assert gap["id_arguments"] == ["id"] and gap["field"] == "resource"

    top = verified("demo")[0]
    assert (top["kind"], top["payload"]) == ("add_id_argument", {"argument": "id"})
    assert top["verification"]["gaps_closed"] >= 1 and top["verification"]["false_blocks"] == 0
    assert apply("demo", top).status_code == 200
    assert gql("{ resource(id: 102) { id name } }").status_code == 403  # Layer 1 stops it again


def test_a_missing_mutation_target_is_found_and_repaired():
    repair.inject_fault("demo", "missing_delete_target")
    refused = gql("mutation { deleteResource(id: 103) }", user=103).json()
    assert refused["errors"][0]["extensions"]["code"] == "MUTATION_NOT_REGISTERED"
    gql("mutation { deleteResource(id: 102) }", user=101)

    top = verified("demo")[0]
    assert top["payload"] == {"mutation": "deleteResource", "argument": "id", "key": "Resource"}
    assert top["verification"]["owners_unblocked"] >= 1 and top["verification"]["non_owners_still_denied"] >= 1
    apply("demo", top)
    assert gql("mutation { deleteResource(id: 102) }", user=101).status_code == 403
    conn = get_db_connection()
    conn.execute("INSERT OR IGNORE INTO objects (id, object_type, owner_id, name) VALUES (777, 'document', 101, 'tmp')")
    conn.commit()
    conn.close()
    assert gql("mutation { deleteResource(id: 777) }", user=101).json()["data"]["deleteResource"] is True


def test_an_owned_type_left_out_is_found_and_repaired():
    repair.inject_fault("demo", "missing_resource_type")
    leak = gql("{ resource(id: 102) { id name } }").json()["data"]["resource"]
    assert leak is not None  # the mistake exposes another user's document
    top = verified("demo")[0]
    assert top["payload"] == {"type": "ResourceType", "key": "Resource"}
    assert top["verification"]["exposures_found"] >= 1
    apply("demo", top)
    assert gql("{ resource(id: 102) { id name } }").status_code == 403


def test_clinic_mutation_with_variables_is_recorded_and_repaired():
    """graphql-core 3.3 passes variables as a VariableValues record."""
    repair.inject_fault("clinic", "missing_create_record_target")
    for user, patient in ((102, 2), (101, 2)):
        gql("mutation($p: ID!) { createRecord(patientId: $p, diagnosis: \"x\") { diagnosis } }", user=user,
            path="/clinic/graphql", variables={"p": to_global_id("Patient", patient)})
    assert repair.UNREGISTERED["clinic"][0]["variables"] == {"p": to_global_id("Patient", 2)}
    top = verified("clinic")[0]
    assert top["payload"] == {"mutation": "createRecord", "argument": "patientId", "key": "Patient"}


# ------------------------------------------------------------ what is not repaired

def test_a_correct_configuration_gets_no_repairs():
    for query in ("{ resource(id: 101) { id } }", "{ resource(id: 201) { children { id } } }",
                  'mutation { updateResource(id: 101, name: "n") { id } }'):
        gql(query)
    assert suggestions("demo")["repairs"] == []


def test_relationship_gaps_are_explained_not_repaired():
    gql("{ resource(id: 201) { id children { id name } } }")
    result = suggestions("demo")
    assert result["repairs"] == []
    assert [e["kind"] for e in result["explanations"]] == ["relationship_traversal"]


def test_wrong_repairs_fail_verification():
    repair.inject_fault("demo", "wrong_id_argument_name")
    gql("{ resource(id: 102) { id name } }")
    gql('mutation { updateResource(id: 101, name: "renamed") { id } }')
    config = REGISTRY["demo"]
    assert not repair.verify(config, {"kind": "add_id_argument", "payload": {"argument": "name"}})["verified"]


def test_an_ownership_key_another_type_uses_is_refused():
    repair.inject_fault("demo", "missing_user_type")
    gql("{ user(id: 102) { id username } }")
    check = repair.verify(REGISTRY["demo"], {"kind": "add_owned_type", "payload": {"type": "UserType", "key": "Resource"}})
    assert not check["verified"] and check["key_used_by"] == "ResourceType"


# ---------------------------------------------------------------- human control

def test_only_an_admin_can_see_or_apply_repairs():
    assert client.get("/api/v1/security/repairs", headers=token()).status_code == 403
    assert client.post("/api/v1/security/repairs/apply", headers=token(),
                       json={"config": "demo", "kind": "add_id_argument", "payload": {"argument": "id"}}).status_code == 403


def test_an_unverified_repair_cannot_be_applied():
    response = client.post("/api/v1/security/repairs/apply", headers=ADMIN,
                           json={"config": "demo", "kind": "add_id_argument", "payload": {"argument": "name"}})
    assert response.status_code == 409
    assert "name" not in REGISTRY["demo"].id_arguments


def test_repairs_survive_a_restart_and_can_be_reverted():
    repair.inject_fault("demo", "wrong_id_argument_name")
    gql("{ resource(id: 102) { id name } }")
    applied = apply("demo", verified("demo")[0]).json()
    REGISTRY["demo"].id_arguments = ("objectId",)        # as after a restart with the mistake still in code
    assert repair.reapply_stored_repairs() == 1
    assert "id" in REGISTRY["demo"].id_arguments
    client.post(f"/api/v1/security/repairs/{applied['id']}/revert", headers=ADMIN)
    assert "id" not in REGISTRY["demo"].id_arguments
    assert [r["status"] for r in repair.applied_repairs()] == ["reverted"]


def test_the_demonstration_switch_breaks_and_restores_a_configuration():
    response = client.post("/api/v1/security/repairs/demo-fault", headers=ADMIN,
                           json={"config": "demo", "fault": "missing_resource_type"})
    assert response.status_code == 200 and "ResourceType" not in REGISTRY["demo"].owned_types
    client.post("/api/v1/security/repairs/demo-fault", headers=ADMIN, json={"config": "demo"})
    assert "ResourceType" in REGISTRY["demo"].owned_types


def test_the_listing_reports_evidence_and_faults():
    data = client.get("/api/v1/security/repairs", headers=ADMIN).json()
    assert {c["config"] for c in data["configs"]} == {"demo", "clinic"}
    assert "missing_resource_type" in data["faults"]["demo"]
