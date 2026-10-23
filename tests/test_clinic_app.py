"""The clinic application (schema-first graphql-core, global IDs, dict resolvers) under the same
two layers as the demo application, configured only through CLINIC_CONFIG."""
import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.clinic.data import init_clinic, to_global_id
from app.config import settings
from app.core.security import create_access_token
from app.main import app
from app.security.layers import set_layers
from app.seed import seed_database

client = TestClient(app)
DB_FILE = "test_clinic.db"


@pytest.fixture(autouse=True)
def setup_db():
    original = settings.DATABASE_URL
    settings.DATABASE_URL = f"sqlite:///./{DB_FILE}"
    seed_database()
    init_clinic(reset=True)
    set_layers(True, True)
    yield
    set_layers(True, True)
    settings.DATABASE_URL = original
    if os.path.exists(DB_FILE):
        try:
            os.remove(DB_FILE)
        except PermissionError:
            pass


def gid(kind, raw):
    return to_global_id(kind, raw)


def post(query, user=101, role="user", path="/clinic/graphql"):
    token = create_access_token(user_id=user, role=role)
    return client.post(path, json={"query": query}, headers={"Authorization": f"Bearer {token}"})


def diagnosis(record_id):
    conn = sqlite3.connect(DB_FILE)
    try:
        row = conn.execute("SELECT diagnosis FROM clinic_records WHERE id = ?", (record_id,)).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def test_doctor_reads_own_patient():
    response = post(f'{{ patient(id: "{gid("Patient", 1)}") {{ name }} }}')
    assert response.status_code == 200
    assert response.json()["data"]["patient"]["name"] == "Asha Rao"


def test_foreign_patient_blocked_before_execution():
    response = post(f'{{ patient(id: "{gid("Patient", 2)}") {{ name }} }}')
    assert response.status_code == 403
    assert response.json()["detail"]["layer"] == "L1_PRE_EXECUTION"


def test_raw_and_global_ids_are_both_understood():
    assert post("{ patient(id: 2) { name } }").status_code == 403


def test_colleagues_record_is_filtered_from_own_patient():
    # Doctor 101 owns patient 1, but record 12 on that patient belongs to doctor 102.
    response = post(f'{{ patient(id: "{gid("Patient", 1)}") {{ records {{ id diagnosis }} }} }}')
    assert response.status_code == 200
    assert [r["id"] for r in response.json()["data"]["patient"]["records"]] == [gid("Record", 11)]


def test_nested_two_level_relationship_is_filtered():
    response = post(f'{{ record(id: "{gid("Record", 11)}") {{ prescriptions {{ id drug }} }} }}')
    assert [p["id"] for p in response.json()["data"]["record"]["prescriptions"]] == [gid("Prescription", 111)]


def test_reverse_relationship_to_foreign_parent_is_nulled():
    # Doctor 103 owns prescription 112 but not the record it hangs off.
    response = post(f'{{ prescription(id: "{gid("Prescription", 112)}") {{ drug record {{ diagnosis }} }} }}', user=103)
    data = response.json()["data"]["prescription"]
    assert data["drug"] == "Prednisolone" and data["record"] is None


def test_type_confused_global_id_is_checked_as_both_types():
    # A Prescription ID that doctor 101 owns, passed where a Record is expected.
    response = post(f'{{ record(id: "{gid("Prescription", 111)}") {{ diagnosis }} }}')
    assert response.status_code == 403


def test_foreign_update_never_executes():
    response = post(f'mutation {{ updateRecord(id: "{gid("Record", 21)}", diagnosis: "x") {{ id }} }}')
    assert response.status_code == 403
    assert diagnosis(21) == "Hypertension"


def test_create_on_foreign_patient_is_blocked():
    response = post(f'mutation {{ createRecord(patientId: "{gid("Patient", 2)}", diagnosis: "x") {{ id }} }}')
    assert response.status_code == 403


def test_create_on_own_patient_is_allowed():
    response = post(f'mutation {{ createRecord(patientId: "{gid("Patient", 1)}", diagnosis: "Follow-up") {{ diagnosis }} }}')
    assert response.status_code == 200
    assert response.json()["data"]["createRecord"]["diagnosis"] == "Follow-up"


def test_layer2_alone_blocks_foreign_write():
    set_layers(False, True)
    response = post(f'mutation {{ updateRecord(id: "{gid("Record", 21)}", diagnosis: "x") {{ id }} }}')
    assert response.json()["errors"][0]["extensions"]["code"] == "MUTATION_AUTHORIZATION_DENIED"
    assert diagnosis(21) == "Hypertension"


def test_layer2_alone_nulls_foreign_read():
    set_layers(False, True)
    response = post(f'{{ patient(id: "{gid("Patient", 2)}") {{ name }} }}')
    assert response.json()["data"]["patient"] is None


def test_admin_reads_everything():
    response = post(f'{{ patient(id: "{gid("Patient", 1)}") {{ records {{ id }} }} }}', user=104, role="admin")
    assert len(response.json()["data"]["patient"]["records"]) == 2


def test_insecure_baseline_leaks():
    response = post(f'{{ patient(id: "{gid("Patient", 1)}") {{ records {{ diagnosis }} }} }}',
                    path="/clinic/graphql-insecure")
    diagnoses = {r["diagnosis"] for r in response.json()["data"]["patient"]["records"]}
    assert "Cardiology second opinion" in diagnoses
