import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app import config
from app.config import settings
from app.core.passwords import hash_password, verify_password
from app.core.security import create_access_token
from app.graphql.mutations import MUTATION_TARGETS
from app.graphql.schema import schema
from app.main import app
from app.seed import seed_database

client = TestClient(app)

DEMO_ACCOUNTS = ["balanilavan", "kapilesh", "sakthivel", "chinmayanand"]


@pytest.fixture(autouse=True)
def setup_test_db():
    original_url = settings.DATABASE_URL
    settings.DATABASE_URL = "sqlite:///./test_hardening.db"
    seed_database()
    yield
    db_file = settings.DATABASE_URL.replace("sqlite:///", "")
    settings.DATABASE_URL = original_url
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except PermissionError:
            pass


def headers(user_id=101, role="user"):
    return {"Authorization": f"Bearer {create_access_token(user_id=user_id, role=role)}"}


def audit_rows():
    conn = sqlite3.connect("test_hardening.db")
    try:
        return conn.execute("SELECT object_id, layer FROM audit_logs").fetchall()
    finally:
        conn.close()


# ---------------------------------------------------------------- passwords

def test_password_hash_round_trip():
    stored = hash_password("balanilavan123")
    assert stored.startswith("pbkdf2_sha256$")
    assert "balanilavan123" not in stored
    assert verify_password("balanilavan123", stored)
    assert not verify_password("wrong", stored)
    assert not verify_password("balanilavan123", "hash_balanilavan123")


@pytest.mark.parametrize("username", DEMO_ACCOUNTS)
def test_every_demo_account_uses_username_123(username):
    response = client.post("/api/v1/auth/login", json={"username": username, "password": f"{username}123"})
    assert response.status_code == 200


@pytest.mark.parametrize("username,password", [
    ("bala", "balanilavan123"),
    ("balanilavan", "bala123"),
    ("kapil", "kapil123"),
    ("chinmay", "chinmay123"),
])
def test_short_aliases_no_longer_log_in(username, password):
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 401


# ---------------------------------------------------------------- data exposure

def test_dashboard_stats_hides_audit_rows_without_admin_token():
    client.post("/graphql", json={"query": "{ resource(id: 101) { id } }"}, headers=headers())
    for request_headers in ({}, headers(101, "user")):
        data = client.get("/api/v1/dashboard-stats", headers=request_headers).json()
        assert data["recent_logs"] == []
        assert data["recent_logs_restricted"] is True
        assert data["stats"]["total"] >= 1


def test_dashboard_stats_shows_audit_rows_to_admin():
    client.post("/graphql", json={"query": "{ resource(id: 101) { id } }"}, headers=headers())
    data = client.get("/api/v1/dashboard-stats", headers=headers(104, "admin")).json()
    assert data["recent_logs_restricted"] is False
    assert data["recent_logs"]


def test_layer_events_hidden_without_admin_token():
    client.post("/graphql", json={"query": "{ resource(id: 102) { id } }"}, headers=headers())
    public = client.get("/api/v1/security/layers").json()
    assert public["recent"] == [] and public["recent_restricted"] is True
    assert public["counts"].get("L1_BLOCKED", 0) >= 1
    admin = client.get("/api/v1/security/layers", headers=headers(104, "admin")).json()
    assert admin["recent"]


# ---------------------------------------------------------------- audit counting

def test_allowed_object_is_audited_once_per_request():
    client.post("/graphql", json={"query": "{ resource(id: 101) { id } }"}, headers=headers())
    assert audit_rows() == [(101, "L1")]


def test_object_only_layer2_sees_is_audited_by_layer2():
    client.post("/graphql", json={"query": "{ resource(id: 201) { id children { id } } }"}, headers=headers())
    rows = audit_rows()
    assert (201, "L1") in rows
    assert (202, "L2") in rows and (203, "L2") in rows
    assert len(rows) == 3


# ---------------------------------------------------------------- mutations

def test_every_mutation_has_a_registered_ownership_target():
    mutation_type = schema._schema.mutation_type
    assert set(mutation_type.fields) == set(MUTATION_TARGETS)
    for field_name, (argument, _) in MUTATION_TARGETS.items():
        assert argument in mutation_type.fields[field_name].args


def test_transfer_to_missing_user_is_rejected():
    response = client.post(
        "/graphql",
        json={"query": "mutation { transferOwnership(id: 101, newOwnerId: 999) { id ownerId } }"},
        headers=headers(),
    )
    payload = response.json()
    assert payload["errors"][0]["message"] == "User 999 does not exist."
    conn = sqlite3.connect("test_hardening.db")
    try:
        assert conn.execute("SELECT owner_id FROM objects WHERE id = 101").fetchone()[0] == 101
    finally:
        conn.close()


# ---------------------------------------------------------------- query limits

def test_query_depth_limit():
    depth = settings.MAX_QUERY_DEPTH + 1
    query = "{ resource(id: 201) { " + "children { " * depth + "id" + " }" * depth + " } }"
    response = client.post("/graphql", json={"query": query}, headers=headers())
    assert "exceeds maximum operation depth" in response.json()["errors"][0]["message"]


def test_alias_limit():
    aliases = " ".join(f"a{i}: health {{ status }}" for i in range(settings.MAX_QUERY_ALIASES + 1))
    response = client.post("/graphql", json={"query": "{ " + aliases + " }"}, headers=headers())
    assert "aliases found" in response.json()["errors"][0]["message"]


# ---------------------------------------------------------------- configuration

def test_production_refuses_development_secret(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "JWT_SECRET", config.DEV_JWT_SECRET)
    with pytest.raises(RuntimeError):
        config.check_production_settings()
    monkeypatch.setattr(settings, "JWT_SECRET", "a-real-secret")
    config.check_production_settings()


def test_risky_demo_switches_are_off_by_default():
    defaults = config.Settings.model_fields
    assert defaults["ENABLE_INSECURE_BASELINE"].default is False
    assert defaults["ENABLE_LAYER_TOGGLE"].default is False
