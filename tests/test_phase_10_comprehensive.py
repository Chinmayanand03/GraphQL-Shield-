import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import get_db_connection
from app.seed import seed_database
from app.config import settings
from app.core.security import create_access_token
from datetime import timedelta
import os

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_test_db():
    original_url = settings.DATABASE_URL
    settings.DATABASE_URL = "sqlite:///./test_shield.db"
    seed_database()
    yield
    db_file = settings.DATABASE_URL.replace("sqlite:///", "")
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except PermissionError:
            pass
    settings.DATABASE_URL = original_url

# ================= AUTHENTICATION =================
def test_01_valid_jwt():
    token = create_access_token(user_id=101, role="user")
    res = client.get("/api/v1/protected", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200

def test_02_missing_jwt():
    res = client.get("/api/v1/protected")
    assert res.status_code in (401, 403)

def test_03_invalid_jwt():
    res = client.get("/api/v1/protected", headers={"Authorization": "Bearer invalid"})
    assert res.status_code == 401

def test_04_expired_jwt():
    token = create_access_token(user_id=101, role="user", expires_delta=timedelta(seconds=-1))
    res = client.get("/api/v1/protected", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401

# ================= AUTHORIZATION =================
def test_05_user_accessing_own_object():
    token = create_access_token(user_id=101, role="user")
    query = "{ resource(id: 101) { name } }"
    res = client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200

def test_06_user_accessing_another_users_object():
    token = create_access_token(user_id=101, role="user")
    query = "{ resource(id: 102) { name } }"
    res = client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code in (401, 403)

def test_07_admin_access():
    token = create_access_token(user_id=103, role="admin")
    query = "{ resource(id: 102) { name } }"
    res = client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200

def test_08_unauthorized_role_access():
    token = create_access_token(user_id=101, role="user")
    res = client.get("/api/v1/audit-logs", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code in (401, 403)

# ================= BOLA =================
def test_09_direct_object_id_manipulation():
    token = create_access_token(user_id=101, role="user")
    query = "{ resource(id: 103) { name } }" # Charlie's resource
    res = client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code in (401, 403)
    assert res.json()["detail"]["reason"] == "OWNERSHIP_MISMATCH"

def test_10_multiple_object_ids():
    token = create_access_token(user_id=101, role="user")
    # Mixing an authorized object (101) with an unauthorized object (102)
    query = "{ r1: resource(id: 101) { name } r2: resource(id: 102) { name } }"
    res = client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403 # Entire payload should be instantly rejected

def test_11_nested_bola():
    token = create_access_token(user_id=101, role="user")
    query = "{ user(id: 101) { resource(id: 102) { name } } }"
    res = client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code in (401, 403)
    assert res.json()["detail"]["reason"] == "NESTED_AUTHORIZATION_VIOLATION"

def test_12_bola_through_variables():
    token = create_access_token(user_id=101, role="user")
    query = "query($resId: Int!) { resource(id: $resId) { name } }"
    variables = {"resId": 102}
    res = client.post("/graphql", json={"query": query, "variables": variables}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code in (401, 403)

def test_13_bola_through_fragments():
    token = create_access_token(user_id=101, role="user")
    query = "fragment X on Query { resource(id: 102) { name } } query { ...X }"
    res = client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code in (401, 403)

# ================= GRAPHQL =================
def test_14_valid_query():
    token = create_access_token(user_id=101, role="user")
    query = "{ user(id: 101) { username } }"
    res = client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200

def test_15_invalid_query():
    token = create_access_token(user_id=101, role="user")
    query = "{"
    res = client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    # GraphQL typically returns 200 with an "errors" payload for syntax errors
    assert "errors" in res.json()

def test_16_unsupported_query_structure():
    token = create_access_token(user_id=101, role="user")
    query = "{ __schema { queryType { name } } }"
    res = client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200 # Allowed through gateway since no protected objects identified

# ================= ENFORCEMENT =================
def test_17_authorized_request_reaches_backend():
    token = create_access_token(user_id=101, role="user")
    query = "{ resource(id: 101) { name } }"
    res = client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert "data" in res.json()

def test_18_unauthorized_request_does_not_reach_backend():
    token = create_access_token(user_id=101, role="user")
    query = "{ resource(id: 102) { name } }"
    res = client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    # If it reached the backend, it would return standard GraphQL format "data" / "errors"
    # Because it is blocked at the gateway, it returns FastAPI's "detail"
    assert "detail" in res.json()
    assert "data" not in res.json()

def test_19_unauthorized_request_returns_http_403():
    token = create_access_token(user_id=101, role="user")
    query = "{ resource(id: 102) { name } }"
    res = client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code in (401, 403)

# ================= AUDIT =================
def test_20_denied_request_creates_audit_event():
    token = create_access_token(user_id=101, role="user")
    query = "{ resource(id: 102) { name } }"
    client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 1")
    log = dict(c.fetchone())
    conn.close()
    
    assert log["decision"] == "DENY"
    assert log["risk_level"] == "HIGH"

def test_21_allowed_request_creates_audit_event():
    token = create_access_token(user_id=101, role="user")
    query = "{ resource(id: 101) { name } }"
    client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 1")
    log = dict(c.fetchone())
    conn.close()
    
    assert log["decision"] == "ALLOW"
    assert log["risk_level"] == "LOW"
