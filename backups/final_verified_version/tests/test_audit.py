import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import get_db_connection
from app.core.security import create_access_token
from app.seed import seed_database
from app.config import settings
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

def test_audit_logging_allow():
    token = create_access_token(user_id=101, role="user")
    query = "query { resource(id: 101) { name } }"
    client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs WHERE user_id = 101 AND object_id = 101 ORDER BY id DESC LIMIT 1")
    log = dict(cursor.fetchone())
    conn.close()
    
    assert log["decision"] == "ALLOW"
    assert log["reason"] == "OWNER_MATCH"
    assert log["timestamp"] is not None
    assert log["object_type"] == "Resource"
    assert log["path"] == "resource"
    assert log["risk_level"] == "LOW"

def test_audit_logging_deny():
    token = create_access_token(user_id=101, role="user")
    query = "query { resource(id: 102) { name } }"
    client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs WHERE user_id = 101 AND object_id = 102 ORDER BY id DESC LIMIT 1")
    log = dict(cursor.fetchone())
    conn.close()
    
    assert log["decision"] == "DENY"
    assert log["reason"] == "OWNERSHIP_MISMATCH"
    assert log["risk_level"] == "HIGH"
    assert log["risk_score"] >= 80

def test_audit_log_endpoint():
    # Attempt as normal user -> 403
    token = create_access_token(user_id=101, role="user")
    res = client.get("/api/v1/audit-logs", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403
    
    # Attempt as admin -> 200
    admin_token = create_access_token(user_id=103, role="admin")
    res2 = client.get("/api/v1/audit-logs", headers={"Authorization": f"Bearer {admin_token}"})
    assert res2.status_code == 200
    assert "logs" in res2.json()
    assert isinstance(res2.json()["logs"], list)
