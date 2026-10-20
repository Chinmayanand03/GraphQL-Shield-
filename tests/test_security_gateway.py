import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.seed import seed_database
from app.config import settings
from app.core.security import create_access_token
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

def test_gateway_allow_own_object():
    # User 101 logs in
    token = create_access_token(user_id=101, role="user")
    
    query = """
    query GetResource($id: Int!) {
        resource(id: $id) {
            name
        }
    }
    """
    # Object 101 is owned by User 101 -> ALLOW
    response = client.post(
        "/graphql", 
        json={"query": query, "variables": {"id": 101}},
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["data"]["resource"]["name"] == "Balanilavan's Secret Note"

def test_gateway_deny_other_user_object():
    # User 101 logs in
    token = create_access_token(user_id=101, role="user")
    
    query = """
    query {
        resource(id: 102) {
            name
        }
    }
    """
    # Object 102 is owned by User 102 -> DENY
    response = client.post(
        "/graphql", 
        json={"query": query},
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 403
    data = response.json()
    assert data["detail"]["decision"] == "DENY"
    assert data["detail"]["reason"] == "OWNERSHIP_MISMATCH"
    assert data["detail"]["user_id"] == 101
    assert data["detail"]["object_id"] == 102

def test_gateway_deny_missing_jwt():
    query = """
    query {
        resource(id: 101) {
            name
        }
    }
    """
    response = client.post("/graphql", json={"query": query})
    assert response.status_code in (401, 403) # HTTPBearer returns 403 for missing credentials

def test_gateway_deny_invalid_jwt():
    query = """
    query {
        resource(id: 101) {
            name
        }
    }
    """
    response = client.post(
        "/graphql", 
        json={"query": query},
        headers={"Authorization": "Bearer not_a_real_token"}
    )
    assert response.status_code == 401
    assert "Invalid token" in response.json()["detail"]
