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

def test_nested_authorization_violation_deny():
    # User 101 (Alice) logs in
    token = create_access_token(user_id=101, role="user")
    
    # Alice requests her own user, but attempts to fetch Bob's resource (102) through it
    query = """
    query {
        user(id: 101) {
            username
            resource(id: 102) {
                name
            }
        }
    }
    """
    
    response = client.post(
        "/graphql", 
        json={"query": query},
        headers={"Authorization": f"Bearer {token}"}
    )
    
    # Expected: DENY, HTTP 403, NESTED_AUTHORIZATION_VIOLATION
    assert response.status_code == 403
    data = response.json()
    assert data["detail"]["decision"] == "DENY"
    assert data["detail"]["reason"] == "NESTED_AUTHORIZATION_VIOLATION"
    assert data["detail"]["user_id"] == 101
    assert data["detail"]["object_id"] == 102

def test_nested_authorization_allow():
    # User 101 (Alice) logs in
    token = create_access_token(user_id=101, role="user")
    
    # Alice requests her own user, and her own resource (101) through it
    query = """
    query {
        user(id: 101) {
            username
            resource(id: 101) {
                name
            }
        }
    }
    """
    
    response = client.post(
        "/graphql", 
        json={"query": query},
        headers={"Authorization": f"Bearer {token}"}
    )
    
    # Expected: ALLOW, HTTP 200, Backend Resolves properly
    assert response.status_code == 200
    data = response.json()
    assert data["data"]["user"]["username"] == "alice"
    assert data["data"]["user"]["resource"]["name"] == "Alice's Secret Note"
