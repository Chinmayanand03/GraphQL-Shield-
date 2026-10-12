import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.security import create_access_token
from datetime import timedelta
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

def test_login_success():
    response = client.post("/api/v1/auth/login", json={"username": "alice", "password": "alice123"})
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"

def test_login_failure():
    response = client.post("/api/v1/auth/login", json={"username": "alice", "password": "wrong"})
    assert response.status_code == 401

def test_protected_valid_token():
    # Login to get token
    response = client.post("/api/v1/auth/login", json={"username": "alice", "password": "alice123"})
    token = response.json()["access_token"]
    
    # Access protected route
    protected_resp = client.get("/api/v1/protected", headers={"Authorization": f"Bearer {token}"})
    assert protected_resp.status_code == 200
    data = protected_resp.json()
    assert data["user"]["user_id"] == 101
    assert data["user"]["role"] == "user"

def test_protected_missing_token():
    protected_resp = client.get("/api/v1/protected")
    assert protected_resp.status_code in (401, 403)  # HTTPBearer default for missing credentials

def test_protected_invalid_token():
    protected_resp = client.get("/api/v1/protected", headers={"Authorization": "Bearer not.a.valid.token"})
    assert protected_resp.status_code == 401
    assert "Invalid token" in protected_resp.json()["detail"]

def test_protected_expired_token():
    # Create manually expired token for User 101
    token = create_access_token(user_id=101, role="user", expires_delta=timedelta(seconds=-1))
    protected_resp = client.get("/api/v1/protected", headers={"Authorization": f"Bearer {token}"})
    assert protected_resp.status_code == 401
    assert "expired" in protected_resp.json()["detail"].lower()
