import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_rest_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "message": "FastAPI is running"}

from app.core.security import create_access_token

def test_graphql_health_check():
    token = create_access_token(user_id=101, role="user")
    query = """
    query {
        health {
            status
            message
        }
    }
    """
    response = client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert data["data"]["health"]["status"] == "ok"
