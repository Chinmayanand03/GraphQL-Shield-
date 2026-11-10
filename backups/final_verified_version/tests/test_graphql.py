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

def test_graphql_user_query():
    token = create_access_token(user_id=101, role="user")
    query = """
    query {
        user(id: 101) {
            id
            username
        }
    }
    """
    response = client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["data"]["user"]["id"] == 101
    assert data["data"]["user"]["username"] == "alice"

def test_graphql_resource_query():
    token = create_access_token(user_id=102, role="user")
    query = """
    query {
        resource(id: 102) {
            id
            name
            ownerId
        }
    }
    """
    response = client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["data"]["resource"]["id"] == 102
    assert data["data"]["resource"]["ownerId"] == 102
    assert data["data"]["resource"]["name"] == "Bob's Financial Record"

def test_graphql_nested_relationship():
    token = create_access_token(user_id=101, role="user")
    query = """
    query {
        user(id: 101) {
            username
            resources {
                id
                name
                children {
                    id
                    name
                }
            }
        }
    }
    """
    response = client.post("/graphql", json={"query": query}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()["data"]["user"]
    assert data["username"] == "alice"
    
    # Alice should have multiple resources. One of them is a folder (id: 201) with children.
    resources = data["resources"]
    assert len(resources) > 0
    
    folder = next((r for r in resources if r["id"] == 201), None)
    assert folder is not None
    assert folder["name"] == "Alice's Projects"
    
    # Check children inside folder
    children = folder["children"]
    assert len(children) == 2
    assert any(c["id"] == 202 for c in children)
