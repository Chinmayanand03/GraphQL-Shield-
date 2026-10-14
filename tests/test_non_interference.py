import os
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings
from app.seed import seed_database
from app.core.security import create_access_token

client = TestClient(app)

TEST_DB_URL = "sqlite:///./test_non_interference.db"


@pytest.fixture(autouse=True)
def non_interference_db():
    original_url = settings.DATABASE_URL
    settings.DATABASE_URL = TEST_DB_URL
    db_file = TEST_DB_URL.replace("sqlite:///", "")

    seed_database()
    yield

    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except PermissionError:
            pass
    settings.DATABASE_URL = original_url


def user_headers(user_id: int, role: str = "user"):
    token = create_access_token(user_id=user_id, role=role)
    return {"Authorization": f"Bearer {token}"}


def test_legitimate_single_resource_access_not_interfered():
    """Alice accessing her own authorized resource directly must succeed completely."""
    query = """
    query {
        resource(id: 101) {
            id
            name
            ownerId
        }
    }
    """
    response = client.post(
        "/graphql",
        json={"query": query},
        headers=user_headers(user_id=101, role="user"),
    )
    assert response.status_code == 200
    payload = response.json()
    assert "errors" not in payload
    assert payload["data"]["resource"]["id"] == 101
    assert payload["data"]["resource"]["name"] == "Balanilavan's Secret Note"
    assert payload["data"]["resource"]["ownerId"] == 101


def test_legitimate_children_traversal_not_interfered():
    """Alice accessing her folder and her own child resources must preserve all children."""
    query = """
    query {
        resource(id: 201) {
            id
            children {
                id
                name
                ownerId
            }
        }
    }
    """
    response = client.post(
        "/graphql",
        json={"query": query},
        headers=user_headers(user_id=101, role="user"),
    )
    assert response.status_code == 200
    payload = response.json()
    assert "errors" not in payload
    children = payload["data"]["resource"]["children"]
    child_ids = {c["id"] for c in children}
    assert {202, 203}.issubset(child_ids)


def test_admin_access_to_any_resource_not_interfered():
    """Admin must be able to query any user's resource without gateway or guard interference."""
    for resource_id in [101, 102, 103, 104]:
        query = f"""
        query {{
            resource(id: {resource_id}) {{
                id
                name
                ownerId
            }}
        }}
        """
        response = client.post(
            "/graphql",
            json={"query": query},
            headers=user_headers(user_id=104, role="admin"),
        )
        assert response.status_code == 200
        payload = response.json()
        assert "errors" not in payload
        assert payload["data"]["resource"]["id"] == resource_id


def test_insecure_endpoint_not_interfered():
    """Vulnerable comparison baseline (/graphql-insecure) must remain unconstrained."""
    # Alice querying Bob's document directly on the insecure endpoint
    query = """
    query {
        resource(id: 102) {
            id
            name
            ownerId
        }
    }
    """
    response = client.post(
        "/graphql-insecure",
        json={"query": query},
        headers=user_headers(user_id=101, role="user"),
    )
    assert response.status_code == 200
    payload = response.json()
    assert "errors" not in payload
    assert payload["data"]["resource"]["id"] == 102
    assert payload["data"]["resource"]["ownerId"] == 102


def test_graphql_introspection_not_interfered():
    """Schema introspection queries must pass cleanly through the gateway."""
    query = """
    query {
        __schema {
            queryType {
                name
            }
        }
    }
    """
    response = client.post(
        "/graphql",
        json={"query": query},
        headers=user_headers(user_id=101, role="user"),
    )
    assert response.status_code == 200
    payload = response.json()
    assert "errors" not in payload
    assert payload["data"]["__schema"]["queryType"]["name"] == "Query"


def test_rest_endpoints_not_interfered():
    """Non-GraphQL REST routes must operate without interference."""
    # Health check
    health_res = client.get("/health")
    assert health_res.status_code == 200
    assert health_res.json()["status"] == "ok"

    # Dashboard stats
    stats_res = client.get("/api/v1/dashboard-stats")
    assert stats_res.status_code == 200
    data = stats_res.json()
    assert "stats" in data
    assert "total" in data["stats"]

    # Dashboard HTML
    dash_res = client.get("/dashboard")
    assert dash_res.status_code == 200
    assert "<!doctype html>" in dash_res.text.lower()
