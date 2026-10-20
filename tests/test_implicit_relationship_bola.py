import os

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings
from app.database import get_db_connection
from app.seed import seed_database
from app.core.security import create_access_token


client = TestClient(app)

TEST_DATABASE_URL = "sqlite:///./test_implicit_relationship.db"


@pytest.fixture
def relationship_test_db():
    original_database_url = settings.DATABASE_URL
    settings.DATABASE_URL = TEST_DATABASE_URL
    db_path = TEST_DATABASE_URL.replace("sqlite:///", "")

    try:
        # Create isolated test data.
        seed_database()

        # Put Kapilesh's document beneath Balanilavan's folder.
        conn = get_db_connection()
        try:
            conn.execute(
                "UPDATE objects SET parent_id = ? WHERE id = ?",
                (201, 102),
            )
            conn.commit()
        finally:
            conn.close()

        yield

    finally:
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except PermissionError:
                pass

        settings.DATABASE_URL = original_database_url


def balanilavan_headers():
    token = create_access_token(user_id=101, role="user")
    return {"Authorization": f"Bearer {token}"}


RELATIONSHIP_QUERY = """
query {
    resource(id: 201) {
        id
        name
        children {
            id
            name
            ownerId
            parentId
        }
    }
}
"""


def test_insecure_endpoint_exposes_foreign_owned_child(
    relationship_test_db,
):
    response = client.post(
        "/graphql-insecure",
        json={"query": RELATIONSHIP_QUERY},
        headers=balanilavan_headers(),
    )

    assert response.status_code == 200, response.text

    payload = response.json()
    assert "errors" not in payload, payload

    children = payload["data"]["resource"]["children"]

    # The intentionally vulnerable endpoint returns Kapilesh's document.
    foreign_child = next(
        child for child in children if child["id"] == 102
    )

    assert foreign_child["ownerId"] == 102
    assert foreign_child["parentId"] == 201


def test_protected_endpoint_hides_foreign_owned_child(
    relationship_test_db,
):
    response = client.post(
        "/graphql",
        json={"query": RELATIONSHIP_QUERY},
        headers=balanilavan_headers(),
    )

    assert response.status_code == 200, response.text

    payload = response.json()
    assert "errors" not in payload, payload

    resource = payload["data"]["resource"]
    children = resource["children"]
    child_ids = {child["id"] for child in children}

    # Kapilesh's document must not be exposed to Balanilavan.
    assert 102 not in child_ids

    # Balanilavan's legitimate children must remain accessible.
    assert {202, 203}.issubset(child_ids)
