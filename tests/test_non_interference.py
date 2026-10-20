import os
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings
from app.database import get_db_connection
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
    """Balanilavan accessing his own authorized resource directly must succeed completely."""
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
    """Balanilavan accessing his folder and his own child resources must preserve all children."""
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
    # Balanilavan querying Kapilesh's document directly on the insecure endpoint
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


# ============================================================
# PHASE 3: NON-INTERFERENCE PROPERTY TESTS
# ============================================================

PHASE3_RELATIONSHIP_QUERY = """
query Phase3FolderChildren {
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


def set_kapilesh_document_state(name: str) -> None:
    """
    Change only the name of document 102 and ensure it is nested
    under Balanilavan's folder 201.

    This runs against the isolated test database configured by
    the non_interference_db fixture.
    """
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            """
            UPDATE objects
            SET parent_id = ?, name = ?
            WHERE id = ?
            """,
            (201, name, 102),
        )

        assert cursor.rowcount == 1, (
            "Expected document 102 to exist in the test database"
        )

        conn.commit()
    finally:
        conn.close()


def query_folder_children(endpoint: str) -> dict:
    """Execute Balanilavan's identical query against an endpoint."""
    response = client.post(
        endpoint,
        json={"query": PHASE3_RELATIONSHIP_QUERY},
        headers=user_headers(user_id=101, role="user"),
    )

    assert response.status_code == 200, response.text

    payload = response.json()
    assert "errors" not in payload, payload
    assert payload.get("data") is not None, payload
    assert payload["data"]["resource"] is not None, payload

    return payload["data"]


def normalize_folder_response(data: dict) -> dict:
    """
    Normalize the observable response so child ordering does not
    create a false difference between the two database states.
    """
    folder = data["resource"]

    children = [
        {
            "id": child["id"],
            "name": child["name"],
            "ownerId": child["ownerId"],
            "parentId": child["parentId"],
        }
        for child in folder["children"]
    ]

    return {
        "resource": {
            "id": folder["id"],
            "name": folder["name"],
            "children": sorted(
                children,
                key=lambda item: item["id"],
            ),
        }
    }


def test_protected_response_is_independent_of_foreign_secret_change():
    """
    Property: changing the name of another user's document should
    not change Balanilavan's authorized response through /graphql.
    """
    # State A: original confidential value.
    set_kapilesh_document_state("CONFIDENTIAL_STATE_A")

    data_before = query_folder_children("/graphql")
    before_ids = {
        child["id"]
        for child in data_before["resource"]["children"]
    }

    # Authorized children are visible; Kapilesh's child is not.
    assert {202, 203}.issubset(before_ids)
    assert 102 not in before_ids

    # State B: change only the foreign document's name.
    set_kapilesh_document_state("CONFIDENTIAL_STATE_B")

    data_after = query_folder_children("/graphql")
    after_ids = {
        child["id"]
        for child in data_after["resource"]["children"]
    }

    assert {202, 203}.issubset(after_ids)
    assert 102 not in after_ids

    # Balanilavan must observe the same authorized result.
    assert normalize_folder_response(
        data_before
    ) == normalize_folder_response(data_after)


def test_vulnerable_baseline_exposes_foreign_secret_change():
    """
    Negative control: /graphql-insecure should expose document
    102 and its changed name, demonstrating that this experiment
    can detect the targeted information leak.
    """
    # State A.
    set_kapilesh_document_state("CONFIDENTIAL_STATE_A")

    data_before = query_folder_children("/graphql-insecure")

    kapilesh_before = next(
        (
            child
            for child in data_before["resource"]["children"]
            if child["id"] == 102
        ),
        None,
    )

    assert kapilesh_before is not None
    assert kapilesh_before["name"] == "CONFIDENTIAL_STATE_A"
    assert kapilesh_before["ownerId"] == 102
    assert kapilesh_before["parentId"] == 201

    # State B.
    set_kapilesh_document_state("CONFIDENTIAL_STATE_B")

    data_after = query_folder_children("/graphql-insecure")

    kapilesh_after = next(
        (
            child
            for child in data_after["resource"]["children"]
            if child["id"] == 102
        ),
        None,
    )

    assert kapilesh_after is not None
    assert kapilesh_after["name"] == "CONFIDENTIAL_STATE_B"

    # The insecure observable response should differ.
    assert normalize_folder_response(
        data_before
    ) != normalize_folder_response(data_after)


# ============================================================
# Derived-value non-interference tests
# ============================================================

CHILDREN_COUNT_QUERY = """
query FolderChildCount {
    resource(id: 201) {
        id
        childrenCount
    }
}
"""


def set_foreign_child_attached(attached: bool) -> None:
    """Control whether foreign-owned document 102 is nested in folder 201."""
    parent_id = 201 if attached else None

    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "UPDATE objects SET parent_id = ? WHERE id = ?",
            (parent_id, 102),
        )
        assert cursor.rowcount == 1, "Expected document 102 to exist"
        conn.commit()
    finally:
        conn.close()


def query_children_count(endpoint: str) -> int:
    """Query the derived child count as Balanilavan (user 101)."""
    response = client.post(
        endpoint,
        json={"query": CHILDREN_COUNT_QUERY},
        headers=user_headers(user_id=101, role="user"),
    )

    assert response.status_code == 200, response.text

    payload = response.json()
    assert "errors" not in payload, payload

    return payload["data"]["resource"]["childrenCount"]


def test_protected_count_does_not_reveal_foreign_child():
    """
    Adding a foreign-owned child must not change the protected
    count returned to Balanilavan.
    """
    # State A: Kapilesh's document is attached to folder 201.
    set_foreign_child_attached(True)
    count_with_foreign_child = query_children_count("/graphql")

    # State B: The foreign-owned document is detached.
    set_foreign_child_attached(False)
    count_without_foreign_child = query_children_count("/graphql")

    assert count_with_foreign_child == 2
    assert count_without_foreign_child == 2
    assert count_with_foreign_child == count_without_foreign_child


def test_insecure_count_reveals_foreign_child():
    """
    Negative control: the vulnerable endpoint counts the foreign
    child and therefore reveals its presence through the count.
    """
    set_foreign_child_attached(True)
    count_with_foreign_child = query_children_count("/graphql-insecure")

    set_foreign_child_attached(False)
    count_without_foreign_child = query_children_count("/graphql-insecure")

    assert count_with_foreign_child == 3
    assert count_without_foreign_child == 2
    assert count_with_foreign_child != count_without_foreign_child

