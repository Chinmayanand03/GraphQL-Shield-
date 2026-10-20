from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.core.security import create_access_token
from app.database import get_db_connection
from app.main import app
from app.seed import seed_database
from app.security.dynamic_verifier import AccessObservation, _compare


RELATIONSHIP_QUERY = """
query RelationshipBOLA {
  resource(id: 201) {
    id
    children { id name ownerId parentId }
  }
}
"""


@pytest.fixture
def relationship_client(tmp_path, monkeypatch):
    """Seed a foreign-owned child beneath Balanilavan's otherwise authorized folder."""
    db_path = tmp_path / "relationship_auth_regression.db"
    monkeypatch.setattr(settings, "DATABASE_URL", f"sqlite:///{db_path}")
    seed_database()

    conn = get_db_connection()
    try:
        conn.execute("UPDATE objects SET parent_id = ? WHERE id = ?", (201, 102))
        conn.commit()
    finally:
        conn.close()

    with TestClient(app) as client:
        yield client


def _observation(outcome: str, *, endpoint: str = "/graphql", visible: bool = True) -> AccessObservation:
    statuses = {"BLOCKED": 403, "EXPOSED_CONFIRMED": 200, "NOT_EXPOSED": 200, "POSSIBLE_EXPOSURE": 200, "INCONCLUSIVE": 500}
    return AccessObservation(
        endpoint=endpoint,
        http_status=statuses[outcome],
        outcome=outcome,
        target_id_observed=visible,
        response_path_found=True,
    )


def test_legitimate_control_is_not_counted_as_a_protection_failure():
    exposed = _observation("EXPOSED_CONFIRMED")
    assert _compare(exposed, exposed, expected_authorized=True) == "LEGITIMATE_ACCESS_PRESERVED"
    assert _compare(exposed, _observation("BLOCKED", visible=False), expected_authorized=True) == "UNEXPECTED_PROTECTED_DENIAL"


def test_bola_verdict_distinguishes_blocking_from_field_level_target_absence():
    exposed = _observation("EXPOSED_CONFIRMED")
    assert _compare(exposed, _observation("BLOCKED", visible=False), expected_authorized=False) == "PROTECTION_VERIFIED"
    assert _compare(exposed, _observation("NOT_EXPOSED", visible=False), expected_authorized=False) == "PROTECTION_VERIFIED_BY_TARGET_ABSENCE"
    assert _compare(exposed, exposed, expected_authorized=False) == "PROTECTION_FAILED_CONFIRMED"


def test_protected_children_filters_foreign_owned_child_but_keeps_owned_children(relationship_client):
    token = create_access_token(user_id=101, role="user")
    headers = {"Authorization": f"Bearer {token}"}

    baseline = relationship_client.post(
        "/graphql-insecure", json={"query": RELATIONSHIP_QUERY}, headers=headers
    )
    protected = relationship_client.post(
        "/graphql", json={"query": RELATIONSHIP_QUERY}, headers=headers
    )

    assert baseline.status_code == 200
    baseline_children = baseline.json()["data"]["resource"]["children"]
    assert {child["id"] for child in baseline_children} == {102, 202, 203}

    assert protected.status_code == 200
    protected_children = protected.json()["data"]["resource"]["children"]
    assert {child["id"] for child in protected_children} == {202, 203}
    assert all(child["ownerId"] == 101 for child in protected_children)


def test_admin_can_still_read_foreign_owned_child(relationship_client):
    token = create_access_token(user_id=103, role="admin")
    response = relationship_client.post(
        "/graphql",
        json={"query": RELATIONSHIP_QUERY},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    children = response.json()["data"]["resource"]["children"]
    assert 102 in {child["id"] for child in children}
