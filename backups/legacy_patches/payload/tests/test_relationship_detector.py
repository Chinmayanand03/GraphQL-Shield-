from __future__ import annotations

from app.benchmarks.relationship_detector import detect_implicit_relationship_bola


QUERY = """
query RelationshipProbe($parentId: Int!) {
  resource(id: $parentId) {
    id
    children { id name ownerId parentId }
  }
}
"""


CATALOG = {
    "Resource": {
        "101": {"id": 101, "type": "Resource", "owner_id": 101, "object_type": "document", "parent_id": None},
        "102": {"id": 102, "type": "Resource", "owner_id": 102, "object_type": "document", "parent_id": 201},
        "201": {"id": 201, "type": "Resource", "owner_id": 101, "object_type": "folder", "parent_id": None},
        "202": {"id": 202, "type": "Resource", "owner_id": 101, "object_type": "document", "parent_id": 201},
        "203": {"id": 203, "type": "Resource", "owner_id": 101, "object_type": "document", "parent_id": 201},
        "204": {"id": 204, "type": "Resource", "owner_id": 102, "object_type": "folder", "parent_id": None},
        "205": {"id": 205, "type": "Resource", "owner_id": 102, "object_type": "document", "parent_id": 204},
        "206": {"id": 206, "type": "Resource", "owner_id": 102, "object_type": "document", "parent_id": 204},
    },
}


def test_flags_foreign_owned_child_under_authorized_parent():
    result = detect_implicit_relationship_bola(
        QUERY, {"parentId": 201}, principal_id=101, role="user", object_catalog=CATALOG
    )
    assert result["detected"] is True
    assert result["analysis_status"] == "ok"
    assert result["unauthorized_child_ids"] == ["102"]
    assert result["relationship_path_count"] == 1


def test_does_not_flag_relationship_with_only_owned_children():
    result = detect_implicit_relationship_bola(
        QUERY, {"parentId": 204}, principal_id=102, role="user", object_catalog=CATALOG
    )
    assert result["detected"] is False
    assert result["unauthorized_child_ids"] == []
    assert result["resolved_child_count"] == 2


def test_administrator_relationship_access_is_not_flagged():
    result = detect_implicit_relationship_bola(
        QUERY, {"parentId": 201}, principal_id=103, role="admin", object_catalog=CATALOG
    )
    assert result["detected"] is False
    assert result["analysis_status"] == "administrator_bypass"


def test_unknown_child_owner_is_reported_as_inconclusive_not_confirmed_bola():
    incomplete = {
        "Resource": {
            "201": {"id": 201, "type": "Resource", "owner_id": 101, "parent_id": None},
            "207": {"id": 207, "type": "Resource", "parent_id": 201},
        }
    }
    result = detect_implicit_relationship_bola(
        QUERY, {"parentId": 201}, principal_id=101, role="user", object_catalog=incomplete
    )
    assert result["detected"] is False
    assert result["unknown_owner_child_ids"] == ["207"]
    assert result["analysis_status"] == "inconclusive_unknown_child_ownership"


def test_generated_relationship_scenarios_have_aligned_detection_and_labels():
    from app.benchmarks.dataset import generate_dataset

    cases = generate_dataset(count=250, seed=20261011)
    relationship_cases = [case for case in cases if case.scenario.startswith("relationship_")]
    assert relationship_cases

    for case in relationship_cases:
        result = detect_implicit_relationship_bola(
            case.query,
            case.variables,
            principal_id=case.principal_id,
            role=case.role,
        )
        if case.scenario == "relationship_bola":
            assert case.is_bola is True
            assert result["detected"] is True
        else:
            assert case.scenario == "relationship_legitimate"
            assert case.is_bola is False
            assert result["detected"] is False
