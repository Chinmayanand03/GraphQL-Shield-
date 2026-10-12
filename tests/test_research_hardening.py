from app.benchmarks.attack_variants import generate_variants_from_findings
from app.benchmarks.ground_truth import evaluate_ground_truth, label_case_with_oracle
from app.security.relationship_extractor import (
    extract_relationship_paths,
    resolve_relationship_objects,
)


OBJECTS = {
    "Resource": {
        "201": {"id": 201, "type": "Resource", "owner_id": 101, "children": [202, 203]},
        "202": {"id": 202, "type": "Resource", "owner_id": 101},
        "203": {"id": 203, "type": "Resource", "owner_id": 102},
        "204": {"id": 204, "type": "Resource", "owner_id": 102},
    }
}


def test_ground_truth_uses_ownership_not_existing_label_or_scenario():
    case = {
        "principal_id": 101,
        "target_object_id": 204,
        "target_object_type": "Resource",
        "scenario": "direct_legitimate",
        "is_bola": False,
    }
    labels = label_case_with_oracle(case, OBJECTS)
    assert labels["ground_truth_authorized"] is False
    assert labels["ground_truth_is_bola"] is True
    assert labels["ground_truth_reason"] == "object_owned_by_another_subject"


def test_ground_truth_allows_owner_and_admin():
    owner = evaluate_ground_truth(101, 202, "Resource", OBJECTS)
    admin = evaluate_ground_truth(999, 204, "Resource", OBJECTS, subject_role="admin")
    assert owner.authorized is True
    assert admin.authorized is True


def test_ground_truth_fails_closed_when_owner_unknown():
    decision = evaluate_ground_truth(101, 999, "Resource", OBJECTS)
    assert decision.authorized is False
    assert decision.is_bola is False
    assert decision.reason == "unknown_ownership_denied"


def test_implicit_relationship_query_is_extracted_and_resolved():
    query = """
    query ReadChildren($parentId: ID!) {
      resource(id: $parentId) {
        children { id name ownerId }
      }
    }
    """
    paths = extract_relationship_paths(query, {"parentId": 201})
    assert len(paths) == 1
    access = paths[0]
    assert access.parent_field == "resource"
    assert access.relation_field == "children"
    assert access.parent_id == 201
    assert access.response_path == ("resource", "children")

    children = resolve_relationship_objects(access, OBJECTS)
    assert [int(child["id"]) for child in children] == [202, 203]


def test_relationship_extractor_supports_relationship_map():
    query = "query Q($parentId: ID!) { resource(id: $parentId) { children { id } } }"
    access = extract_relationship_paths(query, {"parentId": 201})[0]
    children = resolve_relationship_objects(access, {}, {(201, "children"): [202, 203]})
    assert [int(child["id"]) for child in children] == [202, 203]


def test_attack_variants_have_unique_ids_and_mutate_target_variables():
    finding = {
        "finding_id": "finding-1",
        "query": "query Q($objectId: ID!) { resource(id: $objectId) { id ownerId } }",
        "variables": {"objectId": 201},
        "principal_id": 101,
        "target_object_id": 201,
        "target_object_type": "Resource",
        "target_response_path": ["resource"],
        # Conflicting existing labels must not control the independent oracle.
        "is_bola": True,
        "expected_authorized": True,
    }
    variants = generate_variants_from_findings([finding], OBJECTS, variants_per_finding=3)
    assert len(variants) == 3
    assert len({variant.variant_id for variant in variants}) == len(variants)
    assert variants[0].expected_authorized is True
    assert variants[1].variables["objectId"] == 202
    assert variants[1].expected_authorized is True
    assert variants[2].variables["objectId"] == 203
    assert variants[2].expected_authorized is False


def test_missing_query_is_skipped_instead_of_inventing_schema():
    variants = generate_variants_from_findings([{"finding_id": "no-query"}], OBJECTS)
    assert variants == []
