from __future__ import annotations

import httpx

from app.benchmarks.attack_variants import generate_variants_from_findings, to_attack_cases
from app.benchmarks.dataset import generate_dataset
from app.benchmarks.evaluator import classify_http_response
from app.benchmarks.ground_truth import label_case_with_oracle
from app.benchmarks.research_hardening_integration import (
    build_resource_catalog,
    generate_relationship_probe_variants,
    label_cases_with_oracle,
)
from app.security.attack_generator import AttackCase
from app.security.dynamic_verifier import _observe_response


RELATIONSHIP_QUERY = """
query RelationshipTest($parentId: Int!) {
  resource(id: $parentId) {
    id name
    children { id name ownerId parentId }
  }
}
"""


def test_catalog_contains_foreign_owned_child_under_authorized_parent():
    catalog = build_resource_catalog()
    folder = catalog["Resource"]["201"]
    assert folder["owner_id"] == 101
    assert {int(value) for value in folder["children"]} == {102, 202, 203}
    assert catalog["Resource"]["102"]["owner_id"] == 102


def test_oracle_recomputes_labels_from_catalog_not_case_owner_or_label():
    catalog = build_resource_catalog()
    case = {
        "case_id": "conflicting-label",
        "query": RELATIONSHIP_QUERY,
        "variables": {"parentId": 201},
        "principal_id": 101,
        "role": "user",
        "target_id": 102,
        "target_type": "Resource",
        "target_owner_id": 101,  # Deliberately conflicts with catalog.
        "is_bola": False,
        "expected_authorized": True,
    }
    labelled = label_cases_with_oracle([case], catalog)[0]
    assert labelled["ground_truth_authorized"] is False
    assert labelled["ground_truth_is_bola"] is True
    assert labelled["is_bola"] is True
    assert labelled["expected_authorized"] is False
    assert labelled["ground_truth_reason"] == "object_owned_by_another_subject"


def test_relationship_probe_variants_cover_all_resolved_children():
    catalog = build_resource_catalog()
    case = {
        "case_id": "relationship-case",
        "query": RELATIONSHIP_QUERY,
        "variables": {"parentId": 201},
        "principal_id": 101,
        "role": "user",
        "scenario": "does_not_drive_oracle",
        "target_id": 102,
        "target_type": "Resource",
    }
    variants, stats = generate_relationship_probe_variants([case], catalog)
    by_target = {int(variant.target_object_id): variant for variant in variants}

    assert set(by_target) == {102, 202, 203}
    assert by_target[102].expected_authorized is False
    assert by_target[202].expected_authorized is True
    assert by_target[203].expected_authorized is True
    assert all(variant.target_response_path == ("resource", "children") for variant in variants)
    assert stats["relationship_probe_count"] == 3


def test_explicit_nested_id_is_not_mistaken_for_implicit_relationship():
    catalog = build_resource_catalog()
    case = {
        "case_id": "explicit-nested",
        "query": "query Q($userId: Int!, $resourceId: Int!) { user(id: $userId) { resource(id: $resourceId) { id name } } }",
        "variables": {"userId": 101, "resourceId": 102},
        "principal_id": 101,
        "role": "user",
    }
    variants, stats = generate_relationship_probe_variants([case], catalog)
    assert variants == []
    assert stats["relationship_probe_count"] == 0


def test_finding_variants_adapt_to_existing_attack_case():
    catalog = build_resource_catalog()
    finding = {
        "finding_id": "f-1",
        "query": "query Q($id: Int!) { resource(id: $id) { id name } }",
        "variables": {"id": 101},
        "principal_id": 101,
        "principal_role": "user",
        "target_object_id": 101,
        "target_object_type": "Resource",
        "target_response_path": "resource",
    }
    variants = generate_variants_from_findings([finding], catalog, variants_per_finding=4)
    attack_cases = to_attack_cases(variants, AttackCase)
    assert len(attack_cases) == 4
    assert len({case.case_id for case in attack_cases}) == 4
    assert all(case.query == finding["query"] for case in attack_cases)
    assert all(case.source_path == "resource" for case in attack_cases)


def test_dynamic_verifier_does_not_call_siblings_possible_target_exposure():
    case = AttackCase(
        case_id="rel-child-102",
        principal_id="101",
        action="read",
        query=RELATIONSHIP_QUERY,
        variables={"parentId": 201},
        operation_name="RelationshipTest",
        source_id="relationship:201:children",
        source_path="resource.children",
        source_kind="variable",
        target_type="Resource",
        target_id=102,
        target_owner_id=102,
        expected_authorized=False,
        reason="Implicit relationship target check",
    )
    response = httpx.Response(
        200,
        json={"data": {"resource": {"children": [{"id": 202}, {"id": 203}]}}},
    )
    observation = _observe_response(response, "/graphql", case)
    assert observation.outcome == "NOT_EXPOSED"
    assert observation.target_id_observed is False


def test_dataset_includes_oracle_labelled_implicit_relationship_cases():
    cases = generate_dataset(count=300, seed=20261011)
    relationship_cases = [case for case in cases if case.scenario.startswith("relationship_")]
    assert relationship_cases
    bola = [case for case in relationship_cases if case.scenario == "relationship_bola"]
    legit = [case for case in relationship_cases if case.scenario == "relationship_legitimate"]
    assert bola and legit
    assert all(
        case.is_bola and not case.expected_authorized and case.target_id == 102
        and case.principal_id == 101 and case.variables["parentId"] == 201
        for case in bola
    )
    assert all(
        not case.is_bola and case.expected_authorized and case.target_id in {205, 206}
        and case.principal_id == 102 and case.variables["parentId"] == 204
        for case in legit
    )


def test_benchmark_evaluator_does_not_treat_collection_siblings_as_target_exposure():
    response = httpx.Response(
        200,
        json={"data": {"resource": {"children": [{"id": 202}, {"id": 203}]}}},
    )
    result = classify_http_response(response, "resource.children", 102)
    assert result["outcome"] == "NOT_EXPOSED"
    assert result["target_confirmed"] is False
    assert result["target_exposed"] is False


def test_research_hardening_runner_replays_variants_and_relationships(tmp_path):
    catalog = build_resource_catalog()

    class FakeLocalClient:
        def post(self, path, *, json, headers):
            query = json.get("query", "")
            variables = json.get("variables") or {}
            principal = 101
            if "children" in query:
                children = [
                    {"id": child_id, "name": catalog["Resource"][str(child_id)]["name"]}
                    for child_id in catalog["Resource"]["201"]["children"]
                ]
                if path == "/graphql" and principal == 101:
                    children = [child for child in children if child["id"] != 102]
                return httpx.Response(200, json={"data": {"resource": {"children": children}}})

            target_id = int(variables.get("id", 101))
            owner_id = catalog["Resource"].get(str(target_id), {}).get("owner_id")
            if path == "/graphql" and owner_id != principal:
                return httpx.Response(403, json={"detail": "forbidden"})
            return httpx.Response(200, json={"data": {"resource": {"id": target_id, "name": "test"}}})

    finding = {
        "finding_id": "f-integration",
        "query": "query Q($id: Int!) { resource(id: $id) { id name } }",
        "variables": {"id": 101},
        "principal_id": 101,
        "principal_role": "user",
        "target_object_id": 101,
        "target_object_type": "Resource",
        "target_response_path": "resource",
    }
    relationship_case = {
        "case_id": "relationship-integration",
        "query": RELATIONSHIP_QUERY,
        "variables": {"parentId": 201},
        "principal_id": 101,
        "role": "user",
        "target_id": 102,
        "target_type": "Resource",
        "is_bola": True,
        "expected_authorized": False,
    }

    from app.benchmarks.research_hardening_integration import run_research_hardening_verification

    report = run_research_hardening_verification(
        test_client=FakeLocalClient(),
        cases=[relationship_case],
        tokens={101: "local-test-token"},
        findings=[finding],
        object_catalog=catalog,
        output_dir=tmp_path,
        max_generated_variants=4,
        variants_per_finding=4,
    )

    assert report["finding_variant_generation"]["variants_generated"] == 4
    assert report["implicit_relationship_analysis"]["relationship_probe_count"] == 3
    assert report["replay"]["executed_attack_cases"] == 7
    assert report["replay"]["http_requests_for_replays"] == 14
    assert (tmp_path / "research_hardening_verification.json").exists()
    assert (tmp_path / "research_hardening_verification_raw.csv").exists()
