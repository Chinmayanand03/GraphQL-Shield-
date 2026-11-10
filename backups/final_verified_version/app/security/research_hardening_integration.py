"""Connect the benchmark's independent oracle and generators to live local replays.

This module is deliberately separate from the production security gateway. It uses
existing analyzer findings to generate ID-substitution variants and separately
extracts implicit relationship traversals (such as resource.children) so the
benchmark can test child-object authorization beneath an authorized parent.
"""
from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence

import httpx

from app.benchmarks.attack_variants import (
    AttackVariant,
    generate_variants_from_findings,
    to_attack_cases,
)
from app.benchmarks.dataset import OBJECTS
from app.benchmarks.ground_truth import evaluate_ground_truth, label_case_with_oracle
from app.security.relationship_extractor import (
    extract_relationship_paths,
    resolve_relationship_objects,
)
from app.security.dynamic_verifier import verify_attack_case


def _get(value: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        candidate = value.get(name) if isinstance(value, Mapping) else getattr(value, name, None)
        if candidate is not None:
            return candidate
    return default


def _json_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def build_resource_catalog(objects: Mapping[Any, Mapping[str, Any]] | None = None) -> dict[str, dict[str, dict[str, Any]]]:
    """Normalize dataset objects for the oracle, relationship resolver and variant generator.

    The app's object model calls every returned GraphQL object a Resource, while
    ``object_type`` differentiates documents and folders. The ``type`` field is
    therefore normalized to ``Resource`` for compatible ID substitutions.
    Child lists are built from ``parent_id`` rather than assumed from labels.
    """
    source = objects if objects is not None else OBJECTS
    records: dict[str, dict[str, Any]] = {}
    for object_id, data in source.items():
        records[str(object_id)] = {
            "id": int(object_id) if str(object_id).isdigit() else object_id,
            "type": "Resource",
            "object_type": data.get("object_type", "resource"),
            "owner_id": data.get("owner_id"),
            "name": data.get("name"),
            "parent_id": data.get("parent_id"),
            "children": [],
        }
    for record in records.values():
        parent_id = record.get("parent_id")
        if parent_id is not None and str(parent_id) in records:
            records[str(parent_id)]["children"].append(record["id"])
    return {"Resource": records}


def _relationship_is_implicit(access: Any) -> bool:
    """Avoid treating explicit nested resource(id: ...) as an implicit edge."""
    id_argument_names = {"id", "resourceid", "objectid", "childid", "nodeid"}
    for name, value in (_get(access, "relation_args", default={}) or {}).items():
        if str(name).lower() in id_argument_names and value is not None:
            return False
    return True


def label_cases_with_oracle(
    cases: Sequence[dict[str, Any]],
    object_catalog: Any = None,
) -> list[dict[str, Any]]:
    """Recompute benchmark labels with the standalone oracle, ignoring input labels."""
    catalog = object_catalog if object_catalog is not None else build_resource_catalog()
    labelled: list[dict[str, Any]] = []
    parent_cache: dict[str, list[Any]] = {}
    for original in cases:
        case = dict(original)
        query = case.get("query", "")
        variables = case.get("variables") or {}
        signature = _json_key({"query": query, "variables": variables})
        if signature not in parent_cache:
            if "children" not in query.lower():
                parent_cache[signature] = []
            else:
                try:
                    accesses = extract_relationship_paths(query, variables)
                    parent_cache[signature] = [
                        access.parent_id
                        for access in accesses
                        if access.parent_id is not None and _relationship_is_implicit(access)
                    ]
                except Exception:
                    # An invalid query should still get fail-closed oracle labeling.
                    parent_cache[signature] = []
        oracle_input = {
            **case,
            "target_object_id": case.get("target_object_id", case.get("target_id")),
            "target_object_type": case.get("target_object_type", case.get("target_type", "Resource")),
            "principal_role": case.get("principal_role", case.get("role", "user")),
            "parent_chain": parent_cache[signature],
        }
        # Ownership must come from the independent object catalog, never from
        # mutable per-case owner metadata or prior labels.
        for owner_key in ("target_owner_id", "resource_owner_id", "object_owner_id", "owner_id", "ownerId"):
            oracle_input.pop(owner_key, None)
        labels = label_case_with_oracle(oracle_input, object_catalog=catalog)
        case.update(labels)
        # Keep the legacy field names used by metrics and replay in sync with
        # oracle-derived results, including when reading older JSONL files.
        case["is_bola"] = bool(labels["ground_truth_is_bola"])
        case["expected_authorized"] = bool(labels["ground_truth_authorized"])
        labelled.append(case)
    return labelled


def _stable_relationship_id(
    query: str,
    variables: Mapping[str, Any],
    principal_id: Any,
    parent_id: Any,
    relation_field: str,
    child_id: Any,
) -> str:
    material = _json_key({
        "query": query,
        "variables": variables,
        "principal_id": principal_id,
        "parent_id": parent_id,
        "relation_field": relation_field,
        "child_id": child_id,
    })
    return "rel_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def generate_relationship_probe_variants(
    cases: Sequence[dict[str, Any]],
    object_catalog: Any = None,
) -> tuple[list[AttackVariant], dict[str, Any]]:
    """Build one replay probe per resolved child on an implicit relationship path."""
    catalog = object_catalog if object_catalog is not None else build_resource_catalog()
    variants: list[AttackVariant] = []
    skipped_unknown = 0
    unique_operation_count = 0
    seen_operations: set[str] = set()
    seen_variants: set[str] = set()

    for case in cases:
        query = case.get("query")
        variables = dict(case.get("variables") or {})
        if not isinstance(query, str) or not query.strip():
            continue
        operation_signature = _json_key({
            "query": query,
            "variables": variables,
            "principal_id": case.get("principal_id"),
        })
        if operation_signature in seen_operations:
            continue
        seen_operations.add(operation_signature)
        if "children" not in query.lower():
            continue
        unique_operation_count += 1
        try:
            accesses = extract_relationship_paths(query, variables)
        except Exception:
            continue

        for access in accesses:
            if not _relationship_is_implicit(access) or access.parent_id is None:
                continue
            children = resolve_relationship_objects(access, catalog)
            for child in children:
                child_id = _get(child, "id", "object_id", "resource_id", "target_object_id")
                if child_id is None:
                    continue
                principal_id = case.get("principal_id")
                role = case.get("role", "user")
                child_owner = _get(child, "owner_id", "ownerId", "user_id", "created_by")
                decision = evaluate_ground_truth(
                    subject_id=principal_id,
                    object_id=child_id,
                    object_type="Resource",
                    object_catalog=catalog,
                    subject_role=role,
                    owner_id=child_owner,
                    parent_chain=[access.parent_id],
                )
                if decision.reason.startswith(("unknown_", "missing_")):
                    skipped_unknown += 1
                    continue
                variant_id = _stable_relationship_id(
                    query, variables, principal_id, access.parent_id,
                    access.relation_field, child_id,
                )
                if variant_id in seen_variants:
                    continue
                seen_variants.add(variant_id)
                variants.append(AttackVariant(
                    variant_id=variant_id,
                    finding_id=f"relationship:{access.parent_id}:{access.relation_field}",
                    kind="implicit_relationship_traversal",
                    query=query,
                    variables=variables,
                    principal_id=principal_id,
                    target_object_id=child_id,
                    target_object_type="Resource",
                    expected_authorized=decision.authorized,
                    target_response_path=tuple(access.response_path),
                    description=(
                        f"Resolve child {child_id} through "
                        f"{access.parent_field}.{access.relation_field} "
                        f"under parent {access.parent_id}."
                    ),
                ))

    return variants, {
        "unique_operations_inspected": unique_operation_count,
        "relationship_probe_count": len(variants),
        "unknown_or_incomplete_children_skipped": skipped_unknown,
        "relationship_paths_are_implicit_only": True,
    }


def _unique_findings(findings: Sequence[Any]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for finding in findings:
        query = _get(finding, "query", "graphql_query", "original_query", "operation")
        variables = _get(finding, "variables", "query_variables", "graphql_variables", default={}) or {}
        principal_id = _get(finding, "principal_id", "subject_id", "user_id", "actor_id", "requester_id")
        target_id = _get(finding, "target_object_id", "object_id", "resource_id", "target_id", "child_id")
        path = _get(finding, "target_response_path", "response_path", "graphql_path", default=())
        if not isinstance(query, str) or not query.strip() or principal_id is None or target_id is None:
            continue
        try:
            target_is_bound = any(str(value) == str(target_id) for value in variables.values())
        except AttributeError:
            target_is_bound = False
        if not target_is_bound:
            # A parent variable is not the returned child ID for implicit
            # relationships. Those probes are built by the relationship path.
            continue
        signature = _json_key({
            "query": query, "variables": variables, "principal_id": principal_id,
            "target_id": target_id, "path": path,
        })
        record = dict(finding) if isinstance(finding, Mapping) else {
            "query": query, "variables": dict(variables),
            "principal_id": principal_id, "target_object_id": target_id,
            "target_response_path": path,
        }
        record["finding_id"] = "finding_" + hashlib.sha256(signature.encode("utf-8")).hexdigest()[:12]
        record.setdefault("target_object_type", "Resource")
        record.setdefault("principal_role", _get(finding, "role", "principal_role", default="user"))
        unique[signature] = record
    return [unique[key] for key in sorted(unique)]


def _forward_to_test_client(test_client: Any):
    """Expose FastAPI TestClient requests through a synchronous httpx transport."""
    def handler(request: httpx.Request) -> httpx.Response:
        try:
            payload = json.loads(request.content.decode("utf-8")) if request.content else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {}
        headers: dict[str, str] = {}
        authorization = request.headers.get("authorization")
        content_type = request.headers.get("content-type")
        if authorization:
            headers["Authorization"] = authorization
        if content_type:
            headers["Content-Type"] = content_type
        try:
            response = test_client.post(request.url.path, json=payload, headers=headers)
            return httpx.Response(
                status_code=response.status_code,
                headers={"content-type": response.headers.get("content-type", "application/json")},
                content=response.content,
                request=request,
            )
        except Exception as exc:
            return httpx.Response(
                status_code=599,
                json={"detail": f"test_client_forwarding_error:{type(exc).__name__}"},
                request=request,
            )
    return handler


def run_research_hardening_verification(
    *,
    test_client: Any,
    cases: Sequence[dict[str, Any]],
    tokens: Mapping[int, str],
    findings: Sequence[Any],
    object_catalog: Any = None,
    output_dir: str | Path = "results/research_benchmark",
    max_generated_variants: int = 64,
    variants_per_finding: int = 4,
) -> dict[str, Any]:
    """Replay analyzer-derived variants and implicit relationship child probes.

    Calls are made only against the in-process local TestClient provided by the
    benchmark runner. The cap prevents the new exploration layer from making a
    5,000-case benchmark prohibitively slow. Variant sampling is deterministic.
    """
    if max_generated_variants < 0:
        raise ValueError("max_generated_variants must be non-negative")
    if variants_per_finding < 1:
        raise ValueError("variants_per_finding must be at least 1")

    catalog = object_catalog if object_catalog is not None else build_resource_catalog()
    unique_findings = _unique_findings(list(findings))
    finding_limit = (
        max(1, (max_generated_variants + variants_per_finding - 1) // variants_per_finding)
        if max_generated_variants else 0
    )
    sampled_findings = unique_findings[:finding_limit]
    generated = generate_variants_from_findings(
        sampled_findings,
        resource_catalog=catalog,
        variants_per_finding=variants_per_finding,
        include_control_variant=True,
    ) if sampled_findings else []
    generated = sorted(generated, key=lambda variant: variant.variant_id)[:max_generated_variants]

    relationship_variants, relationship_stats = generate_relationship_probe_variants(
        cases, object_catalog=catalog,
    )
    # Ensure the cap applies only to general finding-derived variants. Every
    # distinct relationship child is retained because that is the hardening
    # condition being measured (usually only a handful of synthetic children).
    all_variants = [*generated, *relationship_variants]
    attack_cases = to_attack_cases(
        [variant for variant in all_variants if variant.expected_authorized is not None]
    )
    variant_by_id = {variant.variant_id: variant for variant in all_variants}

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    raw_rows: list[dict[str, Any]] = []
    skipped_no_token = 0
    skipped_unknown_label = sum(variant.expected_authorized is None for variant in all_variants)
    for attack_case in attack_cases:
        try:
            principal_id = int(attack_case.principal_id)
        except (TypeError, ValueError):
            skipped_no_token += 1
            continue
        token = tokens.get(principal_id)
        if not token:
            skipped_no_token += 1
            continue
        try:
            result = verify_attack_case(
                attack_case,
                token=token,
                base_url="http://graphql-shield.test",
                transport=httpx.MockTransport(_forward_to_test_client(test_client)),
            )
            result_dict = result.to_dict()
            variant = variant_by_id.get(attack_case.case_id)
            expected_authorized = variant.expected_authorized if variant else attack_case.expected_authorized
            raw_rows.append({
                "case_id": attack_case.case_id,
                "finding_id": variant.finding_id if variant else attack_case.source_id,
                "variant_kind": variant.kind if variant else "unknown",
                "principal_id": principal_id,
                "target_object_id": attack_case.target_id,
                "target_response_path": attack_case.source_path,
                "expected_authorized": expected_authorized,
                "ground_truth_is_bola": expected_authorized is False,
                "description": attack_case.reason,
                "baseline_outcome": result.baseline.outcome,
                "baseline_status": result.baseline.http_status,
                "baseline_target_visible": result.baseline.target_id_observed,
                "protected_outcome": result.protected.outcome,
                "protected_status": result.protected.http_status,
                "protected_target_visible": result.protected.target_id_observed,
                "verdict": result.verdict,
                "baseline_detail": result.baseline.detail,
                "protected_detail": result.protected.detail,
                "baseline_graphql_errors": ";".join(result.baseline.graphql_errors),
                "protected_graphql_errors": ";".join(result.protected.graphql_errors),
            })
        except Exception as exc:
            raw_rows.append({
                "case_id": attack_case.case_id,
                "finding_id": attack_case.source_id,
                "variant_kind": "verification_error",
                "principal_id": attack_case.principal_id,
                "target_object_id": attack_case.target_id,
                "target_response_path": attack_case.source_path,
                "expected_authorized": attack_case.expected_authorized,
                "ground_truth_is_bola": not attack_case.expected_authorized,
                "description": attack_case.reason,
                "baseline_outcome": "INCONCLUSIVE",
                "baseline_status": None,
                "baseline_target_visible": False,
                "protected_outcome": "INCONCLUSIVE",
                "protected_status": None,
                "protected_target_visible": False,
                "verdict": "INCONCLUSIVE",
                "baseline_detail": f"verification exception: {type(exc).__name__}",
                "protected_detail": "verification exception",
                "baseline_graphql_errors": "",
                "protected_graphql_errors": "",
            })

    def _summary(rows: list[dict[str, Any]], authorized: bool) -> dict[str, Any]:
        group = [row for row in rows if row["expected_authorized"] is authorized]
        return {
            "count": len(group),
            "baseline_target_confirmed": sum(row["baseline_outcome"] == "EXPOSED_CONFIRMED" for row in group),
            "protected_http_blocked": sum(row["protected_outcome"] == "BLOCKED" for row in group),
            "protected_target_not_visible": sum(
                row["protected_outcome"] in {"BLOCKED", "NOT_EXPOSED"} and not row["protected_target_visible"]
                for row in group
            ),
            "protected_target_confirmed": sum(row["protected_target_visible"] for row in group),
            "protection_verified_by_target_absence": sum(
                row["baseline_outcome"] == "EXPOSED_CONFIRMED"
                and row["protected_outcome"] in {"BLOCKED", "NOT_EXPOSED"}
                and not row["protected_target_visible"]
                for row in group
            ) if not authorized else 0,
            "unexpected_protected_denials": sum(
                row["protected_outcome"] == "BLOCKED"
                for row in group
            ) if authorized else 0,
        }

    bola_summary = _summary(raw_rows, authorized=False)
    legitimate_summary = _summary(raw_rows, authorized=True)
    verdict_counts = dict(sorted(Counter(row["verdict"] for row in raw_rows).items()))
    dynamic_http_calls = len(raw_rows) * 2

    report = {
        "version": "1.0",
        "methodology": (
            "Independent oracle labels are recomputed from subject, ownership, role and relationship-path metadata. "
            "ID-substitution variants come from analyzer findings; implicit relationship probes are generated "
            "from parsed, resolved object-valued relationship paths. Replays target only the in-process local app."
        ),
        "ground_truth": {
            "labelled_cases": len(cases),
            "bola_cases": sum(bool(case.get("is_bola")) for case in cases),
            "legitimate_cases": sum(not bool(case.get("is_bola")) for case in cases),
            "reason_counts": dict(sorted(Counter(str(case.get("ground_truth_reason", "missing_reason")) for case in cases).items())),
            "oracle_module": "app.benchmarks.ground_truth",
            "not_derived_from": ["scenario label", "existing is_bola value", "detector prediction", "PolicyEngine prediction"],
        },
        "finding_variant_generation": {
            "raw_analyzer_findings": len(findings),
            "unique_query_target_findings": len(unique_findings),
            "findings_sampled": len(sampled_findings),
            "variants_generated": len(generated),
            "max_generated_variants": max_generated_variants,
            "variants_per_finding": variants_per_finding,
            "cap_applied": len(unique_findings) > len(sampled_findings) or len(generated) >= max_generated_variants,
        },
        "implicit_relationship_analysis": relationship_stats,
        "replay": {
            "generated_attack_cases": len(all_variants),
            "executed_attack_cases": len(raw_rows),
            "http_requests_for_replays": dynamic_http_calls,
            "skipped_no_token": skipped_no_token,
            "skipped_unknown_ground_truth": skipped_unknown_label,
            "verdict_counts": verdict_counts,
            "bola_probe_summary": bola_summary,
            "legitimate_control_summary": legitimate_summary,
        },
        "limitations": [
            "This is a seeded synthetic local workload, not a sample of arbitrary production GraphQL schemas.",
            "The general attack-variant count is capped for runtime; the report records the cap and sampled count.",
            "Target absence is reported separately from HTTP 401/403 blocking because field-level GraphQL denial can return HTTP 200.",
            "Relationship probes only resolve relationships represented by the supplied object catalog or relationship map.",
        ],
    }

    json_path = output_path / "research_hardening_verification.json"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    csv_path = output_path / "research_hardening_verification_raw.csv"
    if raw_rows:
        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(raw_rows[0].keys()))
            writer.writeheader()
            writer.writerows(raw_rows)
    else:
        csv_path.write_text("case_id\n", encoding="utf-8")
    report["artifacts"] = {
        "report_json": str(json_path),
        "raw_csv": str(csv_path),
    }
    # Rewrite with artifact links included.
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


__all__ = [
    "build_resource_catalog",
    "label_cases_with_oracle",
    "generate_relationship_probe_variants",
    "run_research_hardening_verification",
]
