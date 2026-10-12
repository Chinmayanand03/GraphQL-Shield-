from __future__ import annotations

import contextlib
import csv
import io
import json
import tempfile
import time
import tracemalloc
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.benchmarks.dataset import (
    generate_dataset,
    read_jsonl,
    write_jsonl,
)
from app.benchmarks.evaluator import classify_http_response
from app.benchmarks.integrated_verification import (
    verify_labelled_bola_cases,
)
from app.benchmarks.metrics import (
    classification_metrics,
    latency_summary,
)
from app.benchmarks.research_hardening_integration import (
    build_resource_catalog,
    label_cases_with_oracle,
    run_research_hardening_verification,
)


def _build_analyzer_predictions(case: dict[str, Any]) -> dict:
    """Run taint analysis and the existing authorization policy."""
    from app.security.authorization import (
        AuthorizationContext,
        PolicyEngine,
    )
    from app.security.ownership import get_object_owner
    from app.security.taint_models import AuthorizationBoundary
    from app.security.taint_propagation import propagate_taint
    from app.security.taint_transfer import authorization_aware_transfer
    from app.security.relationship_extractor import extract_relationship_paths

    analysis = propagate_taint(
        query=case["query"],
        variables=case.get("variables") or {},
    )

    # Ablation baseline 1: presence of an ID source alone.
    source_only = bool(analysis.sources)

    # Ablation baseline 2: tracked taint reaches the configured sink.
    sink_path = case["sensitive_sink_path"]

    sink_nodes = [
        node
        for node in analysis.nodes
        if node.node_type == "graphql_field"
        and node.graphql_path == sink_path
        and node.taint_source_ids
    ]

    taint_reaches_sink = bool(sink_nodes)

    # Authorization-aware candidate: use observed ownership and
    # the current policy engine, never the dataset's is_bola label.
    policy_engine = PolicyEngine()
    boundaries = []

    for source in analysis.sources:
        try:
            object_id = int(source.value)
            principal_id = int(case["principal_id"])
        except (ValueError, TypeError):
            continue

        object_type = source.field_name.capitalize()
        owner_id = get_object_owner(object_type, object_id)

        context = AuthorizationContext(
            user_id=principal_id,
            role=str(case["role"]),
            operation=source.operation_type,
            object_type=object_type,
            object_id=object_id,
            path=source.graphql_path,
            owner_id=owner_id,
            metadata={"benchmark": True},
        )

        decision = policy_engine.evaluate(context)

        boundaries.append(
            AuthorizationBoundary(
                principal_id=str(principal_id),
                action="read",
                object_type=object_type,
                object_id=object_id,
                authorized=decision.get("decision") == "ALLOW",
                reason=str(decision.get("reason", "UNKNOWN")),
                policy_name="GraphQLShield.PolicyEngine",
                graphql_path=source.graphql_path,
            )
        )

    authorization_aware_transfer(
        result=analysis,
        principal_id=str(case["principal_id"]),
        action="read",
        boundaries=boundaries,
        sensitive_sink_paths=[sink_path],
    )

    candidate = any(
        finding.category in {"direct_bola", "indirect_bola"}
        and finding.status == "suspected"
        for finding in analysis.findings
    )

    # Parse implicit object-valued relationship paths as a separate analysis
    # signal. The runner uses these paths to resolve child objects and replay
    # each child target, rather than assuming authorization of the parent
    # authorizes every object returned beneath it.
    relationship_parse_warning = None
    try:
        parsed_relationship_accesses = (
            extract_relationship_paths(
                query=case["query"],
                variables=case.get("variables") or {},
            )
            if "children" in case["query"].lower()
            else []
        )
    except Exception as exc:
        parsed_relationship_accesses = []
        relationship_parse_warning = f"relationship_parse:{type(exc).__name__}"
    id_argument_names = {"id", "resourceid", "objectid", "childid", "nodeid"}
    relationship_accesses = [
        access for access in parsed_relationship_accesses
        if not any(
            str(name).lower() in id_argument_names and value is not None
            for name, value in (access.relation_args or {}).items()
        )
    ]

    # Enrich suspected analyzer findings with the request metadata required by
    # the data-driven attack-variant generator. Only use query variables that
    # actually carry the reported target ID; parent IDs for implicit child
    # paths are handled by the relationship extractor instead.
    variant_findings = []
    for finding_index, finding in enumerate(analysis.findings):
        if finding.category not in {"direct_bola", "indirect_bola"} or finding.status != "suspected":
            continue
        if "children" in case["query"]:
            continue
        variables = case.get("variables") or {}
        if not any(str(value) == str(case.get("target_id")) for value in variables.values()):
            continue
        variant_findings.append({
            "finding_id": f"{case['case_id']}:finding:{finding_index}",
            "query": case["query"],
            "variables": dict(variables),
            "principal_id": case["principal_id"],
            "principal_role": case.get("role", "user"),
            "target_object_id": case["target_id"],
            "target_object_type": case.get("target_type", "Resource"),
            "target_owner_id": case.get("target_owner_id"),
            "target_response_path": case["graphql_path"],
            "finding_category": finding.category,
            "finding_status": finding.status,
        })

    return {
        "source_only_prediction": source_only,
        "context_sensitive_taint_prediction": taint_reaches_sink,
        "authorization_aware_candidate": candidate,
        "source_count": len(analysis.sources),
        "node_count": len(analysis.nodes),
        "edge_count": len(analysis.edges),
        "finding_count": len(analysis.findings),
        "relationship_path_count": len(relationship_accesses),
        "relationship_paths": ";".join(
            ".".join(access.graphql_path)
            for access in relationship_accesses
        ),
        "_variant_findings": variant_findings,
        "finding_categories": ";".join(
            sorted({
                finding.category
                for finding in analysis.findings
            })
        ),
        "analysis_warnings": ";".join(
            [*analysis.warnings, *([relationship_parse_warning] if relationship_parse_warning else [])]
        ),
    }


def _record_metric_rows(
    cases: list[dict],
    rows: list[dict],
) -> dict:
    """Evaluate detector predictions separately from endpoint outcomes."""
    actual = [bool(case["is_bola"]) for case in cases]

    predictions = {
        "taint_source_only": [
            bool(row["source_only_prediction"])
            for row in rows
        ],
        "context_sensitive_taint_only": [
            bool(row["context_sensitive_taint_prediction"])
            for row in rows
        ],
        "authorization_aware_candidate": [
            bool(row["authorization_aware_candidate"])
            for row in rows
        ],
    }

    overall = {
        name: classification_metrics(actual, predicted)
        for name, predicted in predictions.items()
    }

    groups = {
        "direct_access": {
            "direct_legitimate",
            "direct_bola",
            "admin_access",
        },
        "nested_access": {
            "nested_legitimate",
            "nested_bola",
        },
        "implicit_relationship_access": {
            "relationship_legitimate",
            "relationship_bola",
        },
        "implicit_relationship_bola_only": {"relationship_bola"},
        "direct_bola_only": {"direct_bola"},
        "nested_bola_only": {"nested_bola"},
    }

    by_group = {}

    for group_name, scenarios in groups.items():
        indices = [
            index
            for index, case in enumerate(cases)
            if case["scenario"] in scenarios
        ]

        if not indices:
            continue

        group_actual = [actual[index] for index in indices]

        by_group[group_name] = {
            name: classification_metrics(
                group_actual,
                [values[index] for index in indices],
            )
            for name, values in predictions.items()
        }

    return {
        "overall": overall,
        "by_scenario_group": by_group,
        "interpretation": (
            "These are detector predictions compared with benchmark "
            "labels. Runtime attack-replay outcomes are reported "
            "separately and are not silently substituted for detector "
            "predictions. The authorization-aware candidate uses the "
            "current policy engine and is not an independent oracle."
        ),
    }


def run_research_benchmark(
    count: int = 1000,
    seed: int = 20261011,
    output_dir: str | Path = "results/research_benchmark",
    dataset_path: str | Path | None = None,
) -> dict:
    """Benchmark endpoints, taint analysis and actual generated attack replays."""
    if not 1 <= count <= 5000:
        raise ValueError("count must be between 1 and 5000")

    from fastapi.testclient import TestClient

    from app.config import settings
    from app.core.security import create_access_token
    from app.seed import seed_database

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    dataset_file = (
        Path(dataset_path)
        if dataset_path
        else output_path / "benchmark_dataset.jsonl"
    )

    if dataset_path:
        cases = read_jsonl(dataset_file)

        if not cases:
            raise ValueError("Provided benchmark dataset is empty")

        if len(cases) > 5000:
            raise ValueError("Dataset exceeds the 5000-case limit")

        dataset_manifest = {
            "path": str(dataset_file),
            "count": len(cases),
            "loaded_from_existing_dataset": True,
        }
    else:
        generated = generate_dataset(count=count, seed=seed)
        dataset_manifest = write_jsonl(generated, dataset_file)
        dataset_manifest["seed"] = seed
        dataset_manifest["loaded_from_existing_dataset"] = False
        cases = [case.to_dict() for case in generated]

    resource_catalog = build_resource_catalog()
    # Recompute labels even for an imported JSONL dataset. This prevents the
    # benchmark's final metric labels from being trusted from an existing
    # scenario or previous detector run.
    cases = label_cases_with_oracle(cases, object_catalog=resource_catalog)
    dataset_manifest["ground_truth_method"] = "app.benchmarks.ground_truth.label_case_with_oracle"
    dataset_manifest["labels_recomputed_from_ownership_and_path_metadata"] = True

    # Use a temporary database for the benchmark. The original configured
    # database URL is restored in finally, even if evaluation fails.
    original_database_url = settings.DATABASE_URL
    evaluation_directory = tempfile.TemporaryDirectory(
        prefix="graphql_shield_research_eval_"
    )
    evaluation_db = Path(evaluation_directory.name) / "research_eval.db"

    settings.DATABASE_URL = f"sqlite:///{evaluation_db.as_posix()}"

    baseline_latencies: list[float] = []
    protected_latencies: list[float] = []
    analyzer_latencies: list[float] = []
    rows: list[dict[str, Any]] = []
    analyzer_findings: list[dict[str, Any]] = []
    research_hardening_verification: dict[str, Any] = {}

    wall_start = None
    wall_end = None
    cpu_start = None
    cpu_end = None
    peak_memory_bytes = 0
    tracing_started = False
    integrated_dynamic_verification: dict[str, Any] = {}

    try:
        seed_database()
        # Keep the cross-owner child fixture local to this temporary benchmark
        # DB. It does not modify the user's configured development database.
        from app.database import get_db_connection
        fixture_connection = get_db_connection()
        try:
            fixture_connection.execute(
                "UPDATE objects SET parent_id = ? WHERE id = ?",
                (201, 102),
            )
            fixture_connection.commit()
        finally:
            fixture_connection.close()

        from app.main import app

        tokens = {
            101: create_access_token(user_id=101, role="user"),
            102: create_access_token(user_id=102, role="user"),
            103: create_access_token(user_id=103, role="admin"),
        }

        with TestClient(app) as client:
            tracemalloc.start()
            tracing_started = True

            wall_start = time.perf_counter()
            cpu_start = time.process_time()

            with contextlib.redirect_stdout(io.StringIO()):
                # Phase A: run the same labelled cases through both
                # endpoints and the static/policy analysis pipeline.
                for case in cases:
                    payload = {
                        "query": case["query"],
                        "variables": case.get("variables") or {},
                        "operationName": case.get("operation_name"),
                    }

                    principal_id = int(case["principal_id"])
                    token = tokens.get(principal_id)

                    if token is None:
                        raise ValueError(
                            f"No token for synthetic principal {principal_id}"
                        )

                    headers = {
                        "Authorization": f"Bearer {token}"
                    }

                    start = time.perf_counter()
                    baseline_response = client.post(
                        "/graphql-insecure",
                        json=payload,
                        headers=headers,
                    )
                    baseline_ms = (
                        time.perf_counter() - start
                    ) * 1000
                    baseline_latencies.append(baseline_ms)

                    baseline = classify_http_response(
                        baseline_response,
                        case["graphql_path"],
                        case["target_id"],
                    )

                    start = time.perf_counter()
                    protected_response = client.post(
                        "/graphql",
                        json=payload,
                        headers=headers,
                    )
                    protected_ms = (
                        time.perf_counter() - start
                    ) * 1000
                    protected_latencies.append(protected_ms)

                    protected = classify_http_response(
                        protected_response,
                        case["graphql_path"],
                        case["target_id"],
                    )

                    start = time.perf_counter()
                    analyzer = _build_analyzer_predictions(case)
                    analysis_ms = (
                        time.perf_counter() - start
                    ) * 1000
                    analyzer_latencies.append(analysis_ms)
                    analyzer_findings.extend(analyzer.pop("_variant_findings", []))

                    rows.append({
                        "case_id": case["case_id"],
                        "scenario": case["scenario"],
                        "principal_id": case["principal_id"],
                        "role": case["role"],
                        "target_id": case["target_id"],
                        "target_owner_id": case["target_owner_id"],
                        "is_bola": bool(case["is_bola"]),
                        "expected_authorized": bool(
                            case["expected_authorized"]
                        ),
                        "ground_truth_authorized": bool(case["ground_truth_authorized"]),
                        "ground_truth_is_bola": bool(case["ground_truth_is_bola"]),
                        "ground_truth_reason": case.get("ground_truth_reason", "unknown"),
                        "ground_truth_owner_id": case.get("ground_truth_owner_id"),
                        "baseline_outcome": baseline["outcome"],
                        "baseline_status": baseline["http_status"],
                        "baseline_target_confirmed": baseline[
                            "target_confirmed"
                        ],
                        "baseline_target_exposed": baseline[
                            "target_exposed"
                        ],
                        "baseline_latency_ms": round(
                            baseline_ms, 5
                        ),
                        "protected_outcome": protected["outcome"],
                        "protected_status": protected["http_status"],
                        "protected_blocked": protected["blocked"],
                        "protected_target_confirmed": protected[
                            "target_confirmed"
                        ],
                        "protected_latency_ms": round(
                            protected_ms, 5
                        ),
                        "analysis_latency_ms": round(
                            analysis_ms, 5
                        ),
                        **analyzer,
                    })

                # Phase B: generate and replay attack cases through
                # the actual local application using dynamic_verifier.py.
                integrated_dynamic_verification = (
                    verify_labelled_bola_cases(
                        test_client=client,
                        cases=cases,
                        tokens=tokens,
                        output_dir=output_path,
                    )
                )

                # New exploration layer: vary IDs from actual analyzer findings
                # and independently generate probes for resolved implicit child
                # relationships. This supplements, rather than replaces, the
                # existing labelled attack replay.
                research_hardening_verification = run_research_hardening_verification(
                    test_client=client,
                    cases=cases,
                    tokens=tokens,
                    findings=analyzer_findings,
                    object_catalog=resource_catalog,
                    output_dir=output_path,
                    max_generated_variants=64,
                    variants_per_finding=4,
                )

            wall_end = time.perf_counter()
            cpu_end = time.process_time()

            _, peak_memory_bytes = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            tracing_started = False

    finally:
        if tracing_started:
            try:
                tracemalloc.stop()
            except RuntimeError:
                pass

        settings.DATABASE_URL = original_database_url
        evaluation_directory.cleanup()

    elapsed = (
        wall_end - wall_start
        if wall_start is not None and wall_end is not None
        else 0.0
    )

    cpu_seconds = (
        cpu_end - cpu_start
        if cpu_start is not None and cpu_end is not None
        else 0.0
    )

    scenario_counts = dict(
        sorted(Counter(
            case["scenario"] for case in cases
        ).items())
    )

    detection_metrics = _record_metric_rows(cases, rows)

    bola_rows = [row for row in rows if row["is_bola"]]
    legitimate_rows = [row for row in rows if not row["is_bola"]]

    protected_bola_blocks = sum(
        row["protected_outcome"] == "BLOCKED"
        for row in bola_rows
    )

    protected_legitimate_blocks = sum(
        row["protected_outcome"] == "BLOCKED"
        for row in legitimate_rows
    )

    baseline_exposures = sum(
        row["baseline_target_confirmed"]
        for row in bola_rows
    )
    protected_bola_target_absence = sum(
        (not row["protected_target_confirmed"])
        and row["protected_outcome"] in {"BLOCKED", "NOT_EXPOSED"}
        for row in bola_rows
    )

    baseline_latency_stats = latency_summary(baseline_latencies)
    protected_latency_stats = latency_summary(protected_latencies)
    analysis_latency_stats = latency_summary(analyzer_latencies)

    baseline_mean = baseline_latency_stats["mean_ms"]
    protected_mean = protected_latency_stats["mean_ms"]

    overhead_ms = round(protected_mean - baseline_mean, 4)
    overhead_pct = (
        round(overhead_ms / baseline_mean * 100, 4)
        if baseline_mean
        else 0.0
    )

    replay_http_calls = int(
        integrated_dynamic_verification.get(
            "http_requests_for_replays",
            0,
        )
    )

    hardening_http_calls = int(
        research_hardening_verification.get("replay", {}).get(
            "http_requests_for_replays", 0
        )
    )
    total_http_calls = len(cases) * 2 + replay_http_calls + hardening_http_calls
    oracle_reason_counts = dict(sorted(Counter(
        str(case.get("ground_truth_reason", "missing_reason")) for case in cases
    ).items()))

    report = {
        "report_version": "2.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "benchmark_scope": (
            "Synthetic local GraphQL BOLA benchmark. "
            "No external endpoints are called."
        ),
        "dataset": {
            **dataset_manifest,
            "actual_count": len(cases),
            "scenario_counts": scenario_counts,
            "bola_count": sum(
                bool(case["is_bola"]) for case in cases
            ),
            "legitimate_count": sum(
                not bool(case["is_bola"]) for case in cases
            ),
            "ground_truth_method": "app.benchmarks.ground_truth.label_case_with_oracle",
            "ground_truth_reason_counts": oracle_reason_counts,
            "labels_recomputed_independently": True,
        },
        "endpoint_summary": {
            "baseline_graphql_insecure": {
                "latency": baseline_latency_stats,
                "confirmed_bola_exposures": baseline_exposures,
                "bola_exposure_rate": (
                    round(
                        baseline_exposures / len(bola_rows),
                        6,
                    )
                    if bola_rows else 0.0
                ),
            },
            "protected_graphql": {
                "latency": protected_latency_stats,
                "authorization_latency_overhead_ms": overhead_ms,
                "authorization_latency_overhead_percent": overhead_pct,
                "bola_requests_blocked": protected_bola_blocks,
                "bola_block_rate": (
                    round(
                        protected_bola_blocks / len(bola_rows),
                        6,
                    )
                    if bola_rows else 0.0
                ),
                "bola_target_nonexposure_count": protected_bola_target_absence,
                "bola_target_nonexposure_rate": (
                    round(protected_bola_target_absence / len(bola_rows), 6)
                    if bola_rows else 0.0
                ),
                "legitimate_requests_blocked": protected_legitimate_blocks,
                "legitimate_false_block_rate": (
                    round(
                        protected_legitimate_blocks
                        / len(legitimate_rows),
                        6,
                    )
                    if legitimate_rows else 0.0
                ),
            },
            "analysis_pipeline": {
                "latency": analysis_latency_stats,
            },
        },
        "detection_metrics": detection_metrics,
        "integrated_dynamic_verification": (
            integrated_dynamic_verification
        ),
        "research_hardening_verification": research_hardening_verification,
        "ablation_study": {
            "meaning": {
                "taint_source_only": (
                    "Flags requests with any tracked object ID."
                ),
                "context_sensitive_taint_only": (
                    "Flags taint reaching the configured sensitive sink."
                ),
                "authorization_aware_candidate": (
                    "Flags requests for which authorization-aware "
                    "analysis finds a suspected direct or indirect BOLA."
                ),
            },
            "metrics": detection_metrics["overall"],
        },
        "performance": {
            "request_cases": len(cases),
            "baseline_and_protected_http_calls": len(cases) * 2,
            "dynamic_replay_http_calls": replay_http_calls,
            "research_hardening_replay_http_calls": hardening_http_calls,
            "total_http_calls": total_http_calls,
            "elapsed_seconds_end_to_end": round(elapsed, 4),
            "cases_per_second_end_to_end": (
                round(len(cases) / elapsed, 3)
                if elapsed else 0.0
            ),
            "http_calls_per_second_end_to_end": (
                round(total_http_calls / elapsed, 3)
                if elapsed else 0.0
            ),
            "process_cpu_seconds": round(cpu_seconds, 4),
            "tracemalloc_peak_bytes": peak_memory_bytes,
            "measurement_note": (
                "In-process FastAPI TestClient latency. The full elapsed "
                "time includes dynamic replay calls. tracemalloc affects "
                "timing. Run separate uninstrumented trials for "
                "publication-quality latency measurements."
            ),
        },
        "warnings": [
            "All benchmark cases use synthetic local data.",
            "Dynamic replay validates labelled cases and a capped set of analyzer-generated variants; "
            "it does not by itself establish autonomous discovery recall.",
            "Implicit relationship probes are resolved against the synthetic object catalog; "
            "real applications may require schema- and resolver-specific relationship maps.",
            "Detector metrics and observed endpoint/replay outcomes "
            "are reported separately.",
        ],
    }

    # Save the end-to-end benchmark outputs.
    report_file = output_path / "research_benchmark_report.json"
    report_file.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    raw_csv = output_path / "research_benchmark_raw.csv"

    if rows:
        with raw_csv.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=list(rows[0].keys()),
            )
            writer.writeheader()
            writer.writerows(rows)

    manifest_file = (
        output_path / "benchmark_dataset_manifest.json"
    )
    manifest_file.write_text(
        json.dumps(dataset_manifest, indent=2),
        encoding="utf-8",
    )

    return report
