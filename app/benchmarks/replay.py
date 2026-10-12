from __future__ import annotations

import csv
import copy
from pathlib import Path
from typing import Any

import httpx

from app.benchmarks.dataset import OBJECTS
from app.security.attack_generator import (
    AttackTarget,
    generate_bola_attacks,
)
from app.security.dynamic_verifier import verify_attack_case
from app.security.taint_sources import track_sources


class FastAPITestClientTransport(httpx.BaseTransport):
    """Adapter that runs HTTPX requests through FastAPI TestClient."""

    def __init__(self, test_client):
        self.test_client = test_client

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.url.query:
            path += "?" + request.url.query.decode("ascii")

        headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() not in {"host", "content-length"}
        }

        response = self.test_client.request(
            method=request.method,
            url=path,
            headers=headers,
            content=request.read(),
        )

        return httpx.Response(
            status_code=response.status_code,
            headers=response.headers,
            content=response.content,
            request=request,
        )

    def close(self) -> None:
        pass


def _owned_seed_id(principal_id: int) -> int | None:
    """Find a seeded object owned by the principal."""
    for object_id, item in OBJECTS.items():
        if str(item["owner_id"]) == str(principal_id):
            return int(object_id)
    return None


def build_attack_from_benchmark_case(
    case: dict[str, Any],
):
    """
    Use a labelled synthetic BOLA scenario to generate a reproducible
    ID-substitution test. This is attack replay validation, not a
    claim that the label itself was automatically discovered.
    """
    if not case.get("is_bola"):
        return None, "Case is not labelled as a BOLA scenario"

    query = case["query"]
    variables = copy.deepcopy(case.get("variables") or {})

    tracking = track_sources(query, variables)
    if not tracking.valid:
        return None, "GraphQL request could not be analysed"

    target_path = case["graphql_path"]

    source = next(
        (
            item
            for item in tracking.sources
            if item.field_name == "resource"
            and item.graphql_path == target_path
            and item.variable_name
        ),
        None,
    )

    if source is None:
        return None, (
            f"No variable-backed resource ID source at {target_path}"
        )

    principal_id = int(case["principal_id"])
    owned_id = _owned_seed_id(principal_id)

    if owned_id is None:
        return None, "No seeded owned object found for principal"

    target_id = case["target_id"]

    if str(owned_id) == str(target_id):
        return None, "Seed ID equals attack target ID"

    # Start with an object the principal is expected to access.
    # The attack generator substitutes the labelled foreign object.
    variables[source.variable_name] = owned_id

    target = AttackTarget(
        object_type=case["target_type"],
        object_id=target_id,
        field_name="resource",
        expected_authorized=False,
        owner_id=case["target_owner_id"],
        graphql_path=target_path,
        reason="Synthetic cross-owner BOLA replay",
    )

    generated = generate_bola_attacks(
        query=query,
        variables=variables,
        principal_id=str(principal_id),
        action="read",
        targets=[target],
    )

    if not generated.cases:
        details = "; ".join(generated.warnings + generated.skipped)
        return None, details or "No attack case generated"

    return generated.cases[0], None


def verify_labelled_bola_cases(
    test_client,
    cases: list[dict[str, Any]],
    tokens: dict[int, str],
    output_dir: str | Path,
) -> dict[str, Any]:
    """
    Replay labelled BOLA cases against both local endpoints and
    collect actual dynamic-verification outcomes.

    Dataset labels are used to select attack-replay scenarios, not
    as predictions in detector precision/recall calculations.
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    raw_rows: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []

    verdict_counts: dict[str, int] = {}
    baseline_counts: dict[str, int] = {}
    protected_counts: dict[str, int] = {}

    attack_cases = 0

    transport = FastAPITestClientTransport(test_client)

    for case in cases:
        if not case.get("is_bola"):
            continue

        generated_case, skip_reason = build_attack_from_benchmark_case(
            case
        )

        if generated_case is None:
            skipped.append({
                "case_id": str(case["case_id"]),
                "reason": skip_reason or "Generation failed",
            })
            continue

        token = tokens.get(int(case["principal_id"]))
        if not token:
            skipped.append({
                "case_id": str(case["case_id"]),
                "reason": "No token supplied for the principal",
            })
            continue

        verification = verify_attack_case(
            case=generated_case,
            token=token,
            transport=transport,
        )

        attack_cases += 1

        baseline_outcome = verification.baseline.outcome
        protected_outcome = verification.protected.outcome
        verdict = verification.verdict

        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        baseline_counts[baseline_outcome] = (
            baseline_counts.get(baseline_outcome, 0) + 1
        )
        protected_counts[protected_outcome] = (
            protected_counts.get(protected_outcome, 0) + 1
        )

        raw_rows.append({
            "benchmark_case_id": case["case_id"],
            "attack_case_id": generated_case.case_id,
            "scenario": case["scenario"],
            "principal_id": case["principal_id"],
            "target_id": case["target_id"],
            "target_owner_id": case["target_owner_id"],
            "expected_authorized": False,
            "baseline_outcome": baseline_outcome,
            "baseline_http_status": verification.baseline.http_status,
            "baseline_target_observed": (
                verification.baseline.target_id_observed
            ),
            "protected_outcome": protected_outcome,
            "protected_http_status": verification.protected.http_status,
            "protected_target_observed": (
                verification.protected.target_id_observed
            ),
            "verdict": verdict,
        })

    raw_csv = output_path / "integrated_dynamic_verification_raw.csv"

    columns = [
        "benchmark_case_id",
        "attack_case_id",
        "scenario",
        "principal_id",
        "target_id",
        "target_owner_id",
        "expected_authorized",
        "baseline_outcome",
        "baseline_http_status",
        "baseline_target_observed",
        "protected_outcome",
        "protected_http_status",
        "protected_target_observed",
        "verdict",
    ]

    with raw_csv.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(raw_rows)

    verified = verdict_counts.get("PROTECTION_VERIFIED", 0)
    baseline_exposed = baseline_counts.get("EXPOSED_CONFIRMED", 0)
    protected_blocked = protected_counts.get("BLOCKED", 0)
    protected_confirmed_exposure = protected_counts.get(
        "EXPOSED_CONFIRMED", 0
    )

    summary = {
        "method": "labelled_attack_generation_and_dynamic_replay",
        "labelled_bola_cases": sum(
            bool(case.get("is_bola")) for case in cases
        ),
        "attack_cases_generated_and_executed": attack_cases,
        "cases_skipped": len(skipped),
        "http_requests_for_replays": attack_cases * 2,
        "baseline_outcomes": baseline_counts,
        "protected_outcomes": protected_counts,
        "verdict_counts": verdict_counts,
        "baseline_confirmed_exposures": baseline_exposed,
        "protected_blocks": protected_blocked,
        "protected_confirmed_exposures": protected_confirmed_exposure,
        "protection_verified_rate": (
            round(verified / attack_cases, 6)
            if attack_cases else None
        ),
        "raw_csv": str(raw_csv),
        "skipped_cases": skipped,
        "interpretation": (
            "These are observed replay results for labelled synthetic "
            "BOLA scenarios. They measure runtime verification and "
            "protection for those replay cases, not autonomous detector "
            "recall over all possible GraphQL vulnerabilities."
        ),
    }

    import json

    summary_path = output_path / "integrated_dynamic_verification.json"
    summary_path.write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    return summary
