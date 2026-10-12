from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import httpx

from .attack_generator import AttackCase


ObservationStatus = Literal[
    "BLOCKED",
    "EXPOSED_CONFIRMED",
    "POSSIBLE_EXPOSURE",
    "NOT_EXPOSED",
    "INCONCLUSIVE",
]


@dataclass(frozen=True)
class AccessObservation:
    endpoint: str
    http_status: int | None
    outcome: ObservationStatus
    target_id_observed: bool
    response_path_found: bool
    graphql_errors: tuple[str, ...] = ()
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "endpoint": self.endpoint,
            "http_status": self.http_status,
            "outcome": self.outcome,
            "target_id_observed": self.target_id_observed,
            "response_path_found": self.response_path_found,
            "graphql_errors": list(self.graphql_errors),
            "detail": self.detail,
        }


@dataclass(frozen=True)
class DynamicVerificationResult:
    case_id: str
    baseline: AccessObservation
    protected: AccessObservation
    verdict: str

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "baseline": self.baseline.to_dict(),
            "protected": self.protected.to_dict(),
            "verdict": self.verdict,
        }


def _same_id(left: object, right: object) -> bool:
    if left is None or right is None:
        return False
    return str(left) == str(right)


def _resolve_path(data: object, path: str) -> tuple[bool, object]:
    """
    Resolve an aliased GraphQL response path.
    Supports lists at intermediate levels.
    """
    parts = [part for part in path.split(".") if part]

    if not parts:
        return False, None

    current = data

    for part in parts:
        if isinstance(current, list):
            results = []
            found_any = False

            for item in current:
                found, value = _resolve_path(item, part)
                if found:
                    found_any = True
                    results.append(value)

            if not found_any:
                return False, None

            current = results

        elif isinstance(current, dict) and part in current:
            current = current[part]

        else:
            return False, None

    return True, current


def _target_id_visible(value: object, target_id: object) -> bool:
    """Check the returned target object or list items, not descendants."""
    if isinstance(value, dict):
        return _same_id(value.get("id"), target_id)

    if isinstance(value, list):
        return any(
            isinstance(item, dict)
            and _same_id(item.get("id"), target_id)
            for item in value
        )

    return False


def _nonempty(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, (dict, list, str)):
        return bool(value)
    return True


def _observe_response(
    response: httpx.Response,
    endpoint: str,
    case: AttackCase,
) -> AccessObservation:
    status = response.status_code

    if status in (401, 403):
        return AccessObservation(
            endpoint=endpoint,
            http_status=status,
            outcome="BLOCKED",
            target_id_observed=False,
            response_path_found=False,
            detail="HTTP authorization block",
        )

    if status < 200 or status >= 300:
        return AccessObservation(
            endpoint=endpoint,
            http_status=status,
            outcome="INCONCLUSIVE",
            target_id_observed=False,
            response_path_found=False,
            detail="Unexpected HTTP status",
        )

    try:
        payload = response.json()
    except (ValueError, TypeError):
        return AccessObservation(
            endpoint=endpoint,
            http_status=status,
            outcome="INCONCLUSIVE",
            target_id_observed=False,
            response_path_found=False,
            detail="Response was not valid JSON",
        )

    if not isinstance(payload, dict):
        return AccessObservation(
            endpoint=endpoint,
            http_status=status,
            outcome="INCONCLUSIVE",
            target_id_observed=False,
            response_path_found=False,
            detail="Unexpected GraphQL response shape",
        )

    errors = payload.get("errors") or ()
    error_messages = tuple(
        str(error.get("message", "GraphQL error"))
        if isinstance(error, dict)
        else "GraphQL error"
        for error in errors
    )

    if "data" not in payload or not isinstance(payload["data"], dict):
        return AccessObservation(
            endpoint=endpoint,
            http_status=status,
            outcome="INCONCLUSIVE",
            target_id_observed=False,
            response_path_found=False,
            graphql_errors=error_messages,
            detail="GraphQL data is missing",
        )

    found, value = _resolve_path(payload["data"], case.source_path)

    if not found:
        return AccessObservation(
            endpoint=endpoint,
            http_status=status,
            outcome="INCONCLUSIVE",
            target_id_observed=False,
            response_path_found=False,
            graphql_errors=error_messages,
            detail="Requested response path was not found",
        )

    if not _nonempty(value):
        return AccessObservation(
            endpoint=endpoint,
            http_status=status,
            outcome=(
                "INCONCLUSIVE" if error_messages else "NOT_EXPOSED"
            ),
            target_id_observed=False,
            response_path_found=True,
            graphql_errors=error_messages,
            detail="Target path returned no object",
        )

    target_visible = _target_id_visible(value, case.target_id)

    # Collection paths (for example resource.children) can legitimately return
    # sibling objects while filtering out the queried child. Those siblings do
    # not imply that the target was exposed. Preserve POSSIBLE_EXPOSURE for a
    # non-empty single-object path whose ID differs, but classify a list without
    # the target ID as NOT_EXPOSED.
    if target_visible:
        outcome = "EXPOSED_CONFIRMED"
        detail = "Target ID was returned at the tested path"
    elif isinstance(value, list):
        outcome = "INCONCLUSIVE" if error_messages else "NOT_EXPOSED"
        detail = (
            "Target ID was absent from the returned collection"
            if not error_messages
            else "GraphQL errors prevent a conclusive collection check"
        )
    else:
        outcome = "POSSIBLE_EXPOSURE"
        detail = "Data was returned, but the target ID was not confirmed"

    return AccessObservation(
        endpoint=endpoint,
        http_status=status,
        outcome=outcome,
        target_id_observed=target_visible,
        response_path_found=True,
        graphql_errors=error_messages,
        detail=detail,
    )


def _send_case(
    client: httpx.Client,
    endpoint: str,
    token: str,
    case: AttackCase,
) -> AccessObservation:
    body = {
        "query": case.query,
        "variables": case.variables,
    }

    if case.operation_name is not None:
        body["operationName"] = case.operation_name

    try:
        response = client.post(
            endpoint,
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        )
    except httpx.HTTPError as exc:
        return AccessObservation(
            endpoint=endpoint,
            http_status=None,
            outcome="INCONCLUSIVE",
            target_id_observed=False,
            response_path_found=False,
            detail=f"HTTP request failed: {type(exc).__name__}",
        )

    return _observe_response(response, endpoint, case)


def _compare(
    baseline: AccessObservation,
    protected: AccessObservation,
    expected_authorized: bool | None = None,
) -> str:
    """Compare endpoint outcomes without treating allowed controls as failures.

    ``expected_authorized`` comes from the independent benchmark oracle. When it
    is true, a visible target on the protected endpoint is a successful legitimate
    control, not a protection failure. For unauthorized probes, HTTP blocking and
    target absence are reported distinctly because GraphQL field denial can return
    HTTP 200 with the unauthorized object omitted.
    """
    baseline_exposed = baseline.outcome in {
        "EXPOSED_CONFIRMED",
        "POSSIBLE_EXPOSURE",
    }
    protected_exposed = protected.outcome in {
        "EXPOSED_CONFIRMED",
        "POSSIBLE_EXPOSURE",
    }

    if expected_authorized is True:
        if protected.outcome == "BLOCKED":
            return "UNEXPECTED_PROTECTED_DENIAL"
        if protected.outcome == "EXPOSED_CONFIRMED":
            return "LEGITIMATE_ACCESS_PRESERVED"
        if protected.outcome == "POSSIBLE_EXPOSURE":
            return "LEGITIMATE_ACCESS_UNCONFIRMED"
        if protected.outcome == "NOT_EXPOSED":
            return "LEGITIMATE_ACCESS_NOT_PRESERVED"
        return "INCONCLUSIVE"

    if (
        baseline.outcome == "EXPOSED_CONFIRMED"
        and protected.outcome == "BLOCKED"
    ):
        return "PROTECTION_VERIFIED"

    if (
        baseline.outcome == "POSSIBLE_EXPOSURE"
        and protected.outcome == "BLOCKED"
    ):
        return "BLOCKED_POSSIBLE_EXPOSURE_BASELINE"

    if (
        baseline.outcome == "EXPOSED_CONFIRMED"
        and protected.outcome == "EXPOSED_CONFIRMED"
    ):
        return "PROTECTION_FAILED_CONFIRMED"

    if baseline_exposed and protected_exposed:
        return "PROTECTION_MAY_HAVE_FAILED"

    if baseline.outcome == "NOT_EXPOSED":
        return "BASELINE_NOT_REPRODUCED"

    if (
        baseline.outcome == "EXPOSED_CONFIRMED"
        and protected.outcome == "NOT_EXPOSED"
    ):
        return "PROTECTION_VERIFIED_BY_TARGET_ABSENCE"

    if protected.outcome == "NOT_EXPOSED":
        return "PROTECTED_RESPONSE_NOT_EXPOSED_BUT_NOT_BLOCKED"

    return "INCONCLUSIVE"


def verify_attack_case(
    case: AttackCase,
    token: str,
    base_url: str = "http://127.0.0.1:8000",
    vulnerable_path: str = "/graphql-insecure",
    protected_path: str = "/graphql",
    timeout: float = 5.0,
    transport: httpx.BaseTransport | None = None,
) -> DynamicVerificationResult:
    """
    Execute a generated attack against the local vulnerable and
    protected endpoints. This function never changes gateway policy.
    """
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    with httpx.Client(
        base_url=base_url.rstrip("/"),
        timeout=timeout,
        transport=transport,
        follow_redirects=False,
    ) as client:
        baseline = _send_case(
            client, vulnerable_path, token, case
        )
        protected = _send_case(
            client, protected_path, token, case
        )

    return DynamicVerificationResult(
        case_id=case.case_id,
        baseline=baseline,
        protected=protected,
        verdict=_compare(baseline, protected, expected_authorized=case.expected_authorized),
    )
