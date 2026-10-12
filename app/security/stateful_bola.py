from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx

from .graphql_parser import parse_query


AccessExpectation = Literal["allowed", "denied"]

StepOutcome = Literal[
    "ALLOWED",
    "BLOCKED",
    "EXPOSED_CONFIRMED",
    "POSSIBLE_EXPOSURE",
    "NOT_EXPOSED",
    "INCONCLUSIVE",
]


@dataclass(frozen=True, slots=True)
class ResponseReference:
    """Reference a value returned by an earlier plan step."""

    step_index: int
    json_path: str


@dataclass(frozen=True, slots=True)
class StatefulStep:
    step_id: str
    principal_id: str
    query: str
    variables: dict[str, Any] = field(default_factory=dict)
    operation_name: str | None = None
    endpoint: str = "/graphql"
    expected_access: AccessExpectation = "denied"
    response_path: str | None = None
    target_id_variable: str | None = None


@dataclass(frozen=True, slots=True)
class StatefulPlan:
    plan_id: str
    steps: tuple[StatefulStep, ...]


@dataclass(frozen=True, slots=True)
class StatefulStepResult:
    step_id: str
    principal_id: str
    outcome: StepOutcome
    expected_access: AccessExpectation
    expectation_met: bool
    http_status: int | None
    response_path_found: bool
    target_id_observed: bool
    detail: str

    def to_dict(self) -> dict:
        return {
            "step_id": self.step_id,
            "principal_id": self.principal_id,
            "outcome": self.outcome,
            "expected_access": self.expected_access,
            "expectation_met": self.expectation_met,
            "http_status": self.http_status,
            "response_path_found": self.response_path_found,
            "target_id_observed": self.target_id_observed,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class StatefulPlanResult:
    plan_id: str
    steps: tuple[StatefulStepResult, ...]
    passed: bool
    failure_count: int

    def to_dict(self) -> dict:
        return {
            "plan_id": self.plan_id,
            "passed": self.passed,
            "failure_count": self.failure_count,
            "step_count": len(self.steps),
            "steps": [step.to_dict() for step in self.steps],
        }


def _resolve_json_path(
    document: Any,
    path: str,
) -> tuple[bool, Any]:
    current = document

    for part in (part for part in path.split(".") if part):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif (
            isinstance(current, list)
            and part.isdigit()
            and int(part) < len(current)
        ):
            current = current[int(part)]
        else:
            return False, None

    return True, current


def _resolve_value(
    value: Any,
    previous_payloads: list[dict | None],
    current_index: int,
) -> tuple[bool, Any, str]:
    """Resolve references only from earlier completed steps."""

    if isinstance(value, ResponseReference):
        if value.step_index < 0 or value.step_index >= current_index:
            return (
                False,
                None,
                "Response references must point to an earlier step",
            )

        payload = previous_payloads[value.step_index]

        if payload is None:
            return (
                False,
                None,
                f"Step {value.step_index} has no usable JSON response",
            )

        found, resolved = _resolve_json_path(
            payload,
            value.json_path,
        )

        if not found:
            return (
                False,
                None,
                f"Response path not found: {value.json_path}",
            )

        if resolved is None:
            return (
                False,
                None,
                f"Response path is null: {value.json_path}",
            )

        return True, copy.deepcopy(resolved), ""

    if isinstance(value, dict):
        resolved_dict = {}

        for key, nested in value.items():
            ok, resolved, error = _resolve_value(
                nested,
                previous_payloads,
                current_index,
            )
            if not ok:
                return False, None, error
            resolved_dict[key] = resolved

        return True, resolved_dict, ""

    if isinstance(value, list):
        resolved_list = []

        for nested in value:
            ok, resolved, error = _resolve_value(
                nested,
                previous_payloads,
                current_index,
            )
            if not ok:
                return False, None, error
            resolved_list.append(resolved)

        return True, resolved_list, ""

    return True, copy.deepcopy(value), ""


def _is_nonempty(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (dict, list, str)):
        return bool(value)
    return True


def _target_id_visible(value: Any, target_id: Any) -> bool:
    if target_id is None:
        return False

    if isinstance(value, dict):
        return (
            "id" in value
            and str(value["id"]) == str(target_id)
        )

    if isinstance(value, list):
        return any(
            isinstance(item, dict)
            and "id" in item
            and str(item["id"]) == str(target_id)
            for item in value
        )

    return False


def _make_step_result(
    step: StatefulStep,
    outcome: StepOutcome,
    status: int | None,
    response_path_found: bool,
    target_id_observed: bool,
    detail: str,
) -> StatefulStepResult:
    if step.expected_access == "allowed":
        expected_outcome = outcome == "ALLOWED"
    else:
        expected_outcome = outcome in {
            "BLOCKED",
            "NOT_EXPOSED",
        }

    return StatefulStepResult(
        step_id=step.step_id,
        principal_id=step.principal_id,
        outcome=outcome,
        expected_access=step.expected_access,
        expectation_met=expected_outcome,
        http_status=status,
        response_path_found=response_path_found,
        target_id_observed=target_id_observed,
        detail=detail,
    )


def _classify_response(
    step: StatefulStep,
    status: int,
    payload: Any,
    variables: dict,
) -> StatefulStepResult:
    if status in (401, 403):
        return _make_step_result(
            step, "BLOCKED", status, False, False,
            "Request was rejected by HTTP authentication/authorization.",
        )

    if not 200 <= status < 300:
        return _make_step_result(
            step, "INCONCLUSIVE", status, False, False,
            "Unexpected HTTP status; authorization outcome is unknown.",
        )

    if not isinstance(payload, dict):
        return _make_step_result(
            step, "INCONCLUSIVE", status, False, False,
            "Response was not a JSON object.",
        )

    errors = payload.get("errors") or []

    if not isinstance(errors, list):
        errors = ["Invalid GraphQL errors structure"]

    if step.response_path:
        found, value = _resolve_json_path(
            payload,
            step.response_path,
        )
    else:
        found, value = "data" in payload, payload.get("data")

    if not found:
        return _make_step_result(
            step, "INCONCLUSIVE", status, False, False,
            "Expected response path was not found.",
        )

    if step.expected_access == "allowed":
        if errors:
            return _make_step_result(
                step, "INCONCLUSIVE", status, True, False,
                "GraphQL returned errors; legitimate access was not confirmed.",
            )

        if _is_nonempty(value):
            return _make_step_result(
                step, "ALLOWED", status, True, False,
                "Expected response data was returned.",
            )

        return _make_step_result(
            step, "NOT_EXPOSED", status, True, False,
            "Expected response path contained no data.",
        )

    target_id = None

    if step.target_id_variable:
        target_id = variables.get(step.target_id_variable)

    if value is None or value == [] or value == {}:
        if errors:
            return _make_step_result(
                step, "INCONCLUSIVE", status, True, False,
                "GraphQL errors prevent reliable exposure classification.",
            )

        return _make_step_result(
            step, "NOT_EXPOSED", status, True, False,
            "No object was returned at the target response path.",
        )

    if target_id is not None and _target_id_visible(value, target_id):
        return _make_step_result(
            step, "EXPOSED_CONFIRMED", status, True, True,
            "The exact target ID was returned to a principal expected to be denied.",
        )

    if _is_nonempty(value):
        return _make_step_result(
            step, "POSSIBLE_EXPOSURE", status, True, False,
            "Data was returned, but the exact target object was not confirmed.",
        )

    return _make_step_result(
        step, "INCONCLUSIVE", status, True, False,
        "Unable to determine whether the target was exposed.",
    )


def execute_stateful_plan(
    plan: StatefulPlan,
    principal_tokens: dict[str, str],
    base_url: str = "http://127.0.0.1:8000",
    timeout: float = 5.0,
    transport: httpx.BaseTransport | None = None,
) -> StatefulPlanResult:
    """
    Execute a multi-step BOLA test plan against the local application.

    Tokens are supplied separately and are never included in the result.
    Each step may use values extracted from earlier response JSON.
    """
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    if not plan.steps:
        raise ValueError("A stateful plan must contain at least one step")

    previous_payloads: list[dict | None] = []
    step_results: list[StatefulStepResult] = []

    with httpx.Client(
        base_url=base_url.rstrip("/") + "/",
        timeout=timeout,
        transport=transport,
        follow_redirects=False,
    ) as client:
        for index, step in enumerate(plan.steps):
            if not step.endpoint.startswith("/"):
                payload = None
                step_results.append(
                    _make_step_result(
                        step, "INCONCLUSIVE", None, False, False,
                        "Endpoint must be a local absolute path beginning with '/'.",
                    )
                )
                previous_payloads.append(payload)
                continue

            if parse_query(step.query) is None:
                step_results.append(
                    _make_step_result(
                        step, "INCONCLUSIVE", None, False, False,
                        "GraphQL query failed parsing.",
                    )
                )
                previous_payloads.append(None)
                continue

            ok, variables, error = _resolve_value(
                step.variables,
                previous_payloads,
                index,
            )

            if not ok:
                step_results.append(
                    _make_step_result(
                        step, "INCONCLUSIVE", None, False, False,
                        f"Variable resolution failed: {error}",
                    )
                )
                previous_payloads.append(None)
                continue

            token = principal_tokens.get(step.principal_id)

            if not token:
                step_results.append(
                    _make_step_result(
                        step, "INCONCLUSIVE", None, False, False,
                        "No token was supplied for this principal.",
                    )
                )
                previous_payloads.append(None)
                continue

            body = {
                "query": step.query,
                "variables": variables,
            }

            if step.operation_name:
                body["operationName"] = step.operation_name

            try:
                response = client.post(
                    step.endpoint,
                    json=body,
                    headers={"Authorization": f"Bearer {token}"},
                )
            except httpx.HTTPError as exc:
                step_results.append(
                    _make_step_result(
                        step, "INCONCLUSIVE", None, False, False,
                        f"HTTP request failed: {type(exc).__name__}",
                    )
                )
                previous_payloads.append(None)
                continue

            try:
                payload = response.json()
            except (ValueError, TypeError):
                payload = None

            result = _classify_response(
                step,
                response.status_code,
                payload,
                variables,
            )

            step_results.append(result)
            previous_payloads.append(
                payload if isinstance(payload, dict) else None
            )

    failure_count = sum(
        not result.expectation_met
        for result in step_results
    )

    return StatefulPlanResult(
        plan_id=plan.plan_id,
        steps=tuple(step_results),
        passed=failure_count == 0,
        failure_count=failure_count,
    )
