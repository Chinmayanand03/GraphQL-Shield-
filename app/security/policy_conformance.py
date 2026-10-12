from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

from app.security.authorization import (
    AuthorizationContext,
    PolicyEngine,
)

Decision = Literal["ALLOW", "DENY"]


@dataclass(frozen=True, slots=True)
class FormalDecision:
    decision: Decision
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)


def evaluate_reference_policy(
    context: AuthorizationContext,
) -> FormalDecision:
    """
    Executable reference specification for the current GraphQL Shield
    PolicyEngine. Rule order intentionally matches authorization.py.
    """

    if (
        not context.user_id
        or not context.object_type
        or context.object_id is None
    ):
        return FormalDecision("DENY", "INVALID_CONTEXT")

    if context.owner_id is None:
        return FormalDecision("DENY", "OBJECT_NOT_FOUND")

    if context.role.upper() == "ADMIN":
        return FormalDecision("ALLOW", "ADMIN_OVERRIDE")

    if str(context.user_id) == str(context.owner_id):
        return FormalDecision("ALLOW", "OWNER_MATCH")

    if "." in context.path:
        return FormalDecision(
            "DENY",
            "NESTED_AUTHORIZATION_VIOLATION",
        )

    return FormalDecision("DENY", "OWNERSHIP_MISMATCH")


def compare_policy_implementation(
    context: AuthorizationContext,
    engine: PolicyEngine | None = None,
) -> dict:
    """
    Compare the running policy implementation with the reference model.

    Risk scores are reported but not compared because this reference
    model specifies authorization decisions, not risk calculations.
    """
    expected = evaluate_reference_policy(context)
    active_engine = engine if engine is not None else PolicyEngine()
    actual = active_engine.evaluate(context)

    mismatches = []

    for key, expected_value in (
        ("decision", expected.decision),
        ("reason", expected.reason),
    ):
        if actual.get(key) != expected_value:
            mismatches.append(
                {
                    "field": key,
                    "expected": expected_value,
                    "actual": actual.get(key),
                }
            )

    return {
        "matches": not mismatches,
        "expected": expected.to_dict(),
        "actual": {
            "decision": actual.get("decision"),
            "reason": actual.get("reason"),
        },
        "mismatches": mismatches,
        "risk_score": actual.get("risk_score"),
        "risk_level": actual.get("risk_level"),
    }


def verify_policy_invariants(
    context: AuthorizationContext,
    result: dict | None = None,
) -> dict:
    """
    Check basic authorization invariants against an existing decision.
    """
    actual = result or PolicyEngine().evaluate(context)
    decision = actual.get("decision")
    violations = []

    if (
        not context.user_id
        or not context.object_type
        or context.object_id is None
    ) and decision != "DENY":
        violations.append("INVALID_CONTEXT_MUST_DENY")

    if context.owner_id is None and decision != "DENY":
        violations.append("MISSING_OBJECT_MUST_DENY")

    if (
        context.role.upper() == "ADMIN"
        and context.owner_id is not None
        and context.user_id
        and context.object_type
        and context.object_id is not None
        and (
            decision != "ALLOW"
            or actual.get("reason") != "ADMIN_OVERRIDE"
        )
    ):
        violations.append("ADMIN_OVERRIDE_RULE_MISMATCH")

    if (
        context.owner_id is not None
        and str(context.user_id) == str(context.owner_id)
        and context.user_id
        and context.object_type
        and context.object_id is not None
        and (
            decision != "ALLOW"
            or actual.get("reason") != "OWNER_MATCH"
        )
        and context.role.upper() != "ADMIN"
    ):
        violations.append("OWNER_ACCESS_RULE_MISMATCH")

    return {
        "valid": not violations,
        "violations": violations,
        "decision": decision,
        "reason": actual.get("reason"),
    }
