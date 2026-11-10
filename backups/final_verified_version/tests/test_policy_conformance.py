import pytest

from app.security.authorization import (
    AuthorizationContext,
    PolicyEngine,
)
from app.security.policy_conformance import (
    compare_policy_implementation,
    evaluate_reference_policy,
    verify_policy_invariants,
)


@pytest.fixture(autouse=True)
def deterministic_risk_score(monkeypatch):
    monkeypatch.setattr(
        "app.security.authorization.calculate_risk",
        lambda context, reason: (0, "LOW"),
    )


def make_context(**overrides):
    values = {
        "user_id": 101,
        "role": "user",
        "operation": "query",
        "object_type": "Resource",
        "object_id": 201,
        "path": "resource",
        "owner_id": 101,
        "metadata": {},
    }
    values.update(overrides)
    return AuthorizationContext(**values)


@pytest.mark.parametrize(
    ("overrides", "decision", "reason"),
    [
        (
            {"user_id": None},
            "DENY",
            "INVALID_CONTEXT",
        ),
        (
            {"object_type": ""},
            "DENY",
            "INVALID_CONTEXT",
        ),
        (
            {"object_id": None},
            "DENY",
            "INVALID_CONTEXT",
        ),
        (
            {"owner_id": None},
            "DENY",
            "OBJECT_NOT_FOUND",
        ),
        (
            {"role": "admin", "owner_id": 202},
            "ALLOW",
            "ADMIN_OVERRIDE",
        ),
        (
            {"user_id": 101, "owner_id": 101},
            "ALLOW",
            "OWNER_MATCH",
        ),
        (
            {"owner_id": 202, "path": "user.resource"},
            "DENY",
            "NESTED_AUTHORIZATION_VIOLATION",
        ),
        (
            {"owner_id": 202, "path": "resource"},
            "DENY",
            "OWNERSHIP_MISMATCH",
        ),
    ],
)
def test_reference_policy(overrides, decision, reason):
    result = evaluate_reference_policy(make_context(**overrides))

    assert result.decision == decision
    assert result.reason == reason


def test_reference_matches_actual_policy_engine():
    engine = PolicyEngine()

    contexts = [
        make_context(),
        make_context(owner_id=202),
        make_context(owner_id=202, path="user.resource"),
        make_context(role="admin", owner_id=202),
        make_context(owner_id=None),
        make_context(user_id=None),
        make_context(object_id=None),
    ]

    for context in contexts:
        result = compare_policy_implementation(context, engine)
        assert result["matches"], result


def test_matching_result_has_no_mismatches():
    result = compare_policy_implementation(make_context())

    assert result["matches"] is True
    assert result["mismatches"] == []
    assert result["expected"]["decision"] == "ALLOW"
    assert result["actual"]["decision"] == "ALLOW"


def test_invariant_checker_accepts_valid_owner_access():
    context = make_context()
    result = PolicyEngine().evaluate(context)

    check = verify_policy_invariants(context, result)

    assert check["valid"] is True
    assert check["violations"] == []


def test_invariant_checker_rejects_invalid_context_allow():
    context = make_context(user_id=None)

    check = verify_policy_invariants(
        context,
        {
            "decision": "ALLOW",
            "reason": "INCORRECT_ALLOW",
        },
    )

    assert check["valid"] is False
    assert "INVALID_CONTEXT_MUST_DENY" in check["violations"]


def test_invariant_checker_rejects_missing_object_allow():
    context = make_context(owner_id=None)

    check = verify_policy_invariants(
        context,
        {
            "decision": "ALLOW",
            "reason": "INCORRECT_ALLOW",
        },
    )

    assert check["valid"] is False
    assert "MISSING_OBJECT_MUST_DENY" in check["violations"]
