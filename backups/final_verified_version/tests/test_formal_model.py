from app.security.formal_model import (
    AuthorizationPolicy,
    PolicyRule,
    Principal,
    ProtectedObject,
    Relationship,
)


def owner_policy():
    return AuthorizationPolicy(
        version="1.0",
        rules=(
            PolicyRule(
                policy_id="owner-read",
                effect="allow",
                actions=frozenset({"read"}),
                object_types=frozenset({"Document"}),
                owner_only=True,
            ),
        ),
    )


def test_owner_is_authorized():
    decision = owner_policy().evaluate(
        Principal("Alice"),
        "read",
        ProtectedObject("D101", "Document", "Alice"),
    )

    assert decision.authorized
    assert "owner-read" in decision.matched_policy_ids


def test_other_user_is_denied_by_default():
    decision = owner_policy().evaluate(
        Principal("Alice"),
        "read",
        ProtectedObject("D201", "Document", "Bob"),
    )

    assert not decision.authorized
    assert "Default deny" in decision.reason


def test_admin_access_requires_explicit_rule():
    policy = AuthorizationPolicy(
        version="1.0",
        rules=(
            PolicyRule(
                policy_id="admin-read",
                effect="allow",
                actions=frozenset({"read"}),
                object_types=frozenset({"Document"}),
                required_roles=frozenset({"admin"}),
            ),
        ),
    )

    decision = policy.evaluate(
        Principal("AdminUser", frozenset({"admin"})),
        "read",
        ProtectedObject("D201", "Document", "Bob"),
    )

    assert decision.authorized


def test_explicit_deny_overrides_allow():
    policy = AuthorizationPolicy(
        version="1.0",
        rules=(
            PolicyRule(
                policy_id="allow-reader",
                effect="allow",
                actions=frozenset({"read"}),
                object_types=frozenset({"Document"}),
            ),
            PolicyRule(
                policy_id="deny-reader",
                effect="deny",
                actions=frozenset({"read"}),
                object_types=frozenset({"Document"}),
                required_roles=frozenset({"blocked"}),
            ),
        ),
    )

    decision = policy.evaluate(
        Principal("Alice", frozenset({"blocked"})),
        "read",
        ProtectedObject("D101", "Document", "Alice"),
    )

    assert not decision.authorized
    assert decision.matched_policy_ids == (
        "allow-reader",
        "deny-reader",
    )


def test_unsupported_action_is_denied():
    decision = owner_policy().evaluate(
        Principal("Alice"),
        "delete",
        ProtectedObject("D101", "Document", "Alice"),
    )

    assert not decision.authorized


def test_parent_allow_does_not_authorize_foreign_child():
    policy = AuthorizationPolicy(
        version="1.0",
        rules=(
            PolicyRule(
                policy_id="owner-read",
                effect="allow",
                actions=frozenset({"read"}),
                object_types=frozenset({"Order", "Payment"}),
                owner_only=True,
            ),
        ),
    )

    result = policy.evaluate_path(
        principal=Principal("Alice"),
        action="read",
        objects=(
            ProtectedObject("O101", "Order", "Alice"),
            ProtectedObject("P201", "Payment", "Bob"),
        ),
        relationships=(
            Relationship("O101", "P201", "payment"),
        ),
    )

    assert not result.authorized
    assert result.blocked_object_id == "P201"
    assert len(result.decisions) == 2


def test_relationship_policy_requires_correct_parent_and_child():
    policy = AuthorizationPolicy(
        version="1.0",
        rules=(
            PolicyRule(
                policy_id="order-payment-read",
                effect="allow",
                actions=frozenset({"read"}),
                object_types=frozenset({"Payment"}),
                relationship_name="payment",
                parent_object_type="Order",
            ),
        ),
    )

    parent = ProtectedObject("O101", "Order", "Alice")
    child = ProtectedObject("P101", "Payment", "Bob")

    correct_relation = Relationship("O101", "P101", "payment")
    wrong_relation = Relationship("O999", "P101", "payment")

    allowed = policy.evaluate(
        Principal("Alice"),
        "read",
        child,
        relationship=correct_relation,
        parent=parent,
    )

    denied = policy.evaluate(
        Principal("Alice"),
        "read",
        child,
        relationship=wrong_relation,
        parent=parent,
    )

    assert allowed.authorized
    assert not denied.authorized


def test_empty_path_fails_closed():
    result = owner_policy().evaluate_path(
        Principal("Alice"),
        "read",
        objects=(),
    )

    assert not result.authorized
    assert result.blocked_object_id is None


def test_policy_version_is_recorded():
    decision = owner_policy().evaluate(
        Principal("Alice"),
        "read",
        ProtectedObject("D101", "Document", "Alice"),
    )

    assert decision.policy_version == "1.0"
