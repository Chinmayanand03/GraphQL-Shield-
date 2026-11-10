from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Sequence

from .taint_models import ScalarId

PolicyEffect = Literal["allow", "deny"]


@dataclass(frozen=True, slots=True)
class Principal:
    principal_id: str
    roles: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class ProtectedObject:
    object_id: ScalarId
    object_type: str
    owner_id: ScalarId | None = None


@dataclass(frozen=True, slots=True)
class Relationship:
    parent_object_id: ScalarId
    child_object_id: ScalarId
    name: str


@dataclass(frozen=True, slots=True)
class PolicyRule:
    policy_id: str
    effect: PolicyEffect
    actions: frozenset[str]
    object_types: frozenset[str]
    required_roles: frozenset[str] = frozenset()
    owner_only: bool = False
    relationship_name: str | None = None
    parent_object_type: str | None = None


@dataclass(frozen=True, slots=True)
class AccessDecision:
    authorized: bool
    principal_id: str
    action: str
    object_type: str
    object_id: ScalarId
    reason: str
    matched_policy_ids: tuple[str, ...] = ()
    policy_version: str = "1.0"


@dataclass(frozen=True, slots=True)
class PathAuthorizationDecision:
    authorized: bool
    principal_id: str
    action: str
    decisions: tuple[AccessDecision, ...]
    blocked_object_id: ScalarId | None
    reason: str


@dataclass(frozen=True, slots=True)
class AuthorizationPolicy:
    version: str
    rules: tuple[PolicyRule, ...] = field(default_factory=tuple)

    def evaluate(
        self,
        principal: Principal,
        action: str,
        target: ProtectedObject,
        relationship: Relationship | None = None,
        parent: ProtectedObject | None = None,
    ) -> AccessDecision:
        matching: list[PolicyRule] = []

        for rule in self.rules:
            if "*" not in rule.actions and action not in rule.actions:
                continue

            if (
                "*" not in rule.object_types
                and target.object_type not in rule.object_types
            ):
                continue

            if (
                rule.required_roles
                and not principal.roles.intersection(
                    rule.required_roles
                )
            ):
                continue

            if rule.owner_only:
                if target.owner_id is None:
                    continue

                if str(target.owner_id) != str(principal.principal_id):
                    continue

            if rule.relationship_name is not None:
                if relationship is None:
                    continue

                if relationship.name != rule.relationship_name:
                    continue

                if str(relationship.child_object_id) != str(
                    target.object_id
                ):
                    continue

                if parent is None:
                    continue

                if str(relationship.parent_object_id) != str(
                    parent.object_id
                ):
                    continue

            if rule.parent_object_type is not None:
                if parent is None:
                    continue

                if parent.object_type != rule.parent_object_type:
                    continue

            matching.append(rule)

        denied = [
            rule for rule in matching if rule.effect == "deny"
        ]

        allowed = [
            rule for rule in matching if rule.effect == "allow"
        ]

        matched_ids = tuple(rule.policy_id for rule in matching)

        if denied:
            return AccessDecision(
                authorized=False,
                principal_id=principal.principal_id,
                action=action,
                object_type=target.object_type,
                object_id=target.object_id,
                reason="An explicit deny policy matched.",
                matched_policy_ids=matched_ids,
                policy_version=self.version,
            )

        if allowed:
            return AccessDecision(
                authorized=True,
                principal_id=principal.principal_id,
                action=action,
                object_type=target.object_type,
                object_id=target.object_id,
                reason="An allow policy matched and no deny policy matched.",
                matched_policy_ids=matched_ids,
                policy_version=self.version,
            )

        return AccessDecision(
            authorized=False,
            principal_id=principal.principal_id,
            action=action,
            object_type=target.object_type,
            object_id=target.object_id,
            reason="Default deny: no applicable allow policy matched.",
            matched_policy_ids=matched_ids,
            policy_version=self.version,
        )

    def evaluate_path(
        self,
        principal: Principal,
        action: str,
        objects: Sequence[ProtectedObject],
        relationships: Sequence[Relationship] = (),
    ) -> PathAuthorizationDecision:
        """
        A path is authorized only if every object on it is authorized.

        For objects[0], no parent relationship is assumed.
        Each subsequent object must have a matching relationship
        to the previous object if relationship-specific policies
        are required.
        """
        if not objects:
            return PathAuthorizationDecision(
                authorized=False,
                principal_id=principal.principal_id,
                action=action,
                decisions=(),
                blocked_object_id=None,
                reason="Default deny: the object path is empty.",
            )

        decisions: list[AccessDecision] = []

        for index, target in enumerate(objects):
            parent = objects[index - 1] if index > 0 else None
            relationship = None

            if parent is not None:
                relationship = next(
                    (
                        item
                        for item in relationships
                        if str(item.parent_object_id)
                        == str(parent.object_id)
                        and str(item.child_object_id)
                        == str(target.object_id)
                    ),
                    None,
                )

            decision = self.evaluate(
                principal=principal,
                action=action,
                target=target,
                relationship=relationship,
                parent=parent,
            )

            decisions.append(decision)

            if not decision.authorized:
                return PathAuthorizationDecision(
                    authorized=False,
                    principal_id=principal.principal_id,
                    action=action,
                    decisions=tuple(decisions),
                    blocked_object_id=target.object_id,
                    reason=(
                        f"Path blocked at {target.object_type} "
                        f"{target.object_id}: {decision.reason}"
                    ),
                )

        return PathAuthorizationDecision(
            authorized=True,
            principal_id=principal.principal_id,
            action=action,
            decisions=tuple(decisions),
            blocked_object_id=None,
            reason="Every object on the path passed authorization.",
        )
