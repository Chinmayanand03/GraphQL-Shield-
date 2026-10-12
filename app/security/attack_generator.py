from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Iterable

from graphql.language.ast import (
    EnumValueNode,
    FieldNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    InlineFragmentNode,
    IntValueNode,
    OperationDefinitionNode,
    StringValueNode,
)

from .graphql_parser import parse_query
from .taint_models import ScalarId, TaintSource
from .taint_sources import track_sources


@dataclass(frozen=True, slots=True)
class AttackTarget:
    """A test object whose expected authorization is known."""

    object_type: str
    object_id: ScalarId
    field_name: str
    expected_authorized: bool
    owner_id: ScalarId | None = None
    graphql_path: str | None = None
    reason: str = "Known unauthorized test target"


@dataclass(frozen=True, slots=True)
class AttackCase:
    case_id: str
    principal_id: str
    action: str
    query: str
    variables: dict
    operation_name: str | None
    source_id: str
    source_path: str
    source_kind: str
    target_type: str
    target_id: ScalarId
    target_owner_id: ScalarId | None
    expected_authorized: bool
    reason: str

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "principal_id": self.principal_id,
            "action": self.action,
            "query": self.query,
            "variables": copy.deepcopy(self.variables),
            "operation_name": self.operation_name,
            "source_id": self.source_id,
            "source_path": self.source_path,
            "source_kind": self.source_kind,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "target_owner_id": self.target_owner_id,
            "expected_authorized": self.expected_authorized,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class AttackGenerationResult:
    cases: tuple[AttackCase, ...] = ()
    warnings: tuple[str, ...] = ()
    skipped: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "cases": [case.to_dict() for case in self.cases],
            "warnings": list(self.warnings),
            "skipped": list(self.skipped),
            "case_count": len(self.cases),
        }


def _scalar_value(node):
    if isinstance(node, StringValueNode):
        return node.value

    if isinstance(node, IntValueNode):
        try:
            return int(node.value)
        except (ValueError, TypeError):
            return None

    if isinstance(node, EnumValueNode):
        return node.value

    return None


def _operation_matches(operation, source: TaintSource) -> bool:
    name = operation.name.value if operation.name else None

    return (
        operation.operation.value == source.operation_type
        and name == source.operation_name
    )


def _find_literal_spans(query: str, source: TaintSource) -> list[tuple[int, int, object]]:
    """
    Find literal argument locations matching a tracked source.

    Fragment selections are expanded at each use site so the tracked
    GraphQL response path is preserved.
    """
    document = parse_query(query)

    if document is None:
        return []

    fragments = {
        definition.name.value: definition
        for definition in document.definitions
        if isinstance(definition, FragmentDefinitionNode)
    }

    spans: list[tuple[int, int, object]] = []

    def visit_selection_set(
        selection_set,
        parent_path: str,
        fragment_stack: frozenset[str],
    ) -> None:
        if selection_set is None:
            return

        for selection in selection_set.selections:
            if isinstance(selection, FieldNode):
                field_name = selection.name.value
                response_key = (
                    selection.alias.value
                    if selection.alias
                    else field_name
                )

                path = (
                    f"{parent_path}.{response_key}"
                    if parent_path
                    else response_key
                )

                if (
                    path == source.graphql_path
                    and field_name == source.field_name
                ):
                    for argument in selection.arguments or ():
                        if argument.name.value != source.argument_name:
                            continue

                        value_node = argument.value
                        value = _scalar_value(value_node)

                        if (
                            value == source.value
                            and getattr(value_node, "loc", None) is not None
                        ):
                            spans.append(
                                (
                                    value_node.loc.start,
                                    value_node.loc.end,
                                    value_node,
                                )
                            )

                visit_selection_set(
                    selection.selection_set,
                    path,
                    fragment_stack,
                )

            elif isinstance(selection, FragmentSpreadNode):
                fragment_name = selection.name.value
                fragment = fragments.get(fragment_name)

                if fragment is None or fragment_name in fragment_stack:
                    continue

                visit_selection_set(
                    fragment.selection_set,
                    parent_path,
                    fragment_stack | {fragment_name},
                )

            elif isinstance(selection, InlineFragmentNode):
                visit_selection_set(
                    selection.selection_set,
                    parent_path,
                    fragment_stack,
                )

    for definition in document.definitions:
        if (
            isinstance(definition, OperationDefinitionNode)
            and _operation_matches(definition, source)
        ):
            visit_selection_set(
                definition.selection_set,
                "",
                frozenset(),
            )

    return spans


def _render_literal(value_node, target_id: ScalarId) -> str:
    if isinstance(value_node, StringValueNode):
        return json.dumps(str(target_id), ensure_ascii=False)

    if isinstance(value_node, IntValueNode):
        if isinstance(target_id, bool):
            raise ValueError("Boolean is not a valid integer object ID")

        try:
            return str(int(target_id))
        except (ValueError, TypeError):
            raise ValueError(
                "Integer GraphQL argument requires a numeric target ID"
            ) from None

    if isinstance(value_node, EnumValueNode):
        target = str(target_id)

        if not re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]*", target):
            raise ValueError(
                "Enum target ID must be a valid GraphQL enum name"
            )

        return target

    raise ValueError("Unsupported GraphQL literal type")


def _replace_literal(
    query: str,
    source: TaintSource,
    target_id: ScalarId,
) -> str:
    spans = _find_literal_spans(query, source)

    if not spans:
        raise ValueError(
            f"Could not locate literal source at {source.graphql_path}"
        )

    replacements = []

    for start, end, value_node in spans:
        replacements.append(
            (start, end, _render_literal(value_node, target_id))
        )

    updated = query

    # Replace backwards so earlier source offsets remain valid.
    for start, end, replacement in sorted(
        replacements,
        key=lambda item: item[0],
        reverse=True,
    ):
        updated = updated[:start] + replacement + updated[end:]

    return updated


def _case_id(
    principal_id: str,
    action: str,
    source: TaintSource,
    target: AttackTarget,
) -> str:
    raw = "|".join(
        (
            principal_id,
            action,
            source.source_id,
            target.object_type,
            str(target.object_id),
            target.field_name,
            target.graphql_path or "",
        )
    )

    return "attack-" + sha256(raw.encode("utf-8")).hexdigest()[:20]


def generate_bola_attacks(
    query: str,
    variables: dict | None,
    principal_id: str,
    targets: Iterable[AttackTarget],
    action: str = "read",
    identifier_arguments: Iterable[str] = ("id",),
) -> AttackGenerationResult:
    """
    Generate reproducible ID-substitution tests from tracked sources.

    Only targets explicitly labelled expected_authorized=False generate
    attack cases. This function does not determine authorization itself
    and does not execute requests against a backend.
    """
    tracking = track_sources(
        query=query,
        variables=variables,
        identifier_arguments=identifier_arguments,
    )

    if not tracking.valid:
        return AttackGenerationResult(
            warnings=tracking.warnings,
        )

    if parse_query(query) is None:
        return AttackGenerationResult(
            warnings=("invalid_graphql",),
        )

    original_variables = copy.deepcopy(variables or {})
    cases: list[AttackCase] = []
    warnings = list(tracking.warnings)
    skipped: list[str] = []
    seen_case_ids: set[str] = set()

    for target in targets:
        if target.expected_authorized is not False:
            skipped.append(
                f"Skipped {target.object_type}:{target.object_id}: "
                "target is not explicitly marked unauthorized"
            )
            continue

        if isinstance(target.object_id, bool):
            skipped.append("Skipped boolean target ID")
            continue

        if not isinstance(target.object_id, (str, int)):
            skipped.append(
                f"Skipped unsupported target ID type: "
                f"{type(target.object_id).__name__}"
            )
            continue

        if isinstance(target.object_id, str) and not target.object_id.strip():
            skipped.append("Skipped empty target ID")
            continue

        matching_sources = [
            source
            for source in tracking.sources
            if source.field_name == target.field_name
            and (
                target.graphql_path is None
                or source.graphql_path == target.graphql_path
            )
        ]

        if not matching_sources:
            skipped.append(
                f"No source matched target field "
                f"{target.field_name} at {target.graphql_path or '*'}"
            )
            continue

        for source in matching_sources:
            if source.value == target.object_id:
                skipped.append(
                    f"Skipped unchanged ID at {source.graphql_path}"
                )
                continue

            attack_query = query
            attack_variables = copy.deepcopy(original_variables)

            if source.source_kind in {"variable", "default"}:
                if not source.variable_name:
                    skipped.append(
                        f"Missing variable name for {source.source_id}"
                    )
                    continue

                # GraphQL variables may be shared by several locations;
                # this case intentionally substitutes that variable.
                attack_variables[source.variable_name] = target.object_id

            elif source.source_kind == "literal":
                try:
                    attack_query = _replace_literal(
                        query,
                        source,
                        target.object_id,
                    )
                except ValueError as exc:
                    skipped.append(
                        f"{source.graphql_path}: {exc}"
                    )
                    continue

            else:
                skipped.append(
                    f"Unsupported source kind: {source.source_kind}"
                )
                continue

            if parse_query(attack_query) is None:
                warnings.append(
                    f"Generated request did not parse at "
                    f"{source.graphql_path}"
                )
                continue

            case_id = _case_id(
                principal_id,
                action,
                source,
                target,
            )

            if case_id in seen_case_ids:
                continue

            seen_case_ids.add(case_id)

            cases.append(
                AttackCase(
                    case_id=case_id,
                    principal_id=principal_id,
                    action=action,
                    query=attack_query,
                    variables=attack_variables,
                    operation_name=source.operation_name,
                    source_id=source.source_id,
                    source_path=source.graphql_path,
                    source_kind=source.source_kind,
                    target_type=target.object_type,
                    target_id=target.object_id,
                    target_owner_id=target.owner_id,
                    expected_authorized=False,
                    reason=target.reason,
                )
            )

    return AttackGenerationResult(
        cases=tuple(cases),
        warnings=tuple(dict.fromkeys(warnings)),
        skipped=tuple(skipped),
    )
