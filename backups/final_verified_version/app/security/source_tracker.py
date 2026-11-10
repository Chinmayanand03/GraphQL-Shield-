from __future__ import annotations

from hashlib import sha256
from typing import Iterable

from graphql import (
    EnumValueNode,
    FieldNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    InlineFragmentNode,
    IntValueNode,
    OperationDefinitionNode,
    StringValueNode,
    VariableNode,
)
from graphql.language.ast import ValueNode

from .graphql_parser import parse_query
from .taint_models import (
    ScalarId,
    SourceTrackingResult,
    TaintSource,
    TaintSourceKind,
)


def _scalar_id(value: object) -> ScalarId | None:
    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return value

    if isinstance(value, str) and value.strip():
        return value

    return None


def _literal_scalar(
    value_node: ValueNode | None,
) -> ScalarId | None:
    if isinstance(value_node, StringValueNode):
        return _scalar_id(value_node.value)

    if isinstance(value_node, IntValueNode):
        try:
            return int(value_node.value)
        except (ValueError, TypeError):
            return None

    if isinstance(value_node, EnumValueNode):
        return _scalar_id(value_node.value)

    return None


def _make_source_id(
    operation_type: str,
    operation_name: str | None,
    path: str,
    field_name: str,
    argument_name: str,
    source_kind: str,
    variable_name: str | None,
    value: ScalarId,
) -> str:
    data = "|".join(
        (
            operation_type,
            operation_name or "",
            path,
            field_name,
            argument_name,
            source_kind,
            variable_name or "",
            f"{type(value).__name__}:{value}",
        )
    )

    digest = sha256(data.encode("utf-8")).hexdigest()[:16]
    return f"src-{digest}"


def track_sources(
    query: str,
    variables: dict | None = None,
    identifier_arguments: Iterable[str] = ("id",),
) -> SourceTrackingResult:
    """
    Identify externally supplied object IDs in a GraphQL document.

    This function identifies candidate taint sources. It does not
    decide whether a request is vulnerable or should be blocked.
    """
    document = parse_query(query)

    if document is None:
        return SourceTrackingResult(
            warnings=("invalid_graphql",),
            operation_count=0,
        )

    runtime_variables = variables if variables is not None else {}
    id_arguments = frozenset(identifier_arguments)

    fragments = {
        definition.name.value: definition
        for definition in document.definitions
        if isinstance(definition, FragmentDefinitionNode)
    }

    operations = [
        definition
        for definition in document.definitions
        if isinstance(definition, OperationDefinitionNode)
    ]

    sources: list[TaintSource] = []
    warnings: list[str] = []

    for operation in operations:
        operation_type = operation.operation.value
        operation_name = (
            operation.name.value if operation.name else None
        )

        defaults: dict[str, ValueNode] = {}

        for definition in operation.variable_definitions or ():
            if definition.default_value is not None:
                defaults[definition.variable.name.value] = (
                    definition.default_value
                )

        def add_source(
            *,
            value: ScalarId,
            source_kind: TaintSourceKind,
            path: str,
            field_name: str,
            argument_name: str,
            variable_name: str | None = None,
        ) -> None:
            source_id = _make_source_id(
                operation_type,
                operation_name,
                path,
                field_name,
                argument_name,
                source_kind,
                variable_name,
                value,
            )

            sources.append(
                TaintSource(
                    source_id=source_id,
                    value=value,
                    source_kind=source_kind,
                    graphql_path=path,
                    field_name=field_name,
                    argument_name=argument_name,
                    operation_type=operation_type,
                    operation_name=operation_name,
                    variable_name=variable_name,
                )
            )

        def visit_selection_set(
            selection_set,
            parent_path: str,
            fragment_stack: frozenset[str] = frozenset(),
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

                    for argument in selection.arguments or ():
                        argument_name = argument.name.value

                        if argument_name not in id_arguments:
                            continue

                        value_node = argument.value

                        if isinstance(value_node, VariableNode):
                            variable_name = value_node.name.value

                            # An explicitly supplied value overrides
                            # the GraphQL default, even if it is null
                            # or not a supported scalar identifier.
                            if variable_name in runtime_variables:
                                value = _scalar_id(
                                    runtime_variables[variable_name]
                                )

                                if value is not None:
                                    add_source(
                                        value=value,
                                        source_kind="variable",
                                        path=path,
                                        field_name=field_name,
                                        argument_name=argument_name,
                                        variable_name=variable_name,
                                    )

                            elif variable_name in defaults:
                                value = _literal_scalar(
                                    defaults[variable_name]
                                )

                                if value is not None:
                                    add_source(
                                        value=value,
                                        source_kind="default",
                                        path=path,
                                        field_name=field_name,
                                        argument_name=argument_name,
                                        variable_name=variable_name,
                                    )

                        else:
                            value = _literal_scalar(value_node)

                            if value is not None:
                                add_source(
                                    value=value,
                                    source_kind="literal",
                                    path=path,
                                    field_name=field_name,
                                    argument_name=argument_name,
                                )

                    visit_selection_set(
                        selection.selection_set,
                        path,
                        fragment_stack,
                    )

                elif isinstance(selection, FragmentSpreadNode):
                    name = selection.name.value
                    fragment = fragments.get(name)

                    if fragment is None:
                        warnings.append(f"missing_fragment:{name}")
                        continue

                    if name in fragment_stack:
                        warnings.append(f"fragment_cycle:{name}")
                        continue

                    visit_selection_set(
                        fragment.selection_set,
                        parent_path,
                        fragment_stack | {name},
                    )

                elif isinstance(selection, InlineFragmentNode):
                    visit_selection_set(
                        selection.selection_set,
                        parent_path,
                        fragment_stack,
                    )

        visit_selection_set(operation.selection_set, "")

    return SourceTrackingResult(
        sources=tuple(sources),
        warnings=tuple(dict.fromkeys(warnings)),
        operation_count=len(operations),
    )


def extract_taint_sources(
    query: str,
    variables: dict | None = None,
    identifier_arguments: Iterable[str] = ("id",),
) -> tuple[TaintSource, ...]:
    """Convenience API returning sources without the result wrapper."""
    return track_sources(
        query,
        variables,
        identifier_arguments,
    ).sources
