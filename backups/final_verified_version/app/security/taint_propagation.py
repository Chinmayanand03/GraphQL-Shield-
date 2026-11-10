from __future__ import annotations

from hashlib import sha256
from typing import Iterable

from graphql.language.ast import (
    FieldNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    InlineFragmentNode,
    OperationDefinitionNode,
    SelectionSetNode,
)

from .graphql_parser import parse_query
from .taint_models import (
    AnalysisEdge,
    AnalysisNode,
    AnalysisResult,
    TaintSource,
)
from .taint_sources import track_sources


def _stable_id(prefix: str, *parts: object) -> str:
    raw = "|".join(str(part) for part in parts)
    digest = sha256(raw.encode("utf-8")).hexdigest()[:20]
    return f"{prefix}-{digest}"


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def propagate_taint(
    query: str,
    variables: dict | None = None,
    identifier_arguments: Iterable[str] = ("id",),
) -> AnalysisResult:
    """
    Build context-sensitive taint propagation evidence for a GraphQL request.

    The analyzer:
      1. Extracts externally supplied ID sources.
      2. Creates context-specific nodes for GraphQL fields.
      3. Propagates ancestor taint through nested selections.
      4. Keeps separate operations, aliases and paths distinct.
      5. Expands fragment selections at their use sites.

    This function does not decide whether a request is authorized.
    It does not confirm BOLA. Runtime authorization must remain active.
    """
    result = AnalysisResult()

    tracking = track_sources(
        query=query,
        variables=variables,
        identifier_arguments=identifier_arguments,
    )

    result.sources.extend(tracking.sources)
    result.warnings.extend(tracking.warnings)

    if not tracking.valid:
        return result

    document = parse_query(query)
    if document is None:
        result.warnings.append("invalid_graphql")
        return result

    fragments: dict[str, FragmentDefinitionNode] = {
        definition.name.value: definition
        for definition in document.definitions
        if isinstance(definition, FragmentDefinitionNode)
    }

    operations = [
        definition
        for definition in document.definitions
        if isinstance(definition, OperationDefinitionNode)
    ]

    if not operations:
        result.warnings.append("no_operation_found")
        return result

    sources_by_operation: dict[
        tuple[str, str | None], list[TaintSource]
    ] = {}

    for source in tracking.sources:
        key = (source.operation_type, source.operation_name)
        sources_by_operation.setdefault(key, []).append(source)

    nodes_by_id: dict[str, AnalysisNode] = {}
    edges_by_key: dict[tuple[str, str, str], AnalysisEdge] = {}

    def add_node(node: AnalysisNode) -> None:
        nodes_by_id[node.node_id] = node

    def add_edge(edge: AnalysisEdge) -> None:
        key = (
            edge.source_node_id,
            edge.target_node_id,
            edge.edge_type,
        )
        edges_by_key[key] = edge

    for operation in operations:
        operation_type = operation.operation.value
        operation_name = (
            operation.name.value if operation.name else None
        )

        operation_key = (operation_type, operation_name)
        operation_sources = sources_by_operation.get(
            operation_key, []
        )

        sources_by_path: dict[str, list[TaintSource]] = {}
        for source in operation_sources:
            sources_by_path.setdefault(
                source.graphql_path, []
            ).append(source)

        def visit_selection_set(
            selection_set: SelectionSetNode | None,
            parent_path: str,
            parent_node_id: str | None,
            inherited_source_ids: tuple[str, ...],
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

                    local_sources = [
                        source
                        for source in sources_by_path.get(path, [])
                        if source.field_name == field_name
                    ]

                    local_source_ids = tuple(
                        source.source_id
                        for source in local_sources
                    )

                    active_source_ids = _unique(
                        (*inherited_source_ids, *local_source_ids)
                    )

                    context_key = (
                        f"{operation_type}:"
                        f"{operation_name or '<anonymous>'}:"
                        f"{path}:"
                        f"{','.join(active_source_ids)}"
                    )

                    field_node_id = _stable_id(
                        "field",
                        operation_type,
                        operation_name or "",
                        path,
                        *active_source_ids,
                    )

                    direct_object_id = (
                        local_sources[0].value
                        if local_sources
                        else None
                    )

                    add_node(
                        AnalysisNode(
                            node_id=field_node_id,
                            node_type="graphql_field",
                            label=field_name,
                            graphql_path=path,
                            object_type=None,
                            object_id=direct_object_id,
                            taint_source_ids=active_source_ids,
                            context_key=context_key,
                        )
                    )

                    # Bind each ID source to the field using that ID.
                    for source in local_sources:
                        source_node_id = (
                            f"source-node:{source.source_id}"
                        )

                        add_node(
                            AnalysisNode(
                                node_id=source_node_id,
                                node_type="taint_source",
                                label=(
                                    f"{source.field_name}."
                                    f"{source.argument_name}"
                                ),
                                graphql_path=source.graphql_path,
                                object_type=None,
                                object_id=source.value,
                                taint_source_ids=(source.source_id,),
                                context_key=context_key,
                            )
                        )

                        add_edge(
                            AnalysisEdge(
                                source_node_id=source_node_id,
                                target_node_id=field_node_id,
                                edge_type="source_binding",
                                field_name=source.field_name,
                                evidence=(
                                    f"{source.source_kind} ID source "
                                    f"for argument "
                                    f"{source.argument_name}"
                                ),
                            )
                        )

                    # Propagate only taint already present in the
                    # parent selection. Local sources are bound above.
                    if parent_node_id and inherited_source_ids:
                        add_edge(
                            AnalysisEdge(
                                source_node_id=parent_node_id,
                                target_node_id=field_node_id,
                                edge_type="taint_propagation",
                                field_name=field_name,
                                evidence=(
                                    "Inherited source IDs: "
                                    + ", ".join(inherited_source_ids)
                                ),
                            )
                        )

                    visit_selection_set(
                        selection.selection_set,
                        path,
                        field_node_id,
                        active_source_ids,
                        fragment_stack,
                    )

                elif isinstance(selection, FragmentSpreadNode):
                    fragment_name = selection.name.value
                    fragment = fragments.get(fragment_name)

                    if fragment is None:
                        result.warnings.append(
                            f"missing_fragment:{fragment_name}"
                        )
                        continue

                    if fragment_name in fragment_stack:
                        result.warnings.append(
                            f"fragment_cycle:{fragment_name}"
                        )
                        continue

                    visit_selection_set(
                        fragment.selection_set,
                        parent_path,
                        parent_node_id,
                        inherited_source_ids,
                        fragment_stack | {fragment_name},
                    )

                elif isinstance(selection, InlineFragmentNode):
                    visit_selection_set(
                        selection.selection_set,
                        parent_path,
                        parent_node_id,
                        inherited_source_ids,
                        fragment_stack,
                    )

        visit_selection_set(
            operation.selection_set,
            parent_path="",
            parent_node_id=None,
            inherited_source_ids=(),
            fragment_stack=frozenset(),
        )

    result.nodes.extend(nodes_by_id.values())
    result.edges.extend(edges_by_key.values())
    result.warnings[:] = list(dict.fromkeys(result.warnings))

    return result


def analyze_taint_propagation(
    query: str,
    variables: dict | None = None,
    identifier_arguments: Iterable[str] = ("id",),
) -> AnalysisResult:
    """Public alias for the context-sensitive propagation analysis."""
    return propagate_taint(
        query=query,
        variables=variables,
        identifier_arguments=identifier_arguments,
    )
