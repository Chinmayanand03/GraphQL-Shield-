from __future__ import annotations

from hashlib import sha256
from collections.abc import Iterable

from .taint_models import (
    AnalysisEdge,
    AnalysisNode,
    AnalysisResult,
    AuthorizationBoundary,
)


def _boundary_node_id(boundary: AuthorizationBoundary) -> str:
    raw = "|".join(
        (
            boundary.principal_id,
            boundary.action,
            boundary.object_type,
            str(boundary.object_id),
            boundary.graphql_path or "",
            str(boundary.authorized),
            boundary.reason,
        )
    )
    digest = sha256(raw.encode("utf-8")).hexdigest()[:20]
    return f"auth-boundary-{digest}"


def _matching_field_nodes(
    result: AnalysisResult,
    boundary: AuthorizationBoundary,
) -> list[AnalysisNode]:
    if boundary.graphql_path is None:
        return []

    matches = []

    for node in result.nodes:
        if node.node_type != "graphql_field":
            continue

        if node.graphql_path != boundary.graphql_path:
            continue

        # A known, different object ID cannot match this boundary.
        if (
            node.object_id is not None
            and node.object_id != boundary.object_id
        ):
            continue

        matches.append(node)

    return matches


def apply_authorization_boundaries(
    result: AnalysisResult,
    boundaries: Iterable[AuthorizationBoundary],
) -> AnalysisResult:
    """
    Add observed authorization decisions to the analysis graph.

    A boundary applies only to its principal, action, object and path.
    Passing one boundary never clears taint from every descendant.
    """
    for boundary in boundaries:
        if boundary not in result.boundaries:
            result.boundaries.append(boundary)

        matching_nodes = _matching_field_nodes(result, boundary)

        source_ids = tuple(
            dict.fromkeys(
                source_id
                for node in matching_nodes
                for source_id in node.taint_source_ids
            )
        )

        boundary_id = _boundary_node_id(boundary)

        boundary_node = AnalysisNode(
            node_id=boundary_id,
            node_type="authorization_boundary",
            label=(
                f"{boundary.action}:"
                f"{boundary.object_type}:"
                f"{boundary.object_id}"
            ),
            graphql_path=boundary.graphql_path or "",
            object_type=boundary.object_type,
            object_id=boundary.object_id,
            taint_source_ids=source_ids,
            context_key=(
                f"{boundary.principal_id}:"
                f"{boundary.action}:"
                f"{boundary.object_type}:"
                f"{boundary.object_id}:"
                f"{boundary.authorized}"
            ),
        )

        if not any(
            node.node_id == boundary_id for node in result.nodes
        ):
            result.nodes.append(boundary_node)

        if boundary.authorized is True:
            edge_type = "authorization_boundary_passed"
        elif boundary.authorized is False:
            edge_type = "authorization_boundary_failed"
        else:
            edge_type = "authorization_boundary_unknown"

        existing_edges = {
            (
                edge.source_node_id,
                edge.target_node_id,
                edge.edge_type,
            )
            for edge in result.edges
        }

        for node in matching_nodes:
            edge_key = (node.node_id, boundary_id, edge_type)

            if edge_key in existing_edges:
                continue

            result.edges.append(
                AnalysisEdge(
                    source_node_id=node.node_id,
                    target_node_id=boundary_id,
                    edge_type=edge_type,
                    field_name=node.label,
                    evidence=boundary.reason,
                )
            )
            existing_edges.add(edge_key)

    return result
