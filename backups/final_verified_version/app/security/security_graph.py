from __future__ import annotations

from collections import deque
from hashlib import sha256
from typing import Iterable
import json

from .taint_models import AnalysisEdge, AnalysisNode, AnalysisResult


def add_sensitive_sinks(
    result: AnalysisResult,
    sink_paths: Iterable[str],
) -> AnalysisResult:
    """Mark configured GraphQL paths as sensitive sinks."""
    existing_node_ids = {node.node_id for node in result.nodes}
    existing_edges = {
        (edge.source_node_id, edge.target_node_id, edge.edge_type)
        for edge in result.edges
    }

    for path in dict.fromkeys(sink_paths):
        matching_nodes = [
            node
            for node in result.nodes
            if node.node_type == "graphql_field"
            and node.graphql_path == path
        ]

        if not matching_nodes:
            warning = f"sensitive_sink_path_not_found:{path}"
            if warning not in result.warnings:
                result.warnings.append(warning)
            continue

        source_ids = tuple(
            dict.fromkeys(
                source_id
                for node in matching_nodes
                for source_id in node.taint_source_ids
            )
        )

        digest_input = f"{path}|{','.join(source_ids)}"
        digest = sha256(digest_input.encode()).hexdigest()[:20]
        sink_id = f"sink-{digest}"

        if sink_id not in existing_node_ids:
            result.nodes.append(
                AnalysisNode(
                    node_id=sink_id,
                    node_type="sensitive_sink",
                    label=path.rsplit(".", 1)[-1],
                    graphql_path=path,
                    object_type=matching_nodes[0].object_type,
                    object_id=matching_nodes[0].object_id,
                    taint_source_ids=source_ids,
                    context_key=f"sink:{path}",
                )
            )
            existing_node_ids.add(sink_id)

        for node in matching_nodes:
            key = (node.node_id, sink_id, "sink_reachability")
            if key in existing_edges:
                continue

            result.edges.append(
                AnalysisEdge(
                    source_node_id=node.node_id,
                    target_node_id=sink_id,
                    edge_type="sink_reachability",
                    field_name=node.label,
                    evidence=f"Configured sensitive sink: {path}",
                )
            )
            existing_edges.add(key)

    return result


def _adjacency(
    result: AnalysisResult,
) -> dict[str, list[str]]:
    known_ids = {node.node_id for node in result.nodes}
    graph: dict[str, list[str]] = {
        node_id: [] for node_id in known_ids
    }

    for edge in result.edges:
        if (
            edge.source_node_id in known_ids
            and edge.target_node_id in known_ids
        ):
            graph[edge.source_node_id].append(edge.target_node_id)

    for node_id in graph:
        graph[node_id] = sorted(set(graph[node_id]))

    return graph


def find_paths(
    result: AnalysisResult,
    start_node_id: str,
    end_node_id: str,
    max_depth: int = 20,
    max_paths: int = 20,
) -> list[list[str]]:
    """Find bounded simple paths between two graph nodes."""
    if max_depth < 1 or max_paths < 1:
        raise ValueError("max_depth and max_paths must be positive")

    graph = _adjacency(result)

    if start_node_id not in graph or end_node_id not in graph:
        return []

    queue = deque([[start_node_id]])
    paths: list[list[str]] = []

    while queue and len(paths) < max_paths:
        path = queue.popleft()
        current = path[-1]

        if current == end_node_id:
            paths.append(path)
            continue

        if len(path) - 1 >= max_depth:
            continue

        for neighbour in graph[current]:
            if neighbour not in path:
                queue.append(path + [neighbour])

    return paths


def source_to_sink_paths(
    result: AnalysisResult,
    max_depth: int = 20,
    max_paths: int = 100,
) -> list[dict]:
    """Return reachable taint-source-to-sensitive-sink paths."""
    source_nodes = [
        node for node in result.nodes
        if node.node_type == "taint_source"
    ]
    sink_nodes = [
        node for node in result.nodes
        if node.node_type == "sensitive_sink"
    ]

    output = []

    for source in source_nodes:
        for sink in sink_nodes:
            remaining = max_paths - len(output)
            if remaining <= 0:
                return output

            paths = find_paths(
                result,
                source.node_id,
                sink.node_id,
                max_depth=max_depth,
                max_paths=remaining,
            )

            for path in paths:
                output.append({
                    "source_node_id": source.node_id,
                    "source_id": source.node_id.removeprefix(
                        "source-node:"
                    ),
                    "sink_node_id": sink.node_id,
                    "sink_path": sink.graphql_path,
                    "node_ids": path,
                    "labels": [
                        next(
                            node.label
                            for node in result.nodes
                            if node.node_id == node_id
                        )
                        for node_id in path
                    ],
                })

                if len(output) >= max_paths:
                    return output

    return output


def build_security_graph(result: AnalysisResult) -> dict:
    """Create a JSON-serializable graph and analysis summary."""
    edge_types: dict[str, int] = {}

    for edge in result.edges:
        edge_types[edge.edge_type] = (
            edge_types.get(edge.edge_type, 0) + 1
        )

    return {
        "nodes": [
            {
                "node_id": node.node_id,
                "node_type": node.node_type,
                "label": node.label,
                "graphql_path": node.graphql_path,
                "object_type": node.object_type,
                "object_id": node.object_id,
                "taint_source_ids": list(node.taint_source_ids),
                "context_key": node.context_key,
            }
            for node in result.nodes
        ],
        "edges": [
            {
                "source_node_id": edge.source_node_id,
                "target_node_id": edge.target_node_id,
                "edge_type": edge.edge_type,
                "field_name": edge.field_name,
                "evidence": edge.evidence,
            }
            for edge in result.edges
        ],
        "sources": [source.to_dict() for source in result.sources],
        "boundaries": [
            {
                "principal_id": boundary.principal_id,
                "action": boundary.action,
                "object_type": boundary.object_type,
                "object_id": boundary.object_id,
                "authorized": boundary.authorized,
                "reason": boundary.reason,
                "policy_name": boundary.policy_name,
                "graphql_path": boundary.graphql_path,
            }
            for boundary in result.boundaries
        ],
        "findings": [
            {
                "finding_id": finding.finding_id,
                "status": finding.status,
                "category": finding.category,
                "principal_id": finding.principal_id,
                "target_type": finding.target_type,
                "target_id": finding.target_id,
                "graphql_path": finding.graphql_path,
                "reason": finding.reason,
                "evidence": list(finding.evidence),
                "confidence": finding.confidence,
            }
            for finding in result.findings
        ],
        "source_to_sink_paths": source_to_sink_paths(result),
        "warnings": list(result.warnings),
        "summary": {
            "node_count": len(result.nodes),
            "edge_count": len(result.edges),
            "source_count": len(result.sources),
            "boundary_count": len(result.boundaries),
            "finding_count": len(result.findings),
            "sensitive_sink_count": sum(
                node.node_type == "sensitive_sink"
                for node in result.nodes
            ),
            "edge_types": edge_types,
        },
    }


def export_security_graph(
    result: AnalysisResult,
    output_path: str,
) -> None:
    """Save the graph to a JSON file."""
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(
            build_security_graph(result),
            file,
            indent=2,
            ensure_ascii=False,
        )
        file.write("\n")
