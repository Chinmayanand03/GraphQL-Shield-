import json

from app.security.security_graph import (
    add_sensitive_sinks,
    build_security_graph,
    find_paths,
    source_to_sink_paths,
)
from app.security.taint_propagation import propagate_taint


def make_result():
    query = """
    query GetResource($id: ID!) {
        resource(id: $id) {
            name
        }
    }
    """
    return propagate_taint(query, {"id": "R101"})


def test_sensitive_sink_is_added_to_graph():
    result = make_result()

    add_sensitive_sinks(result, ["resource.name"])

    assert any(
        node.node_type == "sensitive_sink"
        and node.graphql_path == "resource.name"
        for node in result.nodes
    )


def test_missing_sink_path_adds_warning():
    result = make_result()

    add_sensitive_sinks(result, ["resource.nonexistent"])

    assert (
        "sensitive_sink_path_not_found:resource.nonexistent"
        in result.warnings
    )


def test_graph_contains_source_and_propagation_edges():
    result = make_result()
    add_sensitive_sinks(result, ["resource.name"])

    graph = build_security_graph(result)

    assert graph["summary"]["node_count"] > 0
    assert graph["summary"]["edge_count"] > 0
    assert any(
        edge["edge_type"] == "source_binding"
        for edge in graph["edges"]
    )
    assert any(
        edge["edge_type"] == "sink_reachability"
        for edge in graph["edges"]
    )


def test_source_to_sink_path_is_found():
    result = make_result()
    add_sensitive_sinks(result, ["resource.name"])

    paths = source_to_sink_paths(result)

    assert paths
    assert paths[0]["sink_path"] == "resource.name"
    assert paths[0]["labels"][0] == "resource.id"
    assert paths[0]["labels"][-1] == "name"


def test_json_graph_is_serializable():
    result = make_result()
    add_sensitive_sinks(result, ["resource.name"])

    serialized = json.dumps(build_security_graph(result))

    assert '"nodes"' in serialized
    assert '"edges"' in serialized
    assert '"source_to_sink_paths"' in serialized


def test_find_paths_returns_empty_for_unknown_node():
    result = make_result()

    assert find_paths(result, "missing-start", "missing-end") == []


def test_duplicate_sink_registration_is_idempotent():
    result = make_result()

    add_sensitive_sinks(result, ["resource.name"])
    node_count = len(result.nodes)
    edge_count = len(result.edges)

    add_sensitive_sinks(result, ["resource.name"])

    assert len(result.nodes) == node_count
    assert len(result.edges) == edge_count


def test_graph_summary_counts_sinks():
    result = make_result()
    add_sensitive_sinks(result, ["resource.name"])

    summary = build_security_graph(result)["summary"]

    assert summary["source_count"] == 1
    assert summary["sensitive_sink_count"] == 1
