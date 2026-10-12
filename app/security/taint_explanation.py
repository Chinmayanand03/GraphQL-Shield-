from __future__ import annotations

from .taint_models import AnalysisResult, BolaFinding
from .security_graph import source_to_sink_paths


def explain_finding(
    finding: BolaFinding,
    result: AnalysisResult,
) -> dict:
    """Produce an evidence-backed explanation of a finding."""
    source_ids = [
        evidence.removeprefix("source:")
        for evidence in finding.evidence
        if evidence.startswith("source:")
    ]

    source_map = {
        source.source_id: source
        for source in result.sources
    }

    source_details = [
        source_map[source_id].to_dict()
        for source_id in dict.fromkeys(source_ids)
        if source_id in source_map
    ]

    relevant_boundaries = [
        {
            "principal_id": boundary.principal_id,
            "action": boundary.action,
            "object_type": boundary.object_type,
            "object_id": boundary.object_id,
            "authorized": boundary.authorized,
            "reason": boundary.reason,
            "graphql_path": boundary.graphql_path,
        }
        for boundary in result.boundaries
        if (
            boundary.principal_id == finding.principal_id
            and (
                boundary.graphql_path == finding.graphql_path
                or boundary.object_id == finding.target_id
            )
        )
    ]

    related_nodes = [
        {
            "node_id": node.node_id,
            "node_type": node.node_type,
            "label": node.label,
            "graphql_path": node.graphql_path,
        }
        for node in result.nodes
        if (
            node.graphql_path == finding.graphql_path
            or node.graphql_path.startswith(
                finding.graphql_path + "."
            )
        )
    ]

    status_summaries = {
        "suspected": (
            "The analysis found evidence of a potentially "
            "unauthorized object access. Verify it against the "
            "runtime policy and backend response."
        ),
        "confirmed": (
            "The finding was marked confirmed by the analysis "
            "pipeline. Include the associated runtime evidence "
            "when reporting it."
        ),
        "not_confirmed": (
            "The available verification did not confirm the "
            "suspected vulnerability."
        ),
        "inconclusive": (
            "The available evidence is insufficient to determine "
            "whether unauthorized access is possible."
        ),
    }

    related_paths = [
        path
        for path in source_to_sink_paths(result)
        if path["sink_path"] == finding.graphql_path
        or finding.graphql_path.startswith(path["sink_path"] + ".")
    ]

    return {
        "finding_id": finding.finding_id,
        "status": finding.status,
        "category": finding.category,
        "summary": status_summaries.get(
            finding.status,
            "No status explanation is available.",
        ),
        "principal_id": finding.principal_id,
        "target": {
            "type": finding.target_type,
            "id": finding.target_id,
        },
        "graphql_path": finding.graphql_path,
        "reason": finding.reason,
        "source_evidence": source_details,
        "authorization_evidence": relevant_boundaries,
        "related_nodes": related_nodes,
        "source_to_sink_paths": related_paths,
        "raw_evidence": list(finding.evidence),
    }


def explain_all_findings(result: AnalysisResult) -> list[dict]:
    return [
        explain_finding(finding, result)
        for finding in result.findings
    ]
