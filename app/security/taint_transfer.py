from __future__ import annotations

from hashlib import sha256
from collections.abc import Iterable

from .taint_boundaries import (
    _matching_field_nodes,
    apply_authorization_boundaries,
)
from .taint_models import (
    AnalysisResult,
    AuthorizationBoundary,
    BolaFinding,
    TaintSource,
)


def _finding_id(
    category: str,
    principal_id: str,
    action: str,
    object_type: str,
    object_id: object,
    graphql_path: str,
) -> str:
    raw = "|".join(
        (
            category,
            principal_id,
            action,
            object_type,
            str(object_id),
            graphql_path,
        )
    )
    digest = sha256(raw.encode("utf-8")).hexdigest()[:20]
    return f"bola-{digest}"


def _source_map(
    sources: Iterable[TaintSource],
) -> dict[str, TaintSource]:
    return {source.source_id: source for source in sources}


def _active_sources(
    source_ids: Iterable[str],
    sources: dict[str, TaintSource],
) -> list[TaintSource]:
    return [
        sources[source_id]
        for source_id in dict.fromkeys(source_ids)
        if source_id in sources
    ]


def _is_indirect_path(
    graphql_path: str,
    active_sources: Iterable[TaintSource],
) -> bool:
    for source in active_sources:
        source_path = source.graphql_path

        if (
            source_path != graphql_path
            and graphql_path.startswith(source_path + ".")
        ):
            return True

    return False


def authorization_aware_transfer(
    result: AnalysisResult,
    principal_id: str,
    action: str,
    boundaries: Iterable[AuthorizationBoundary] | None = None,
    sensitive_sink_paths: Iterable[str] = (),
) -> AnalysisResult:
    """
    Evaluate tainted paths against explicit authorization observations.

    Denial creates a suspected BOLA finding, not a confirmed exploit.
    Unknown authorization stays inconclusive.

    A successful authorization observation applies only to the exact
    observed object/path. It does not automatically authorize children.
    """
    selected_boundaries = list(
        result.boundaries if boundaries is None else boundaries
    )

    apply_authorization_boundaries(result, selected_boundaries)

    sources = _source_map(result.sources)
    relevant_boundaries = [
        boundary
        for boundary in selected_boundaries
        if boundary.principal_id == principal_id
        and boundary.action == action
        and boundary.graphql_path is not None
    ]

    new_findings: list[BolaFinding] = []

    # First, evaluate explicit authorization observations.
    for boundary in relevant_boundaries:
        nodes = _matching_field_nodes(result, boundary)

        tainted_nodes = [
            node
            for node in nodes
            if node.taint_source_ids
        ]

        if not tainted_nodes:
            continue

        active_ids = tuple(
            dict.fromkeys(
                source_id
                for node in tainted_nodes
                for source_id in node.taint_source_ids
            )
        )
        active = _active_sources(active_ids, sources)

        if boundary.authorized is True:
            # This boundary authorizes only this observed object.
            # Keep taint available for checks on descendant objects.
            continue

        if boundary.authorized is False:
            category = (
                "indirect_bola"
                if _is_indirect_path(
                    boundary.graphql_path or "",
                    active,
                )
                else "direct_bola"
            )
            status = "suspected"
            reason = (
                "The supplied authorization observation denied "
                "access to this tainted object."
            )
        else:
            category = "authorization_unknown"
            status = "inconclusive"
            reason = (
                "Authorization for this tainted object could not "
                "be determined. Access must not be assumed safe."
            )

        evidence = tuple(
            [f"source:{source_id}" for source_id in active_ids]
            + [
                f"boundary:{boundary.object_type}:"
                f"{boundary.object_id}",
                f"authorization_reason:{boundary.reason}",
            ]
        )

        new_findings.append(
            BolaFinding(
                finding_id=_finding_id(
                    category,
                    principal_id,
                    action,
                    boundary.object_type,
                    boundary.object_id,
                    boundary.graphql_path or "",
                ),
                status=status,
                category=category,
                principal_id=principal_id,
                target_type=boundary.object_type,
                target_id=boundary.object_id,
                graphql_path=boundary.graphql_path or "",
                reason=reason,
                evidence=evidence,
            )
        )

    # Then look for missing checks at explicitly configured sinks.
    # The analyzer does not guess which fields are sensitive.
    sink_paths = set(sensitive_sink_paths)

    for sink_path in sink_paths:
        sink_nodes = [
            node
            for node in result.nodes
            if node.node_type == "graphql_field"
            and node.graphql_path == sink_path
            and node.taint_source_ids
        ]

        if not sink_nodes:
            continue

        boundary_at_sink = any(
            boundary.graphql_path == sink_path
            for boundary in relevant_boundaries
        )

        if boundary_at_sink:
            continue

        # If an ancestor was explicitly denied, the path is already
        # rejected. Do not create a redundant missing-boundary finding.
        denied_ancestor = any(
            boundary.authorized is False
            and (
                sink_path == boundary.graphql_path
                or sink_path.startswith(
                    (boundary.graphql_path or "") + "."
                )
            )
            for boundary in relevant_boundaries
        )

        if denied_ancestor:
            continue

        active_ids = tuple(
            dict.fromkeys(
                source_id
                for node in sink_nodes
                for source_id in node.taint_source_ids
            )
        )

        new_findings.append(
            BolaFinding(
                finding_id=_finding_id(
                    "missing_authorization_boundary",
                    principal_id,
                    action,
                    "Unknown",
                    "Unknown",
                    sink_path,
                ),
                status="inconclusive",
                category="missing_authorization_boundary",
                principal_id=principal_id,
                target_type=None,
                target_id=None,
                graphql_path=sink_path,
                reason=(
                    "This configured sensitive sink has taint, "
                    "but no authorization observation was supplied "
                    "for the exact sink path."
                ),
                evidence=tuple(
                    f"source:{source_id}"
                    for source_id in active_ids
                ),
            )
        )

    existing_finding_ids = {
        finding.finding_id for finding in result.findings
    }

    for finding in new_findings:
        if finding.finding_id not in existing_finding_ids:
            result.findings.append(finding)
            existing_finding_ids.add(finding.finding_id)

    return result
