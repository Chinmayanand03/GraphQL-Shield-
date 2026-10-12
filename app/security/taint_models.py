from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

ScalarId = str | int

TaintSourceKind = Literal["variable", "literal", "default"]

FindingStatus = Literal[
    "suspected",
    "confirmed",
    "not_confirmed",
    "inconclusive",
]


@dataclass(frozen=True, slots=True)
class TaintSource:
    source_id: str
    value: ScalarId
    source_kind: TaintSourceKind
    graphql_path: str
    field_name: str
    argument_name: str
    operation_type: str
    operation_name: str | None = None
    variable_name: str | None = None

    def to_dict(self) -> dict:
        return {
            "source_id": self.source_id,
            "value": self.value,
            "source_kind": self.source_kind,
            "graphql_path": self.graphql_path,
            "field_name": self.field_name,
            "argument_name": self.argument_name,
            "operation_type": self.operation_type,
            "operation_name": self.operation_name,
            "variable_name": self.variable_name,
        }


@dataclass(frozen=True, slots=True)
class AnalysisNode:
    node_id: str
    node_type: str
    label: str
    graphql_path: str
    object_type: str | None = None
    object_id: ScalarId | None = None
    taint_source_ids: tuple[str, ...] = ()
    context_key: str | None = None


@dataclass(frozen=True, slots=True)
class AnalysisEdge:
    source_node_id: str
    target_node_id: str
    edge_type: str
    field_name: str | None = None
    evidence: str | None = None


@dataclass(frozen=True, slots=True)
class AuthorizationBoundary:
    principal_id: str
    action: str
    object_type: str
    object_id: ScalarId
    authorized: bool | None
    reason: str
    policy_name: str | None = None
    graphql_path: str | None = None


@dataclass(frozen=True, slots=True)
class BolaFinding:
    finding_id: str
    status: FindingStatus
    category: str
    principal_id: str | None
    target_type: str | None
    target_id: ScalarId | None
    graphql_path: str
    reason: str
    evidence: tuple[str, ...] = ()
    confidence: float | None = None


@dataclass(frozen=True, slots=True)
class SourceTrackingResult:
    sources: tuple[TaintSource, ...] = ()
    warnings: tuple[str, ...] = ()
    operation_count: int = 0

    @property
    def valid(self) -> bool:
        return "invalid_graphql" not in self.warnings


@dataclass(slots=True)
class AnalysisResult:
    sources: list[TaintSource] = field(default_factory=list)
    nodes: list[AnalysisNode] = field(default_factory=list)
    edges: list[AnalysisEdge] = field(default_factory=list)
    boundaries: list[AuthorizationBoundary] = field(
        default_factory=list
    )
    findings: list[BolaFinding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
