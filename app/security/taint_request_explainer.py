"""Authenticated, read-only API for per-request taint-source and authorization explanation.

This endpoint does not execute GraphQL or enforce access. It runs the existing
source tracker and authorization policy in explanation mode, so the dashboard
can show why the observed request was denied or permitted.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from graphql import FieldNode, FragmentDefinitionNode, FragmentSpreadNode, OperationDefinitionNode

from app.core.dependencies import get_current_user
from app.security.authorization import AuthorizationContext, PolicyEngine
from app.security.graphql_parser import parse_query
from app.security.object_extractor import normalize_query
from app.security.ownership import get_object_owner
from app.security.taint_sources import track_sources

router = APIRouter(prefix="/api/v1", tags=["taint-explanation"])


class TaintExplanationRequest(BaseModel):
    query: str = Field(min_length=1, max_length=20000)
    variables: dict[str, Any] = Field(default_factory=dict)


def _reason_explanation(reason: str, principal_id: Any, owner_id: Any, role: str) -> str:
    explanations = {
        "OWNER_MATCH": f"The authenticated principal {principal_id} matches this object's owner {owner_id}.",
        "ADMIN_OVERRIDE": f"The authenticated role {role.upper()} is permitted by the configured administrator policy.",
        "OWNERSHIP_MISMATCH": f"The authenticated principal {principal_id} does not own this object (owner {owner_id}); the policy denies access.",
        "NESTED_AUTHORIZATION_VIOLATION": f"The requested object is reached through a nested GraphQL path and the policy denies this principal's access.",
        "OBJECT_NOT_FOUND": "No owner was found for the requested object, so access is denied by the configured policy.",
        "INVALID_CONTEXT": "The authorization context is incomplete, so access is denied.",
    }
    return explanations.get(reason, f"The policy engine returned {reason}.")


def _collect_nested_selection_paths(query: str) -> list[str]:
    """Return nested selection paths present in the submitted GraphQL document.

    This describes query structure. It does not claim that every nested field
    was dynamically taint-propagated or that hidden child objects were observed.
    """
    ast = parse_query(query)
    if ast is None:
        return []
    fragments = {
        definition.name.value: definition
        for definition in ast.definitions
        if isinstance(definition, FragmentDefinitionNode)
    }
    paths: list[str] = []

    def visit(selection_set: Any, parent_path: str, stack: set[str]) -> None:
        if selection_set is None:
            return
        for selection in selection_set.selections:
            if isinstance(selection, FieldNode):
                field_name = selection.alias.value if selection.alias else selection.name.value
                path = f"{parent_path}.{field_name}" if parent_path else field_name
                if selection.selection_set:
                    if parent_path:
                        paths.append(path)
                    visit(selection.selection_set, path, stack)
            elif isinstance(selection, FragmentSpreadNode):
                name = selection.name.value
                fragment = fragments.get(name)
                if fragment and name not in stack:
                    stack.add(name)
                    visit(fragment.selection_set, parent_path, stack)
                    stack.remove(name)
            elif hasattr(selection, "selection_set"):
                visit(getattr(selection, "selection_set", None), parent_path, stack)

    for definition in ast.definitions:
        if isinstance(definition, OperationDefinitionNode):
            visit(definition.selection_set, "", set())
    return list(dict.fromkeys(paths))


def build_taint_explanation(
    query: str,
    variables: dict[str, Any],
    principal: dict[str, Any],
) -> dict[str, Any]:
    """Build request-specific evidence using the project's existing modules."""
    tracking = track_sources(query, variables)
    normalized = normalize_query(query, variables)
    if not tracking.valid or normalized is None:
        raise ValueError("The query could not be parsed for taint and authorization explanation.")

    principal_id = principal.get("user_id", principal.get("sub"))
    if principal_id is None:
        raise ValueError("The authenticated token does not contain a user ID.")
    try:
        principal_id = int(principal_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("The authenticated user ID is not a valid integer.") from exc
    role = str(principal.get("role", "user"))
    operation = str(normalized.get("operation") or "query")
    sources = [source.to_dict() for source in tracking.sources]
    objects: list[dict[str, Any]] = []
    policy_engine = PolicyEngine()

    for item in normalized.get("objects", []):
        object_type = str(item.get("type") or "Resource")
        object_id = item.get("id")
        path = str(item.get("path") or object_type.lower())
        matching_sources = [
            source for source in sources
            if str(source.get("value")) == str(object_id)
            and (source.get("graphql_path") == path or str(source.get("graphql_path", "")).endswith(path))
        ]
        try:
            owner_id = get_object_owner(object_type, object_id)
            context = AuthorizationContext(
                user_id=principal_id,
                role=role,
                operation=operation,
                object_type=object_type,
                object_id=object_id,
                path=path,
                owner_id=owner_id,
                metadata={"purpose": "dashboard_read_only_explanation"},
            )
            result = policy_engine.evaluate(context)
            decision = str(result.get("decision", "UNKNOWN")).upper()
            reason = str(result.get("reason", "UNKNOWN"))
            risk_score = result.get("risk_score")
            risk_level = result.get("risk_level")
            explanation = _reason_explanation(reason, principal_id, owner_id, role)
        except Exception as exc:  # never turn an analysis error into an allow decision
            owner_id = None
            decision = "INCONCLUSIVE"
            reason = "EXPLANATION_EVALUATION_FAILED"
            risk_score = None
            risk_level = "UNKNOWN"
            explanation = f"The explanation could not evaluate this object safely ({type(exc).__name__}). No allow conclusion was inferred."

        objects.append({
            "object_type": object_type,
            "object_id": object_id,
            "graphql_path": path,
            "owner_id": owner_id,
            "matched_taint_sources": matching_sources,
            "authorization": {
                "decision": decision,
                "reason": reason,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "explanation": explanation,
                "policy_engine_replay": True,
            },
        })

    return {
        "principal": {"user_id": principal_id, "role": role},
        "operation": operation,
        "source_tracking": {
            "valid": tracking.valid,
            "operation_count": tracking.operation_count,
            "source_count": len(sources),
            "warnings": list(tracking.warnings),
        },
        "taint_sources": sources,
        "objects": objects,
        "relationship_paths": _collect_nested_selection_paths(query),
        "notes": [
            "Taint-source entries come from the project's track_sources() function.",
            "Authorization results are a read-only replay of the existing PolicyEngine; this endpoint does not execute or enforce the GraphQL request.",
            "A nested selection path describes query structure. It does not by itself prove a child was leaked or filtered; compare it with the observed response and resolver behavior.",
            "If no source is returned, the source tracker did not recognize an ID-like input in this query; this must not be interpreted as proof that the query is safe.",
        ],
    }


@router.post("/taint-explain")
def explain_taint_request(
    request: TaintExplanationRequest,
    current_user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Expose authenticated, read-only explanation data for the local dashboard."""
    try:
        return build_taint_explanation(request.query, request.variables, current_user)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
