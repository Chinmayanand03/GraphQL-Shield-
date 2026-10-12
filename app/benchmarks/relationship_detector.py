"""Detect unauthorized objects reachable through implicit GraphQL relationships.

This is a benchmark analysis helper, not a replacement for resolver-level
authorization. It inspects object-valued GraphQL selections (for example,
``resource(id: $parentId) { children { id ownerId } }``), resolves the children
from an ownership/relationship catalog, and flags a path when at least one
resolved child is owned by somebody other than the authenticated principal.

Unknown ownership is recorded as inconclusive rather than asserted to be BOLA.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.security.relationship_extractor import (
    extract_relationship_paths,
    resolve_relationship_objects,
)

_ID_ARGUMENT_NAMES = {"id", "resourceid", "objectid", "childid", "nodeid"}
_ADMIN_ROLES = {"admin", "administrator", "superuser", "system"}


def _value(record: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        candidate = record.get(name) if isinstance(record, Mapping) else getattr(record, name, None)
        if candidate is not None:
            return candidate
    return default


def _normalise_catalog(object_catalog: Any = None) -> dict[str, dict[str, dict[str, Any]]]:
    """Return the flat Resource catalogue format consumed by relationship_extractor.

    Accepted inputs are the benchmark's raw ``OBJECTS`` mapping, the existing
    ``{"Resource": {id: record}}`` format, or a sequence of records.
    Relationship children are derived from ``parent_id`` so stale/missing
    precomputed ``children`` arrays cannot mask a relationship.
    """
    if object_catalog is None:
        from app.benchmarks.dataset import OBJECTS
        source: Any = OBJECTS
    else:
        source = object_catalog

    if isinstance(source, Mapping) and isinstance(source.get("Resource"), Mapping):
        source = source["Resource"]

    if isinstance(source, Mapping):
        items = list(source.items())
    elif isinstance(source, Sequence) and not isinstance(source, (str, bytes, bytearray)):
        items = [(None, item) for item in source]
    else:
        items = []

    records: dict[str, dict[str, Any]] = {}
    for key, raw in items:
        if not isinstance(raw, Mapping):
            continue
        object_id = _value(raw, "id", "object_id", "resource_id", "target_object_id", default=key)
        if object_id is None:
            continue
        record = dict(raw)
        record["id"] = object_id
        record.setdefault("type", "Resource")
        record.setdefault("owner_id", _value(raw, "ownerId", "user_id", "userId", "created_by"))
        record.setdefault("parent_id", _value(raw, "parentId", "parent_object_id"))
        record["children"] = []
        records[str(object_id)] = record

    for record in records.values():
        parent_id = record.get("parent_id")
        if parent_id is None:
            continue
        parent = records.get(str(parent_id))
        if parent is not None:
            parent["children"].append(record["id"])

    return {"Resource": records}


def _is_admin(role: Any) -> bool:
    if isinstance(role, (list, tuple, set, frozenset)):
        roles = {str(item).strip().lower() for item in role}
    else:
        roles = {str(role).strip().lower()} if role is not None else set()
    return bool(roles.intersection(_ADMIN_ROLES))


def _is_implicit_relationship(access: Any) -> bool:
    relation_args = _value(access, "relation_args", default={}) or {}
    return not any(
        str(name).lower() in _ID_ARGUMENT_NAMES and value is not None
        for name, value in relation_args.items()
    )


def detect_implicit_relationship_bola(
    query: str,
    variables: Mapping[str, Any] | None,
    principal_id: Any,
    role: Any = "user",
    object_catalog: Any = None,
) -> dict[str, Any]:
    """Return relationship-path findings for one query/principal pair.

    ``detected`` is true only when a resolved child has known, non-public
    ownership belonging to a different principal. Missing owner metadata is
    reported under ``unknown_owner_child_ids`` and does not inflate confirmed
    BOLA detections.
    """
    report: dict[str, Any] = {
        "detected": False,
        "analysis_status": "ok",
        "relationship_path_count": 0,
        "resolved_child_count": 0,
        "unauthorized_child_ids": [],
        "unknown_owner_child_ids": [],
        "evidence": [],
    }

    if _is_admin(role):
        report["analysis_status"] = "administrator_bypass"
        return report

    try:
        accesses = extract_relationship_paths(query, dict(variables or {}))
    except Exception as exc:  # parser errors should be visible in the report
        report["analysis_status"] = f"parse_error:{type(exc).__name__}"
        return report

    catalogue = _normalise_catalog(object_catalog)
    implicit_accesses = [
        access for access in accesses
        if _is_implicit_relationship(access) and _value(access, "parent_id") is not None
    ]
    report["relationship_path_count"] = len(implicit_accesses)

    unauthorized_ids: set[str] = set()
    unknown_ids: set[str] = set()
    evidence: list[dict[str, Any]] = []
    resolved_child_count = 0

    for access in implicit_accesses:
        parent_id = _value(access, "parent_id")
        children = resolve_relationship_objects(access, catalogue)
        for child in children:
            child_id = _value(child, "id", "object_id", "resource_id", "target_object_id")
            if child_id is None:
                continue
            resolved_child_count += 1
            owner_id = _value(child, "owner_id", "ownerId", "user_id", "userId", "created_by")
            is_public = bool(_value(child, "public", "is_public", "isPublic", default=False))
            if is_public:
                continue
            if owner_id is None:
                unknown_ids.add(str(child_id))
                continue
            if str(owner_id) != str(principal_id):
                unauthorized_ids.add(str(child_id))
                evidence.append({
                    "parent_id": parent_id,
                    "relationship_field": _value(access, "relation_field"),
                    "response_path": list(_value(access, "response_path", default=()) or ()),
                    "child_id": child_id,
                    "child_owner_id": owner_id,
                    "principal_id": principal_id,
                    "reason": "child_owned_by_another_subject",
                })

    report["resolved_child_count"] = resolved_child_count
    report["unauthorized_child_ids"] = sorted(unauthorized_ids, key=str)
    report["unknown_owner_child_ids"] = sorted(unknown_ids, key=str)
    report["evidence"] = evidence
    report["detected"] = bool(unauthorized_ids)
    if not implicit_accesses:
        report["analysis_status"] = "no_implicit_relationship_path"
    elif resolved_child_count == 0:
        report["analysis_status"] = "relationship_children_unresolved"
    elif not unauthorized_ids and unknown_ids:
        report["analysis_status"] = "inconclusive_unknown_child_ownership"
    return report


__all__ = ["detect_implicit_relationship_bola"]
