"""Independent, data-driven ground-truth oracle for BOLA benchmark cases.

This module deliberately does not import the application's PolicyEngine and does
not use a case's scenario name, detector output, or existing ``is_bola`` label to
make the decision. It derives the expected authorization result from the actor,
role, target object, and ownership metadata/catalog supplied to it.

Catalog formats accepted:
  * {"Resource": {"201": {"id": 201, "owner_id": 101}}}
  * {("Resource", 201): {"id": 201, "owner_id": 101}}
  * {201: {"id": 201, "type": "Resource", "owner_id": 101}}
  * [{"id": 201, "type": "Resource", "owner_id": 101}, ...]

Unknown ownership is denied by default (fail closed). Update aliases here if your
benchmark's field names differ. This is a benchmark oracle, not production auth.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping, Optional, Sequence


_MISSING = object()


@dataclass(frozen=True)
class GroundTruthDecision:
    authorized: bool
    reason: str
    subject_id: Optional[str]
    object_id: Optional[str]
    object_type: Optional[str]
    owner_id: Optional[str]

    @property
    def is_bola(self) -> bool:
        # A confirmed BOLA requires evidence that the target/path belongs to
        # someone else. Unknown ownership is denied, but is not labelled as a
        # confirmed BOLA finding.
        return self.reason in {"object_owned_by_another_subject", "parent_not_owned_by_subject"}

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["is_bola"] = self.is_bola
        return result


def _get(value: Any, *names: str, default: Any = None) -> Any:
    """Read the first non-None name from a mapping or object."""
    for name in names:
        candidate = value.get(name, _MISSING) if isinstance(value, Mapping) else getattr(value, name, _MISSING)
        if candidate is not _MISSING and candidate is not None:
            return candidate
    return default


def _norm_id(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value).strip()


def _record_owner(record: Any) -> Any:
    return _get(
        record,
        "owner_id",
        "ownerId",
        "user_id",
        "userId",
        "created_by",
        "createdBy",
        "created_by_id",
        "createdById",
        "principal_id",
    )


def _catalog_records(catalog: Any) -> list[Any]:
    if catalog is None:
        return []
    if isinstance(catalog, Sequence) and not isinstance(catalog, (str, bytes, bytearray)):
        return list(catalog)
    if isinstance(catalog, Mapping):
        records: list[Any] = []
        for key, value in catalog.items():
            # Type -> {id -> record} layout.
            if isinstance(value, Mapping) and not any(
                k in value for k in ("id", "object_id", "resource_id", "owner_id", "ownerId")
            ):
                for inner_key, inner_value in value.items():
                    if isinstance(inner_value, Mapping) or hasattr(inner_value, "__dict__"):
                        if _get(inner_value, "id", "object_id", "resource_id", default=None) is None:
                            try:
                                inner_value = dict(inner_value, id=inner_key, type=key)
                            except (TypeError, ValueError):
                                pass
                        records.append(inner_value)
                continue
            if isinstance(value, Mapping) or hasattr(value, "__dict__"):
                # Tuple keys commonly mean (type, id); scalar keys commonly mean id.
                if _get(value, "id", "object_id", "resource_id", default=None) is None:
                    extras: dict[str, Any] = {}
                    if isinstance(key, tuple) and len(key) >= 2:
                        extras.update(type=key[0], id=key[1])
                    elif isinstance(key, (str, int)):
                        extras.update(id=key)
                    try:
                        value = dict(value, **extras)
                    except (TypeError, ValueError):
                        pass
                records.append(value)
        return records
    return []


def _find_record(object_id: Any, object_type: Optional[str], catalog: Any) -> Any:
    if object_id is None or catalog is None:
        return None
    if isinstance(catalog, Mapping):
        direct_keys: list[Any] = [object_id, str(object_id)]
        try:
            direct_keys.append(int(object_id))
        except (TypeError, ValueError):
            pass
        if object_type is not None:
            direct_keys = [(object_type, object_id), (object_type, str(object_id)), *direct_keys]
        for key in direct_keys:
            try:
                value = catalog.get(key, _MISSING)
            except (TypeError, AttributeError):
                value = _MISSING
            if value is not _MISSING and value is not None:
                # A nested type -> id -> record map may need one more lookup.
                if isinstance(value, Mapping) and object_id is not None and not any(
                    name in value for name in ("owner_id", "ownerId", "user_id", "created_by", "id", "object_id")
                ):
                    nested = value.get(object_id, value.get(str(object_id), _MISSING))
                    if nested is not _MISSING:
                        return nested
                return value
    wanted_id = _norm_id(object_id)
    wanted_type = str(object_type).lower() if object_type is not None else None
    for record in _catalog_records(catalog):
        record_id = _get(record, "id", "object_id", "resource_id", "target_object_id")
        record_type = _get(record, "type", "object_type", "resource_type", "__typename")
        if _norm_id(record_id) != wanted_id:
            continue
        if wanted_type and record_type and str(record_type).lower() != wanted_type:
            continue
        return record
    return None


def _object_descriptor(item: Any, catalog: Any) -> tuple[Any, Optional[str], Any, Any]:
    """Return (id, type, record, explicit_owner) for a chain entry."""
    if isinstance(item, Mapping) or hasattr(item, "__dict__"):
        object_id = _get(item, "object_id", "target_object_id", "resource_id", "id")
        object_type = _get(item, "object_type", "resource_type", "type", "__typename", default="Resource")
        explicit_owner = _get(item, "target_owner_id", "resource_owner_id", "owner_id", "ownerId")
        record = item if _record_owner(item) is not None or _get(item, "public", "is_public") is not None else _find_record(object_id, object_type, catalog)
        if explicit_owner is None:
            explicit_owner = _record_owner(record)
        return object_id, str(object_type) if object_type is not None else None, record, explicit_owner
    record = _find_record(item, None, catalog)
    object_type = _get(record, "type", "object_type", "resource_type", default="Resource")
    return item, str(object_type) if object_type is not None else None, record, _record_owner(record)


def _is_public(record: Any) -> bool:
    return bool(_get(record, "public", "is_public", "isPublic", default=False))


def _is_admin(role: Any, is_admin: bool = False) -> bool:
    if is_admin:
        return True
    if isinstance(role, (list, tuple, set, frozenset)):
        roles = {str(value).strip().lower() for value in role}
    else:
        roles = {str(role).strip().lower()} if role is not None else set()
    return bool(roles.intersection({"admin", "administrator", "superuser", "system"}))


def evaluate_ground_truth(
    subject_id: Any,
    object_id: Any,
    object_type: Optional[str] = "Resource",
    object_catalog: Any = None,
    *,
    subject_role: Any = "user",
    is_admin: bool = False,
    owner_id: Any = None,
    parent_chain: Optional[Sequence[Any]] = None,
) -> GroundTruthDecision:
    """Evaluate read authorization using the benchmark's independent oracle.

    Policy: administrators can read all objects; public objects can be read by
    anyone; otherwise the subject must own every object in the supplied path.
    Missing ownership metadata is denied. This explicit policy can be adjusted
    if the benchmark's stated policy differs, but should not call PolicyEngine.
    """
    subject = _norm_id(subject_id)
    target = _norm_id(object_id)
    type_name = str(object_type) if object_type is not None else None

    if _is_admin(subject_role, is_admin):
        return GroundTruthDecision(True, "administrator_access", subject, target, type_name, _norm_id(owner_id))
    if subject is None or target is None:
        return GroundTruthDecision(False, "missing_subject_or_object_id", subject, target, type_name, _norm_id(owner_id))

    for path_item in list(parent_chain or []):
        path_id, path_type, record, path_owner = _object_descriptor(path_item, object_catalog)
        path_id_norm = _norm_id(path_id)
        if path_id_norm is None:
            return GroundTruthDecision(False, "missing_parent_object_id", subject, target, type_name, _norm_id(owner_id))
        if _is_public(record):
            continue
        if path_owner is None:
            return GroundTruthDecision(False, "unknown_parent_ownership_denied", subject, target, type_name, None)
        if _norm_id(path_owner) != subject:
            return GroundTruthDecision(False, "parent_not_owned_by_subject", subject, path_id_norm, path_type, _norm_id(path_owner))

    record = _find_record(target, type_name, object_catalog)
    # An explicit owner on the case is acceptable as oracle input metadata. The
    # existing label/scenario/detector prediction is never used to infer it.
    actual_owner = owner_id if owner_id is not None else _record_owner(record)
    if _is_public(record):
        return GroundTruthDecision(True, "public_object", subject, target, type_name, _norm_id(actual_owner))
    if actual_owner is None:
        return GroundTruthDecision(False, "unknown_ownership_denied", subject, target, type_name, None)
    if _norm_id(actual_owner) == subject:
        return GroundTruthDecision(True, "subject_owns_object", subject, target, type_name, _norm_id(actual_owner))
    return GroundTruthDecision(False, "object_owned_by_another_subject", subject, target, type_name, _norm_id(actual_owner))


def label_case_with_oracle(case: Any, object_catalog: Any = None) -> dict[str, Any]:
    """Create independent ground-truth labels for a dict or benchmark-case object.

    Deliberately ignores ``is_bola``, ``expected_authorized``, ``scenario``, and
    detector fields when determining the expected result.
    """
    subject_id = _get(case, "principal_id", "subject_id", "user_id", "actor_id", "requester_id")
    target_id = _get(case, "target_object_id", "object_id", "resource_id", "target_id", "child_id")
    target_type = _get(case, "target_object_type", "object_type", "resource_type", "target_type", default="Resource")
    owner_id = _get(case, "target_owner_id", "resource_owner_id", "object_owner_id", "owner_id", "ownerId")
    role = _get(case, "principal_role", "user_role", "role", default="user")
    is_admin = bool(_get(case, "is_admin", "principal_is_admin", default=False))
    parent_chain = _get(case, "parent_chain", "object_path", "access_chain", default=None)

    decision = evaluate_ground_truth(
        subject_id,
        target_id,
        target_type,
        object_catalog,
        subject_role=role,
        is_admin=is_admin,
        owner_id=owner_id,
        parent_chain=parent_chain,
    )
    return {
        "ground_truth_authorized": decision.authorized,
        "ground_truth_is_bola": decision.is_bola,
        "ground_truth_reason": decision.reason,
        "ground_truth_subject_id": decision.subject_id,
        "ground_truth_object_id": decision.object_id,
        "ground_truth_object_type": decision.object_type,
        "ground_truth_owner_id": decision.owner_id,
    }


def annotate_case_with_oracle(case: Any, object_catalog: Any = None) -> Any:
    """Return a copy of a dict case with oracle labels attached.

    For dataclass/model instances, use ``label_case_with_oracle`` and merge the
    returned mapping with your project's existing dataset serialization. This
    avoids silently mutating objects that may be frozen or validated models.
    """
    labels = label_case_with_oracle(case, object_catalog)
    if isinstance(case, Mapping):
        return {**dict(case), **labels}
    raise TypeError("annotate_case_with_oracle expects a mapping; use label_case_with_oracle for model instances")


__all__ = [
    "GroundTruthDecision",
    "evaluate_ground_truth",
    "label_case_with_oracle",
    "annotate_case_with_oracle",
]
