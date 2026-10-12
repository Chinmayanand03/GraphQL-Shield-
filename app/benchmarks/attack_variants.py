"""Generate reproducible, data-driven variants from analyzer findings.

The generator preserves the finding's original GraphQL operation and varies an
object-ID variable using IDs from the supplied object catalog. It never labels a
case from its scenario name or detector prediction. Ground-truth labels are
computed separately with ``app.benchmarks.ground_truth`` when ownership data is
available.

Use ``to_attack_cases`` as an adapter if your dynamic verifier expects the
project's existing AttackCase class. This module does not replace that class.
"""

from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping, Optional, Sequence


@dataclass(frozen=True)
class AttackVariant:
    variant_id: str
    finding_id: str
    kind: str
    query: str
    variables: dict[str, Any]
    principal_id: Any = None
    target_object_id: Any = None
    target_object_type: str = "Resource"
    expected_authorized: Optional[bool] = None
    target_response_path: tuple[str, ...] = ()
    description: str = ""

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["target_response_path"] = list(self.target_response_path)
        return result


def _get(value: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        candidate = value.get(name) if isinstance(value, Mapping) else getattr(value, name, None)
        if candidate is not None:
            return candidate
    return default


def _variables(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return dict(parsed) if isinstance(parsed, Mapping) else {}
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
    return {}


def _normal_path(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(part for part in value.replace("[", ".").replace("]", "").split(".") if part)
    if isinstance(value, Sequence):
        return tuple(str(part) for part in value)
    return (str(value),)


def _records(catalog: Any) -> list[Any]:
    if catalog is None:
        return []
    if isinstance(catalog, Sequence) and not isinstance(catalog, (str, bytes, bytearray)):
        return list(catalog)
    if not isinstance(catalog, Mapping):
        return []
    output: list[Any] = []
    for key, value in catalog.items():
        if isinstance(value, Mapping) and not any(
            name in value for name in ("id", "object_id", "resource_id", "owner_id", "ownerId")
        ):
            for inner_key, inner_value in value.items():
                if isinstance(inner_value, Mapping):
                    rec = dict(inner_value)
                    rec.setdefault("id", inner_key)
                    if isinstance(key, str):
                        rec.setdefault("type", key)
                    output.append(rec)
        elif isinstance(value, Mapping):
            rec = dict(value)
            if isinstance(key, tuple) and len(key) >= 2:
                rec.setdefault("type", key[0])
                rec.setdefault("id", key[1])
            elif isinstance(key, (str, int)):
                rec.setdefault("id", key)
            output.append(rec)
    return output


def _value(record: Any, *names: str) -> Any:
    for name in names:
        val = record.get(name) if isinstance(record, Mapping) else getattr(record, name, None)
        if val is not None:
            return val
    return None


def _record_id(record: Any) -> Any:
    return _value(record, "id", "object_id", "resource_id", "target_object_id")


def _candidate_ids(catalog: Any, object_type: Optional[str], current_id: Any) -> list[Any]:
    wanted_type = str(object_type).lower() if object_type else None
    output: list[Any] = []
    seen: set[str] = set()
    for record in _records(catalog):
        record_type = _value(record, "type", "object_type", "resource_type", "__typename")
        if wanted_type and record_type and str(record_type).lower() != wanted_type:
            continue
        object_id = _record_id(record)
        if object_id is None:
            continue
        norm = str(object_id)
        if norm == str(current_id) or norm in seen:
            continue
        seen.add(norm)
        output.append(object_id)
    return output


def _id_variable_keys(variables: Mapping[str, Any], target_id: Any) -> list[str]:
    keys = list(variables.keys())
    exact = [key for key in keys if target_id is not None and str(variables[key]) == str(target_id)]
    def looks_like_id(key: str) -> bool:
        lowered = key.lower()
        return "id" in lowered and any(term in lowered for term in ("resource", "object", "target", "parent", "child", "node", "item"))
    preferred = [key for key in exact if looks_like_id(key)]
    if preferred:
        return preferred
    id_like = [key for key in keys if looks_like_id(key)]
    if id_like:
        return id_like
    exact_id = [key for key in exact if "id" in key.lower()]
    if exact_id:
        return exact_id
    return [key for key in keys if "id" in key.lower()]


def _cast_like(value: Any, example: Any) -> Any:
    if isinstance(example, int) and not isinstance(example, bool):
        try:
            return int(value)
        except (TypeError, ValueError):
            return value
    return str(value) if isinstance(example, str) else value


def _oracle_authorized(
    principal_id: Any,
    target_id: Any,
    target_type: str,
    role: Any,
    is_admin: bool,
    catalog: Any,
) -> Optional[bool]:
    if principal_id is None or target_id is None or catalog is None:
        return None
    try:
        from app.benchmarks.ground_truth import label_case_with_oracle

        labels = label_case_with_oracle(
            {
                "principal_id": principal_id,
                "target_object_id": target_id,
                "target_object_type": target_type,
                "principal_role": role,
                "is_admin": is_admin,
            },
            object_catalog=catalog,
        )
        # Missing/unknown ownership should be labelled unknown here, rather than
        # being silently transformed into an expected BOLA result.
        if str(labels.get("ground_truth_reason", "")).startswith(("unknown_", "missing_")):
            return None
        return bool(labels["ground_truth_authorized"])
    except (ImportError, TypeError, ValueError, KeyError):
        return None


def _stable_id(finding_id: str, ordinal: int, kind: str, query: str, variables: Mapping[str, Any]) -> str:
    material = json.dumps(
        {"finding": finding_id, "ordinal": ordinal, "kind": kind, "query": query, "variables": variables},
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    )
    return "av_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def generate_variants_from_findings(
    findings: Iterable[Any],
    resource_catalog: Any = None,
    *,
    variants_per_finding: int = 8,
    include_control_variant: bool = True,
) -> list[AttackVariant]:
    """Return unique attack variants based on actual analyzer findings.

    Expected useful finding fields include ``query``/``graphql_query``,
    ``variables``, ``principal_id``/``user_id``, ``target_object_id``/``object_id``,
    ``target_object_type``/``object_type``, and ``target_response_path``/``graphql_path``.
    If a finding contains no query, it is skipped rather than inventing a schema.
    """
    if variants_per_finding < 1:
        raise ValueError("variants_per_finding must be at least 1")

    variants: list[AttackVariant] = []
    used_ids: set[str] = set()

    for finding_index, finding in enumerate(findings):
        query = _get(finding, "query", "graphql_query", "original_query", "operation")
        if not isinstance(query, str) or not query.strip():
            continue
        base_variables = _variables(_get(finding, "variables", "query_variables", "graphql_variables", default={}))
        principal_id = _get(finding, "principal_id", "subject_id", "user_id", "actor_id", "requester_id")
        target_id = _get(finding, "target_object_id", "object_id", "resource_id", "target_id", "child_id")
        target_type = str(_get(finding, "target_object_type", "object_type", "resource_type", "target_type", default="Resource"))
        role = _get(finding, "principal_role", "user_role", "role", default="user")
        is_admin = bool(_get(finding, "is_admin", "principal_is_admin", default=False))
        raw_finding_id = _get(finding, "finding_id", "attack_id", "case_id", "id")
        finding_id = str(raw_finding_id if raw_finding_id is not None else f"finding_{finding_index}")
        response_path = _normal_path(_get(finding, "target_response_path", "response_path", "graphql_path", default=()))

        candidates: list[tuple[str, dict[str, Any], Any, str]] = []
        if include_control_variant:
            candidates.append(("source", dict(base_variables), target_id, "Replay the source finding without changing its variables."))

        variable_keys = _id_variable_keys(base_variables, target_id)
        if variable_keys:
            # Prefer changing the variable that appears to point at the target.
            primary_key = variable_keys[0]
            for candidate_id in _candidate_ids(resource_catalog, target_type, target_id):
                mutated = dict(base_variables)
                mutated[primary_key] = _cast_like(candidate_id, base_variables[primary_key])
                candidates.append(("object_id_substitution", mutated, candidate_id, f"Substitute {primary_key} with catalog object {candidate_id}."))
                if len(candidates) >= variants_per_finding:
                    break

        # Findings may carry a query specifically targeting a nested relationship.
        # Preserve it as an independent variant when it differs from the main query.
        for query_name, kind in (("relationship_query", "relationship_traversal"), ("nested_query", "nested_object")):
            special_query = _get(finding, query_name)
            if isinstance(special_query, str) and special_query.strip() and special_query != query:
                special_vars = _variables(_get(finding, f"{query_name}_variables", default=base_variables))
                candidates.append((kind, special_vars, _get(finding, f"{query_name}_target_id", default=target_id), f"Use the finding's {kind.replace('_', ' ')} query."))
                if len(candidates) >= variants_per_finding:
                    break

        seen_payloads: set[str] = set()
        ordinal = 0
        for kind, variables, variant_target_id, description in candidates:
            if len(variants) and ordinal >= variants_per_finding:
                break
            payload = json.dumps({"query": query if kind not in ("relationship_traversal", "nested_object") else _get(finding, "relationship_query" if kind == "relationship_traversal" else "nested_query"), "variables": variables}, sort_keys=True, default=str)
            # The local de-duplication removes repeated payloads while retaining
            # distinct query/variable combinations for meaningful variant diversity.
            if payload in seen_payloads:
                continue
            seen_payloads.add(payload)
            actual_query = query
            if kind == "relationship_traversal":
                actual_query = str(_get(finding, "relationship_query"))
            elif kind == "nested_object":
                actual_query = str(_get(finding, "nested_query"))

            if kind not in ("source", "relationship_traversal", "nested_object"):
                kind = "object_id_substitution"
            expected = _oracle_authorized(principal_id, variant_target_id, target_type, role, is_admin, resource_catalog)
            variant_id = _stable_id(finding_id, ordinal, kind, actual_query, variables)
            while variant_id in used_ids:
                ordinal += 1
                variant_id = _stable_id(finding_id, ordinal, kind, actual_query, variables)
            used_ids.add(variant_id)
            variants.append(
                AttackVariant(
                    variant_id=variant_id,
                    finding_id=finding_id,
                    kind=kind,
                    query=actual_query,
                    variables=dict(variables),
                    principal_id=principal_id,
                    target_object_id=variant_target_id,
                    target_object_type=target_type,
                    expected_authorized=expected,
                    target_response_path=response_path,
                    description=description,
                )
            )
            ordinal += 1
            if ordinal >= variants_per_finding:
                break

    return variants


def to_attack_cases(variants: Iterable[AttackVariant], attack_case_type: Any = None) -> list[Any]:
    """Adapt variants to the existing project's AttackCase type.

    Constructor fields are detected at runtime, so this does not force a change
    to the project's AttackCase implementation. If a required field cannot be
    mapped, a useful error is raised instead of silently dropping the variant.
    """
    if attack_case_type is None:
        try:
            from app.security.attack_generator import AttackCase as attack_case_type
        except ImportError as exc:
            raise ImportError(
                "Could not import app.security.attack_generator.AttackCase. "
                "Pass your AttackCase class explicitly to to_attack_cases()."
            ) from exc

    aliases: dict[str, Any]
    results: list[Any] = []
    signature = inspect.signature(attack_case_type)
    parameters = signature.parameters
    accepts_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in parameters.values())

    for variant in variants:
        source_path = ".".join(variant.target_response_path) if variant.target_response_path else "resource"
        aliases = {
            "id": variant.variant_id,
            "attack_id": variant.variant_id,
            "case_id": variant.variant_id,
            "attack_case_id": variant.variant_id,
            "variant_id": variant.variant_id,
            "query": variant.query,
            "graphql_query": variant.query,
            "operation": variant.query,
            "variables": dict(variant.variables),
            "query_variables": dict(variant.variables),
            "principal_id": str(variant.principal_id) if variant.principal_id is not None else "anonymous",
            "subject_id": variant.principal_id,
            "user_id": variant.principal_id,
            "actor_id": variant.principal_id,
            "action": "read",
            "operation_name": None,
            "source_id": variant.finding_id,
            "source_path": source_path,
            "source_kind": "variable",
            "target_object_id": variant.target_object_id,
            "object_id": variant.target_object_id,
            "resource_id": variant.target_object_id,
            "target_id": variant.target_object_id,
            "target_type": variant.target_object_type,
            "target_object_type": variant.target_object_type,
            "object_type": variant.target_object_type,
            "resource_type": variant.target_object_type,
            "target_owner_id": None,
            "expected_authorized": bool(variant.expected_authorized) if variant.expected_authorized is not None else False,
            "should_be_authorized": variant.expected_authorized,
            "target_response_path": list(variant.target_response_path),
            "response_path": list(variant.target_response_path),
            "description": variant.description,
            "name": variant.description,
            "reason": variant.description or f"Attack variant {variant.kind}",
            "scenario": variant.kind,
            "variant_kind": variant.kind,
            "finding_id": variant.finding_id,
        }
        if accepts_kwargs:
            kwargs = dict(aliases)
        else:
            kwargs = {name: aliases[name] for name in parameters if name in aliases}
            missing = [
                name for name, parameter in parameters.items()
                if name not in kwargs
                and parameter.default is inspect.Parameter.empty
                and parameter.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
            ]
            if missing:
                raise TypeError(
                    f"Cannot adapt AttackVariant to {attack_case_type!r}; required constructor fields not mapped: {missing}. "
                    "Add their aliases in to_attack_cases()."
                )
        results.append(attack_case_type(**kwargs))
    return results


__all__ = ["AttackVariant", "generate_variants_from_findings", "to_attack_cases"]
