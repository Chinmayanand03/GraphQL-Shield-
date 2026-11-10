"""Extract implicit object relationships from GraphQL selection sets.

This module is schema-agnostic: it identifies object-valued field traversal such
as ``resource(id: $parentId) { children { id ownerId } }`` and can resolve those
relationships against an in-memory object catalog or an explicit relationship
map. It does not import the application's enforcement middleware or database
models, so it can be tested independently before integration.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping, Optional, Sequence

try:
    from graphql import parse
    from graphql.language import value_from_ast_untyped
except ImportError:  # Lightweight fallback keeps this helper testable without graphql-core.
    import json
    import re
    from dataclasses import dataclass as _dataclass
    from types import SimpleNamespace

    @_dataclass
    class _FallbackVariable:
        name: Any

    @_dataclass
    class _FallbackName:
        value: str

    @_dataclass
    class _FallbackArgument:
        name: _FallbackName
        value: Any

    @_dataclass
    class _FallbackSelectionSet:
        selections: list[Any]
        kind: str = "selection_set"

    @_dataclass
    class _FallbackField:
        name: _FallbackName
        alias: Any = None
        arguments: list[Any] = None
        selection_set: Any = None
        kind: str = "field"

    @_dataclass
    class _FallbackOperation:
        selection_set: _FallbackSelectionSet
        kind: str = "operation_definition"

    @_dataclass
    class _FallbackFragment:
        name: _FallbackName
        selection_set: _FallbackSelectionSet
        kind: str = "fragment_definition"

    @_dataclass
    class _FallbackFragmentSpread:
        name: _FallbackName
        kind: str = "fragment_spread"

    @_dataclass
    class _FallbackInlineFragment:
        selection_set: _FallbackSelectionSet
        kind: str = "inline_fragment"

    def value_from_ast_untyped(node: Any, variables: Mapping[str, Any]) -> Any:
        if isinstance(node, _FallbackVariable):
            return variables.get(node.name.value)
        if isinstance(node, list):
            return [value_from_ast_untyped(item, variables) for item in node]
        if isinstance(node, dict):
            return {key: value_from_ast_untyped(value, variables) for key, value in node.items()}
        return node

    class _FallbackParser:
        _token_re = re.compile(
            r'\.\.\.|"(?:\\.|[^"\\])*"|#[^\n]*|[A-Za-z_][A-Za-z0-9_]*|-?\d+(?:\.\d+)?|[$!():{}\[\]=@|&,]'
        )

        def __init__(self, source: str):
            self.tokens = [m.group(0) for m in self._token_re.finditer(source) if not m.group(0).startswith("#") and m.group(0) != ","]
            self.pos = 0

        def peek(self, offset: int = 0) -> Optional[str]:
            idx = self.pos + offset
            return self.tokens[idx] if idx < len(self.tokens) else None

        def take(self) -> Optional[str]:
            value = self.peek()
            if value is not None:
                self.pos += 1
            return value

        def skip_balanced(self, opening: str, closing: str) -> None:
            if self.peek() != opening:
                return
            depth = 0
            while self.peek() is not None:
                token = self.take()
                if token == opening:
                    depth += 1
                elif token == closing:
                    depth -= 1
                    if depth == 0:
                        return

        def skip_directives(self) -> None:
            while self.peek() == "@":
                self.take()
                if self.peek() is not None:
                    self.take()
                if self.peek() == "(":
                    self.skip_balanced("(", ")")

        def seek_selection_body(self) -> bool:
            paren_depth = 0
            bracket_depth = 0
            while self.peek() is not None:
                token = self.peek()
                if token == "(" :
                    paren_depth += 1
                elif token == ")":
                    paren_depth = max(0, paren_depth - 1)
                elif token == "[":
                    bracket_depth += 1
                elif token == "]":
                    bracket_depth = max(0, bracket_depth - 1)
                elif token == "{" and paren_depth == 0 and bracket_depth == 0:
                    return True
                self.take()
            return False

        def parse_value(self) -> Any:
            token = self.take()
            if token is None:
                return None
            if token == "$":
                name = self.take() or ""
                return _FallbackVariable(_FallbackName(name))
            if token == "[":
                values = []
                while self.peek() is not None and self.peek() != "]":
                    values.append(self.parse_value())
                if self.peek() == "]":
                    self.take()
                return values
            if token == "{":
                values: dict[str, Any] = {}
                while self.peek() is not None and self.peek() != "}":
                    key = self.take()
                    if key is None:
                        break
                    if self.peek() == ":":
                        self.take()
                        values[key] = self.parse_value()
                    else:
                        break
                if self.peek() == "}":
                    self.take()
                return values
            if token.startswith('"'):
                try:
                    return json.loads(token)
                except (ValueError, TypeError):
                    return token[1:-1]
            if token == "true":
                return True
            if token == "false":
                return False
            if token == "null":
                return None
            if re.fullmatch(r"-?\d+", token):
                try:
                    return int(token)
                except ValueError:
                    pass
            if re.fullmatch(r"-?\d+\.\d+", token):
                try:
                    return float(token)
                except ValueError:
                    pass
            return token  # enum literal

        def parse_selection_set(self) -> _FallbackSelectionSet:
            if self.peek() == "{":
                self.take()
            selections: list[Any] = []
            while self.peek() is not None and self.peek() != "}":
                if self.peek() == "...":
                    self.take()
                    if self.peek() == "on":
                        self.take()
                        if self.peek() is not None:
                            self.take()  # Type condition
                        self.skip_directives()
                        if self.peek() == "{":
                            selections.append(_FallbackInlineFragment(self.parse_selection_set()))
                        continue
                    fragment_name = self.take() or ""
                    self.skip_directives()
                    selections.append(_FallbackFragmentSpread(_FallbackName(fragment_name)))
                    continue

                first = self.take()
                if first in (None, "}"):
                    break
                alias = None
                field_name = first
                if self.peek() == ":":
                    self.take()
                    alias = _FallbackName(first)
                    field_name = self.take() or ""

                arguments: list[Any] = []
                if self.peek() == "(":
                    self.take()
                    while self.peek() is not None and self.peek() != ")":
                        arg_name = self.take()
                        if arg_name is None:
                            break
                        if self.peek() == ":":
                            self.take()
                            arguments.append(_FallbackArgument(_FallbackName(arg_name), self.parse_value()))
                        else:
                            break
                    if self.peek() == ")":
                        self.take()
                self.skip_directives()
                nested = self.parse_selection_set() if self.peek() == "{" else None
                selections.append(_FallbackField(_FallbackName(field_name), alias, arguments, nested))
            if self.peek() == "}":
                self.take()
            return _FallbackSelectionSet(selections)

        def parse_document(self) -> Any:
            definitions: list[Any] = []
            while self.peek() is not None:
                token = self.peek()
                if token == "fragment":
                    self.take()
                    fragment_name = self.take() or "fragment"
                    if not self.seek_selection_body():
                        break
                    definitions.append(_FallbackFragment(_FallbackName(fragment_name), self.parse_selection_set()))
                    continue
                if token in ("query", "mutation", "subscription"):
                    self.take()
                    # Skip operation name, variable declaration, and directives
                    # until the operation's top-level selection set begins.
                    if not self.seek_selection_body():
                        break
                    definitions.append(_FallbackOperation(self.parse_selection_set()))
                    continue
                if token == "{":
                    definitions.append(_FallbackOperation(self.parse_selection_set()))
                    continue
                self.take()
            return SimpleNamespace(definitions=definitions)

    def parse(source: str) -> Any:
        return _FallbackParser(source).parse_document()


@dataclass(frozen=True)
class RelationshipAccess:
    parent_field: str
    relation_field: str
    parent_id: Any
    relation_args: dict[str, Any]
    response_path: tuple[str, ...]
    parent_response_path: tuple[str, ...]
    graphql_path: tuple[str, ...]
    selection_fields: tuple[str, ...]
    depth: int
    parent_type: Optional[str] = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _field_value(node: Any, variables: Mapping[str, Any]) -> Any:
    """Resolve GraphQL argument AST values, including ``$variables``."""
    if value_from_ast_untyped is None:
        return None
    try:
        return value_from_ast_untyped(node, variables)
    except Exception:
        return None


def _args(field_node: Any, variables: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for argument in getattr(field_node, "arguments", None) or []:
        result[argument.name.value] = _field_value(argument.value, variables)
    return result


def _response_key(field_node: Any) -> str:
    alias = getattr(field_node, "alias", None)
    return alias.value if alias is not None else field_node.name.value


def _selection_names(field_node: Any) -> tuple[str, ...]:
    selection_set = getattr(field_node, "selection_set", None)
    if selection_set is None:
        return ()
    names: list[str] = []
    for selection in selection_set.selections:
        name_node = getattr(selection, "name", None)
        if name_node is not None:
            names.append(name_node.value)
    return tuple(names)


def extract_relationship_paths(query: str, variables: Optional[Mapping[str, Any]] = None) -> list[RelationshipAccess]:
    """Find implicit relationship traversals in a GraphQL query.

    Each returned edge represents a nested object-valued field, for example
    ``resource -> children`` or ``resource -> owner``. Root arguments are carried
    into ``parent_id`` so a caller can resolve the parent before checking all
    objects returned through the nested field. Fragments and inline fragments
    are expanded; fragment cycles are guarded.
    """
    if parse is None:
        raise RuntimeError("GraphQL parsing requires the 'graphql-core' package")
    if not isinstance(query, str) or not query.strip():
        raise ValueError("query must be a non-empty GraphQL string")

    document = parse(query)
    variable_values = dict(variables or {})
    fragments: dict[str, Any] = {}
    operations: list[Any] = []
    for definition in document.definitions:
        kind = getattr(definition, "kind", "")
        if kind == "fragment_definition":
            fragments[definition.name.value] = definition
        elif kind == "operation_definition":
            operations.append(definition)

    relationships: list[RelationshipAccess] = []

    def visit_selection_set(
        selection_set: Any,
        parent_context: Optional[dict[str, Any]],
        response_path: tuple[str, ...],
        graphql_path: tuple[str, ...],
        fragment_stack: frozenset[str],
        depth: int,
    ) -> None:
        if selection_set is None:
            return
        for selection in selection_set.selections:
            selection_kind = getattr(selection, "kind", "")
            if selection_kind == "inline_fragment":
                visit_selection_set(
                    selection.selection_set,
                    parent_context,
                    response_path,
                    graphql_path,
                    fragment_stack,
                    depth,
                )
                continue
            if selection_kind == "fragment_spread":
                fragment_name = selection.name.value
                if fragment_name in fragment_stack or fragment_name not in fragments:
                    continue
                fragment = fragments[fragment_name]
                visit_selection_set(
                    fragment.selection_set,
                    parent_context,
                    response_path,
                    graphql_path,
                    fragment_stack | {fragment_name},
                    depth,
                )
                continue
            if selection_kind != "field":
                continue

            field_name = selection.name.value
            response_key = _response_key(selection)
            field_args = _args(selection, variable_values)
            current_response_path = response_path + (response_key,)
            current_graphql_path = graphql_path + (field_name,)
            current_context = {
                "field_name": field_name,
                "response_key": response_key,
                "args": field_args,
                "response_path": current_response_path,
                "graphql_path": current_graphql_path,
                "selection_fields": _selection_names(selection),
            }

            # Only object-valued fields have a nested selection set. Scalar
            # leaves such as id/name do not create relationship edges.
            if parent_context is not None and getattr(selection, "selection_set", None) is not None:
                parent_args = parent_context["args"]
                parent_id = None
                for id_name in ("id", "resourceId", "objectId", "userId", "parentId", "nodeId"):
                    if parent_args.get(id_name) is not None:
                        parent_id = parent_args[id_name]
                        break
                parent_type = parent_context.get("parent_type")
                relationships.append(
                    RelationshipAccess(
                        parent_field=parent_context["field_name"],
                        relation_field=field_name,
                        parent_id=parent_id,
                        relation_args=field_args,
                        response_path=current_response_path,
                        parent_response_path=parent_context["response_path"],
                        graphql_path=current_graphql_path,
                        selection_fields=_selection_names(selection),
                        depth=depth,
                        parent_type=parent_type,
                    )
                )

            # Type conditions cannot be resolved without a schema; preserve the
            # path and let the caller/catalog determine actual types.
            visit_selection_set(
                getattr(selection, "selection_set", None),
                current_context,
                current_response_path,
                current_graphql_path,
                fragment_stack,
                depth + 1,
            )

    for operation in operations:
        visit_selection_set(operation.selection_set, None, (), (), frozenset(), 1)

    return relationships


def _record_id(record: Any) -> Any:
    if isinstance(record, Mapping):
        for key in ("id", "object_id", "resource_id", "target_object_id"):
            if record.get(key) is not None:
                return record[key]
    else:
        for key in ("id", "object_id", "resource_id", "target_object_id"):
            value = getattr(record, key, None)
            if value is not None:
                return value
    return None


def _record_type(record: Any) -> Optional[str]:
    if isinstance(record, Mapping):
        value = next((record[k] for k in ("type", "object_type", "resource_type", "__typename") if record.get(k)), None)
    else:
        value = next((getattr(record, k, None) for k in ("type", "object_type", "resource_type", "__typename") if getattr(record, k, None)), None)
    return str(value) if value is not None else None


def _catalog_records(object_catalog: Any) -> list[Any]:
    if object_catalog is None:
        return []
    if isinstance(object_catalog, Sequence) and not isinstance(object_catalog, (str, bytes, bytearray)):
        return list(object_catalog)
    if isinstance(object_catalog, Mapping):
        results: list[Any] = []
        for key, value in object_catalog.items():
            if isinstance(value, Mapping) and not any(k in value for k in ("id", "owner_id", "ownerId", "type")):
                for nested_key, nested in value.items():
                    if isinstance(nested, Mapping):
                        item = dict(nested)
                        item.setdefault("id", nested_key)
                        if isinstance(key, str):
                            item.setdefault("type", key)
                        results.append(item)
            elif isinstance(value, Mapping):
                item = dict(value)
                if isinstance(key, tuple) and len(key) >= 2:
                    item.setdefault("type", key[0])
                    item.setdefault("id", key[1])
                elif isinstance(key, (str, int)):
                    item.setdefault("id", key)
                results.append(item)
        return results
    return []


def _find_by_id(object_id: Any, object_catalog: Any, object_type: Optional[str] = None) -> Any:
    if object_id is None:
        return None
    wanted_id = str(object_id)
    wanted_type = object_type.lower() if object_type else None
    for record in _catalog_records(object_catalog):
        if str(_record_id(record)) != wanted_id:
            continue
        rec_type = _record_type(record)
        if wanted_type and rec_type and rec_type.lower() != wanted_type:
            continue
        return record
    if isinstance(object_catalog, Mapping):
        candidates = [object_id, str(object_id)]
        try:
            candidates.append(int(object_id))
        except (TypeError, ValueError):
            pass
        for key in candidates:
            record = object_catalog.get(key)
            if record is not None:
                return record
    return None


def resolve_relationship_objects(
    access: RelationshipAccess,
    object_catalog: Any,
    relationship_map: Optional[Mapping[Any, Any]] = None,
) -> list[Any]:
    """Resolve child records for an extracted relationship, when data is supplied.

    ``relationship_map`` may use any of these keys:
      ``(parent_id, relation_field)``, ``(parent_type, parent_id, relation_field)``,
      ``"<parent_id>.<relation_field>"``.
    Map values may be a list of child IDs or child records. Otherwise the parent
    record may expose the relation field as a list of IDs/records.
    """
    values: Any = None
    rel_map = relationship_map or {}
    possible_keys = [
        (access.parent_id, access.relation_field),
        (str(access.parent_id), access.relation_field),
        (access.parent_type, access.parent_id, access.relation_field),
        (access.parent_type, str(access.parent_id), access.relation_field),
        f"{access.parent_id}.{access.relation_field}",
    ]
    for key in possible_keys:
        try:
            if key in rel_map:
                values = rel_map[key]
                break
        except TypeError:
            continue

    if values is None:
        parent = _find_by_id(access.parent_id, object_catalog, access.parent_type)
        if isinstance(parent, Mapping):
            values = parent.get(access.relation_field)
        elif parent is not None:
            values = getattr(parent, access.relation_field, None)

    if values is None:
        # Some relationship fields accept an explicit child ID argument.
        child_id = next((access.relation_args[k] for k in ("id", "resourceId", "objectId", "childId") if access.relation_args.get(k) is not None), None)
        if child_id is None:
            return []
        values = [child_id]
    if not isinstance(values, (list, tuple, set)):
        values = [values]

    resolved: list[Any] = []
    for value in values:
        if isinstance(value, Mapping) or (not isinstance(value, (str, int, float)) and hasattr(value, "__dict__")):
            resolved.append(value)
        else:
            record = _find_by_id(value, object_catalog)
            resolved.append(record if record is not None else {"id": value})
    return resolved


def extract_resolved_relationships(
    query: str,
    variables: Optional[Mapping[str, Any]],
    object_catalog: Any,
    relationship_map: Optional[Mapping[Any, Any]] = None,
) -> list[dict[str, Any]]:
    """Convenience API returning each relationship path and resolved children."""
    result: list[dict[str, Any]] = []
    for access in extract_relationship_paths(query, variables):
        children = resolve_relationship_objects(access, object_catalog, relationship_map)
        result.append({
            "access": access.as_dict(),
            "children": children,
            "child_ids": [_record_id(child) for child in children],
        })
    return result


__all__ = [
    "RelationshipAccess",
    "extract_relationship_paths",
    "resolve_relationship_objects",
    "extract_resolved_relationships",
]
