"""
Structural features of a GraphQL operation, computed before execution.

These are the inputs of the blind-spot predictor (app/security/blind_spot_model.py).
They describe only what Layer 1 can see before any resolver runs: the query's
shape, how its object IDs are supplied, and how many of them Layer 1's extractor
actually resolved. They never include ownership data or the enforcement outcome.
"""
from __future__ import annotations

from typing import Any

from graphql import (
    FieldNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    GraphQLList,
    GraphQLNonNull,
    GraphQLObjectType,
    InlineFragmentNode,
    OperationDefinitionNode,
)

from .graphql_parser import parse_query
from .object_extractor import normalize_query

FEATURE_NAMES: list[str] = [
    "batch_size",
    "is_mutation",
    "caller_is_admin",
    "max_depth",
    "field_count",
    "relationship_field_count",
    "relationship_chain_depth",
    "id_argument_count",
    "l1_resolved_id_count",
    "unresolved_id_argument_count",
    "nested_id_lookup_count",
    "variable_count",
    "variable_default_count",
    "inline_fragment_count",
    "fragment_spread_count",
    "alias_count",
    "directive_count",
]

# GraphQL object types whose instances are owned (guarded by Layer 2).
OWNED_TYPE_NAMES = {"ResourceType", "UserType"}


_MAX_FEATURES = {"max_depth", "relationship_chain_depth", "is_mutation", "caller_is_admin", "batch_size"}


def combine_features(per_operation: list[dict[str, int]]) -> dict[str, int]:
    """Combine the features of a batched request's operations into one vector."""
    combined = dict.fromkeys(FEATURE_NAMES, 0)
    for features in per_operation:
        for name in FEATURE_NAMES:
            if name in _MAX_FEATURES:
                combined[name] = max(combined[name], features[name])
            else:
                combined[name] += features[name]
    return combined


def _unwrap(graphql_type) -> tuple[Any, bool]:
    """Return (named type, is_list) for a possibly wrapped GraphQL type."""
    is_list = False
    while isinstance(graphql_type, (GraphQLNonNull, GraphQLList)):
        if isinstance(graphql_type, GraphQLList):
            is_list = True
        graphql_type = graphql_type.of_type
    return graphql_type, is_list


def _graphql_schema():
    # Imported lazily: the schema module imports the security layers.
    from app.graphql.schema import schema

    return schema._schema


def extract_features(query: str, variables: dict | None = None, *, batch_size: int = 1,
                     caller_is_admin: bool = False) -> dict[str, int] | None:
    """Return the feature vector for one operation, or None if it does not parse."""
    ast = parse_query(query or "")
    if ast is None:
        return None

    schema = _graphql_schema()
    variables = variables if isinstance(variables, dict) else {}
    fragments = {d.name.value: d for d in ast.definitions if isinstance(d, FragmentDefinitionNode)}
    features = dict.fromkeys(FEATURE_NAMES, 0)
    features["batch_size"] = batch_size
    features["caller_is_admin"] = int(caller_is_admin)

    def visit(node, parent_type, depth: int, relationship_depth: int, expanding: frozenset) -> None:
        features["directive_count"] += len(getattr(node, "directives", None) or ())

        if isinstance(node, FieldNode):
            features["field_count"] += 1
            features["max_depth"] = max(features["max_depth"], depth)
            if node.alias is not None:
                features["alias_count"] += 1
            if any(arg.name.value == "id" for arg in node.arguments or ()):
                features["id_argument_count"] += 1
                if depth > 1:
                    features["nested_id_lookup_count"] += 1

            field_def = parent_type.fields.get(node.name.value) if isinstance(parent_type, GraphQLObjectType) else None
            child_type, is_list = _unwrap(field_def.type) if field_def else (None, False)
            if is_list and getattr(child_type, "name", None) in OWNED_TYPE_NAMES:
                # A list of owned objects reached through a parent: no ID in the query.
                features["relationship_field_count"] += 1
                relationship_depth += 1
                features["relationship_chain_depth"] = max(features["relationship_chain_depth"], relationship_depth)

            for selection in (node.selection_set.selections if node.selection_set else ()):
                visit(selection, child_type, depth + 1, relationship_depth, expanding)

        elif isinstance(node, InlineFragmentNode):
            features["inline_fragment_count"] += 1
            fragment_type = schema.get_type(node.type_condition.name.value) if node.type_condition else parent_type
            for selection in node.selection_set.selections:
                visit(selection, fragment_type, depth, relationship_depth, expanding)

        elif isinstance(node, FragmentSpreadNode):
            features["fragment_spread_count"] += 1
            name = node.name.value
            fragment = fragments.get(name)
            if fragment is None or name in expanding:
                return
            fragment_type = schema.get_type(fragment.type_condition.name.value)
            for selection in fragment.selection_set.selections:
                visit(selection, fragment_type, depth, relationship_depth, expanding | {name})

    for definition in ast.definitions:
        if not isinstance(definition, OperationDefinitionNode):
            continue
        operation = definition.operation.value
        if operation == "mutation":
            features["is_mutation"] = 1
        root_type = schema.mutation_type if operation == "mutation" else schema.query_type
        for variable in definition.variable_definitions or ():
            features["variable_count"] += 1
            if variable.default_value is not None:
                features["variable_default_count"] += 1
        for selection in definition.selection_set.selections:
            visit(selection, root_type, 1, 0, frozenset())

    normalized = normalize_query(query, variables) or {"objects": []}
    features["l1_resolved_id_count"] = len(normalized["objects"])
    features["unresolved_id_argument_count"] = max(0, features["id_argument_count"] - features["l1_resolved_id_count"])
    return features
