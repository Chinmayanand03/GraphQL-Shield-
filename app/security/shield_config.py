"""
Per-application configuration for GraphQL Shield.

Everything the two enforcement layers need to know about a protected GraphQL
application lives here, so the same Layer 1 / Layer 2 code can guard any
graphql-core based server (Strawberry, Graphene, Ariadne):

  - which GraphQL object types are owned, read from the schema,
  - how to look up an object's owner (a callable, so any data store works),
  - which argument names carry object IDs, and how to decode them (e.g. Relay
    global IDs such as base64("Resource:102")),
  - targets for mutations whose return type does not reveal what they change,
  - aggregate fields, which summarise a relationship (e.g. a child count).

lint_config() checks a configuration against its schema: an owned type left out
would be unprotected by both layers, so it is reported at startup.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from graphql import (
    GraphQLInterfaceType,
    GraphQLList,
    GraphQLNonNull,
    GraphQLObjectType,
    GraphQLSchema,
    GraphQLUnionType,
    is_leaf_type,
)


logger = logging.getLogger(__name__)


def unwrap_type(graphql_type) -> tuple[Any, bool]:
    """Return (named type, is_list) for a possibly wrapped GraphQL type."""
    is_list = False
    while isinstance(graphql_type, (GraphQLNonNull, GraphQLList)):
        if isinstance(graphql_type, GraphQLList):
            is_list = True
        graphql_type = graphql_type.of_type
    return graphql_type, is_list


def plain_id(value: Any) -> tuple[str | None, Any]:
    """Default ID decoder: the value is a raw database ID with no embedded type."""
    return None, value


@dataclass
class ShieldConfig:
    # Returns the graphql-core schema; a callable so schemas can be built lazily.
    schema: Callable[[], GraphQLSchema]
    # GraphQL object type name -> ownership key passed to owner_lookup.
    owned_types: dict[str, str]
    # (ownership key, object id) -> owner id, or None when the object does not exist.
    owner_lookup: Callable[[str, Any], Any]
    # Mutation field name -> (target argument, ownership key). Needed when the
    # mutation's return type does not say what it changes (e.g. returns Boolean).
    mutation_targets: dict[str, tuple[str, str]] = field(default_factory=dict)
    # Argument names that carry an object ID.
    id_arguments: tuple[str, ...] = ("id",)
    # Decodes an ID value into (ownership key embedded in the ID or None, raw id).
    decode_id: Callable[[Any], tuple[str | None, Any]] = plain_id
    # Request paths Layer 2 protects; other paths (benchmark baselines) are skipped.
    protected_paths: tuple[str, ...] = ("/graphql",)
    # Mutations allowed to run without an ownership target (e.g. creating a
    # top-level object owned by the caller). Everything else unlisted is denied.
    unguarded_mutations: frozenset[str] = frozenset()
    # "Type.field" -> the relationship field it summarises. Layer 2 answers these
    # by counting only the related objects the caller may read.
    aggregate_fields: dict[str, str] = field(default_factory=dict)
    # Optional (ownership key, ids) -> {id: owner}. Lets Layer 2 check a list in one
    # query; without it, each list item takes one owner_lookup call.
    owners_lookup: Callable[[str, list], dict] | None = None
    # Object types anyone may read, such as a product catalogue. Only the startup
    # lint uses this, to stay quiet about lookups by ID that are public on purpose.
    public_types: frozenset[str] = frozenset()

    def graphql_schema(self) -> GraphQLSchema:
        return self.schema()

    def owned_key(self, graphql_type) -> str | None:
        """Ownership key of a (possibly wrapped) GraphQL type, if it is owned."""
        named, _ = unwrap_type(graphql_type)
        return self.owned_types.get(getattr(named, "name", None))

    def value_key(self, named_type, value: Any, info: Any = None) -> str | None:
        """Ownership key of a resolved value. An interface or union says nothing about
        ownership by itself, so the concrete type is used; when that cannot be found
        and the abstract type can hold an owned object, the value is guarded anyway."""
        if not isinstance(named_type, (GraphQLInterfaceType, GraphQLUnionType)):
            return self.owned_types.get(getattr(named_type, "name", None))
        name = _concrete_type_name(named_type, value, info)
        if name is not None:
            return self.owned_types.get(name)
        return next(iter(self.abstract_keys(named_type, info)), None)

    def abstract_keys(self, named_type, info: Any = None) -> list[str]:
        """Ownership keys an interface or union field could return."""
        schema = getattr(info, "schema", None) or self.graphql_schema()
        return [self.owned_types[t.name] for t in schema.get_possible_types(named_type)
                if t.name in self.owned_types]

    def aggregate_relationship(self, info: Any) -> str | None:
        parent = getattr(getattr(info, "parent_type", None), "name", None)
        if parent is None or not self.aggregate_fields:
            return None
        return self.aggregate_fields.get(f"{parent}.{getattr(info, 'field_name', None)}")

    def field_definition(self, parent_type, field_name: str):
        if isinstance(parent_type, GraphQLObjectType):
            return parent_type.fields.get(field_name)
        return None

    def mutation_target(self, field_name: str, field_def=None) -> tuple[str, str] | None:
        """(argument, ownership key) for a root mutation, from the registry or schema."""
        if field_name in self.mutation_targets:
            return self.mutation_targets[field_name]
        if field_def is not None:
            key = self.owned_key(field_def.type)
            for argument in self.id_arguments:
                if key and argument in field_def.args:
                    return argument, key
        return None

    def decode(self, value: Any) -> tuple[str | None, Any]:
        try:
            return self.decode_id(value)
        except Exception:
            return None, value


def _concrete_type_name(abstract_type, value: Any, info: Any) -> str | None:
    if isinstance(value, dict) and value.get("__typename"):
        return value["__typename"]
    resolver = getattr(abstract_type, "resolve_type", None)
    if resolver is not None and info is not None:
        try:
            resolved = resolver(value, info, abstract_type)
        except Exception:
            resolved = None
        if isinstance(resolved, str):
            return resolved
    schema = getattr(info, "schema", None)
    if schema is None:
        return None
    for candidate in schema.get_possible_types(abstract_type):
        if candidate.is_type_of is not None and candidate.is_type_of(value, info) is True:
            return candidate.name
    return None


# Field names that suggest a type is owned, or a value summarises other objects.
_OWNER_FIELD = re.compile(
    r"^(owner|owned_?by|belongs_?to|created_?by|author|creator|uploader|submitter|assignee|member|user|"
    r"customer|account|tenant|patient|doctor)(_?id)?$|_?owner(_?id)?$", re.I)
_AGGREGATE_FIELD = re.compile(r"(count|total|sum|size|number)$|^(count|total|num|has)", re.I)


def lint_config(config: ShieldConfig) -> list[dict]:
    """Findings for parts of the schema the configuration may have left unprotected.

    Two kinds of evidence are used. Field names (an ``ownerId``, ``createdBy`` or a
    field of an owned type) suggest a type is owned. Independently of naming, a root
    query that fetches one object of a type by ID suggests the type is a per-user
    object, unless it is configured as owned or declared public. A finding is a
    prompt to look, and a clean result does not prove the configuration is complete.
    """
    schema = config.graphql_schema()
    roots = {t.name for t in (schema.query_type, schema.mutation_type, schema.subscription_type) if t}
    owned_names = set(config.owned_types)
    findings = []
    if schema.query_type is not None:
        for field_name, field_def in schema.query_type.fields.items():
            named, is_list = unwrap_type(field_def.type)
            if (not is_list and isinstance(named, GraphQLObjectType) and named.name not in owned_names
                    and named.name not in config.public_types and named.name not in roots
                    and any(argument in field_def.args for argument in config.id_arguments)):
                findings.append({"kind": "unowned_id_lookup", "type": named.name, "field": f"Query.{field_name}"})
    for name, graphql_type in schema.type_map.items():
        if name.startswith("__") or name in roots or not isinstance(graphql_type, GraphQLObjectType):
            continue
        for field_name, field_def in graphql_type.fields.items():
            named, _ = unwrap_type(field_def.type)
            if name not in owned_names and (_OWNER_FIELD.match(field_name) or getattr(named, "name", None) in owned_names):
                findings.append({"kind": "possible_unowned_type", "type": name, "field": field_name})
            if (name in owned_names and is_leaf_type(named) and _AGGREGATE_FIELD.search(field_name)
                    and f"{name}.{field_name}" not in config.aggregate_fields):
                findings.append({"kind": "undeclared_aggregate", "type": name, "field": field_name})
    return findings


def warn_about_config(config: ShieldConfig) -> None:
    for finding in lint_config(config):
        logger.warning("ShieldConfig: %s at %s.%s", finding["kind"], finding["type"], finding["field"])


_default: ShieldConfig | None = None


def default_config() -> ShieldConfig:
    """Configuration for the GraphQL Shield demo application in this repository."""
    global _default
    if _default is None:
        from app.graphql.mutations import MUTATION_TARGETS
        from app.security.ownership import get_object_owner, get_object_owners

        def schema():
            from app.graphql.schema import schema as strawberry_schema

            return strawberry_schema._schema

        _default = ShieldConfig(
            schema=schema,
            owned_types={"ResourceType": "Resource", "UserType": "User"},
            owner_lookup=get_object_owner,
            owners_lookup=get_object_owners,
            mutation_targets=MUTATION_TARGETS,
            aggregate_fields={"ResourceType.childrenCount": "children"},
        )
    return _default
