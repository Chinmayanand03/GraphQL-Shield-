"""
Per-application configuration for GraphQL Shield.

Everything the two enforcement layers need to know about a protected GraphQL
application lives here, so the same Layer 1 / Layer 2 code can guard any
graphql-core based server (Strawberry, Graphene, Ariadne):

  - which GraphQL object types are owned, read from the schema,
  - how to look up an object's owner (a callable, so any data store works),
  - which argument names carry object IDs, and how to decode them (e.g. Relay
    global IDs such as base64("Resource:102")),
  - targets for mutations whose return type does not reveal what they change.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from graphql import GraphQLList, GraphQLNonNull, GraphQLObjectType, GraphQLSchema


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

    def graphql_schema(self) -> GraphQLSchema:
        return self.schema()

    def owned_key(self, graphql_type) -> str | None:
        """Ownership key of a (possibly wrapped) GraphQL type, if it is owned."""
        named, _ = unwrap_type(graphql_type)
        return self.owned_types.get(getattr(named, "name", None))

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


_default: ShieldConfig | None = None


def default_config() -> ShieldConfig:
    """Configuration for the GraphQL Shield demo application in this repository."""
    global _default
    if _default is None:
        from app.graphql.mutations import MUTATION_TARGETS
        from app.security.ownership import get_object_owner

        def schema():
            from app.graphql.schema import schema as strawberry_schema

            return strawberry_schema._schema

        _default = ShieldConfig(
            schema=schema,
            owned_types={"ResourceType": "Resource", "UserType": "User"},
            owner_lookup=get_object_owner,
            mutation_targets=MUTATION_TARGETS,
        )
    return _default
