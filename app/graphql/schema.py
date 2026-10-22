import strawberry
from strawberry.extensions import (
    DisableIntrospection,
    MaxAliasesLimiter,
    MaxTokensLimiter,
    QueryDepthLimiter,
)
from strawberry.schema.config import BatchingConfig, StrawberryConfig

from app.config import settings
from app.graphql.mutations import Mutation
from app.graphql.queries import Query
from app.security.runtime_object_guard import (
    RuntimeObjectAuthorizationExtension,
)

extensions = [
    lambda: QueryDepthLimiter(max_depth=settings.MAX_QUERY_DEPTH),
    lambda: MaxAliasesLimiter(max_alias_count=settings.MAX_QUERY_ALIASES),
    lambda: MaxTokensLimiter(max_token_count=settings.MAX_QUERY_TOKENS),
    RuntimeObjectAuthorizationExtension,
]
if not settings.ENABLE_INTROSPECTION:
    extensions.append(DisableIntrospection)

schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    extensions=extensions,
    config=StrawberryConfig(
        batching_config=BatchingConfig(max_operations=settings.MAX_BATCH_OPERATIONS)
    ),
)
