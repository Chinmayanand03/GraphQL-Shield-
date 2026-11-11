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

class ShieldSchema(strawberry.Schema):
    """Strawberry logs every GraphQL error with a full traceback. A Layer 2 denial
    is the guard working as intended, not a crash, so only other errors are logged.
    The client still receives the error; the denial is still audited."""

    def process_errors(self, errors, execution_context=None):
        unexpected = [
            error for error in errors
            if (getattr(error, "extensions", None) or {}).get("layer") != "L2_EXECUTION_TIME"
        ]
        if unexpected:
            super().process_errors(unexpected, execution_context)


schema = ShieldSchema(
    query=Query,
    mutation=Mutation,
    extensions=extensions,
    config=StrawberryConfig(
        batching_config=BatchingConfig(max_operations=settings.MAX_BATCH_OPERATIONS)
    ),
)
