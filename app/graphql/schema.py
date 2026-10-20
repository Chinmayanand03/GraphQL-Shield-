import strawberry
from strawberry.schema.config import BatchingConfig, StrawberryConfig

from app.config import settings
from app.graphql.mutations import Mutation
from app.graphql.queries import Query
from app.security.runtime_object_guard import (
    RuntimeObjectAuthorizationExtension,
)

schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    extensions=[RuntimeObjectAuthorizationExtension],
    config=StrawberryConfig(
        batching_config=BatchingConfig(max_operations=settings.MAX_BATCH_OPERATIONS)
    ),
)

