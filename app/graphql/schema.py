import strawberry

from app.graphql.queries import Query
from app.security.runtime_object_guard import (
    RuntimeObjectAuthorizationExtension,
)

schema = strawberry.Schema(
    query=Query,
    extensions=[RuntimeObjectAuthorizationExtension],
)

