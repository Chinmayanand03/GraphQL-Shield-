from __future__ import annotations

import inspect
import logging
from typing import Any

from strawberry.extensions import SchemaExtension

from app.graphql.types import ResourceType
from app.security.authorization import AuthorizationContext, PolicyEngine
from app.security.ownership import get_object_owner

logger = logging.getLogger(__name__)

# Stateless policy engine reused by this extension.
_policy_engine = PolicyEngine()


class RuntimeObjectAuthorizationExtension(SchemaExtension):
    """
    Prototype runtime guard for ResourceType objects.

    It checks actual resolver results before GraphQL resolves the
    object's nested fields. Lists are filtered item by item.

    Scope:
      - Protected /graphql endpoint only.
      - ResourceType objects with canonical integer IDs.
      - Ownership from the trusted database lookup.

    This is a prototype, not a universal GraphQL security guarantee.
    """

    def resolve(self, _next, root, info, *args, **kwargs):
        result = _next(root, info, *args, **kwargs)

        # Support synchronous and asynchronous resolvers.
        if inspect.isawaitable(result):

            async def resolve_and_check():
                resolved = await result
                return self._authorize_result(resolved, info)

            return resolve_and_check()

        return self._authorize_result(result, info)

    @staticmethod
    def _get_request(info):
        context = info.context

        if isinstance(context, dict):
            return context.get("request")

        return getattr(context, "request", None)

    def _should_enforce(self, info) -> bool:
        request = self._get_request(info)

        # No request context means a protected resource must fail closed.
        if request is None:
            return True

        path = str(
            getattr(getattr(request, "url", None), "path", "")
        ).rstrip("/")

        # Preserve the intentionally vulnerable comparison endpoint.
        if path == "/graphql-insecure":
            return False

        return path == "/graphql"

    def _authorize_result(self, result: Any, info):
        if not self._should_enforce(info):
            return result

        if isinstance(result, ResourceType):
            return result if self._is_authorized(result, info) else None

        if isinstance(result, list):
            # Preserve authorized siblings when one child is denied.
            return [
                item
                for item in result
                if not isinstance(item, ResourceType)
                or self._is_authorized(item, info)
            ]

        # Scalars and non-resource objects are outside this prototype's scope.
        return result

    @staticmethod
    def _format_path(path) -> str:
        parts = []

        while path is not None:
            parts.append(str(path.key))
            path = path.prev

        return ".".join(reversed(parts))

    def _is_authorized(self, resource: ResourceType, info) -> bool:
        request = self._get_request(info)

        if request is None:
            return False

        current_user = getattr(
            getattr(request, "state", None),
            "current_user",
            None,
        )

        if not isinstance(current_user, dict):
            return False

        try:
            user_id = int(current_user["user_id"])
            object_id = int(resource.id)
            role = str(current_user.get("role", "user"))

            # Never trust the returned object's owner_id as the authority.
            owner_id = get_object_owner("Resource", object_id)

            operation_node = getattr(info, "operation", None)
            operation_value = getattr(
                getattr(operation_node, "operation", None),
                "value",
                "query",
            )

            context = AuthorizationContext(
                user_id=user_id,
                role=role,
                operation=str(operation_value),
                object_type="Resource",
                object_id=object_id,
                path=self._format_path(info.path),
                owner_id=owner_id,
                metadata={
                    "source": "runtime_object_guard",
                    "response_path": self._format_path(info.path),
                },
            )

            decision = _policy_engine.evaluate(context)

            if decision.get("decision") != "ALLOW":
                logger.info(
                    "Runtime object guard denied access: "
                    "user_id=%s object_id=%s reason=%s",
                    user_id,
                    object_id,
                    decision.get("reason", "UNKNOWN"),
                )
                return False

            return True

        except Exception:
            # Missing identity, database failure, or policy failure
            # must not silently allow the protected resource.
            logger.exception(
                "Runtime object authorization failed; denying resource"
            )
            return False
