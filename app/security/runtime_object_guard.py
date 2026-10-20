from __future__ import annotations

import inspect
import logging
from typing import Any
from unittest.mock import MagicMock

from graphql import GraphQLError
from strawberry.extensions import SchemaExtension

from app.graphql.types import ResourceType, UserType
from app.security.audit import log_decision
from app.security.authorization import AuthorizationContext, PolicyEngine
from app.security.layers import (
    EVENT_L1_BLIND_SPOT,
    EVENT_L2_FILTERED,
    EVENT_L2_MUTATION_BLOCKED,
    is_enabled,
    layer1_saw,
    record_layer_event,
)
from app.security.ownership import get_object_owner

logger = logging.getLogger(__name__)

# Stateless policy engine reused by this extension.
_policy_engine = PolicyEngine()


class RequestSecurityState:
    """Stores authorization decisions, evidence, and data provenance per request."""

    def __init__(self):
        self.authorization_evidence: list[dict[str, Any]] = []
        self.provenance: list[dict[str, Any]] = []


def get_request_security_state(context: Any = None) -> RequestSecurityState:
    """
    Retrieve or initialize the RequestSecurityState associated with the request context.
    """
    request = None
    if isinstance(context, dict):
        request = context.get("request")
    elif context is not None:
        request = getattr(context, "request", context)

    if request is not None and hasattr(request, "state"):
        sec_state = getattr(request.state, "security_state", None)
        if isinstance(sec_state, RequestSecurityState):
            return sec_state
        sec_state = RequestSecurityState()
        try:
            setattr(request.state, "security_state", sec_state)
        except Exception:
            pass
        return sec_state

    return RequestSecurityState()


def make_request(user_id: int = 1, role: str = "USER") -> Any:
    """Helper to create a mock request with security state for unit testing."""
    request = MagicMock()
    request.url.path = "/graphql"
    request.state = MagicMock()
    request.state.current_user = {"user_id": user_id, "role": role}
    sec_state = RequestSecurityState()
    request.state.security_state = sec_state
    return request


def make_extension(request: Any = None) -> RuntimeObjectAuthorizationExtension:
    """Helper to instantiate RuntimeObjectAuthorizationExtension with optional request."""
    ext = RuntimeObjectAuthorizationExtension()
    if request is not None:
        ext._request = request
    return ext


def make_resource(
    id: int,
    owner_id: int,
    parent_id: int | None = None,
    name: str | None = None,
    object_type: str = "Resource",
) -> ResourceType:
    """Helper to instantiate ResourceType objects for testing."""
    return ResourceType(
        id=id,
        name=name if name is not None else f"Resource {id}",
        owner_id=owner_id,
        object_type=object_type,
        parent_id=parent_id,
    )


def make_info(
    request: Any,
    path_name: str = "resource",
    field_name: str = "children",
) -> Any:
    """Helper to create mock GraphQL info context with path linked list."""
    info = MagicMock()
    info.operation.operation.value = "query"

    p1 = MagicMock()
    p1.key = path_name
    p1.prev = None

    p2 = MagicMock()
    p2.key = field_name
    p2.prev = p1

    info.path = p2
    info.field_name = field_name
    info.context = {"request": request}
    return info


# Owned GraphQL object types guarded at execution time, and the ownership-table type
# name used for each. A UserType is owned by the user it describes.
GUARDED_TYPES = {ResourceType: "Resource", UserType: "User"}


class RuntimeObjectAuthorizationExtension(SchemaExtension):
    """
    Prototype runtime guard for ResourceType objects.

    It checks actual resolver results before GraphQL resolves the
    object's nested fields. Lists are filtered item by item.
    Enforcement decisions, audit logs, authorization evidence, and
    object provenance graphs are recorded on request security state.

    Scope:
      - Protected /graphql endpoint only.
      - ResourceType objects with canonical integer IDs.
      - Ownership from the trusted database lookup.

    This is a prototype, not a universal GraphQL security guarantee.
    """

    def __init__(self, execution_context=None, request: Any = None):
        super().__init__(execution_context=execution_context)
        self._request = request

    def resolve(self, _next, root, info, *args, **kwargs):
        self._guard_mutation_arguments(info, kwargs)
        result = _next(root, info, *args, **kwargs)

        # Support synchronous and asynchronous resolvers.
        if inspect.isawaitable(result):

            async def resolve_and_check():
                resolved = await result
                return self._guard_result(resolved, root, info)

            return resolve_and_check()

        return self._guard_result(result, root, info)

    def _get_request(self, info):
        context = getattr(info, "context", None)

        if isinstance(context, dict):
            req = context.get("request")
            if req is not None:
                return req

        req = getattr(context, "request", None)
        if req is not None:
            return req

        return getattr(self, "_request", None)

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

        return path == "/graphql" and is_enabled("layer2")

    @staticmethod
    def _format_path(path) -> str:
        parts = []
        curr = path
        while curr is not None:
            parts.append(str(curr.key))
            curr = curr.prev
        return ".".join(reversed(parts))

    @staticmethod
    def _format_path_list(path) -> list[Any]:
        parts = []
        curr = path
        while curr is not None:
            parts.append(curr.key)
            curr = curr.prev
        return list(reversed(parts))

    def _check_resource_authorization(
        self,
        resource: Any,
        info: Any,
        object_type: str = "Resource",
    ) -> tuple[bool, dict[str, Any]]:
        request = self._get_request(info)

        if request is None:
            return False, {
                "user_id": None,
                "role": "unknown",
                "owner_id": None,
                "decision": "DENY",
                "reason": "MISSING_REQUEST",
                "risk_score": 100,
                "risk_level": "CRITICAL",
            }

        current_user = getattr(
            getattr(request, "state", None),
            "current_user",
            None,
        )

        if not isinstance(current_user, dict):
            return False, {
                "user_id": None,
                "role": "unknown",
                "owner_id": None,
                "decision": "DENY",
                "reason": "MISSING_USER",
                "risk_score": 100,
                "risk_level": "CRITICAL",
            }

        try:
            user_id = int(current_user["user_id"])
            object_id = int(resource.id)
            role = str(current_user.get("role", "user"))

            # Never trust the returned object's owner_id as the authority.
            owner_id = get_object_owner(object_type, object_id)

            operation_node = getattr(info, "operation", None)
            operation_value = getattr(
                getattr(operation_node, "operation", None),
                "value",
                "query",
            )

            path_str = self._format_path(getattr(info, "path", None))

            context = AuthorizationContext(
                user_id=user_id,
                role=role,
                operation=str(operation_value),
                object_type=object_type,
                object_id=object_id,
                path=path_str,
                owner_id=owner_id,
                metadata={
                    "source": "runtime_object_guard",
                    "response_path": path_str,
                },
            )

            decision = _policy_engine.evaluate(context)

            # Audit log the decision
            try:
                log_decision(
                    user_id=user_id,
                    role=role,
                    operation=str(operation_value),
                    object_type=object_type,
                    object_id=object_id,
                    path=path_str,
                    decision=decision.get("decision", "DENY"),
                    reason=decision.get("reason", "UNKNOWN"),
                    risk_score=decision.get("risk_score", 0),
                    risk_level=decision.get("risk_level", "LOW"),
                )
            except Exception:
                logger.debug("Audit logging skipped or suppressed in runtime guard")

            decision_info = {
                "user_id": user_id,
                "role": role,
                "owner_id": owner_id,
                "decision": decision.get("decision", "DENY"),
                "reason": decision.get("reason", "UNKNOWN"),
                "risk_score": decision.get("risk_score", 0),
                "risk_level": decision.get("risk_level", "LOW"),
            }

            if decision.get("decision") != "ALLOW":
                logger.info(
                    "Runtime object guard denied access: "
                    "user_id=%s object_id=%s reason=%s",
                    user_id,
                    object_id,
                    decision.get("reason", "UNKNOWN"),
                )
                return False, decision_info

            return True, decision_info

        except Exception:
            logger.exception(
                "Runtime object authorization failed; denying resource"
            )
            decision_info = {
                "user_id": current_user.get("user_id") if isinstance(current_user, dict) else None,
                "role": current_user.get("role", "user") if isinstance(current_user, dict) else "user",
                "owner_id": None,
                "decision": "DENY",
                "reason": "INTERNAL_ERROR",
                "risk_score": 100,
                "risk_level": "CRITICAL",
            }
            return False, decision_info

    def _is_authorized(self, resource: ResourceType, info: Any) -> bool:
        is_auth, _ = self._check_resource_authorization(resource, info)
        return is_auth

    def _authorize_result(self, result: Any, info: Any) -> Any:
        return self._guard_result(result, None, info)

    def _record_evidence_and_provenance(
        self,
        sec_state: RequestSecurityState,
        resource: Any,
        root: Any,
        field_name: str,
        decision_info: dict[str, Any],
        enforcement: str,
        emitted_path: list[Any] | None,
        object_type: str = "Resource",
    ) -> None:
        principal_id = decision_info.get("user_id")
        owner_id = decision_info.get("owner_id")
        decision = decision_info.get("decision", "DENY")
        reason = decision_info.get("reason", "UNKNOWN")
        object_id = int(resource.id)

        evidence_entry = {
            "object_id": object_id,
            "decision": decision,
            "principal_id": principal_id,
            "owner_id": owner_id,
            "reason": reason,
            "enforcement": enforcement,
            "emitted_path": emitted_path,
        }
        sec_state.authorization_evidence.append(evidence_entry)

        edges = []
        if root is not None:
            parent_id = str(getattr(root, "id", ""))
            parent_type = "Resource"
            edges.append({
                "parent_id": parent_id,
                "parent_type": parent_type,
                "field": str(field_name),
                "child_id": str(object_id),
                "child_type": object_type,
            })

        provenance_entry = {
            "object_id": object_id,
            "object_type": object_type,
            "owner_id": owner_id,
            "source": {
                "table": "objects",
                "primary_key": str(object_id),
            },
            "provenance": {
                "rows": [
                    {"table": "objects", "id": str(object_id)}
                ],
                "edges": edges,
            },
            "emitted_path": emitted_path,
        }
        sec_state.provenance.append(provenance_entry)

    def _guard_result(self, result: Any, root: Any, info: Any) -> Any:
        if not self._should_enforce(info):
            return result

        request = self._get_request(info)
        sec_state = get_request_security_state({"request": request})

        path_node = getattr(info, "path", None)
        base_path_list = self._format_path_list(path_node)
        field_name = str(getattr(info, "field_name", None) or (path_node.key if path_node else "children"))

        object_type = GUARDED_TYPES.get(type(result))
        if object_type is not None:
            is_auth, decision_info = self._check_resource_authorization(result, info, object_type)
            if is_auth:
                emitted_path = list(base_path_list)
                self._record_evidence_and_provenance(
                    sec_state=sec_state,
                    resource=result,
                    root=root,
                    field_name=field_name,
                    decision_info=decision_info,
                    enforcement="allowed",
                    emitted_path=emitted_path,
                    object_type=object_type,
                )
                return result
            else:
                self._record_evidence_and_provenance(
                    sec_state=sec_state,
                    resource=result,
                    root=root,
                    field_name=field_name,
                    decision_info=decision_info,
                    enforcement="denied",
                    emitted_path=None,
                    object_type=object_type,
                )
                self._record_denial(request, decision_info, object_type, result, base_path_list)
                return None

        if isinstance(result, list):
            filtered_result = []
            for item in result:
                item_type = GUARDED_TYPES.get(type(item))
                if item_type is not None:
                    is_auth, decision_info = self._check_resource_authorization(item, info, item_type)
                    if is_auth:
                        emitted_idx = len(filtered_result)
                        emitted_path = list(base_path_list) + [emitted_idx]
                        self._record_evidence_and_provenance(
                            sec_state=sec_state,
                            resource=item,
                            root=root,
                            field_name=field_name,
                            decision_info=decision_info,
                            enforcement="allowed",
                            emitted_path=emitted_path,
                            object_type=item_type,
                        )
                        filtered_result.append(item)
                    else:
                        self._record_evidence_and_provenance(
                            sec_state=sec_state,
                            resource=item,
                            root=root,
                            field_name=field_name,
                            decision_info=decision_info,
                            enforcement="filtered",
                            emitted_path=None,
                            object_type=item_type,
                        )
                        self._record_denial(request, decision_info, item_type, item, base_path_list)
                else:
                    filtered_result.append(item)
            return filtered_result

        # Scalars and non-owned objects are outside this prototype's scope.
        return result

    # ------------------------------------------------------------------ mutation argument guard
    def _guard_mutation_arguments(self, info: Any, kwargs: dict) -> None:
        """Block a root mutation that targets an object the caller does not own.

        Uses the engine-coerced `id` argument, so it is unaffected by how the client
        spelled the request (variables, aliases, fragments, directives).
        """
        parent_type = getattr(getattr(info, "parent_type", None), "name", None)
        if parent_type != "Mutation" or "id" not in kwargs:
            return
        if not self._should_enforce(info):
            return

        target = _OwnedRef(kwargs["id"])
        is_auth, decision_info = self._check_resource_authorization(target, info, "Resource")
        if is_auth:
            return

        request = self._get_request(info)
        path = self._format_path_list(getattr(info, "path", None))
        record_layer_event(decision_info.get("user_id"), "L2", EVENT_L2_MUTATION_BLOCKED, "Resource",
                           target.id, ".".join(map(str, path)), decision_info.get("reason", "DENY"))
        self._record_blind_spot(request, decision_info, "Resource", target.id, path)
        raise GraphQLError(
            "GraphQL Shield: mutation blocked, caller does not own the target object.",
            extensions={
                "code": "MUTATION_AUTHORIZATION_DENIED",
                "layer": "L2_EXECUTION_TIME",
                "object_id": target.id,
                "reason": decision_info.get("reason", "DENY"),
                "risk_level": decision_info.get("risk_level", "HIGH"),
            },
        )

    # ------------------------------------------------------------------ cross-layer evidence
    def _record_denial(self, request: Any, decision_info: dict, object_type: str, obj: Any, path: list) -> None:
        record_layer_event(decision_info.get("user_id"), "L2", EVENT_L2_FILTERED, object_type,
                           int(obj.id), ".".join(map(str, path)), decision_info.get("reason", "DENY"))
        self._record_blind_spot(request, decision_info, object_type, int(obj.id), path)

    @staticmethod
    def _record_blind_spot(request: Any, decision_info: dict, object_type: str, object_id: int, path: list) -> None:
        """Layer 2 denied an object Layer 1 never evaluated: a Layer 1 blind spot."""
        if not is_enabled("layer1") or request is None or layer1_saw(request, object_type, object_id):
            return
        if getattr(getattr(request, "state", None), "layer1_checked", None) is None:
            return
        record_layer_event(decision_info.get("user_id"), "L2", EVENT_L1_BLIND_SPOT, object_type, object_id,
                           ".".join(map(str, path)),
                           "object reached without an ID Layer 1 could see (relationship traversal or unparsed query shape)")


class _OwnedRef:
    """Minimal object carrying the id of a mutation target for the ownership check."""

    def __init__(self, raw_id: Any):
        self.id = int(raw_id)
