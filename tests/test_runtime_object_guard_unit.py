from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch
import pytest

from app.graphql.types import ResourceType
from app.security.runtime_object_guard import (
    RuntimeObjectAuthorizationExtension,
)


def _make_mock_info(
    path_name: str = "resource",
    url_path: str = "/graphql",
    user_id: int | None = 101,
    role: str = "user",
    with_request: bool = True,
):
    info = MagicMock()
    info.operation.operation.value = "query"

    # Set up GraphQL path node (single key)
    path_mock = MagicMock()
    path_mock.key = path_name
    path_mock.prev = None
    info.path = path_mock

    if not with_request:
        info.context = {}
        return info

    request = MagicMock()
    request.url.path = url_path
    if user_id is not None:
        request.state.current_user = {"user_id": user_id, "role": role}
    else:
        request.state.current_user = None

    info.context = {"request": request}
    return info


def test_scalar_and_unrelated_types_bypass_guard():
    ext = RuntimeObjectAuthorizationExtension()
    info = _make_mock_info()

    assert ext._authorize_result("simple string", info) == "simple string"
    assert ext._authorize_result(12345, info) == 12345
    assert ext._authorize_result({"foo": "bar"}, info) == {"foo": "bar"}
    assert ext._authorize_result(None, info) is None


def test_insecure_endpoint_bypasses_guard():
    ext = RuntimeObjectAuthorizationExtension()
    info = _make_mock_info(url_path="/graphql-insecure")
    resource = ResourceType(
        id=102,
        name="Bob's Note",
        owner_id=102,
        object_type="document",
        parent_id=None,
    )

    result = ext._authorize_result(resource, info)
    assert result is resource


def test_missing_request_fails_closed():
    ext = RuntimeObjectAuthorizationExtension()
    info = _make_mock_info(with_request=False)
    resource = ResourceType(
        id=101,
        name="Alice Note",
        owner_id=101,
        object_type="document",
        parent_id=None,
    )

    assert ext._authorize_result(resource, info) is None


def test_missing_user_fails_closed():
    ext = RuntimeObjectAuthorizationExtension()
    info = _make_mock_info(user_id=None)
    resource = ResourceType(
        id=101,
        name="Alice Note",
        owner_id=101,
        object_type="document",
        parent_id=None,
    )

    assert ext._authorize_result(resource, info) is None


def test_owner_match_is_authorized():
    ext = RuntimeObjectAuthorizationExtension()
    info = _make_mock_info(user_id=101, role="user")
    resource = ResourceType(
        id=101,
        name="Alice Note",
        owner_id=101,
        object_type="document",
        parent_id=None,
    )

    with patch(
        "app.security.runtime_object_guard.get_object_owner",
        return_value=101,
    ):
        authorized = ext._is_authorized(resource, info)
        assert authorized is True
        assert ext._authorize_result(resource, info) is resource


def test_foreign_owner_is_denied():
    ext = RuntimeObjectAuthorizationExtension()
    info = _make_mock_info(user_id=101, role="user")
    resource = ResourceType(
        id=102,
        name="Bob Note",
        owner_id=102,
        object_type="document",
        parent_id=None,
    )

    with patch(
        "app.security.runtime_object_guard.get_object_owner",
        return_value=102,
    ):
        authorized = ext._is_authorized(resource, info)
        assert authorized is False
        assert ext._authorize_result(resource, info) is None


def test_admin_is_authorized_for_foreign_object():
    ext = RuntimeObjectAuthorizationExtension()
    info = _make_mock_info(user_id=103, role="admin")
    resource = ResourceType(
        id=102,
        name="Bob Note",
        owner_id=102,
        object_type="document",
        parent_id=None,
    )

    with patch(
        "app.security.runtime_object_guard.get_object_owner",
        return_value=102,
    ):
        authorized = ext._is_authorized(resource, info)
        assert authorized is True
        assert ext._authorize_result(resource, info) is resource


def test_list_filters_foreign_objects_and_preserves_authorized():
    ext = RuntimeObjectAuthorizationExtension()
    info = _make_mock_info(user_id=101, role="user")

    alice_res = ResourceType(
        id=101,
        name="Alice Note",
        owner_id=101,
        object_type="document",
        parent_id=None,
    )
    bob_res = ResourceType(
        id=102,
        name="Bob Note",
        owner_id=102,
        object_type="document",
        parent_id=None,
    )

    def mock_get_owner(obj_type, obj_id):
        return 101 if obj_id == 101 else 102

    with patch(
        "app.security.runtime_object_guard.get_object_owner",
        side_effect=mock_get_owner,
    ):
        items = [alice_res, bob_res, "unrelated_scalar"]
        result = ext._authorize_result(items, info)

        assert alice_res in result
        assert bob_res not in result
        assert "unrelated_scalar" in result


def test_database_exception_fails_closed():
    ext = RuntimeObjectAuthorizationExtension()
    info = _make_mock_info(user_id=101, role="user")
    resource = ResourceType(
        id=101,
        name="Alice Note",
        owner_id=101,
        object_type="document",
        parent_id=None,
    )

    with patch(
        "app.security.runtime_object_guard.get_object_owner",
        side_effect=RuntimeError("Database connection lost"),
    ):
        assert ext._is_authorized(resource, info) is False
        assert ext._authorize_result(resource, info) is None


def test_format_path_linked_list():
    ext = RuntimeObjectAuthorizationExtension()
    p1 = MagicMock()
    p1.key = "resource"
    p1.prev = None

    p2 = MagicMock()
    p2.key = "children"
    p2.prev = p1

    p3 = MagicMock()
    p3.key = "name"
    p3.prev = p2

    assert ext._format_path(p3) == "resource.children.name"
    assert ext._format_path(None) == ""


@pytest.mark.anyio
async def test_async_resolver_execution():
    ext = RuntimeObjectAuthorizationExtension()
    info = _make_mock_info(user_id=101, role="user")
    resource = ResourceType(
        id=101,
        name="Alice Note",
        owner_id=101,
        object_type="document",
        parent_id=None,
    )

    async def async_resolver(*args, **kwargs):
        await asyncio.sleep(0.001)
        return resource

    with patch(
        "app.security.runtime_object_guard.get_object_owner",
        return_value=101,
    ):
        res_coro = ext.resolve(async_resolver, None, info)
        resolved = await res_coro
        assert resolved is resource
