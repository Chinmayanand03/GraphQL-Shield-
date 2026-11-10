import pytest
from app.security.authorization import AuthorizationContext, PolicyEngine

engine = PolicyEngine()

def test_policy_owner_access():
    ctx = AuthorizationContext(
        user_id=101, role="user", operation="query",
        object_type="Resource", object_id=101, path="resource",
        owner_id=101, metadata={}
    )
    res = engine.evaluate(ctx)
    assert res["decision"] == "ALLOW"
    assert res["reason"] == "OWNER_MATCH"

def test_policy_non_owner_access():
    ctx = AuthorizationContext(
        user_id=101, role="user", operation="query",
        object_type="Resource", object_id=102, path="resource",
        owner_id=102, metadata={}
    )
    res = engine.evaluate(ctx)
    assert res["decision"] == "DENY"
    assert res["reason"] == "OWNERSHIP_MISMATCH"

def test_policy_admin_access():
    ctx = AuthorizationContext(
        user_id=103, role="admin", operation="query",
        object_type="Resource", object_id=102, path="resource",
        owner_id=102, metadata={}
    )
    res = engine.evaluate(ctx)
    assert res["decision"] == "ALLOW"
    assert res["reason"] == "ADMIN_OVERRIDE"

def test_policy_nested_resource():
    ctx = AuthorizationContext(
        user_id=101, role="user", operation="query",
        object_type="Resource", object_id=102, path="user.resource",
        owner_id=102, metadata={}
    )
    res = engine.evaluate(ctx)
    assert res["decision"] == "DENY"
    assert res["reason"] == "NESTED_AUTHORIZATION_VIOLATION"

def test_invalid_context():
    ctx = AuthorizationContext(
        user_id=None, role="user", operation="query",
        object_type="Resource", object_id=102, path="resource",
        owner_id=102, metadata={}
    )
    res = engine.evaluate(ctx)
    assert res["decision"] == "DENY"
    assert res["reason"] == "INVALID_CONTEXT"
