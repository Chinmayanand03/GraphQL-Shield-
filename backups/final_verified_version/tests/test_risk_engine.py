import pytest
from unittest.mock import patch
from app.security.authorization import AuthorizationContext, PolicyEngine

engine = PolicyEngine()

@patch('app.security.risk_engine.get_db_connection')
def test_risk_legitimate_request(mock_db):
    mock_db.return_value.cursor.return_value.fetchone.return_value = (0,)
    ctx = AuthorizationContext(
        user_id=101, role="user", operation="query",
        object_type="Resource", object_id=101, path="resource",
        owner_id=101, metadata={}
    )
    res = engine.evaluate(ctx)
    assert res["decision"] == "ALLOW"
    assert res["risk_level"] == "LOW"
    assert res["risk_score"] == 0

@patch('app.security.risk_engine.get_db_connection')
def test_risk_direct_bola(mock_db):
    mock_db.return_value.cursor.return_value.fetchone.return_value = (0,)
    ctx = AuthorizationContext(
        user_id=101, role="user", operation="query",
        object_type="Resource", object_id=102, path="resource",
        owner_id=102, metadata={}
    )
    res = engine.evaluate(ctx)
    assert res["decision"] == "DENY"
    assert res["risk_level"] == "HIGH"
    assert res["risk_score"] >= 80

@patch('app.security.risk_engine.get_db_connection')
def test_risk_nested_suspicious(mock_db):
    mock_db.return_value.cursor.return_value.fetchone.return_value = (0,)
    ctx = AuthorizationContext(
        user_id=101, role="user", operation="query",
        object_type="Resource", object_id=101, path="user.resource",
        owner_id=101, metadata={}
    )
    res = engine.evaluate(ctx)
    # Even if allowed (own resource), nesting gives +20
    assert res["decision"] == "ALLOW"
    assert res["risk_level"] == "LOW"
    assert res["risk_score"] == 20
    
    ctx2 = AuthorizationContext(
        user_id=101, role="user", operation="query",
        object_type="Resource", object_id=102, path="user.resource",
        owner_id=102, metadata={}
    )
    res2 = engine.evaluate(ctx2)
    # BOLA (80) + Nested (20) = 100
    assert res2["decision"] == "DENY"
    assert res2["risk_level"] == "HIGH"
    assert res2["risk_score"] == 100
