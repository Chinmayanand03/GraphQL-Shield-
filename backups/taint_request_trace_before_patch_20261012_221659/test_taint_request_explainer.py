from __future__ import annotations

from app.security import taint_request_explainer as explainer


class FakeSource:
    def to_dict(self):
        return {
            "source_id": "src-test",
            "value": 102,
            "source_kind": "variable",
            "graphql_path": "resource",
            "field_name": "resource",
            "argument_name": "id",
            "operation_type": "query",
            "operation_name": "TestResource",
            "variable_name": "resourceId",
        }


class FakeTracking:
    valid = True
    operation_count = 1
    warnings = ()
    sources = (FakeSource(),)


def _mock_request(monkeypatch, owner_id):
    monkeypatch.setattr(explainer, "track_sources", lambda query, variables: FakeTracking())
    monkeypatch.setattr(
        explainer,
        "normalize_query",
        lambda query, variables: {
            "operation": "query",
            "objects": [{"type": "Resource", "id": 102, "path": "resource"}],
        },
    )
    monkeypatch.setattr(explainer, "get_object_owner", lambda object_type, object_id: owner_id)
    monkeypatch.setattr(explainer, "_collect_nested_selection_paths", lambda query: [])


def test_explanation_tracks_source_and_denies_foreign_object(monkeypatch):
    _mock_request(monkeypatch, owner_id=102)

    result = explainer.build_taint_explanation(
        "query TestResource($resourceId: Int!) { resource(id: $resourceId) { id name } }",
        {"resourceId": 102},
        {"user_id": 101, "role": "user"},
    )

    assert result["source_tracking"]["source_count"] == 1
    assert result["taint_sources"][0]["variable_name"] == "resourceId"
    assert result["objects"][0]["owner_id"] == 102
    assert result["objects"][0]["authorization"]["decision"] == "DENY"
    assert result["objects"][0]["authorization"]["reason"] == "OWNERSHIP_MISMATCH"


def test_explanation_accepts_owned_object(monkeypatch):
    _mock_request(monkeypatch, owner_id=101)

    result = explainer.build_taint_explanation(
        "query TestResource($resourceId: Int!) { resource(id: $resourceId) { id name } }",
        {"resourceId": 102},
        {"user_id": 101, "role": "user"},
    )

    auth = result["objects"][0]["authorization"]
    assert auth["decision"] == "ALLOW"
    assert auth["reason"] == "OWNER_MATCH"
    assert "matches this object's owner" in auth["explanation"]


def test_explanation_accepts_admin_under_admin_policy(monkeypatch):
    _mock_request(monkeypatch, owner_id=102)

    result = explainer.build_taint_explanation(
        "query TestResource($resourceId: Int!) { resource(id: $resourceId) { id name } }",
        {"resourceId": 102},
        {"user_id": 104, "role": "admin"},
    )

    auth = result["objects"][0]["authorization"]
    assert auth["decision"] == "ALLOW"
    assert auth["reason"] == "ADMIN_OVERRIDE"
