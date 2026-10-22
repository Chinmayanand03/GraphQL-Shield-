import os
import sqlite3
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.core.security import create_access_token
from app.main import app
from app.seed import add_shared_folder_scenario, seed_database
from app.security import blind_spot_model
from app.security.live_telemetry import live_sessions, session_features
from app.security.object_extractor import normalize_query
from app.security.query_features import combine_features, extract_features

client = TestClient(app)
DB_FILE = "test_blind_spot.db"


@pytest.fixture(autouse=True)
def setup_test_db():
    original_url = settings.DATABASE_URL
    settings.DATABASE_URL = f"sqlite:///./{DB_FILE}"
    seed_database()
    add_shared_folder_scenario()
    yield
    settings.DATABASE_URL = original_url
    if os.path.exists(DB_FILE):
        try:
            os.remove(DB_FILE)
        except PermissionError:
            pass


def headers(user_id=101, role="user"):
    return {"Authorization": f"Bearer {create_access_token(user_id=user_id, role=role)}"}


def events(name):
    conn = sqlite3.connect(DB_FILE)
    try:
        return conn.execute("SELECT detail FROM layer_events WHERE event = ?", (name,)).fetchall()
    finally:
        conn.close()


# ---------------------------------------------------------------- query features

def test_relationship_fields_are_counted_through_fragments():
    features = extract_features(
        "{ resource(id: 201) { ...Kids } } fragment Kids on ResourceType { children { children { id } } }"
    )
    assert features["relationship_field_count"] == 2
    assert features["relationship_chain_depth"] == 2
    assert features["fragment_spread_count"] == 1
    assert features["l1_resolved_id_count"] == 1
    assert features["unresolved_id_argument_count"] == 0


def test_query_shape_features():
    features = extract_features("query($r: Int = 5) { item: resource(id: $r) @include(if: true) { id } }")
    assert features["variable_default_count"] == 1
    assert features["alias_count"] == 1
    assert features["directive_count"] == 1
    assert features["l1_resolved_id_count"] == 1  # Layer 1 now reads variable defaults


def test_unresolved_ids_are_counted():
    features = extract_features("query($r: Int) { resource(id: $r) { id } }")
    assert features["id_argument_count"] == 1
    assert features["unresolved_id_argument_count"] == 1


def test_batch_features_combine():
    single = extract_features("{ resource(id: 201) { children { id } } }", batch_size=2)
    combined = combine_features([single, single])
    assert combined["relationship_field_count"] == 2
    assert combined["max_depth"] == single["max_depth"]
    assert combined["batch_size"] == 2


def test_unparseable_query_has_no_features():
    assert extract_features("{ resource(id: ") is None


# ---------------------------------------------------------------- Layer 1 fix found by the discovery run

def test_layer1_reads_variable_defaults():
    normalized = normalize_query("query($r: Int = 102) { resource(id: $r) { id } }", {})
    assert [obj["id"] for obj in normalized["objects"]] == [102]
    # A value the client sends overrides the default.
    normalized = normalize_query("query($r: Int = 102) { resource(id: $r) { id } }", {"r": 101})
    assert [obj["id"] for obj in normalized["objects"]] == [101]


def test_variable_default_bola_is_blocked_by_layer1():
    response = client.post("/graphql", json={"query": "query($r: Int = 102) { resource(id: $r) { id } }"}, headers=headers())
    assert response.status_code == 403
    assert response.json()["detail"]["layer"] == "L1_PRE_EXECUTION"
    assert events("L1_BLIND_SPOT_CAUGHT_BY_L2") == []


def test_mutation_variable_default_bola_is_blocked_by_layer1():
    response = client.post(
        "/graphql",
        json={"query": 'mutation($r: Int = 102) { updateResource(id: $r, name: "x") { id } }'},
        headers=headers(),
    )
    assert response.status_code == 403


# ---------------------------------------------------------------- predictor

def test_rule_baseline_flags_relationships_only():
    assert blind_spot_model.rule_baseline(extract_features("{ resource(id: 201) { children { id } } }")) == 1
    assert blind_spot_model.rule_baseline(extract_features("{ resource(id: 101) { id } }")) == 0


def test_score_endpoint_requires_login():
    assert client.post("/api/v1/security/blind-spot-score", json={"query": "{ health { status } }"}).status_code in (401, 403)


def test_score_endpoint_scores_without_executing():
    response = client.post(
        "/api/v1/security/blind-spot-score",
        json={"query": "{ resource(id: 201) { id children { id } } }"},
        headers=headers(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["rule_prediction"] == 1
    assert payload["features"]["relationship_field_count"] == 1
    assert events("L2_FILTERED") == []  # nothing was executed
    if blind_spot_model.model_status()["loaded"]:
        assert payload["prediction"] == 1
        assert payload["contributions"]


def test_score_endpoint_rejects_unparseable_query():
    response = client.post("/api/v1/security/blind-spot-score", json={"query": "{ resource("}, headers=headers())
    assert response.status_code == 400


@pytest.mark.skipif(not blind_spot_model.model_status()["loaded"], reason="blind-spot model not trained")
def test_live_prediction_is_recorded_and_matches_layer2():
    response = client.post("/graphql", json={"query": "{ resource(id: 201) { id children { id } } }"}, headers=headers())
    assert response.status_code == 200
    assert [c["id"] for c in response.json()["data"]["resource"]["children"]] == [202, 203]
    assert events("BLIND_SPOT_PREDICTED")
    caught = events("L1_BLIND_SPOT_CAUGHT_BY_L2")
    assert caught and "predicted p=" in caught[0][0]


@pytest.mark.skipif(not blind_spot_model.model_status()["loaded"], reason="blind-spot model not trained")
def test_plain_lookup_is_not_predicted():
    client.post("/graphql", json={"query": "{ resource(id: 101) { id } }"}, headers=headers())
    assert events("BLIND_SPOT_PREDICTED") == []


def test_model_summary_endpoint():
    data = client.get("/api/v1/security/blind-spot-model").json()
    assert "model_status" in data and "metrics" in data and "discovery" in data


# ---------------------------------------------------------------- live behavioural telemetry

def _row(object_id, seconds, decision="ALLOW", path="resource", cross_owner=0):
    return {"object_id": object_id, "path": path, "decision": decision, "cross_owner": cross_owner,
            "timestamp": (datetime(2026, 10, 22, 12, 0, 0) + timedelta(seconds=seconds)).isoformat(sep=" ")}


def test_session_features_from_audit_rows():
    rows = [_row(101, 0), _row(102, 5, "DENY", cross_owner=1), _row(103, 10, "DENY", cross_owner=1),
            _row(103, 20, "DENY", "resource.children", cross_owner=1), _row(110, 200)]
    features = session_features(rows)
    assert features["requests_per_window"] == 5
    assert features["distinct_objects_count"] == 4
    assert features["repeated_target_count"] == 1
    assert features["recent_denials_count"] == 3
    assert features["cross_owner_attempts_count"] == 3
    assert features["nested_relationship_count"] == 1
    assert features["max_query_depth"] == 2
    assert features["enumeration_score"] == round(2 / 3, 4)  # 101-102-103 consecutive, 103->110 not
    assert features["request_burst_rate"] == 4.0  # 4 decisions inside the first 60 s


def test_live_sessions_from_real_traffic():
    for resource_id in (101, 102, 103):
        client.post("/graphql", json={"query": f"{{ resource(id: {resource_id}) {{ id }} }}"}, headers=headers())
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    try:
        sessions = {s["user_id"]: s for s in live_sessions(conn)}
    finally:
        conn.close()
    features = sessions[101]["features"]
    assert features["requests_per_window"] == 3
    assert features["recent_denials_count"] == 2
    assert features["cross_owner_attempts_count"] == 2
    assert features["enumeration_score"] == 1.0


def test_live_sessions_endpoint_is_admin_only():
    assert client.get("/api/v1/telemetry/live-sessions", headers=headers()).status_code == 403
    client.post("/graphql", json={"query": "{ resource(id: 102) { id } }"}, headers=headers())
    data = client.get("/api/v1/telemetry/live-sessions", headers=headers(104, "admin")).json()
    session = next(s for s in data["sessions"] if s["user_id"] == 101)
    assert session["features"]["recent_denials_count"] == 1
    assert "alert_level" in session["score"]


def test_research_evaluation_hides_live_sessions_from_public():
    client.post("/graphql", json={"query": "{ resource(id: 102) { id } }"}, headers=headers())
    public = client.get("/api/v1/research-evaluation").json()
    assert public["behavioural_alerts_source"] == "live"
    assert public["behavioural_alerts"] == []
    admin = client.get("/api/v1/research-evaluation", headers=headers(104, "admin")).json()
    assert any(alert["session_id"] == "user-101" for alert in admin["behavioural_alerts"])
