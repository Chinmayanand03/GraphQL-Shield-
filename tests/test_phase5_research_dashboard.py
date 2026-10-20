"""
Tests for Phase 5 Research Evaluation Dashboard, Model Service, and Enforcement Independence.

Covers:
1. Dashboard HTML and API data structures (recent decisions, provenance, metrics, limitations).
2. Model-loading errors and graceful fallback to rule baseline.
3. Telemetry session risk-score reporting and alert categorization.
4. Enforcement independence: PolicyEngine and RuntimeObjectAuthorizationExtension
   never allow the ML model to override deterministic allow/deny decisions.
5. Insecure endpoint isolation for benchmark baseline comparisons.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.security import create_access_token
from app.main import app
from app.security.authorization import AuthorizationContext, PolicyEngine
from app.security.model_service import (
    DEFAULT_MODEL_PATH,
    get_model_status,
    get_research_evaluation_summary,
    load_behavioral_model,
    score_session_telemetry,
)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_dashboard_html_contains_research_evaluation_section(client: TestClient) -> None:
    """Verify that /dashboard serves HTML containing the Phase 5 research-evaluation components."""
    response = client.get("/dashboard")
    assert response.status_code == 200
    html = response.text

    assert "id=\"research-evaluation\"" in html
    assert "id=\"modelStatusPill\"" in html
    assert "id=\"metricsComparisonBody\"" in html
    assert "id=\"provEvidenceBody\"" in html
    assert "id=\"behavioralAlertsBody\"" in html
    assert "id=\"nonInterferenceGrid\"" in html
    assert "id=\"telemetryScorerForm\"" in html
    assert "RULE BASELINE OUTPERFORMED ML" in html
    assert "Strict Zero-Trust Enforcement Boundary" in html


def test_dashboard_stats_api_includes_research_evaluation(client: TestClient) -> None:
    """Verify that /api/v1/dashboard-stats returns research_evaluation alongside stats and logs."""
    response = client.get("/api/v1/dashboard-stats")
    assert response.status_code == 200
    data = response.json()

    assert "stats" in data
    assert "recent_logs" in data
    assert "demo_users" in data
    assert "research_evaluation" in data

    re = data["research_evaluation"]
    assert "model_status" in re
    assert "evaluation_metrics" in re
    assert "model_limitations" in re
    assert "non_interference" in re
    assert "provenance_evidence" in re
    assert "behavioural_alerts" in re


def test_research_evaluation_api_metrics_and_limitations(client: TestClient) -> None:
    """Verify /api/v1/research-evaluation endpoint metrics schema and scientific limitations."""
    response = client.get("/api/v1/research-evaluation")
    assert response.status_code == 200
    data = response.json()

    # Evaluation metrics comparison schema
    metrics = data["evaluation_metrics"]
    xgb = metrics["xgboost"]
    rule = metrics["rule_baseline"]

    for m in (xgb, rule):
        assert "accuracy" in m
        assert "precision" in m
        assert "recall" in m
        assert "f1_score" in m
        assert "pr_auc_average_precision" in m
        assert "false_positive_rate" in m
        assert "confusion_matrix" in m

    assert "latency" in metrics
    assert "average_ms_per_batch" in metrics["latency"]
    assert "average_ms_per_session" in metrics["latency"]

    # Model limitations must explicitly disclaim ML superiority
    limits = data["model_limitations"]
    assert limits["ml_superiority_claim"] is False
    assert limits["held_out_family"] == "nested_relational"
    assert "held_out_templates" in limits
    assert "outperforming the XGBoost classifier" in limits["comparative_finding"]

    # Non-interference status
    ni = data["non_interference"]
    assert ni["status"] == "VERIFIED_PASSING"
    assert len(ni["properties"]) >= 6


def test_model_loading_missing_file_graceful_fallback(tmp_path: Path) -> None:
    """Loading a non-existent model file must fail gracefully without raising an exception."""
    bogus_path = tmp_path / "non_existent_model.json"
    model = load_behavioral_model(model_path=bogus_path, force_reload=True)

    assert model is None
    status = get_model_status()
    assert status["loaded"] is False
    assert "not found" in str(status["error"]).lower()

    # Reset cache to default valid model
    load_behavioral_model(force_reload=True)


def test_model_loading_corrupt_file_graceful_fallback(tmp_path: Path) -> None:
    """Loading a corrupted model file must record error and return None safely."""
    corrupt_path = tmp_path / "corrupt_model.json"
    corrupt_path.write_text("NOT_VALID_JSON_MODEL_DATA", encoding="utf-8")

    model = load_behavioral_model(model_path=corrupt_path, force_reload=True)
    assert model is None
    status = get_model_status()
    assert status["loaded"] is False
    assert status["error"] is not None

    # Reset cache to default valid model
    load_behavioral_model(force_reload=True)


def test_telemetry_scoring_without_model() -> None:
    """When ML model is unavailable, telemetry scoring must still work using the rule baseline."""
    benign_session = {
        "requests_per_window": 15,
        "distinct_objects_count": 3,
        "requests_per_minute": 1.0,
        "recent_denials_count": 0,
        "cross_owner_attempts_count": 0,
        "nested_relationship_count": 1,
        "max_query_depth": 2,
        "enumeration_score": 0.03,
        "request_burst_rate": 2.0,
    }

    # Explicitly pass model=None to test headless/unloaded mode
    scored = score_session_telemetry(benign_session, model=None)

    assert scored["rule_baseline"]["prediction"] == 0
    assert scored["rule_baseline"]["score"] < 0.30
    assert scored["xgboost"]["available"] is False
    assert scored["xgboost"]["probability"] is None
    assert scored["is_suspicious"] is False
    assert scored["alert_level"] == "LOW"


def test_telemetry_score_endpoint_normal_session(client: TestClient) -> None:
    """POST /api/v1/telemetry/score-session evaluates a normal steady access session."""
    payload = {
        "requests_per_window": 20,
        "distinct_objects_count": 4,
        "requests_per_minute": 1.33,
        "repeated_target_count": 16,
        "recent_denials_count": 0,
        "cross_owner_attempts_count": 0,
        "nested_relationship_count": 2,
        "max_query_depth": 2,
        "enumeration_score": 0.05,
        "request_burst_rate": 2.5,
    }

    response = client.post("/api/v1/telemetry/score-session", json=payload)
    assert response.status_code == 200
    res = response.json()

    assert res["is_suspicious"] is False
    assert res["alert_level"] in ("LOW", "MEDIUM")
    assert res["rule_baseline"]["prediction"] == 0
    if res["xgboost"]["available"]:
        assert res["xgboost"]["prediction"] == 0


def test_telemetry_score_endpoint_suspicious_session(client: TestClient) -> None:
    """POST /api/v1/telemetry/score-session evaluates an attack session and triggers alert."""
    payload = {
        "requests_per_window": 150,
        "distinct_objects_count": 140,
        "requests_per_minute": 10.0,
        "repeated_target_count": 10,
        "recent_denials_count": 45,
        "cross_owner_attempts_count": 115,
        "nested_relationship_count": 2,
        "max_query_depth": 2,
        "enumeration_score": 0.95,
        "request_burst_rate": 25.0,
    }

    response = client.post("/api/v1/telemetry/score-session", json=payload)
    assert response.status_code == 200
    res = response.json()

    assert res["is_suspicious"] is True
    assert res["alert_level"] in ("HIGH", "CRITICAL")
    assert res["rule_baseline"]["prediction"] == 1
    assert res["rule_baseline"]["score"] >= 0.70
    if res["xgboost"]["available"]:
        assert res["xgboost"]["prediction"] == 1


def test_enforcement_independence_policy_engine(client: TestClient) -> None:
    """
    Verify that the ML model NEVER alters or overrides PolicyEngine access decisions.
    BOLA attempts are strictly denied under PolicyEngine regardless of ML model outputs.
    """
    engine = PolicyEngine()

    # User 101 attempting BOLA access to User 102's resource
    bola_ctx = AuthorizationContext(
        user_id=101,
        role="user",
        operation="query",
        object_type="Resource",
        object_id=102,
        path="resource",
        owner_id=102,
        metadata={},
    )
    decision = engine.evaluate(bola_ctx)
    assert decision["decision"] == "DENY"
    assert decision["reason"] == "OWNERSHIP_MISMATCH"

    # Even if telemetry scoring is invoked simultaneously, policy decision is invariant
    score_session_telemetry({
        "requests_per_window": 1,
        "distinct_objects_count": 1,
        "requests_per_minute": 0.1,
        "recent_denials_count": 0,
        "cross_owner_attempts_count": 0,
        "nested_relationship_count": 0,
        "max_query_depth": 1,
        "enumeration_score": 0.0,
        "request_burst_rate": 1.0,
    })

    # Policy decision must remain DENY
    decision_after = engine.evaluate(bola_ctx)
    assert decision_after["decision"] == "DENY"
    assert decision_after["reason"] == "OWNERSHIP_MISMATCH"


def test_insecure_endpoint_remains_available_for_benchmarking(client: TestClient) -> None:
    """Verify /graphql-insecure remains active and bypasses runtime security for controlled benchmarking."""
    token = create_access_token(user_id=101, role="user")
    headers = {"Authorization": f"Bearer {token}"}

    # BOLA query against insecure endpoint
    query = "{ resource(id: 102) { id name ownerId } }"
    res_insecure = client.post("/graphql-insecure", json={"query": query}, headers=headers)
    assert res_insecure.status_code == 200
    data_insecure = res_insecure.json()
    assert "data" in data_insecure
    # Insecure endpoint leaks the resource without blocking
    assert data_insecure["data"]["resource"]["id"] == 102

    # In contrast, secure endpoint blocks the attack
    res_secure = client.post("/graphql", json={"query": query}, headers=headers)
    assert res_secure.status_code in (200, 403)
    data_secure = res_secure.json()
    if res_secure.status_code == 200:
        # Field level filtration returns null
        assert data_secure.get("data", {}).get("resource") is None
