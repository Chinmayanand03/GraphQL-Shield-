"""
Tests for Phase 4.1 behavioural session dataset and XGBoost evaluation pipeline.

Validates:
1. Dataset reproducibility under fixed random seeds.
2. Strict feature / label separation (no leakage of labels, scenarios, or raw IDs).
3. Balanced class and scenario distributions.
4. Training / test family isolation without template leakage.
5. Metric computation correctness.
6. Non-interference with the live PolicyEngine authorization decisions.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import pytest

from app.benchmarks.behavioral_dataset import (
    FEATURE_NAMES,
    FEATURE_SCHEMA,
    SCENARIO_CONFIGS,
    BehavioralSession,
    generate_behavioral_dataset,
    read_csv_dataset,
    write_csv_dataset,
)
from app.security.authorization import (
    AuthorizationContext,
    PolicyEngine,
)
from scripts.train_behavioral_xgboost import (
    metrics,
    rule_behavioral_score,
)


def test_behavioral_dataset_reproducibility(tmp_path: Path) -> None:
    """Fixed random seed must produce identical session records and CSV hashes."""
    sessions_a = generate_behavioral_dataset(count=200, seed=20261011)
    sessions_b = generate_behavioral_dataset(count=200, seed=20261011)

    assert len(sessions_a) == len(sessions_b) == 200
    assert [s.to_dict() for s in sessions_a] == [s.to_dict() for s in sessions_b]

    csv_path_a = tmp_path / "sessions_a.csv"
    csv_path_b = tmp_path / "sessions_b.csv"

    manifest_a = write_csv_dataset(sessions_a, csv_path_a)
    manifest_b = write_csv_dataset(sessions_b, csv_path_b)

    assert manifest_a["sha256"] == manifest_b["sha256"]
    assert csv_path_a.read_bytes() == csv_path_b.read_bytes()


def test_feature_label_separation() -> None:
    """
    Model feature names must never contain labels, scenario names,
    session identifiers, or direct ownership matches.
    """
    forbidden_tokens = {
        "label",
        "scenario",
        "family",
        "session_id",
        "is_bola",
        "expected_authorized",
        "owner_matches_principal",
        "target_owner_id",
        "principal_id",
        "username",
        "role",
    }

    for feature in FEATURE_NAMES:
        assert feature not in forbidden_tokens, f"Feature '{feature}' violates separation."
        assert feature in FEATURE_SCHEMA, f"Feature '{feature}' missing from schema."

    # Validate feature extraction from a generated session
    session = generate_behavioral_dataset(count=8, seed=42)[0]
    features = session.to_features()

    assert set(features.keys()) == set(FEATURE_NAMES)
    for forbidden in forbidden_tokens:
        assert forbidden not in features


def test_valid_class_and_scenario_distribution() -> None:
    """All 8 scenarios and balanced classes must be represented."""
    count = 800
    sessions = generate_behavioral_dataset(count=count, seed=99)

    assert len(sessions) == count

    labels = [s.label for s in sessions]
    normal_count = labels.count(0)
    suspicious_count = labels.count(1)

    assert normal_count == 400
    assert suspicious_count == 400

    scenarios = {s.scenario for s in sessions}
    assert scenarios == set(SCENARIO_CONFIGS.keys())
    assert len(scenarios) == 8

    # Each scenario should have exactly count / 8 sessions
    for scenario in SCENARIO_CONFIGS:
        scenario_sessions = [s for s in sessions if s.scenario == scenario]
        assert len(scenario_sessions) == 100


def test_training_test_family_isolation() -> None:
    """Held-out scenario families must be completely disjoint from the training set."""
    sessions = generate_behavioral_dataset(count=400, seed=123)

    held_out_family = "nested_relational"

    train_sessions = [s for s in sessions if s.family != held_out_family]
    test_sessions = [s for s in sessions if s.family == held_out_family]

    # Both train and test partitions must have both classes
    train_labels = {s.label for s in train_sessions}
    test_labels = {s.label for s in test_sessions}

    assert train_labels == {0, 1}
    assert test_labels == {0, 1}

    # Held-out scenario templates must NOT appear in training set
    train_scenarios = {s.scenario for s in train_sessions}
    test_scenarios = {s.scenario for s in test_sessions}

    assert train_scenarios.isdisjoint(test_scenarios)
    assert test_scenarios == {"legitimate_nested", "suspicious_nested_probing"}


def test_metric_computation() -> None:
    """Verify accuracy, precision, recall, f1, and confusion matrix arithmetic."""
    y_true = [0, 0, 1, 1]
    predictions = [0, 1, 0, 1]  # TN=1, FP=1, FN=1, TP=1
    scores = [0.1, 0.7, 0.4, 0.9]

    res = metrics(y_true, predictions, scores)

    assert res["accuracy"] == 0.5
    assert res["precision"] == 0.5
    assert res["recall"] == 0.5
    assert res["f1_score"] == 0.5
    assert res["false_positive_rate"] == 0.5
    assert res["confusion_matrix"] == {
        "true_negative": 1,
        "false_positive": 1,
        "false_negative": 1,
        "true_positive": 1,
    }


def test_rule_behavioral_score_bounds_and_discrimination() -> None:
    """Rule baseline must produce bounded scores and distinguish benign from malicious."""
    benign_session = {
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
    benign_score = rule_behavioral_score(benign_session)
    assert 0.0 <= benign_score <= 1.0
    assert benign_score < 0.30  # Should be classified as normal

    malicious_session = {
        "requests_per_window": 120,
        "distinct_objects_count": 110,
        "requests_per_minute": 8.0,
        "repeated_target_count": 10,
        "recent_denials_count": 35,
        "cross_owner_attempts_count": 90,
        "nested_relationship_count": 2,
        "max_query_depth": 2,
        "enumeration_score": 0.92,
        "request_burst_rate": 22.0,
    }
    malicious_score = rule_behavioral_score(malicious_session)
    assert 0.0 <= malicious_score <= 1.0
    assert malicious_score >= 0.70  # Should be flagged as highly suspicious


def test_ml_model_does_not_override_policy_engine() -> None:
    """
    The behavioural ML model is an offline classifier and must never alter
    or interfere with live PolicyEngine access decisions.
    """
    engine = PolicyEngine()

    # Legitimate owner access
    legit_ctx = AuthorizationContext(
        user_id=101,
        role="user",
        operation="query",
        object_type="Resource",
        object_id=101,
        path="resource",
        owner_id=101,
        metadata={},
    )
    decision = engine.evaluate(legit_ctx)
    assert decision["decision"] == "ALLOW"
    assert decision["reason"] == "OWNER_MATCH"

    # Cross-owner BOLA attempt must remain denied regardless of ML model presence
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

