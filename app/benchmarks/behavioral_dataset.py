"""
Behavioral session dataset utilities for GraphQL-Shield Phase 4.1.

Simulates and evaluates session-level behavioural anomalies for BOLA detection.
Deliberately keeps model features strictly separate from scenario labels,
confidential values, and direct ownership comparisons.
"""
from __future__ import annotations

import csv
import hashlib
import json
import random
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence

BEHAVIORAL_DATASET_VERSION = "1.0"

# 10 aggregate behavioural features evaluated by the model.
# Deliberately excludes raw confidential values, usernames, session IDs,
# scenario names, labels, direct object ownership matches, or current auth outcomes.
FEATURE_NAMES: list[str] = [
    "requests_per_window",
    "distinct_objects_count",
    "requests_per_minute",
    "repeated_target_count",
    "recent_denials_count",
    "cross_owner_attempts_count",
    "nested_relationship_count",
    "max_query_depth",
    "enumeration_score",
    "request_burst_rate",
]

FEATURE_SCHEMA: dict[str, str] = {
    "requests_per_window": "integer, total GraphQL requests in session observation window (15 min)",
    "distinct_objects_count": "integer, count of unique resource object IDs requested in the window",
    "requests_per_minute": "float, average request throughput per minute (requests_per_window / 15.0)",
    "repeated_target_count": "integer, count of requests targeting previously accessed IDs in session",
    "recent_denials_count": "integer, authorization denials (403 Forbidden) logged in observation window",
    "cross_owner_attempts_count": "integer, requests targeting resources owned by other principals",
    "nested_relationship_count": "integer, queries requesting nested relationship selections (e.g., children)",
    "max_query_depth": "integer, maximum GraphQL AST selection depth observed in session",
    "enumeration_score": "float [0.0, 1.0], consecutive/incremental object ID traversal pattern score",
    "request_burst_rate": "float, peak request throughput observed in any 60-second window (req/min)",
}

# 8 controlled scenarios partitioned into 4 balanced families.
# Each family contains exactly 1 normal scenario (label 0) and 1 suspicious scenario (label 1).
SCENARIO_CONFIGS: dict[str, dict[str, Any]] = {
    "normal_steady": {
        "label": 0,
        "family": "standard_steady",
        "description": "Routine authenticated access to user's own resources at a steady pace.",
    },
    "legitimate_nested": {
        "label": 0,
        "family": "nested_relational",
        "description": "Legitimate traversal of owned hierarchical folder/document trees with nested fields.",
    },
    "legitimate_high_activity": {
        "label": 0,
        "family": "volumetric",
        "description": "Legitimate power user or automated dashboard polling owned resources at high volume.",
    },
    "mixed_normal": {
        "label": 0,
        "family": "targeted_denial",
        "description": "Standard everyday mix of single-object reads, listings, and folder inspections.",
    },
    "rapid_enumeration": {
        "label": 1,
        "family": "volumetric",
        "description": "Attacker systematically enumerating sequential object IDs across unowned resources.",
    },
    "repeated_denials": {
        "label": 1,
        "family": "targeted_denial",
        "description": "Attacker repeatedly probing restricted resources despite consecutive 403 denials.",
    },
    "repeated_cross_owner": {
        "label": 1,
        "family": "standard_steady",
        "description": "Attacker targeting specific known foreign resources across victim principals.",
    },
    "suspicious_nested_probing": {
        "label": 1,
        "family": "nested_relational",
        "description": "Attacker injecting deep nested queries attempting to bypass root authorization.",
    },
}

WINDOW_MINUTES = 15.0


@dataclass(frozen=True)
class BehavioralSession:
    """A single synthetic session record representing a 15-minute observation window."""

    session_id: str
    scenario: str
    family: str
    label: int  # 0: normal, 1: suspicious
    # 10 Model Features:
    requests_per_window: int
    distinct_objects_count: int
    requests_per_minute: float
    repeated_target_count: int
    recent_denials_count: int
    cross_owner_attempts_count: int
    nested_relationship_count: int
    max_query_depth: int
    enumeration_score: float
    request_burst_rate: float

    def to_dict(self) -> dict[str, Any]:
        """Convert session to flat dictionary for CSV serialization."""
        return asdict(self)

    def to_features(self) -> dict[str, Any]:
        """Extract only the model input features (strictly excluding metadata and labels)."""
        return {name: getattr(self, name) for name in FEATURE_NAMES}


def _generate_normal_steady(session_id: str, rng: random.Random) -> BehavioralSession:
    n_requests = rng.randint(12, 28)
    distinct_objs = rng.randint(2, min(5, n_requests))
    repeated_targets = n_requests - distinct_objs
    recent_denials = 1 if rng.random() < 0.02 else 0
    cross_owner = 1 if rng.random() < 0.03 else 0
    nested_count = rng.randint(0, 3)
    max_depth = rng.choice([1, 2])
    enum_score = round(rng.uniform(0.01, 0.12), 4)
    burst_rate = round(rng.uniform(1.8, 3.6), 2)

    return BehavioralSession(
        session_id=session_id,
        scenario="normal_steady",
        family=SCENARIO_CONFIGS["normal_steady"]["family"],
        label=0,
        requests_per_window=n_requests,
        distinct_objects_count=distinct_objs,
        requests_per_minute=round(n_requests / WINDOW_MINUTES, 2),
        repeated_target_count=repeated_targets,
        recent_denials_count=recent_denials,
        cross_owner_attempts_count=cross_owner,
        nested_relationship_count=nested_count,
        max_query_depth=max_depth,
        enumeration_score=enum_score,
        request_burst_rate=burst_rate,
    )


def _generate_legitimate_nested(session_id: str, rng: random.Random) -> BehavioralSession:
    n_requests = rng.randint(20, 48)
    distinct_objs = rng.randint(4, min(10, n_requests))
    repeated_targets = n_requests - distinct_objs
    recent_denials = 0
    cross_owner = 0
    nested_count = rng.randint(int(n_requests * 0.65), int(n_requests * 0.92))
    max_depth = rng.choice([3, 4, 5])
    enum_score = round(rng.uniform(0.04, 0.18), 4)
    burst_rate = round(rng.uniform(2.5, 5.2), 2)

    return BehavioralSession(
        session_id=session_id,
        scenario="legitimate_nested",
        family=SCENARIO_CONFIGS["legitimate_nested"]["family"],
        label=0,
        requests_per_window=n_requests,
        distinct_objects_count=distinct_objs,
        requests_per_minute=round(n_requests / WINDOW_MINUTES, 2),
        repeated_target_count=repeated_targets,
        recent_denials_count=recent_denials,
        cross_owner_attempts_count=cross_owner,
        nested_relationship_count=nested_count,
        max_query_depth=max_depth,
        enumeration_score=enum_score,
        request_burst_rate=burst_rate,
    )


def _generate_legitimate_high_activity(session_id: str, rng: random.Random) -> BehavioralSession:
    n_requests = rng.randint(90, 215)
    distinct_objs = rng.randint(6, 15)
    repeated_targets = n_requests - distinct_objs
    recent_denials = 1 if rng.random() < 0.02 else 0
    cross_owner = 1 if rng.random() < 0.03 else 0
    nested_count = rng.randint(10, 35)
    max_depth = rng.choice([2, 3])
    enum_score = round(rng.uniform(0.02, 0.16), 4)
    burst_rate = round(rng.uniform(9.0, 22.0), 2)

    return BehavioralSession(
        session_id=session_id,
        scenario="legitimate_high_activity",
        family=SCENARIO_CONFIGS["legitimate_high_activity"]["family"],
        label=0,
        requests_per_window=n_requests,
        distinct_objects_count=distinct_objs,
        requests_per_minute=round(n_requests / WINDOW_MINUTES, 2),
        repeated_target_count=repeated_targets,
        recent_denials_count=recent_denials,
        cross_owner_attempts_count=cross_owner,
        nested_relationship_count=nested_count,
        max_query_depth=max_depth,
        enumeration_score=enum_score,
        request_burst_rate=burst_rate,
    )


def _generate_mixed_normal(session_id: str, rng: random.Random) -> BehavioralSession:
    n_requests = rng.randint(25, 60)
    distinct_objs = rng.randint(4, min(12, n_requests))
    repeated_targets = n_requests - distinct_objs
    recent_denials = 0
    cross_owner = 0
    nested_count = rng.randint(3, 14)
    max_depth = rng.choice([2, 3])
    enum_score = round(rng.uniform(0.05, 0.20), 4)
    burst_rate = round(rng.uniform(2.8, 6.2), 2)

    return BehavioralSession(
        session_id=session_id,
        scenario="mixed_normal",
        family=SCENARIO_CONFIGS["mixed_normal"]["family"],
        label=0,
        requests_per_window=n_requests,
        distinct_objects_count=distinct_objs,
        requests_per_minute=round(n_requests / WINDOW_MINUTES, 2),
        repeated_target_count=repeated_targets,
        recent_denials_count=recent_denials,
        cross_owner_attempts_count=cross_owner,
        nested_relationship_count=nested_count,
        max_query_depth=max_depth,
        enumeration_score=enum_score,
        request_burst_rate=burst_rate,
    )


def _generate_rapid_enumeration(session_id: str, rng: random.Random) -> BehavioralSession:
    n_requests = rng.randint(85, 240)
    distinct_objs = int(n_requests * rng.uniform(0.86, 0.98))
    repeated_targets = n_requests - distinct_objs
    cross_owner = int(distinct_objs * rng.uniform(0.72, 0.94))
    recent_denials = int(cross_owner * rng.uniform(0.72, 0.92))
    nested_count = rng.randint(0, 8)
    max_depth = rng.choice([1, 2])
    enum_score = round(rng.uniform(0.82, 0.99), 4)
    burst_rate = round(rng.uniform(12.5, 32.0), 2)

    return BehavioralSession(
        session_id=session_id,
        scenario="rapid_enumeration",
        family=SCENARIO_CONFIGS["rapid_enumeration"]["family"],
        label=1,
        requests_per_window=n_requests,
        distinct_objects_count=distinct_objs,
        requests_per_minute=round(n_requests / WINDOW_MINUTES, 2),
        repeated_target_count=repeated_targets,
        recent_denials_count=recent_denials,
        cross_owner_attempts_count=cross_owner,
        nested_relationship_count=nested_count,
        max_query_depth=max_depth,
        enumeration_score=enum_score,
        request_burst_rate=burst_rate,
    )


def _generate_repeated_denials(session_id: str, rng: random.Random) -> BehavioralSession:
    n_requests = rng.randint(32, 90)
    distinct_objs = rng.randint(6, 18)
    repeated_targets = n_requests - distinct_objs
    cross_owner = int(n_requests * rng.uniform(0.72, 0.95))
    recent_denials = int(cross_owner * rng.uniform(0.75, 0.95))
    nested_count = rng.randint(1, 8)
    max_depth = rng.choice([1, 2, 3])
    enum_score = round(rng.uniform(0.20, 0.48), 4)
    burst_rate = round(rng.uniform(3.5, 9.8), 2)

    return BehavioralSession(
        session_id=session_id,
        scenario="repeated_denials",
        family=SCENARIO_CONFIGS["repeated_denials"]["family"],
        label=1,
        requests_per_window=n_requests,
        distinct_objects_count=distinct_objs,
        requests_per_minute=round(n_requests / WINDOW_MINUTES, 2),
        repeated_target_count=repeated_targets,
        recent_denials_count=recent_denials,
        cross_owner_attempts_count=cross_owner,
        nested_relationship_count=nested_count,
        max_query_depth=max_depth,
        enumeration_score=enum_score,
        request_burst_rate=burst_rate,
    )


def _generate_repeated_cross_owner(session_id: str, rng: random.Random) -> BehavioralSession:
    n_requests = rng.randint(20, 68)
    distinct_objs = rng.randint(4, 12)
    repeated_targets = n_requests - distinct_objs
    cross_owner = int(n_requests * rng.uniform(0.78, 0.96))
    recent_denials = int(cross_owner * rng.uniform(0.70, 0.90))
    nested_count = rng.randint(2, 10)
    max_depth = rng.choice([2, 3])
    enum_score = round(rng.uniform(0.10, 0.35), 4)
    burst_rate = round(rng.uniform(2.2, 6.5), 2)

    return BehavioralSession(
        session_id=session_id,
        scenario="repeated_cross_owner",
        family=SCENARIO_CONFIGS["repeated_cross_owner"]["family"],
        label=1,
        requests_per_window=n_requests,
        distinct_objects_count=distinct_objs,
        requests_per_minute=round(n_requests / WINDOW_MINUTES, 2),
        repeated_target_count=repeated_targets,
        recent_denials_count=recent_denials,
        cross_owner_attempts_count=cross_owner,
        nested_relationship_count=nested_count,
        max_query_depth=max_depth,
        enumeration_score=enum_score,
        request_burst_rate=burst_rate,
    )


def _generate_suspicious_nested_probing(session_id: str, rng: random.Random) -> BehavioralSession:
    n_requests = rng.randint(24, 78)
    distinct_objs = rng.randint(8, 25)
    repeated_targets = n_requests - distinct_objs
    nested_count = int(n_requests * rng.uniform(0.70, 0.94))
    max_depth = rng.choice([4, 5, 6])
    cross_owner = int(n_requests * rng.uniform(0.58, 0.88))
    recent_denials = int(cross_owner * rng.uniform(0.62, 0.88))
    enum_score = round(rng.uniform(0.18, 0.45), 4)
    burst_rate = round(rng.uniform(2.6, 7.8), 2)

    return BehavioralSession(
        session_id=session_id,
        scenario="suspicious_nested_probing",
        family=SCENARIO_CONFIGS["suspicious_nested_probing"]["family"],
        label=1,
        requests_per_window=n_requests,
        distinct_objects_count=distinct_objs,
        requests_per_minute=round(n_requests / WINDOW_MINUTES, 2),
        repeated_target_count=repeated_targets,
        recent_denials_count=recent_denials,
        cross_owner_attempts_count=cross_owner,
        nested_relationship_count=nested_count,
        max_query_depth=max_depth,
        enumeration_score=enum_score,
        request_burst_rate=burst_rate,
    )


GENERATORS = {
    "normal_steady": _generate_normal_steady,
    "legitimate_nested": _generate_legitimate_nested,
    "legitimate_high_activity": _generate_legitimate_high_activity,
    "mixed_normal": _generate_mixed_normal,
    "rapid_enumeration": _generate_rapid_enumeration,
    "repeated_denials": _generate_repeated_denials,
    "repeated_cross_owner": _generate_repeated_cross_owner,
    "suspicious_nested_probing": _generate_suspicious_nested_probing,
}


def generate_behavioral_dataset(
    count: int = 1000,
    seed: int = 20261011,
) -> list[BehavioralSession]:
    """
    Generate synthetic behavioural session records.

    Balances across the 8 scenarios, with equal distribution of
    normal (label 0) and suspicious (label 1) sessions.
    """
    if count < 8:
        raise ValueError("count must be at least 8 to cover all scenarios.")

    rng = random.Random(seed)
    scenarios = list(SCENARIO_CONFIGS.keys())
    per_scenario = count // len(scenarios)
    remainder = count % len(scenarios)

    sessions: list[BehavioralSession] = []
    session_counter = 1

    for scenario_name in scenarios:
        num_cases = per_scenario + (1 if remainder > 0 else 0)
        remainder -= 1
        generator_fn = GENERATORS[scenario_name]

        for _ in range(num_cases):
            sess_id = f"sess_{session_counter:05d}"
            sessions.append(generator_fn(sess_id, rng))
            session_counter += 1

    # Deterministic shuffle so scenarios are interspersed
    rng.shuffle(sessions)
    return sessions


def write_csv_dataset(
    sessions: Sequence[BehavioralSession],
    destination: str | Path,
) -> dict[str, Any]:
    """Write session records to CSV and compute manifest statistics."""
    dest_path = Path(destination)
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "session_id",
        "scenario",
        "family",
        "label",
    ] + FEATURE_NAMES

    hasher = hashlib.sha256()

    with dest_path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for session in sessions:
            row = session.to_dict()
            writer.writerow(row)

    # Read back bytes for exact SHA-256
    file_bytes = dest_path.read_bytes()
    hasher.update(file_bytes)

    class_counts = dict(Counter(str(s.label) for s in sessions))
    scenario_counts = dict(Counter(s.scenario for s in sessions))
    family_counts = dict(Counter(s.family for s in sessions))

    manifest = {
        "dataset_version": BEHAVIORAL_DATASET_VERSION,
        "dataset_type": "behavioral_session",
        "record_count": len(sessions),
        "class_distribution": class_counts,
        "scenario_distribution": dict(sorted(scenario_counts.items())),
        "family_distribution": dict(sorted(family_counts.items())),
        "feature_schema": FEATURE_SCHEMA,
        "sha256": hasher.hexdigest(),
        "csv_path": str(dest_path),
    }

    return manifest


def read_csv_dataset(path: str | Path) -> list[dict[str, Any]]:
    """Read behavioural sessions from CSV."""
    records: list[dict[str, Any]] = []
    expected_fields = set(
        ["session_id", "scenario", "family", "label"] + FEATURE_NAMES
    )

    with Path(path).open("r", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for line_no, row in enumerate(reader, start=2):
            missing = expected_fields - set(row.keys())
            if missing:
                raise ValueError(
                    f"Line {line_no} missing expected fields: {sorted(missing)}"
                )

            parsed: dict[str, Any] = {
                "session_id": row["session_id"],
                "scenario": row["scenario"],
                "family": row["family"],
                "label": int(row["label"]),
                "requests_per_window": int(row["requests_per_window"]),
                "distinct_objects_count": int(row["distinct_objects_count"]),
                "requests_per_minute": float(row["requests_per_minute"]),
                "repeated_target_count": int(row["repeated_target_count"]),
                "recent_denials_count": int(row["recent_denials_count"]),
                "cross_owner_attempts_count": int(row["cross_owner_attempts_count"]),
                "nested_relationship_count": int(row["nested_relationship_count"]),
                "max_query_depth": int(row["max_query_depth"]),
                "enumeration_score": float(row["enumeration_score"]),
                "request_burst_rate": float(row["request_burst_rate"]),
            }
            records.append(parsed)

    return records
