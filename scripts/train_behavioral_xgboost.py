from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
from collections import Counter
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from xgboost import XGBClassifier

from app.benchmarks.behavioral_dataset import (
    FEATURE_NAMES,
    read_csv_dataset,
)


def rule_behavioral_score(case: dict[str, Any]) -> float:
    """
    Deterministic rule-based behavioural anomaly score (0.0 to 1.0).

    Evaluates observable server-side indicators without ML inference:
    1. Repeated authorization denials (>= 5 denials: +0.40, >= 2: +0.20)
    2. Cross-owner access attempts (>= 10 attempts: +0.35, >= 3: +0.20)
    3. Systematic object-ID enumeration (score >= 0.70: +0.30, >= 0.40: +0.15)
    4. Volumetric bursting on distinct objects (burst >= 10 and distinct ratio >= 0.6: +0.20)
    5. Deep query tree combined with denials/cross-owner (depth >= 4 and (denials > 0 or cross > 0): +0.15)

    Score is capped at 1.0.
    """
    score = 0.0
    recent_denials = case.get("recent_denials_count", 0)
    cross_owner = case.get("cross_owner_attempts_count", 0)
    enum_score = case.get("enumeration_score", 0.0)
    burst_rate = case.get("request_burst_rate", 0.0)
    requests_window = case.get("requests_per_window", 1)
    distinct_objs = case.get("distinct_objects_count", 0)
    query_depth = case.get("max_query_depth", 1)

    # Rule 1: Authorization denials
    if recent_denials >= 5:
        score += 0.40
    elif recent_denials >= 2:
        score += 0.20

    # Rule 2: Cross-owner access attempts
    if cross_owner >= 10:
        score += 0.35
    elif cross_owner >= 3:
        score += 0.20

    # Rule 3: Object ID enumeration
    if enum_score >= 0.70:
        score += 0.30
    elif enum_score >= 0.40:
        score += 0.15

    # Rule 4: Suspicious burst on distinct objects
    distinct_ratio = distinct_objs / max(requests_window, 1)
    if burst_rate >= 10.0 and distinct_ratio >= 0.60:
        score += 0.20

    # Rule 5: Deep query probing with denials/cross-owner
    if query_depth >= 4 and (recent_denials > 0 or cross_owner > 0):
        score += 0.15

    return min(round(score, 4), 1.0)


def metrics(
    y_true: list[int],
    predictions: list[int],
    scores: list[float],
) -> dict[str, Any]:
    """Calculate standard binary classification evaluation metrics."""
    tn, fp, fn, tp = confusion_matrix(
        y_true,
        predictions,
        labels=[0, 1],
    ).ravel()

    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0

    return {
        "accuracy": round(float(accuracy_score(y_true, predictions)), 4),
        "precision": round(
            float(precision_score(y_true, predictions, zero_division=0)), 4
        ),
        "recall": round(
            float(recall_score(y_true, predictions, zero_division=0)), 4
        ),
        "f1_score": round(
            float(f1_score(y_true, predictions, zero_division=0)), 4
        ),
        "pr_auc_average_precision": round(
            float(average_precision_score(y_true, scores)), 4
        ),
        "false_positive_rate": round(float(false_positive_rate), 4),
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train and evaluate behavioural XGBoost model for GraphQL BOLA detection."
    )
    parser.add_argument(
        "--dataset",
        default="results/research_benchmark/behavioral_sessions.csv",
        help="Path to behavioural session CSV dataset.",
    )
    parser.add_argument(
        "--output-dir",
        default="results/research_benchmark/behavioral_xgboost",
        help="Directory to save model artifact and evaluation report.",
    )
    parser.add_argument(
        "--held-out-family",
        default="nested_relational",
        choices=["nested_relational", "volumetric", "targeted_denial", "standard_steady"],
        help="Scenario family held out from training set for zero-template evaluation.",
    )
    parser.add_argument(
        "--decision-threshold",
        type=float,
        default=0.5,
        help="Probability threshold for XGBoost classification (default: 0.5).",
    )
    parser.add_argument(
        "--baseline-threshold",
        type=float,
        default=0.45,
        help="Score threshold for deterministic rule baseline (default: 0.45).",
    )
    args = parser.parse_args()

    sessions = read_csv_dataset(args.dataset)
    if not sessions:
        raise SystemExit(f"Dataset {args.dataset} is empty. Generate it before training.")

    # Split by scenario family to avoid mixing generator templates
    train_sessions = [s for s in sessions if s["family"] != args.held_out_family]
    test_sessions = [s for s in sessions if s["family"] == args.held_out_family]

    if not train_sessions or not test_sessions:
        raise SystemExit(
            f"Invalid split: train={len(train_sessions)}, test={len(test_sessions)}."
        )

    y_train = [s["label"] for s in train_sessions]
    y_test = [s["label"] for s in test_sessions]

    if len(set(y_train)) < 2 or len(set(y_test)) < 2:
        raise SystemExit(
            "Both training and held-out test sets must contain both normal and suspicious labels."
        )

    # Feature matrices strictly contain FEATURE_NAMES (no metadata, scenario, or labels)
    x_train = pd.DataFrame(
        [{key: s[key] for key in FEATURE_NAMES} for s in train_sessions],
        columns=FEATURE_NAMES,
    )
    x_test = pd.DataFrame(
        [{key: key_val for key, key_val in s.items() if key in FEATURE_NAMES} for s in test_sessions],
        columns=FEATURE_NAMES,
    )

    model = XGBClassifier(
        objective="binary:logistic",
        eval_metric="logloss",
        n_estimators=120,
        max_depth=3,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.9,
        random_state=20261011,
        n_jobs=1,
        tree_method="hist",
    )

    model.fit(x_train, y_train)

    # Benchmark inference latency
    start = time.perf_counter()
    repeats = 100
    for _ in range(repeats):
        probabilities = model.predict_proba(x_test)[:, 1]
    elapsed = time.perf_counter() - start

    predictions = (probabilities >= args.decision_threshold).astype(int).tolist()

    # Rule baseline scores and predictions
    baseline_scores = [rule_behavioral_score(s) for s in test_sessions]
    baseline_predictions = [
        int(score >= args.baseline_threshold) for score in baseline_scores
    ]

    y_true = [int(val) for val in y_test]

    results = {
        "dataset": str(Path(args.dataset)),
        "total_sessions": len(sessions),
        "training_sessions": len(train_sessions),
        "held_out_sessions": len(test_sessions),
        "held_out_family": args.held_out_family,
        "split_methodology": (
            f"Family-isolated partition holding out '{args.held_out_family}'. "
            "Neither normal nor suspicious scenario templates in the held-out family "
            "were seen during model training."
        ),
        "class_counts": {
            "all": dict(Counter(str(s["label"]) for s in sessions)),
            "training": dict(Counter(str(val) for val in y_train)),
            "held_out": dict(Counter(str(val) for val in y_test)),
        },
        "feature_names": FEATURE_NAMES,
        "xgboost": metrics(
            y_true,
            predictions,
            probabilities.tolist(),
        ),
        "rule_baseline": metrics(
            y_true,
            baseline_predictions,
            baseline_scores,
        ),
        "xgboost_inference_latency": {
            "average_ms_per_batch": round(
                (elapsed / repeats) * 1000, 4
            ),
            "average_ms_per_session": round(
                (elapsed / repeats / len(test_sessions)) * 1000, 6
            ),
            "batch_size": len(test_sessions),
            "repetitions": repeats,
        },
        "note": (
            "Phase 4.1 behavioural session experiment. Features aggregate server-observable "
            "request statistics over 15-minute windows without raw IDs or direct ownership flags. "
            "The ML model is an offline classifier and does NOT override PolicyEngine decisions."
        ),
    }

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    model_path = output_dir / "behavioral_xgboost_model.json"
    model.save_model(str(model_path))
    results["model_path"] = str(model_path)

    metrics_path = output_dir / "evaluation_metrics.json"
    metrics_path.write_text(
        json.dumps(results, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(results, indent=2))
    print(f"\nSaved model: {model_path}")
    print(f"Saved metrics: {metrics_path}")


if __name__ == "__main__":
    main()
