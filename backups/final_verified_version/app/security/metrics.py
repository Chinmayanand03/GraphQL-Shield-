from __future__ import annotations

import math
from typing import Iterable


def classification_metrics(
    actual: Iterable[bool],
    predicted: Iterable[bool],
) -> dict:
    actual = list(actual)
    predicted = list(predicted)

    if len(actual) != len(predicted):
        raise ValueError(
            "actual and predicted must have the same length"
        )

    if not actual:
        raise ValueError(
            "metrics require at least one observation"
        )

    tp = sum(a and p for a, p in zip(actual, predicted))
    fp = sum((not a) and p for a, p in zip(actual, predicted))
    tn = sum((not a) and (not p) for a, p in zip(actual, predicted))
    fn = sum(a and (not p) for a, p in zip(actual, predicted))

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    accuracy = (tp + tn) / len(actual)
    fpr = fp / (fp + tn) if fp + tn else 0.0
    fnr = fn / (fn + tp) if fn + tp else 0.0

    return {
        "sample_count": len(actual),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": round(accuracy, 6),
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "specificity": round(specificity, 6),
        "false_positive_rate": round(fpr, 6),
        "false_negative_rate": round(fnr, 6),
    }


def latency_summary(latencies_ms: Iterable[float]) -> dict:
    values = sorted(float(value) for value in latencies_ms)

    if not values:
        return {
            "count": 0,
            "mean_ms": 0.0,
            "median_ms": 0.0,
            "p95_ms": 0.0,
            "p99_ms": 0.0,
            "min_ms": 0.0,
            "max_ms": 0.0,
        }

    def percentile(p: float) -> float:
        rank = max(1, math.ceil(p * len(values)))
        return values[rank - 1]

    return {
        "count": len(values),
        "mean_ms": round(sum(values) / len(values), 4),
        "median_ms": round(percentile(0.50), 4),
        "p95_ms": round(percentile(0.95), 4),
        "p99_ms": round(percentile(0.99), 4),
        "min_ms": round(values[0], 4),
        "max_ms": round(values[-1], 4),
    }
