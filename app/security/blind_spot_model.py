"""
Layer 1 blind-spot predictor.

Predicts, before execution and from query structure alone, whether a request will
reach an owned object that Layer 1 never evaluated, i.e. one only Layer 2 can stop.

Training labels are produced by the gateway itself: every L1_BLIND_SPOT_CAUGHT_BY_L2
event is a disagreement between the two layers, so the model learns Layer 1's gaps
without hand labelling (scripts/train_blind_spot_model.py).

Advisory only: the score is recorded and explained, and never changes an
authorization decision.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .query_features import FEATURE_NAMES, combine_features, extract_features

logger = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).resolve().parents[1] / "models"
MODEL_PATH = MODEL_DIR / "blind_spot_xgboost.json"
METRICS_PATH = MODEL_DIR / "blind_spot_metrics.json"
DISCOVERY_PATH = MODEL_DIR / "blind_spot_discovery.json"

DECISION_THRESHOLD = 0.5

_model = None
_model_error: str | None = None


def rule_baseline(features: dict[str, int]) -> int:
    """The hand-written rule for Layer 1's documented blind spot: relationship
    traversal (e.g. `children`)."""
    return int(features["relationship_field_count"] > 0)


def load_model(force_reload: bool = False):
    """Load the trained model once; returns None when unavailable."""
    global _model, _model_error
    if _model is not None and not force_reload:
        return _model
    try:
        from xgboost import XGBClassifier

        model = XGBClassifier()
        model.load_model(str(MODEL_PATH))
        _model, _model_error = model, None
    except Exception as exc:  # missing file or optional ML packages not installed
        _model, _model_error = None, str(exc)
    return _model


def model_status() -> dict[str, Any]:
    load_model()
    return {"loaded": _model is not None, "path": str(MODEL_PATH), "error": _model_error}


def predict(features: dict[str, int], *, explain: bool = False) -> dict[str, Any]:
    """Score one feature vector with the model (when available) and the rule."""
    result: dict[str, Any] = {
        "features": features,
        "rule_prediction": rule_baseline(features),
        "probability": None,
        "prediction": None,
    }
    model = load_model()
    if model is None:
        return result

    import numpy as np

    row = np.array([[features[name] for name in FEATURE_NAMES]], dtype=float)
    probability = float(model.predict_proba(row)[0, 1])
    result["probability"] = round(probability, 4)
    result["prediction"] = int(probability >= DECISION_THRESHOLD)
    if explain:
        result["contributions"] = explain_row(model, row)
    return result


def explain_row(model, row) -> list[dict[str, Any]]:
    """Per-feature SHAP contributions (log-odds) for one row, largest first."""
    import xgboost as xgb

    contributions = model.get_booster().predict(
        xgb.DMatrix(row, feature_names=FEATURE_NAMES), pred_contribs=True
    )[0]
    ranked = sorted(
        ({"feature": name, "value": int(row[0][i]), "contribution": round(float(contributions[i]), 4)}
         for i, name in enumerate(FEATURE_NAMES)),
        key=lambda item: abs(item["contribution"]),
        reverse=True,
    )
    return [item for item in ranked if item["contribution"] != 0][:5]


def score_request(operations: list[dict], *, caller_is_admin: bool, explain: bool = False) -> dict[str, Any] | None:
    """Score a request (one operation, or a batch) before execution."""
    batch_size = len(operations)
    per_operation = []
    for operation in operations:
        features = extract_features(
            operation.get("query", ""),
            operation.get("variables"),
            batch_size=batch_size,
            caller_is_admin=caller_is_admin,
        )
        if features is None:
            return None
        per_operation.append(features)
    if not per_operation:
        return None
    return predict(combine_features(per_operation), explain=explain)


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def summary() -> dict[str, Any]:
    """Model status, evaluation metrics and the discovery run, for the dashboard."""
    return {
        "model_status": model_status(),
        "metrics": _read_json(METRICS_PATH),
        "discovery": _read_json(DISCOVERY_PATH),
    }
