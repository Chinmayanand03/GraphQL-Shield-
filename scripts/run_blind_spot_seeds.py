"""
Repeat the blind-spot predictor evaluation over several random seeds.

Each seed generates a new request set, labels it through the gateway, trains a
fresh model and evaluates it (scripts/train_blind_spot_model.py). Reports mean
and standard deviation across seeds. The deployed model is not changed.

    python -m scripts.run_blind_spot_seeds [--seeds 5] [--count 2000]

Writes results/blind_spot/seeds.json.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import statistics
import sys
import tempfile
from datetime import datetime, timezone

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.config import settings
from app.security.layers import set_layers
from scripts.train_blind_spot_model import DATASET_DIR, build_dataset, evaluate

METRICS = [
    ("random_test", "xgboost", "f1_score"),
    ("random_test", "xgboost", "attack_recall"),
    ("random_test", "rule_baseline", "f1_score"),
    ("random_test", "rule_baseline", "attack_recall"),
    ("held_out_family", "xgboost", "f1_score"),
    ("held_out_family", "rule_baseline", "f1_score"),
]


def mean_std(values: list[float]) -> dict:
    values = [v for v in values if v is not None]
    return {
        "mean": round(statistics.fmean(values), 4) if values else None,
        "std": round(statistics.stdev(values), 4) if len(values) > 1 else 0.0,
        "values": values,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--count", type=int, default=2000)
    parser.add_argument("--first-seed", type=int, default=1001)
    args = parser.parse_args()
    logging.getLogger("strawberry.execution").setLevel(logging.CRITICAL)

    runs = []
    original_url = settings.DATABASE_URL
    try:
        for seed in range(args.first_seed, args.first_seed + args.seeds):
            settings.DATABASE_URL = f"sqlite:///{os.path.join(tempfile.mkdtemp(prefix='shield-seed-'), 'seed.db')}"
            set_layers(True, True)
            rows = build_dataset(args.count, seed)
            _, results = evaluate(rows, seed)
            allowed = [r for r in rows if r["l1_allowed"]]
            runs.append({
                "seed": seed,
                "requests": len(rows),
                "coverage_gap_rate": round(sum(r["label"] for r in allowed) / len(allowed), 4),
                "attacks_caught_only_by_layer2": sum(r["attack"] for r in rows),
                "evaluation": results["evaluation"],
                "top_feature": results["feature_importance"][0]["feature"],
            })
            print(f"seed {seed}: gaps {runs[-1]['coverage_gap_rate']:.3f}, "
                  f"attacks only L2 {runs[-1]['attacks_caught_only_by_layer2']}, "
                  f"XGB F1 {results['evaluation']['random_test']['xgboost']['f1_score']:.3f}, "
                  f"rule F1 {results['evaluation']['random_test']['rule_baseline']['f1_score']:.3f}, "
                  f"top {runs[-1]['top_feature']}")
    finally:
        settings.DATABASE_URL = original_url

    summary = {f"{split}.{model}.{metric}": mean_std([r["evaluation"][split][model][metric] for r in runs])
               for split, model, metric in METRICS}
    summary["coverage_gap_rate"] = mean_std([r["coverage_gap_rate"] for r in runs])
    summary["attacks_caught_only_by_layer2"] = mean_std([r["attacks_caught_only_by_layer2"] for r in runs])
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "seeds": args.seeds,
        "requests_per_seed": args.count,
        "summary": summary,
        "top_feature_by_seed": [r["top_feature"] for r in runs],
        "runs": runs,
    }
    os.makedirs(DATASET_DIR, exist_ok=True)
    output = os.path.join(DATASET_DIR, "seeds.json")
    with open(output, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)
    print("\nmean ± std across seeds:")
    for name, value in summary.items():
        print(f"  {name:36} {value['mean']} ± {value['std']}")
    print(f"Wrote {output}")


if __name__ == "__main__":
    main()
