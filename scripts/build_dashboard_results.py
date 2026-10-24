"""
Copy the research results the dashboard shows into app/models/research_results.json.

The raw outputs under results/ are git-ignored, so a fresh clone would show
empty panels. This keeps a small, tracked summary of:
  - the layer ablation        (scripts/run_layer_ablation.py)
  - the graphql-shield comparison (scripts/run_tool_comparison.py)
  - latency with and without connection pooling (scripts/run_latency_benchmark.py)
  - the multi-seed blind-spot evaluation (scripts/run_blind_spot_seeds.py)

    python -m scripts.build_dashboard_results
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESULTS = os.path.join(ROOT, "results")
OUTPUT = os.path.join(ROOT, "app", "models", "research_results.json")


def _load(*parts):
    path = os.path.join(RESULTS, *parts)
    try:
        with open(path, encoding="utf-8") as file:
            return json.load(file)
    except (OSError, ValueError):
        return None


def ablation():
    data = _load("layer_ablation", "results.json")
    if not data:
        return None
    return {
        "generated_at": data["generated_at"],
        "scenarios": data["scenarios"],
        "configurations": [
            {"layer1": c["layer1"], "layer2": c["layer2"], "outcomes": c["outcomes"], "leaked": c["leaked"]}
            for c in data["configurations"]
        ],
    }


def comparison():
    data = _load("tool_comparison", "results.json")
    if not data:
        return None
    keep = ("attacks_leaked", "attacks", "leaked_scenarios", "benign_failed", "benign", "failed_benign_scenarios")
    return {
        "generated_at": data["generated_at"],
        "configuration_size": data["configuration_size"],
        "systems": {
            system: {variant: {k: summary[k] for k in keep} for variant, summary in variants.items()}
            for system, variants in data["systems"].items()
        },
    }


def latency():
    pooled, no_pool = _load("latency", "latency_pooled.json"), _load("latency", "latency_no_pool.json")
    if not pooled or not no_pool:
        return None
    rows = []
    for request, configs in pooled["results"].items():
        rows.append({
            "request": request,
            "both_layers_pooled": configs["both_layers"],
            "both_layers_no_pool_mean_ms": no_pool["results"][request]["both_layers"]["mean_ms"],
            "insecure_pooled_mean_ms": configs["insecure"]["mean_ms"],
        })
    return {"generated_at": pooled["generated_at"], "method": pooled["method"], "rows": rows}


def seeds():
    data = _load("blind_spot", "seeds.json")
    if not data:
        return None
    return {
        "generated_at": data["generated_at"],
        "seeds": data["seeds"],
        "requests_per_seed": data["requests_per_seed"],
        "summary": {k: {"mean": v["mean"], "std": v["std"]} for k, v in data["summary"].items()},
        "top_feature_by_seed": data["top_feature_by_seed"],
    }


def main() -> None:
    report = {
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ablation": ablation(),
        "tool_comparison": comparison(),
        "latency": latency(),
        "blind_spot_seeds": seeds(),
    }
    with open(OUTPUT, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=1)
    present = [k for k, v in report.items() if k != "built_at" and v]
    print(f"Wrote {OUTPUT} with: {', '.join(present) or 'nothing (run the experiments first)'}")


if __name__ == "__main__":
    main()
