"""
Latency of each enforcement configuration, with repeated runs and 95% CIs.

In-process (FastAPI TestClient, no network), on a temporary database. For each
request type and configuration: warm-up, then REPEATS runs of REQUESTS requests.
Reports per-request mean, p50, p95, p99, and a 95% confidence interval of the
mean across repeats (Student's t), plus overhead against the insecure baseline.

    python -m scripts.run_latency_benchmark [--label NAME] [--no-pool]

Writes results/latency/latency_<label>.json.
"""
from __future__ import annotations

import argparse
import json
import logging
import math
import os
import random
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi.testclient import TestClient

from app.config import settings
from app.core.security import create_access_token
from app.security.layers import set_layers

OUTPUT_DIR = os.path.join(PROJECT_ROOT, "results", "latency")
REQUESTS = 100
REPEATS = 10
WARMUP = 30
# Requests sent after switching configuration and before timing a block.
BLOCK_WARMUP = 10
# Two-sided 95% Student's t critical values by degrees of freedom.
T_95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262}

REQUEST_TYPES = {
    "own_lookup": {"query": "{ resource(id: 101) { id name ownerId } }"},
    "own_relationship": {"query": "{ resource(id: 201) { id children { id name ownerId } } }"},
    "own_update": {"query": 'mutation { updateResource(id: 101, name: "bench") { id } }'},
}
CONFIGURATIONS = {
    "insecure": ("/graphql-insecure", (True, True)),
    "layer1_only": ("/graphql", (True, False)),
    "layer2_only": ("/graphql", (False, True)),
    "both_layers": ("/graphql", (True, True)),
}


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(fraction * len(ordered)) - 1))
    return ordered[index]


def summarize(runs: list[list[float]]) -> dict:
    samples = [value for run in runs for value in run]
    run_means = [statistics.fmean(run) for run in runs]
    mean = statistics.fmean(run_means)
    half_width = T_95[len(runs) - 1] * statistics.stdev(run_means) / math.sqrt(len(runs)) if len(runs) > 1 else 0.0
    return {
        "mean_ms": round(mean, 3),
        "ci95_ms": [round(mean - half_width, 3), round(mean + half_width, 3)],
        "p50_ms": round(percentile(samples, 0.50), 3),
        "p95_ms": round(percentile(samples, 0.95), 3),
        "p99_ms": round(percentile(samples, 0.99), 3),
        "requests": len(samples),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", default="current")
    parser.add_argument("--no-pool", action="store_true",
                        help="Disable connection pooling (a new SQLite connection per query, as before pooling).")
    args = parser.parse_args()
    if args.no_pool:
        from app import database

        database._POOL_MAX_IDLE = 0
    logging.getLogger("strawberry.execution").setLevel(logging.CRITICAL)

    from app.seed import add_shared_folder_scenario, seed_database

    original_url = settings.DATABASE_URL
    settings.DATABASE_URL = f"sqlite:///{os.path.join(tempfile.mkdtemp(prefix='shield-latency-'), 'latency.db')}"
    settings.ENABLE_INSECURE_BASELINE = True
    results = {}
    try:
        seed_database()
        add_shared_folder_scenario()
        from app.main import app

        client = TestClient(app)
        headers = {"Authorization": f"Bearer {create_access_token(user_id=101, role='user')}"}
        # Configurations are interleaved: every repeat times one block of each, in a
        # fresh random order, so a machine that speeds up or slows down during the
        # run affects all configurations alike instead of biasing the comparison.
        order_rng = random.Random(20261108)
        for request_name, body in REQUEST_TYPES.items():
            for config_name, (path, layers) in CONFIGURATIONS.items():
                set_layers(*layers)
                for _ in range(WARMUP):
                    client.post(path, json=body, headers=headers)
            runs = {config_name: [] for config_name in CONFIGURATIONS}
            for _ in range(REPEATS):
                order = list(CONFIGURATIONS)
                order_rng.shuffle(order)
                for config_name in order:
                    path, layers = CONFIGURATIONS[config_name]
                    set_layers(*layers)
                    for _ in range(BLOCK_WARMUP):
                        client.post(path, json=body, headers=headers)
                    timings = []
                    for _ in range(REQUESTS):
                        start = time.perf_counter()
                        response = client.post(path, json=body, headers=headers)
                        timings.append((time.perf_counter() - start) * 1000)
                        assert response.status_code == 200, response.text
                    runs[config_name].append(timings)
            results[request_name] = {config_name: summarize(runs[config_name]) for config_name in CONFIGURATIONS}
            # Paired overhead: within each repeat every configuration was timed next to
            # the insecure baseline, so the per-repeat difference cancels machine drift.
            baseline_means = [statistics.fmean(run) for run in runs["insecure"]]
            for config_name in CONFIGURATIONS:
                diffs = [statistics.fmean(run) - base for run, base in zip(runs[config_name], baseline_means)]
                mean_diff = statistics.fmean(diffs)
                half = T_95[REPEATS - 1] * statistics.stdev(diffs) / math.sqrt(REPEATS)
                results[request_name][config_name]["paired_overhead_ms"] = round(mean_diff, 3)
                results[request_name][config_name]["paired_overhead_ci95_ms"] = [round(mean_diff - half, 3),
                                                                                 round(mean_diff + half, 3)]
            baseline = results[request_name]["insecure"]["mean_ms"]
            for config_name, summary in results[request_name].items():
                summary["overhead_ms"] = round(summary["mean_ms"] - baseline, 3)
                summary["overhead_pct"] = round(100 * (summary["mean_ms"] - baseline) / baseline, 1)
    finally:
        set_layers(True, True)
        settings.DATABASE_URL = original_url

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "label": args.label,
        "connection_pooling": not args.no_pool,
        "method": (f"in-process TestClient; {WARMUP} warm-up, then {REPEATS} repeats, each timing {REQUESTS} requests per "
                   f"configuration in random order after {BLOCK_WARMUP} untimed ones; "
                   f"95% CI of the mean across repeats (t, df={REPEATS - 1})"),
        "results": results,
    }
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output = os.path.join(OUTPUT_DIR, f"latency_{args.label}.json")
    with open(output, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    for request_name, configs in results.items():
        print(f"\n{request_name}")
        for config_name, s in configs.items():
            print(f"  {config_name:12} mean {s['mean_ms']:7.2f} ms  CI95 [{s['ci95_ms'][0]:.2f}, {s['ci95_ms'][1]:.2f}]  "
                  f"p95 {s['p95_ms']:7.2f}  p99 {s['p99_ms']:7.2f}  overhead {s['overhead_pct']:+6.1f}%  "
                  f"paired {s['paired_overhead_ms']:+.2f} ms [{s['paired_overhead_ci95_ms'][0]:+.2f}, {s['paired_overhead_ci95_ms'][1]:+.2f}]")
    print(f"\nWrote {output}")


if __name__ == "__main__":
    main()
