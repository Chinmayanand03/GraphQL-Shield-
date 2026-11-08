"""
Timing channel: can a caller tell a foreign object from a missing one by how long
the denial takes?

The responses are already identical (tests/test_leak_channels.py). This measures the
time. For each pair, requests for a foreign object and for a missing one are sent in
random order, interleaved, so drift on the machine affects both equally. A difference
is reported as the median gap with a bootstrap 95% confidence interval, and tested
with Mann-Whitney U.

    python -m scripts.run_timing_channel
    python -m scripts.run_timing_channel --without-missing-check   # the channel before the fix

Writes evaluation/timing_channel.json (or timing_channel_before_fix.json).
"""
from __future__ import annotations

import argparse
import json
import logging
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
from scipy.stats import mannwhitneyu

from app.config import settings
from app.core.security import create_access_token
from app.security.layers import set_layers

OUTPUT = os.path.join(PROJECT_ROOT, "evaluation", "timing_channel.json")
OUTPUT_BEFORE_FIX = os.path.join(PROJECT_ROOT, "evaluation", "timing_channel_before_fix.json")
PAIRS = 1500
WARMUP = 50
BOOTSTRAP = 2000
FOREIGN, MISSING = 102, 99999

# name -> (layer1, layer2, query template taking the object ID)
SCENARIOS = {
    "read_layer1": (True, True, "{{ resource(id: {id}) {{ id name }} }}"),
    "update_layer1": (True, True, 'mutation {{ updateResource(id: {id}, name: "x") {{ id }} }}'),
    "read_layer2_only": (False, True, "{{ resource(id: {id}) {{ id name }} }}"),
    "update_layer2_only": (False, True, 'mutation {{ updateResource(id: {id}, name: "x") {{ id }} }}'),
}


def median_gap_ci(foreign: list[float], missing: list[float], rng: random.Random) -> list[float]:
    gaps = []
    for _ in range(BOOTSTRAP):
        a = [rng.choice(foreign) for _ in foreign]
        b = [rng.choice(missing) for _ in missing]
        gaps.append(statistics.median(a) - statistics.median(b))
    gaps.sort()
    return [round(gaps[int(0.025 * BOOTSTRAP)], 4), round(gaps[int(0.975 * BOOTSTRAP)], 4)]


def measure(client: TestClient, headers: dict, template: str, rng: random.Random) -> dict:
    bodies = {kind: {"query": template.format(id=object_id)} for kind, object_id in (("foreign", FOREIGN), ("missing", MISSING))}
    for _ in range(WARMUP):
        for body in bodies.values():
            client.post("/graphql", json=body, headers=headers)
    times = {"foreign": [], "missing": []}
    statuses = {"foreign": set(), "missing": set()}
    for _ in range(PAIRS):
        order = ["foreign", "missing"]
        rng.shuffle(order)
        for kind in order:
            start = time.perf_counter()
            response = client.post("/graphql", json=bodies[kind], headers=headers)
            times[kind].append((time.perf_counter() - start) * 1000)
            statuses[kind].add(response.status_code)
    foreign, missing = times["foreign"], times["missing"]
    p_value = mannwhitneyu(foreign, missing, alternative="two-sided").pvalue
    gap = statistics.median(foreign) - statistics.median(missing)
    return {
        "foreign_median_ms": round(statistics.median(foreign), 4),
        "missing_median_ms": round(statistics.median(missing), 4),
        "median_gap_ms": round(gap, 4),
        "median_gap_ci95_ms": median_gap_ci(foreign, missing, rng),
        "relative_gap_pct": round(gap / statistics.median(missing) * 100, 2),
        "mann_whitney_p": float(f"{p_value:.3g}"),
        "status_codes": {kind: sorted(codes) for kind, codes in statuses.items()},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--without-missing-check", action="store_true",
                        help="Skip Layer 2's check of lookups that found nothing, as before the fix.")
    args = parser.parse_args()
    output = OUTPUT
    if args.without_missing_check:
        from app.security.runtime_object_guard import RuntimeObjectAuthorizationExtension

        RuntimeObjectAuthorizationExtension._missing_target = lambda self, info, arguments: None
        output = OUTPUT_BEFORE_FIX
    logging.getLogger("strawberry.execution").setLevel(logging.CRITICAL)
    from app.seed import seed_database

    original_url = settings.DATABASE_URL
    settings.DATABASE_URL = f"sqlite:///{os.path.join(tempfile.mkdtemp(prefix='shield-timing-'), 'timing.db')}"
    rng = random.Random(20261108)
    results = {}
    try:
        seed_database()
        from app.main import app

        client = TestClient(app)
        headers = {"Authorization": f"Bearer {create_access_token(user_id=101, role='user')}"}
        for name, (layer1, layer2, template) in SCENARIOS.items():
            set_layers(layer1, layer2)
            results[name] = measure(client, headers, template, rng)
            r = results[name]
            print(f"{name:20s} foreign {r['foreign_median_ms']:.3f} ms  missing {r['missing_median_ms']:.3f} ms  "
                  f"gap {r['median_gap_ms']:+.3f} ms {r['median_gap_ci95_ms']}  p={r['mann_whitney_p']}", flush=True)
    finally:
        set_layers(True, True)
        settings.DATABASE_URL = original_url

    report = {"generated_at": datetime.now(timezone.utc).isoformat(),
              "method": f"in-process TestClient; {WARMUP} warm-up, {PAIRS} interleaved pairs in random order; "
                        f"median gap with {BOOTSTRAP}-sample bootstrap 95% CI; two-sided Mann-Whitney U",
              "missing_lookup_checked": not args.without_missing_check,
              "foreign_id": FOREIGN, "missing_id": MISSING, "results": results}
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)


if __name__ == "__main__":
    main()
