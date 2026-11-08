"""
How protection cost grows with the number of objects a request returns.

A folder holds N children, one in ten owned by someone else. The same relationship
query runs on the unprotected endpoint and on the protected one, with Layer 2 checking
the list in one query and one audit transaction (batched) and one item at a time.

    python -m scripts.run_scaling_benchmark

Writes evaluation/latency_scaling.json.
"""
from __future__ import annotations

import json
import logging
import os
import random
import sqlite3
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
from app.security import runtime_object_guard
from app.security.layers import set_layers
from scripts.run_latency_benchmark import T_95

OUTPUT = os.path.join(PROJECT_ROOT, "evaluation", "latency_scaling.json")
SIZES = [1, 10, 50, 200]
REPEATS = 8
REQUESTS = 40
WARMUP = 10
FOLDER = 9000


def fill_folder(db_file: str, size: int) -> None:
    conn = sqlite3.connect(db_file)
    conn.execute("DELETE FROM objects WHERE parent_id = ?", (FOLDER,))
    conn.execute("INSERT OR IGNORE INTO objects (id, object_type, owner_id, name, parent_id) VALUES (?, 'folder', 101, 'Bench', NULL)",
                 (FOLDER,))
    conn.executemany("INSERT INTO objects (id, object_type, owner_id, name, parent_id) VALUES (?, 'document', ?, ?, ?)",
                     [(FOLDER + 1 + i, 102 if i % 10 == 9 else 101, f"child {i}", FOLDER) for i in range(size)])
    conn.commit()
    conn.close()


# name -> (endpoint, batch the list check)
VARIANTS = {"unprotected": ("/graphql-insecure", True), "batched": ("/graphql", True), "one_by_one": ("/graphql", False)}


def time_block(client: TestClient, path: str, headers: dict) -> float:
    body = {"query": f"{{ resource(id: {FOLDER}) {{ id children {{ id name }} }} }}"}
    for _ in range(WARMUP):
        client.post(path, json=body, headers=headers)
    start = time.perf_counter()
    for _ in range(REQUESTS):
        response = client.post(path, json=body, headers=headers)
        if response.status_code != 200:
            raise RuntimeError(f"{path} returned {response.status_code}: {response.text[:300]}")
    return (time.perf_counter() - start) * 1000 / REQUESTS


def measure_size(client: TestClient, headers: dict, rng: random.Random) -> dict:
    """Every repeat times each variant once, in random order, so drift on the
    machine affects all three alike."""
    means = {name: [] for name in VARIANTS}
    for _ in range(REPEATS):
        order = list(VARIANTS)
        rng.shuffle(order)
        for name in order:
            path, batched = VARIANTS[name]
            runtime_object_guard.BATCH_LIST_CHECKS = batched
            means[name].append(time_block(client, path, headers))
    runtime_object_guard.BATCH_LIST_CHECKS = True
    row = {}
    for name, values in means.items():
        mean = statistics.fmean(values)
        half_width = T_95[REPEATS - 1] * statistics.stdev(values) / REPEATS ** 0.5
        row[name] = {"mean_ms": round(mean, 3), "ci95_ms": [round(mean - half_width, 3), round(mean + half_width, 3)]}
    return row


def main() -> None:
    logging.getLogger("strawberry.execution").setLevel(logging.CRITICAL)
    from app.seed import seed_database

    original_url = settings.DATABASE_URL
    db_file = os.path.join(tempfile.mkdtemp(prefix="shield-scaling-"), "scaling.db")
    settings.DATABASE_URL = f"sqlite:///{db_file}"
    settings.ENABLE_INSECURE_BASELINE = True
    results = {}
    try:
        seed_database()
        from app.main import app

        client = TestClient(app)
        headers = {"Authorization": f"Bearer {create_access_token(user_id=101, role='user')}"}
        set_layers(True, True)
        rng = random.Random(20261108)
        for size in SIZES:
            fill_folder(db_file, size)
            row = measure_size(client, headers, rng)
            results[str(size)] = row
            print(size, {name: value["mean_ms"] for name, value in row.items()}, flush=True)
    finally:
        settings.DATABASE_URL = original_url

    report = {"generated_at": datetime.now(timezone.utc).isoformat(),
              "method": (f"in-process TestClient; {REPEATS} repeats, each timing {REQUESTS} requests per variant in random "
                         f"order after {WARMUP} untimed ones; 95% CI across repeats"),
              "foreign_share": 0.1, "results": results}
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)


if __name__ == "__main__":
    main()
