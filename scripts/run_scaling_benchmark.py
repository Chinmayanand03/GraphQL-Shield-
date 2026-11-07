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
REPEATS = 5
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


def measure(client: TestClient, path: str, headers: dict) -> dict:
    body = {"query": f"{{ resource(id: {FOLDER}) {{ id children {{ id name }} }} }}"}
    for _ in range(WARMUP):
        client.post(path, json=body, headers=headers)
    means = []
    for _ in range(REPEATS):
        start = time.perf_counter()
        for _ in range(REQUESTS):
            response = client.post(path, json=body, headers=headers)
            if response.status_code != 200:
                raise RuntimeError(f"{path} returned {response.status_code}: {response.text[:300]}")
        means.append((time.perf_counter() - start) * 1000 / REQUESTS)
    mean = statistics.fmean(means)
    half_width = T_95[REPEATS - 1] * statistics.stdev(means) / REPEATS ** 0.5
    return {"mean_ms": round(mean, 3), "ci95_ms": [round(mean - half_width, 3), round(mean + half_width, 3)]}


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
        for size in SIZES:
            fill_folder(db_file, size)
            row = {"unprotected": measure(client, "/graphql-insecure", headers)}
            runtime_object_guard.BATCH_LIST_CHECKS = True
            row["batched"] = measure(client, "/graphql", headers)
            runtime_object_guard.BATCH_LIST_CHECKS = False
            row["one_by_one"] = measure(client, "/graphql", headers)
            runtime_object_guard.BATCH_LIST_CHECKS = True
            results[str(size)] = row
            print(size, {name: value["mean_ms"] for name, value in row.items()}, flush=True)
    finally:
        settings.DATABASE_URL = original_url

    report = {"generated_at": datetime.now(timezone.utc).isoformat(),
              "method": f"in-process TestClient; {WARMUP} warm-up, {REPEATS} repeats x {REQUESTS} requests; 95% CI across repeats",
              "foreign_share": 0.1, "results": results}
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)


if __name__ == "__main__":
    main()
