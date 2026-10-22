"""
Dual-layer ablation experiment.

Runs the same BOLA attacks with each Layer 1 / Layer 2 combination switched on or
off and records which layer stopped each attack, or whether it leaked. Uses a
temporary database, so the development shield.db is never touched.

    python -m scripts.run_layer_ablation

Writes results/layer_ablation/results.json (served by GET /api/v1/security/layer-ablation).
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi.testclient import TestClient

from app.config import settings
from app.core.security import create_access_token
from app.security.layers import set_layers

ATTACKER_ID = 101          # balanilavan
VICTIM_RESOURCE = 102      # owned by kapilesh (102)
SHARED_CHILD = 204         # kapilesh's document inside balanilavan's folder 201
OUTPUT = os.path.join(PROJECT_ROOT, "results", "layer_ablation", "results.json")

RESOURCE_FIELDS = "id name ownerId"

SCENARIOS = {
    "direct": {"query": f"{{ resource(id: {VICTIM_RESOURCE}) {{ {RESOURCE_FIELDS} }} }}"},
    "nested": {"query": f"{{ user(id: {ATTACKER_ID}) {{ id resource(id: {VICTIM_RESOURCE}) {{ {RESOURCE_FIELDS} }} }} }}"},
    "inline_fragment": {"query": f"{{ ... on Query {{ resource(id: {VICTIM_RESOURCE}) {{ {RESOURCE_FIELDS} }} }} }}"},
    "relationship": {"query": f"{{ resource(id: 201) {{ id children {{ {RESOURCE_FIELDS} }} }} }}"},
    "batch": [
        {"query": f"{{ resource(id: {ATTACKER_ID}) {{ {RESOURCE_FIELDS} }} }}"},
        {"query": f"{{ resource(id: {VICTIM_RESOURCE}) {{ {RESOURCE_FIELDS} }} }}"},
    ],
    "mutation_update": {"query": f'mutation {{ updateResource(id: {VICTIM_RESOURCE}, name: "ablation-overwrite") {{ id name }} }}'},
}

CONFIGURATIONS = [
    {"layer1": True, "layer2": True},
    {"layer1": True, "layer2": False},
    {"layer1": False, "layer2": True},
    {"layer1": False, "layer2": False},
]


def _foreign_objects(payload) -> list:
    """Every returned object that carries an ownerId other than the attacker's."""
    found = []
    if isinstance(payload, dict):
        if "ownerId" in payload and payload["ownerId"] != ATTACKER_ID:
            found.append(payload)
        for value in payload.values():
            found.extend(_foreign_objects(value))
    elif isinstance(payload, list):
        for item in payload:
            found.extend(_foreign_objects(item))
    return found


def _victim_name(db_file: str) -> str:
    conn = sqlite3.connect(db_file)
    try:
        return conn.execute("SELECT name FROM objects WHERE id = ?", (VICTIM_RESOURCE,)).fetchone()[0]
    finally:
        conn.close()


def _run_scenario(client, headers, name, body, db_file) -> str:
    """Return 'L1' or 'L2' for the layer that stopped the attack, or 'LEAKED'."""
    before = _victim_name(db_file) if name.startswith("mutation") else None
    response = client.post("/graphql", json=body, headers=headers)
    if response.status_code == 403:
        return "L1"
    if name.startswith("mutation"):
        return "LEAKED" if _victim_name(db_file) != before else "L2"
    return "LEAKED" if _foreign_objects(response.json()) else "L2"


def run() -> dict:
    from app.seed import add_shared_folder_scenario, seed_database

    original_url = settings.DATABASE_URL
    tmp_dir = tempfile.mkdtemp(prefix="shield-ablation-")
    db_file = os.path.join(tmp_dir, "ablation.db")
    settings.DATABASE_URL = f"sqlite:///{db_file}"
    try:
        from app.main import app

        client = TestClient(app)
        headers = {"Authorization": f"Bearer {create_access_token(user_id=ATTACKER_ID, role='user')}"}
        results = []
        for config in CONFIGURATIONS:
            set_layers(config["layer1"], config["layer2"])
            outcomes = {}
            for name, body in SCENARIOS.items():
                seed_database()
                add_shared_folder_scenario()
                outcomes[name] = _run_scenario(client, headers, name, body, db_file)
            results.append({
                **config,
                "outcomes": outcomes,
                "leaked": sum(outcome == "LEAKED" for outcome in outcomes.values()),
            })
    finally:
        set_layers(True, True)
        settings.DATABASE_URL = original_url

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "attacker_user_id": ATTACKER_ID,
        "scenarios": list(SCENARIOS),
        "configurations": results,
    }


def main() -> None:
    # Blocked mutations are expected here; skip Strawberry's per-error tracebacks.
    logging.getLogger("strawberry.execution").setLevel(logging.CRITICAL)
    report = run()
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    width = max(len(name) for name in report["scenarios"])
    print(f"{'scenario':<{width}}  " + "  ".join(
        f"L1={'on ' if c['layer1'] else 'off'} L2={'on ' if c['layer2'] else 'off'}" for c in report["configurations"]))
    for name in report["scenarios"]:
        print(f"{name:<{width}}  " + "  ".join(f"{c['outcomes'][name]:<13}" for c in report["configurations"]))
    print(f"\nWrote {OUTPUT}")


if __name__ == "__main__":
    main()
