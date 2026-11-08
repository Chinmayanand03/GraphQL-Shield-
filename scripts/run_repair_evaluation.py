"""
Evaluation of self-repairing configuration.

For each realistic configuration mistake in the two applications (a wrong ID
argument name, a missing mutation target, an owned type left out), the same
seeded traffic runs three times, each on a fresh database:

  reference  the correct configuration
  faulty     the mistake; Layer 2's evidence is collected and repairs are proposed
  repaired   the mistake plus the verified repairs, applied one round at a time

A run's outcome is the list of (status, body) of every response. The fault's impact
is the number of responses that differ from the reference (leaks, or legitimate
requests refused); the configuration counts as restored when the repaired run
matches the reference exactly. The unmodified configurations are controls: any
repair proposed for them is a false repair.

    python -m scripts.run_repair_evaluation
    python -m scripts.run_repair_evaluation --requests 300 --seeds 1

Writes evaluation/repair_evaluation.json.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import random
import sys
import tempfile
from datetime import datetime, timezone

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi.testclient import TestClient

from app.config import settings
from app.core.security import create_access_token

OUTPUT = os.path.join(PROJECT_ROOT, "evaluation", "repair_evaluation.json")
SEEDS = [20261109, 20261110, 20261111]
USERS = [101, 102, 103]
ADMIN = 104
MAX_ROUNDS = 3
DISPOSABLE_DOCS = range(500, 560)
DISPOSABLE_PRESCRIPTIONS = range(900, 940)


# ------------------------------------------------------------------ fresh worlds

def fresh_database() -> None:
    from app.clinic.data import init_clinic
    from app.database import close_pooled_connections, get_db_connection
    from app.seed import add_shared_folder_scenario, seed_database

    close_pooled_connections()
    settings.DATABASE_URL = f"sqlite:///{os.path.join(tempfile.mkdtemp(prefix='shield-repair-'), 'repair.db')}"
    seed_database()
    add_shared_folder_scenario()
    init_clinic(reset=True)
    conn = get_db_connection()
    rng = random.Random(7)
    conn.executemany("INSERT INTO objects (id, object_type, owner_id, name, parent_id) VALUES (?, 'document', ?, ?, NULL)",
                     [(i, rng.choice(USERS), f"disposable {i}") for i in DISPOSABLE_DOCS])
    conn.executemany("INSERT INTO clinic_prescriptions (id, record_id, owner_id, drug) VALUES (?, ?, ?, ?)",
                     [(i, rng.choice([11, 21, 31]), rng.choice(USERS), f"drug {i}") for i in DISPOSABLE_PRESCRIPTIONS])
    conn.commit()
    conn.close()


def demo_world() -> dict:
    from app.database import get_db_connection

    conn = get_db_connection()
    rows = conn.execute("SELECT id, owner_id, object_type FROM objects").fetchall()
    conn.close()
    owner = {r["id"]: r["owner_id"] for r in rows}
    folders = {u: [r["id"] for r in rows if r["object_type"] == "folder" and r["owner_id"] == u] for u in USERS}
    docs = [r["id"] for r in rows if r["id"] not in DISPOSABLE_DOCS]
    return {"owner": owner, "folders": folders, "docs": docs, "disposable": list(DISPOSABLE_DOCS)}


def clinic_world() -> dict:
    from app.clinic.data import PATIENTS, RECORDS
    from app.database import get_db_connection

    conn = get_db_connection()
    prescriptions = conn.execute("SELECT id, owner_id FROM clinic_prescriptions").fetchall()
    conn.close()
    return {"patients": {p[0]: p[2] for p in PATIENTS}, "records": {r[0]: r[2] for r in RECORDS},
            "prescriptions": {p["id"]: p["owner_id"] for p in prescriptions}}


# ---------------------------------------------------------------------- traffic

def demo_traffic(rng: random.Random, count: int) -> list[tuple[int, str, dict]]:
    world = demo_world()
    requests = []
    for _ in range(count):
        caller = ADMIN if rng.random() < 0.05 else rng.choice(USERS)
        doc = rng.choice(world["docs"])
        kind = rng.choice(["direct", "variable", "user", "nested", "relationship", "update", "delete"])
        if kind == "direct":
            body = {"query": f"{{ resource(id: {doc}) {{ id name }} }}"}
        elif kind == "variable":
            body = {"query": "query($r: Int!) { resource(id: $r) { id name } }", "variables": {"r": doc}}
        elif kind == "user":
            body = {"query": f"{{ user(id: {rng.choice(USERS)}) {{ id username }} }}"}
        elif kind == "nested":
            body = {"query": f"{{ user(id: {caller if caller in USERS else 101}) {{ id resource(id: {doc}) {{ id name }} }} }}"}
        elif kind == "relationship":
            folder = (world["folders"].get(caller) or [201])[0]
            body = {"query": f"{{ resource(id: {folder}) {{ id children {{ id name }} }} }}"}
        elif kind == "update":
            body = {"query": f'mutation {{ updateResource(id: {doc}, name: "renamed {doc}") {{ id name }} }}'}
        else:
            target = rng.choice(world["disposable"])
            body = {"query": f"mutation {{ deleteResource(id: {target}) }}"}
        requests.append((caller, "/graphql", body))
    return requests


def clinic_traffic(rng: random.Random, count: int) -> list[tuple[int, str, dict]]:
    from app.clinic.data import to_global_id

    world = clinic_world()
    requests = []
    disposable = [p for p in world["prescriptions"] if p in DISPOSABLE_PRESCRIPTIONS]
    for _ in range(count):
        caller = ADMIN if rng.random() < 0.05 else rng.choice(USERS)
        kind = rng.choice(["patient", "record", "prescription", "chart", "mine", "update", "create", "delete"])
        patient = to_global_id("Patient", rng.choice(list(world["patients"])))
        record = to_global_id("Record", rng.choice(list(world["records"])))
        if kind == "patient":
            body = {"query": f'{{ patient(id: "{patient}") {{ id name }} }}'}
        elif kind == "record":
            body = {"query": f'{{ record(id: "{record}") {{ id diagnosis }} }}'}
        elif kind == "prescription":
            pid = to_global_id("Prescription", rng.choice([111, 112, 211, 311]))
            body = {"query": f'{{ prescription(id: "{pid}") {{ id drug }} }}'}
        elif kind == "chart":
            body = {"query": f'{{ patient(id: "{patient}") {{ id records {{ id diagnosis }} }} }}'}
        elif kind == "mine":
            body = {"query": "{ myPatients { id name records { id } } }"}
        elif kind == "update":
            body = {"query": f'mutation {{ updateRecord(id: "{record}", diagnosis: "updated") {{ id }} }}'}
        elif kind == "create":
            body = {"query": f'mutation {{ createRecord(patientId: "{patient}", diagnosis: "new") {{ diagnosis }} }}'}
        else:
            pid = to_global_id("Prescription", rng.choice(disposable))
            body = {"query": f'mutation {{ deletePrescription(id: "{pid}") }}'}
        requests.append((caller, "/clinic/graphql", body))
    return requests


TRAFFIC = {"demo": demo_traffic, "clinic": clinic_traffic}

# Wrong repairs a careless engineer (or a naive heuristic) might propose. Verification
# must refuse every one: a non-ID argument read as an ID, or the wrong owned type.
DECOYS = {
    "demo": {
        "wrong_id_argument_name": [{"kind": "add_id_argument", "payload": {"argument": "name"}}],
        "missing_delete_target": [{"kind": "add_mutation_target", "payload": {"mutation": "deleteResource", "argument": "id", "key": "User"}}],
        "missing_resource_type": [{"kind": "add_owned_type", "payload": {"type": "ResourceType", "key": "User"}}],
        "missing_user_type": [{"kind": "add_owned_type", "payload": {"type": "UserType", "key": "Resource"}}],
    },
    "clinic": {
        "missing_id_argument": [{"kind": "add_id_argument", "payload": {"argument": "diagnosis"}}],
        "missing_create_record_target": [{"kind": "add_mutation_target", "payload": {"mutation": "createRecord", "argument": "patientId", "key": "Record"}},
                                         {"kind": "add_mutation_target", "payload": {"mutation": "createRecord", "argument": "diagnosis", "key": "Patient"}}],
        "missing_delete_prescription_target": [{"kind": "add_mutation_target", "payload": {"mutation": "deletePrescription", "argument": "id", "key": "Record"}}],
        "missing_patient_type": [{"kind": "add_owned_type", "payload": {"type": "Patient", "key": "Record"}}],
        "missing_record_type": [{"kind": "add_owned_type", "payload": {"type": "Record", "key": "Prescription"}}],
        "missing_prescription_type": [{"kind": "add_owned_type", "payload": {"type": "Prescription", "key": "Patient"}}],
    },
}


def _role(user: int) -> str:
    return "admin" if user == ADMIN else "user"


def run(client: TestClient, requests: list) -> list:
    tokens = {u: create_access_token(user_id=u, role=_role(u)) for u in [*USERS, ADMIN]}
    outcomes = []
    for caller, path, body in requests:
        response = client.post(path, json=body, headers={"Authorization": f"Bearer {tokens[caller]}"})
        outcomes.append([response.status_code, response.json()])
    return outcomes


def differences(a: list, b: list) -> int:
    return sum(x != y for x, y in zip(a, b))


# ---------------------------------------------------------------- one experiment

def experiment(app_name: str, fault: str | None, seed: int, count: int) -> dict:
    from app.main import app
    from app.security import repair
    from app.security.shield_config import REGISTRY, default_config

    default_config()
    client = TestClient(app)
    config = REGISTRY[app_name]

    def traffic():
        return TRAFFIC[app_name](random.Random(seed), count)

    fresh_database()
    repair.restore(app_name)
    reference = run(client, traffic())

    fresh_database()
    expected = repair.inject_fault(app_name, fault) if fault else None
    faulty = run(client, traffic())
    impact = differences(reference, faulty)
    analysis = repair.analyse(config)
    proposed = [r for r in analysis["repairs"]]
    verified = [r for r in proposed if r["verification"]["verified"]]
    first = verified[0] if verified else None
    expected_id = repair.repair_id(app_name, expected) if expected else None
    rank = next((i + 1 for i, r in enumerate(verified) if r["id"] == expected_id), None)
    decoys = DECOYS.get(app_name, {}).get(fault, []) if fault else []
    decoys_rejected = sum(not repair.verify(config, decoy)["verified"] for decoy in decoys)

    rounds, applied, remaining = 0, [], impact
    while fault and verified and remaining and rounds < MAX_ROUNDS:
        top = verified[0]
        repair._apply_in_place(config, top)
        applied.append(top["title"])
        rounds += 1
        fresh_database()
        repair.clear_evidence(app_name)
        repaired = run(client, traffic())
        remaining = differences(reference, repaired)
        analysis_after = repair.analyse(config)
        verified = [r for r in analysis_after["repairs"] if r["verification"]["verified"]]

    repair.restore(app_name)
    return {
        "app": app_name, "fault": fault or "none", "seed": seed, "requests": count,
        "expected_repair": repair.describe(expected) if expected else None,
        "fault_impact": impact,
        "proposed": len(proposed), "verified": len([r for r in proposed if r["verification"]["verified"]]),
        "first_verified": first["title"] if first else None,
        "first_is_expected": bool(first and first["id"] == expected_id),
        "expected_rank_among_verified": rank,
        "decoys": len(decoys), "decoys_rejected": decoys_rejected,
        "rounds": rounds, "applied": applied, "differences_after_repair": remaining if fault else 0,
        "restored": bool(fault) and remaining == 0,
        "explanations": [e["kind"] for e in analysis["explanations"]],
        "first_verification": first["verification"] if first else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=400)
    parser.add_argument("--seeds", type=int, default=len(SEEDS))
    args = parser.parse_args()
    logging.disable(logging.WARNING)
    settings.ENABLE_INSECURE_BASELINE = True
    original_url = settings.DATABASE_URL

    from app.security import repair

    rows = []
    try:
        for seed in SEEDS[: args.seeds]:
            for app_name in ("demo", "clinic"):
                for fault in [None, *repair.FAULTS[app_name]]:
                    row = experiment(app_name, fault, seed, args.requests)
                    rows.append(row)
                    print(f"{seed} {app_name:6} {row['fault']:36} impact {row['fault_impact']:3}  proposed {row['proposed']}"
                          f"  verified {row['verified']}  first ok {row['first_is_expected']!s:5}  rounds {row['rounds']}"
                          f"  after {row['differences_after_repair']}  decoys rejected {row['decoys_rejected']}/{row['decoys']}", flush=True)
    finally:
        settings.DATABASE_URL = original_url
        logging.disable(logging.NOTSET)

    faults = [r for r in rows if r["fault"] != "none"]
    controls = [r for r in rows if r["fault"] == "none"]
    summary = {
        "fault_runs": len(faults),
        "faults_with_impact": sum(r["fault_impact"] > 0 for r in faults),
        "detected": sum(r["proposed"] > 0 for r in faults),
        "first_verified_repair_is_the_expected_one": sum(r["first_is_expected"] for r in faults),
        "restored": sum(r["restored"] for r in faults),
        "restored_in_one_round": sum(r["restored"] and r["rounds"] == 1 for r in faults),
        "control_runs": len(controls),
        "false_repairs_on_controls": sum(r["proposed"] for r in controls),
        "false_blocks_in_verified_repairs": sum((r["first_verification"] or {}).get("false_blocks", 0) for r in faults),
        "decoy_repairs": sum(r["decoys"] for r in faults),
        "decoy_repairs_rejected": sum(r["decoys_rejected"] for r in faults),
    }
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "seeds": SEEDS[: args.seeds],
              "requests_per_run": args.requests, "summary": summary, "runs": rows}
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
