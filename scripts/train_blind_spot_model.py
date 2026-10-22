"""
Train the Layer 1 blind-spot predictor from the gateway's own cross-layer evidence.

1. Builds a temporary database with folders whose children have mixed owners.
2. Generates varied GraphQL requests (literals, variables, variable defaults,
   aliases, directives, fragments, relationships, batches, mutations) sent by
   different callers.
3. Sends each through the protected endpoint with both layers on. Layer 2 writes
   an audit row (layer='L2') only for owned objects Layer 1 never evaluated, so
   the label is 1 when a request Layer 1 allowed produced such a row: a Layer 1
   coverage gap. The subset where Layer 2 also denied the object
   (L1_BLIND_SPOT_CAUGHT_BY_L2) is tracked as the attacks. No labels are written
   by hand.
4. Trains XGBoost on pre-execution query features only, over the requests Layer 1
   allowed (the ones that execute), and compares it with the hand-written rule for
   Layer 1's documented blind spot (relationship traversal), on a random test split
   and on a held-out query family never seen in training.

    python -m scripts.train_blind_spot_model                 # trains and saves the model
    python -m scripts.train_blind_spot_model --discovery     # analysis only, saved separately

Writes app/models/blind_spot_xgboost.json and app/models/blind_spot_metrics.json
(or app/models/blind_spot_discovery.json with --discovery), and the labelled
dataset to results/blind_spot/.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import random
import sqlite3
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import numpy as np
from fastapi.testclient import TestClient
from sklearn.metrics import average_precision_score, confusion_matrix, precision_recall_fscore_support
from xgboost import XGBClassifier

from app.config import settings
from app.core.security import create_access_token
from app.security import blind_spot_model
from app.security.layers import EVENT_L1_BLIND_SPOT, set_layers
from app.security.query_features import FEATURE_NAMES, combine_features, extract_features

HELD_OUT_FAMILY = "relationship_in_fragment"
DATASET_DIR = os.path.join(PROJECT_ROOT, "results", "blind_spot")

# Extra objects on top of app.seed: folders with mixed-owner children and a nested chain.
#   (id, object_type, owner_id, name, parent_id)
WORLD_OBJECTS = [
    (204, "document", 102, "Kapilesh's Shared Draft", 201),
    (301, "folder", 102, "Kapilesh's Team Folder", None),
    (302, "document", 102, "Team Plan", 301),
    (303, "document", 103, "Sakthivel's Contribution", 301),
    (401, "folder", 103, "Sakthivel's Archive", None),
    (402, "document", 103, "Archive A", 401),
    (403, "document", 103, "Archive B", 401),
    (501, "folder", 101, "Balanilavan's Workspace", None),
    (502, "folder", 101, "Workspace Inbox", 501),
    (503, "document", 102, "Kapilesh's Upload", 502),
    (504, "document", 101, "Inbox Note", 502),
    (601, "folder", 102, "Kapilesh's Reports", None),
    (602, "document", 102, "Report Q1", 601),
]
USERS = [101, 102, 103]
ADMIN = 104


def build_world() -> dict:
    from app.seed import seed_database

    seed_database()
    conn = sqlite3.connect(settings.DATABASE_URL.replace("sqlite:///", ""))
    conn.executemany(
        "INSERT OR REPLACE INTO objects (id, object_type, owner_id, name, parent_id) VALUES (?, ?, ?, ?, ?)",
        WORLD_OBJECTS,
    )
    conn.commit()
    rows = conn.execute("SELECT id, object_type, owner_id FROM objects").fetchall()
    conn.close()
    return {
        "owner": {row[0]: row[2] for row in rows},
        "folders": [row[0] for row in rows if row[1] == "folder"],
        "documents": [row[0] for row in rows if row[1] == "document"],
    }


# ------------------------------------------------------------------ request generator

FIELDS = ["id", "name", "ownerId", "objectType", "parentId"]


def _fields(rng) -> str:
    return " ".join(rng.sample(FIELDS, rng.randint(1, 3)))


def _children(rng, depth: int) -> str:
    inner = _fields(rng)
    for _ in range(depth):
        inner = f"id children {{ {inner} }}"
    return inner


def _target(rng, world, caller: int, pool: str) -> int:
    """Pick an object from the pool; about half the time one the caller does not own."""
    candidates = world[pool]
    own = [i for i in candidates if world["owner"][i] == caller]
    foreign = [i for i in candidates if world["owner"][i] != caller]
    choices = foreign if (not own or rng.random() < 0.5) and foreign else own
    return rng.choice(choices)


def generate_request(rng, world, caller: int) -> tuple[str, object]:
    family = rng.choice([
        "direct_literal", "direct_variable", "variable_default", "alias", "directive",
        "named_fragment", "inline_fragment", "nested_user_lookup", "user_resources",
        "relationship", "relationship_in_fragment", "batch", "mutation", "mutation_variable_default",
    ])
    doc = _target(rng, world, caller, "documents")
    folder = _target(rng, world, caller, "folders")
    fields = _fields(rng)

    if family == "direct_literal":
        body = {"query": f"{{ resource(id: {doc}) {{ {fields} }} }}"}
    elif family == "direct_variable":
        body = {"query": f"query($r: Int!) {{ resource(id: $r) {{ {fields} }} }}", "variables": {"r": doc}}
    elif family == "variable_default":
        body = {"query": f"query($r: Int = {doc}) {{ resource(id: $r) {{ {fields} }} }}"}
    elif family == "alias":
        body = {"query": f"{{ item: resource(id: {doc}) {{ {fields} }} }}"}
    elif family == "directive":
        body = {"query": f"{{ resource(id: {doc}) @include(if: true) {{ {fields} }} }}"}
    elif family == "named_fragment":
        body = {"query": f"query {{ ...F }} fragment F on Query {{ resource(id: {doc}) {{ {fields} }} }}"}
    elif family == "inline_fragment":
        body = {"query": f"{{ ... on Query {{ resource(id: {doc}) {{ {fields} }} }} }}"}
    elif family == "nested_user_lookup":
        body = {"query": f"{{ user(id: {caller}) {{ id resource(id: {doc}) {{ {fields} }} }} }}"}
    elif family == "user_resources":
        body = {"query": f"{{ user(id: {caller}) {{ id resources {{ {fields} }} }} }}"}
    elif family == "relationship":
        body = {"query": f"{{ resource(id: {folder}) {{ {_children(rng, rng.randint(1, 2))} }} }}"}
    elif family == "relationship_in_fragment":
        body = {"query": f"{{ resource(id: {folder}) {{ ...Kids }} }} fragment Kids on ResourceType {{ {_children(rng, rng.randint(1, 2))} }}"}
    elif family == "batch":
        own_doc = rng.choice([i for i in world["documents"] if world["owner"][i] == caller] or world["documents"])
        second = rng.choice([
            f"{{ resource(id: {doc}) {{ {fields} }} }}",
            f"{{ resource(id: {folder}) {{ {_children(rng, 1)} }} }}",
        ])
        body = [{"query": f"{{ resource(id: {own_doc}) {{ id }} }}"}, {"query": second}]
    elif family == "mutation":
        body = {"query": f'mutation {{ updateResource(id: {doc}, name: "renamed") {{ id }} }}'}
    else:  # mutation_variable_default
        body = {"query": f'mutation($r: Int = {doc}) {{ updateResource(id: $r, name: "renamed") {{ id }} }}'}
    return family, body


def request_features(body, caller_is_admin: bool) -> dict[str, int]:
    operations = body if isinstance(body, list) else [body]
    return combine_features([
        extract_features(op["query"], op.get("variables"), batch_size=len(operations), caller_is_admin=caller_is_admin)
        for op in operations
    ])


def _evidence_counts(db_file: str) -> tuple[int, int]:
    """(Layer 2 audit rows, blind-spot denial events) recorded so far."""
    conn = sqlite3.connect(db_file)
    try:
        layer2_rows = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE layer = 'L2'").fetchone()[0]
        denials = conn.execute("SELECT COUNT(*) FROM layer_events WHERE event = ?", (EVENT_L1_BLIND_SPOT,)).fetchone()[0]
        return layer2_rows, denials
    finally:
        conn.close()


def build_dataset(count: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    db_file = settings.DATABASE_URL.replace("sqlite:///", "")
    world = build_world()
    from app.main import app

    client = TestClient(app)
    tokens = {uid: create_access_token(user_id=uid, role="user") for uid in USERS}
    tokens[ADMIN] = create_access_token(user_id=ADMIN, role="admin")

    rows = []
    for _ in range(count):
        caller = ADMIN if rng.random() < 0.1 else rng.choice(USERS)
        family, body = generate_request(rng, world, caller)
        layer2_before, denials_before = _evidence_counts(db_file)
        response = client.post("/graphql", json=body, headers={"Authorization": f"Bearer {tokens[caller]}"})
        layer2_after, denials_after = _evidence_counts(db_file)
        rows.append({
            "family": family,
            "caller": caller,
            "l1_allowed": int(response.status_code != 403),
            "label": int(layer2_after > layer2_before),
            "attack": int(denials_after > denials_before),
            **request_features(body, caller_is_admin=caller == ADMIN),
        })
    return rows


# ------------------------------------------------------------------ evaluation

def _metrics(y_true, y_pred, y_score=None) -> dict:
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    result = {
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4),
        "false_positive_rate": round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    if y_score is not None and len(set(y_true)) > 1:
        result["pr_auc_average_precision"] = round(float(average_precision_score(y_true, y_score)), 4)
    return result


def _matrix(rows) -> tuple[np.ndarray, np.ndarray]:
    return (np.array([[row[name] for name in FEATURE_NAMES] for row in rows], dtype=float),
            np.array([row["label"] for row in rows]))


def evaluate(rows: list[dict], seed: int) -> tuple[XGBClassifier, dict]:
    """Train and evaluate on the requests Layer 1 allowed (the ones that execute)."""
    rng = random.Random(seed)
    rows = [row for row in rows if row["l1_allowed"]]
    held_out = [row for row in rows if row["family"] == HELD_OUT_FAMILY]
    rest = [row for row in rows if row["family"] != HELD_OUT_FAMILY]
    rng.shuffle(rest)
    split = int(len(rest) * 0.75)
    train, test = rest[:split], rest[split:]

    x_train, y_train = _matrix(train)
    model = XGBClassifier(n_estimators=120, max_depth=4, learning_rate=0.1, eval_metric="logloss", random_state=seed)
    model.fit(x_train, y_train)

    evaluation = {}
    for name, subset in (("random_test", test), ("held_out_family", held_out)):
        x, y = _matrix(subset)
        scores = model.predict_proba(x)[:, 1]
        predicted = (scores >= blind_spot_model.DECISION_THRESHOLD).astype(int)
        rule = [blind_spot_model.rule_baseline(row) for row in subset]
        attacks = [i for i, row in enumerate(subset) if row["attack"]]

        def attack_recall(predictions):
            return round(sum(int(predictions[i]) for i in attacks) / len(attacks), 4) if attacks else None

        evaluation[name] = {
            "rows": len(subset),
            "positives": int(y.sum()),
            "attacks": len(attacks),
            "xgboost": {**_metrics(y, predicted, scores), "attack_recall": attack_recall(predicted)},
            "rule_baseline": {**_metrics(y, rule, rule), "attack_recall": attack_recall(rule)},
        }

    # Global importance: mean |SHAP contribution| over every row.
    import xgboost as xgb

    x_all, _ = _matrix(rows)
    contribs = model.get_booster().predict(xgb.DMatrix(x_all, feature_names=FEATURE_NAMES), pred_contribs=True)[:, :-1]
    importance = sorted(
        ({"feature": name, "mean_abs_shap": round(float(np.abs(contribs[:, i]).mean()), 4)} for i, name in enumerate(FEATURE_NAMES)),
        key=lambda item: item["mean_abs_shap"], reverse=True,
    )
    return model, {"splits": {"train_rows": len(train), **{k: v["rows"] for k, v in evaluation.items()}},
                   "evaluation": evaluation, "feature_importance": importance}


def family_rates(rows: list[dict]) -> list[dict]:
    """Per query family: coverage gaps and attacks among the requests Layer 1 allowed."""
    allowed, gaps, attacks, rule_misses = Counter(), Counter(), Counter(), Counter()
    for row in rows:
        if not row["l1_allowed"]:
            continue
        allowed[row["family"]] += 1
        gaps[row["family"]] += row["label"]
        attacks[row["family"]] += row["attack"]
        rule_misses[row["family"]] += int(row["label"] == 1 and blind_spot_model.rule_baseline(row) == 0)
    return sorted(
        ({"family": f, "l1_allowed": allowed[f], "coverage_gaps": gaps[f], "attacks_caught_by_l2": attacks[f],
          "coverage_gap_rate": round(gaps[f] / allowed[f], 4), "gaps_missed_by_rule": rule_misses[f]}
         for f in allowed),
        key=lambda item: item["coverage_gap_rate"], reverse=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--count", type=int, default=4000)
    parser.add_argument("--seed", type=int, default=20261022)
    parser.add_argument("--discovery", action="store_true",
                        help="Analyse the current Layer 1 without replacing the deployed model.")
    args = parser.parse_args()
    logging.getLogger("strawberry.execution").setLevel(logging.CRITICAL)

    original_url = settings.DATABASE_URL
    db_file = os.path.join(tempfile.mkdtemp(prefix="shield-blindspot-"), "blindspot.db")
    settings.DATABASE_URL = f"sqlite:///{db_file}"
    set_layers(True, True)
    try:
        rows = build_dataset(args.count, args.seed)
    finally:
        settings.DATABASE_URL = original_url

    model, results = evaluate(rows, args.seed)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run": "discovery" if args.discovery else "deployed",
        "seed": args.seed,
        "requests": len(rows),
        "l1_blocked_requests": sum(1 - row["l1_allowed"] for row in rows),
        "coverage_gap_requests": sum(row["label"] for row in rows if row["l1_allowed"]),
        "blind_spot_attacks": sum(row["attack"] for row in rows),
        "label_source": ("Layer 2 audit rows (layer='L2'), written only for owned objects Layer 1 never "
                         f"evaluated; attacks are {EVENT_L1_BLIND_SPOT} events. No hand labelling."),
        "held_out_family": HELD_OUT_FAMILY,
        "feature_names": FEATURE_NAMES,
        "rule_baseline": "relationship_field_count > 0 (Layer 1's documented blind spot)",
        **results,
        "family_coverage": family_rates(rows),
    }

    os.makedirs(DATASET_DIR, exist_ok=True)
    tag = "discovery" if args.discovery else "deployed"
    with open(os.path.join(DATASET_DIR, f"dataset_{tag}.csv"), "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    os.makedirs(blind_spot_model.MODEL_DIR, exist_ok=True)
    if args.discovery:
        blind_spot_model.DISCOVERY_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    else:
        model.save_model(str(blind_spot_model.MODEL_PATH))
        blind_spot_model.METRICS_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"{report['requests']} requests ({report['run']} run): {report['l1_blocked_requests']} blocked by Layer 1, "
          f"{report['coverage_gap_requests']} coverage gaps, {report['blind_spot_attacks']} attacks caught only by Layer 2")
    for split, values in results["evaluation"].items():
        x, r = values["xgboost"], values["rule_baseline"]
        print(f"  {split:16} rows={values['rows']:5} gaps={values['positives']:4} attacks={values['attacks']:3}  "
              f"xgboost F1={x['f1_score']:.3f} attack-recall={x['attack_recall']}  |  "
              f"rule F1={r['f1_score']:.3f} attack-recall={r['attack_recall']}")
    print("  top features:", ", ".join(f"{i['feature']}={i['mean_abs_shap']}" for i in results["feature_importance"][:5]))
    print("  coverage gaps by family (Layer 1 allowed):")
    for item in report["family_coverage"]:
        if item["coverage_gaps"]:
            print(f"    {item['family']:26} gaps {item['coverage_gaps']:4}/{item['l1_allowed']:<4} "
                  f"attacks {item['attacks_caught_by_l2']:4}  missed by rule: {item['gaps_missed_by_rule']}")


if __name__ == "__main__":
    main()
