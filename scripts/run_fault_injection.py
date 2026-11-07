"""
Fault-injection evaluation of blind-spot discovery.

One discovered bypass is an anecdote. This turns it into a measurement: each fault
below is a realistic bug in Layer 1, patched into its source at load time (the files
on disk never change). Traffic runs through the real gateway with Layer 2 on, and the
question is what each method can recover from the cross-layer evidence alone:

  detection     did the fault leave evidence the relationship blind spot does not explain?
  prediction    does a method flag the affected requests on unseen traffic?
  localisation  does a method's top-ranked feature name the construct that was broken?

Traffic is composed from independent constructs (ID source, wrapper, location, shape)
rather than fixed templates, so a test row is not a copy of a training row.

    python -m scripts.run_fault_injection                      # all faults, all seeds
    python -m scripts.run_fault_injection --analyse            # recompute from raw rows

Writes evaluation/fault_injection.json (tracked) and raw rows to results/fault_injection/.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import random
import statistics
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

RAW_DIR = os.path.join(PROJECT_ROOT, "results", "fault_injection")
OUTPUT = os.path.join(PROJECT_ROOT, "evaluation", "fault_injection.json")
SEEDS = [20261101, 20261102, 20261103, 20261104, 20261105]
CONTROL = "none"

EXTRACTOR = "app/security/object_extractor.py"
ENFORCEMENT = "app/security/enforcement.py"

_FRAGMENT_GUARD = "if frag_name in fragments and frag_name not in expanding:"
_ROOT_LOOP = '''for selection in definition.selection_set.selections:
            visit(selection, root_type, "", True)'''
_NESTED_LOOP = '''for selection in node.selection_set.selections:
                        visit(selection, child_type, path, False)'''
_VARIABLE_VALUE = "value = variables[name] if name in variables else defaults.get(name)"
_FIELD_START = "            if isinstance(node, FieldNode):\n                field_name = node.name.value\n"

# name -> (file, code to find, replacement, features that name the broken construct).
# An empty feature set means the 17 features have no word for this construct, so
# localisation counts as a miss for every method.
FAULTS: dict[str, tuple[str, str, str, set[str]]] = {
    "no_variable_defaults": (EXTRACTOR, _VARIABLE_VALUE, "value = variables.get(name)", {"variable_default_count"}),
    "no_variables": (EXTRACTOR, _VARIABLE_VALUE, "value = None", {"variable_count"}),
    "no_defaults_in_mutations": (EXTRACTOR, _VARIABLE_VALUE,
                                 "value = variables[name] if name in variables else (None if operation == 'mutation' else defaults.get(name))",
                                 {"variable_default_count", "is_mutation"}),
    "no_inline_fragments": (EXTRACTOR, "fragment_type = schema_type(node.type_condition.name.value) if node.type_condition else parent_type\n",
                            "return\n", {"inline_fragment_count"}),
    "no_untyped_inline_fragments": (EXTRACTOR, "fragment_type = schema_type(node.type_condition.name.value) if node.type_condition else parent_type\n",
                                    "if not node.type_condition:\n                    return\n"
                                    "                fragment_type = schema_type(node.type_condition.name.value)\n", {"inline_fragment_count"}),
    "no_fragment_spreads": (EXTRACTOR, _FRAGMENT_GUARD, "if False:", {"fragment_spread_count"}),
    "no_nested_fragment_spreads": (EXTRACTOR, _FRAGMENT_GUARD, "if frag_name in fragments and not expanding:", {"fragment_spread_count"}),
    "root_fragment_spreads_only": (EXTRACTOR, _FRAGMENT_GUARD, "if frag_name in fragments and frag_name not in expanding and is_root:",
                                   {"fragment_spread_count", "nested_id_lookup_count"}),
    "root_fields_only": (EXTRACTOR, _NESTED_LOOP, "pass", {"nested_id_lookup_count", "max_depth"}),
    "first_nested_selection_only": (EXTRACTOR, _NESTED_LOOP,
                                    "for selection in node.selection_set.selections[:1]:\n"
                                    "                        visit(selection, child_type, path, False)",
                                    {"nested_id_lookup_count", "max_depth"}),
    "first_root_field_only": (EXTRACTOR, _ROOT_LOOP,
                              'for selection in definition.selection_set.selections[:1]:\n'
                              '            visit(selection, root_type, "", True)', set()),
    "aliased_fields_skipped": (EXTRACTOR, _FIELD_START, _FIELD_START.replace(
        "                field_name =", "                if node.alias:\n                    return\n                field_name ="),
        {"alias_count"}),
    "directive_fields_skipped": (EXTRACTOR, _FIELD_START, _FIELD_START.replace(
        "                field_name =", "                if node.directives:\n                    return\n                field_name ="),
        {"directive_count"}),
    "mutation_targets_skipped": (EXTRACTOR, "targets = [target] if target else []", "targets = []", {"is_mutation"}),
    "user_type_skipped": (EXTRACTOR, "embedded_key, raw_id = config.decode(raw_value)\n",
                          "if key == 'User':\n                return\n            embedded_key, raw_id = config.decode(raw_value)\n", set()),
    "first_operation_only": (EXTRACTOR, "    for definition in ast.definitions:\n        if not isinstance(definition, OperationDefinitionNode):\n            continue\n        operation = definition.operation.value\n",
                             "    for definition in [d for d in ast.definitions if isinstance(d, OperationDefinitionNode)][:1]:\n        operation = definition.operation.value\n", set()),
    "first_batch_operation_only": (ENFORCEMENT, "for index, operation in enumerate(data):", "for index, operation in enumerate(data[:1]):", {"batch_size"}),
}


def patched_source(path: str, old: str, new: str) -> str:
    with open(os.path.join(PROJECT_ROOT, path), encoding="utf-8") as handle:
        source = handle.read().replace("\r\n", "\n")
    if old not in source:
        raise ValueError(f"Fault no longer matches {path}: {old[:50]!r}")
    return source.replace(old, new, 1)


def inject_fault(name: str) -> None:
    """Rebuild the affected module in place from patched source."""
    from app.security import enforcement, object_extractor, query_features

    if name != CONTROL:
        path, old, new, _ = FAULTS[name]
        module = enforcement if path == ENFORCEMENT else object_extractor
        exec(compile(patched_source(path, old, new), path, "exec"), module.__dict__)
        enforcement.normalize_query = object_extractor.normalize_query
        query_features.normalize_query = object_extractor.normalize_query
    # The deployed predictor is irrelevant here and would slow every request.
    enforcement._predict_blind_spot = lambda *args, **kwargs: None


# ------------------------------------------------------------------ composed traffic

ID_SOURCES = ["literal", "variable", "default"]
WRAPPERS = ["none", "alias", "directive", "inline", "untyped_inline", "named_fragment", "nested_fragment"]
LOCATIONS = ["root", "under_user"]
SHAPES = ["single", "single", "two_roots", "multi_operation", "batch"]


def compose_request(rng: random.Random, world: dict, caller: int) -> tuple[dict, object]:
    """One request from independently chosen constructs. Returns (constructs, body)."""
    from scripts.train_blind_spot_model import _children, _fields, _target

    kind = rng.choice(["read", "read", "read", "mutation"])
    relationship = kind == "read" and rng.random() < 0.3
    id_source = rng.choice(ID_SOURCES)
    wrapper = rng.choice(WRAPPERS)
    location = "root" if kind == "mutation" else rng.choice(LOCATIONS)
    shape = "single" if kind == "mutation" else rng.choice(SHAPES)
    target = _target(rng, world, caller, "folders" if relationship else "documents")
    own = rng.choice([i for i in world["documents"] if world["owner"][i] == caller] or world["documents"])

    argument = target if id_source == "literal" else "$r"
    header, variables = "", None
    if id_source == "variable":
        header, variables = "($r: Int!)", {"r": target}
    elif id_source == "default":
        header = f"($r: Int = {target})"

    alias = "item: " if wrapper == "alias" else ""
    directive = " @include(if: true)" if wrapper == "directive" else ""
    if kind == "mutation":
        field = f'{alias}updateResource(id: {argument}, name: "renamed"){directive} {{ id }}'
    else:
        inner = _children(rng, rng.randint(1, 2)) if relationship else _fields(rng)
        field = f"{alias}resource(id: {argument}){directive} {{ {inner} }}"

    on_type = "Mutation" if kind == "mutation" else ("UserType" if location == "under_user" else "Query")
    fragments = ""
    if wrapper == "inline":
        field = f"... on {on_type} {{ {field} }}"
    elif wrapper == "untyped_inline":
        field = f"... {{ {field} }}"
    elif wrapper == "named_fragment":
        fragments = f" fragment F on {on_type} {{ {field} }}"
        field = "...F"
    elif wrapper == "nested_fragment":
        fragments = f" fragment G on {on_type} {{ ...F }} fragment F on {on_type} {{ {field} }}"
        field = "...G"

    if location == "under_user":
        field = f"user(id: {caller}) {{ id {field} }}"
    if shape == "two_roots":
        field = f"own: resource(id: {own}) {{ id }} {field}"

    own_query = f"{{ resource(id: {own}) {{ id }} }}"
    keyword = "mutation" if kind == "mutation" else "query"
    if shape == "multi_operation":
        document = f"query Own {{ resource(id: {own}) {{ id }} }} {keyword} Main{header} {{ {field} }}{fragments}"
    else:
        document = f"{keyword}{header} {{ {field} }}{fragments}"

    main = {"query": document}
    if variables:
        main["variables"] = variables
    if shape == "multi_operation":
        main["operationName"] = "Main"
    body = [{"query": own_query}, main] if shape == "batch" else main
    constructs = {"kind": kind, "relationship": int(relationship), "id_source": id_source, "wrapper": wrapper,
                  "location": location, "shape": shape}
    return constructs, body


def collect(fault: str, seed: int, count: int, path: str) -> None:
    """Worker process: run one fault's traffic and write the labelled rows."""
    from fastapi.testclient import TestClient

    from app.config import settings
    from app.core.security import create_access_token
    from app.security.layers import set_layers
    from scripts import train_blind_spot_model as trainer

    world = trainer.build_world()
    inject_fault(fault)
    from app.main import app

    set_layers(layer1=True, layer2=True)
    client = TestClient(app)
    tokens = {uid: create_access_token(user_id=uid, role="user") for uid in trainer.USERS}
    tokens[trainer.ADMIN] = create_access_token(user_id=trainer.ADMIN, role="admin")
    db_file = settings.DATABASE_URL.replace("sqlite:///", "")
    rng = random.Random(seed)
    rows = []
    for _ in range(count):
        caller = trainer.ADMIN if rng.random() < 0.1 else rng.choice(trainer.USERS)
        constructs, body = compose_request(rng, world, caller)
        before = trainer._evidence_counts(db_file)
        response = client.post("/graphql", json=body, headers={"Authorization": f"Bearer {tokens[caller]}"})
        after = trainer._evidence_counts(db_file)
        rows.append({
            **constructs,
            "status": response.status_code,
            "l1_allowed": int(response.status_code != 403),
            "label": int(after[0] > before[0]),
            "attack": int(after[1] > before[1]),
            **trainer.request_features(body, caller_is_admin=caller == trainer.ADMIN),
        })
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(rows, handle)


def run_all(count: int, jobs: int) -> None:
    os.makedirs(RAW_DIR, exist_ok=True)

    def one(task: tuple[str, int]) -> None:
        fault, seed = task
        path = os.path.join(RAW_DIR, f"{fault}__{seed}.json")
        if os.path.exists(path):
            return
        # Each run is deterministic for its seed, so a run that fails under load
        # (SQLite busy on a contended disk) can safely start again.
        for attempt in range(1, 4):
            with tempfile.TemporaryDirectory(prefix="fault-", ignore_cleanup_errors=True) as folder:
                env = {**os.environ, "DATABASE_URL": "sqlite:///" + os.path.join(folder, "f.db").replace("\\", "/"),
                       "ENABLE_LAYER_TOGGLE": "true"}
                result = subprocess.run([sys.executable, "-m", "scripts.run_fault_injection", "--worker", fault, str(seed),
                                         "--count", str(count), "--out", path], cwd=PROJECT_ROOT, env=env,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode == 0:
                break
            print(f"retry {fault} {seed} (attempt {attempt} failed)", flush=True)
        else:
            raise RuntimeError(f"{fault} {seed} failed three times")
        print(f"done {fault} {seed}", flush=True)

    tasks = [(fault, seed) for fault in [CONTROL, *FAULTS] for seed in SEEDS]
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        list(pool.map(one, tasks))


# ------------------------------------------------------------------ analysis

# Layer 1's own output: a request where it resolved fewer IDs than the query names.
# These read the answer off Layer 1, so localisation and the "structural" model omit them.
L1_DERIVED = ("l1_resolved_id_count", "unresolved_id_argument_count")


def _matrix(rows, names):
    import numpy as np

    return np.array([[row[name] for name in names] for row in rows], dtype=float), np.array([row["label"] for row in rows])


def _f1(y_true, y_pred) -> float:
    from sklearn.metrics import f1_score

    return float(f1_score(y_true, y_pred, zero_division=0))


def _models(seed: int):
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.tree import DecisionTreeClassifier
    from xgboost import XGBClassifier

    return {
        "decision_tree": DecisionTreeClassifier(max_depth=3, random_state=seed),
        "logistic": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000)),
        "xgboost": XGBClassifier(n_estimators=120, max_depth=4, learning_rate=0.1, eval_metric="logloss",
                                 random_state=seed, n_jobs=1),
    }


def _ranking(model_name: str, model, x, names) -> list[str]:
    import numpy as np

    if model_name == "xgboost":
        import xgboost as xgb

        contribs = model.get_booster().predict(xgb.DMatrix(x, feature_names=list(names)), pred_contribs=True)[:, :-1]
        scores = np.abs(contribs).mean(axis=0)
    elif model_name == "decision_tree":
        scores = model.feature_importances_
    else:
        scores = np.abs(model[-1].coef_[0])
    order = np.argsort(-scores, kind="stable")
    return [names[i] for i in order if scores[i] > 0]


def _lift_ranking(rows, names) -> list[str]:
    """No model: rank features by how much more often gaps occur when they are present."""
    scores = {}
    for name in names:
        present = [row["label"] for row in rows if row[name] > 0]
        absent = [row["label"] for row in rows if row[name] == 0]
        if present and absent:
            scores[name] = sum(present) / len(present) - sum(absent) / len(absent)
    return [name for name, score in sorted(scores.items(), key=lambda item: -item[1]) if score > 0]


def analyse_run(fault: str, seed: int, rows: list[dict]) -> dict:
    from sklearn.model_selection import train_test_split

    from app.security.blind_spot_model import rule_baseline
    from app.security.query_features import FEATURE_NAMES

    allowed = [row for row in rows if row["l1_allowed"]]
    structural = [name for name in FEATURE_NAMES if name not in L1_DERIVED]
    residual = [row for row in allowed if row["label"] and not rule_baseline(row)]
    train, test = train_test_split(allowed, test_size=0.3, random_state=seed)
    y_test = [row["label"] for row in test]

    result = {
        "allowed": len(allowed),
        "errors": sum(1 for row in rows if row["status"] >= 400 and row["status"] != 403),
        "gaps": sum(row["label"] for row in allowed),
        "residual_gaps": len(residual),
        "unexplained_attacks": sum(row["attack"] for row in residual),
        "f1": {
            "relationship_rule": _f1(y_test, [rule_baseline(row) for row in test]),
            "evidence_rule": _f1(y_test, [int(rule_baseline(row) or row["unresolved_id_argument_count"] > 0) for row in test]),
        },
    }
    for name, model in _models(seed).items():
        x_train, y_train = _matrix(train, structural)
        if len(set(y_train)) < 2:
            result["f1"][f"{name}_structural"] = 0.0
            continue
        model.fit(x_train, y_train)
        result["f1"][f"{name}_structural"] = _f1(y_test, model.predict(_matrix(test, structural)[0]))
    x_train, y_train = _matrix(train, FEATURE_NAMES)
    if len(set(y_train)) > 1:
        model = _models(seed)["xgboost"]
        model.fit(x_train, y_train)
        result["f1"]["xgboost_all_features"] = _f1(y_test, model.predict(_matrix(test, FEATURE_NAMES)[0]))

    # Localisation asks what explains the gaps the known blind spot does not.
    unexplained = [row for row in allowed if not rule_baseline(row)]
    rankings = {"lift": _lift_ranking(unexplained, structural)}
    if residual and len(residual) < len(unexplained):
        x, y = _matrix(unexplained, structural)
        for name, model in _models(seed).items():
            model.fit(x, y)
            rankings[name] = _ranking(name, model, x, structural)
    result["rankings"] = {name: ranking[:3] for name, ranking in rankings.items()}
    return result


def summarise(runs: dict) -> dict:
    per_fault, methods = {}, set()
    for fault, by_seed in runs.items():
        values = list(by_seed.values())
        f1 = {}
        for name in values[0]["f1"]:
            scores = [run["f1"][name] for run in values if name in run["f1"]]
            f1[name] = {"mean": round(statistics.mean(scores), 4), "std": round(statistics.pstdev(scores), 4)}
            methods.add(name)
        expected = FAULTS[fault][3] if fault in FAULTS else set()
        hits = {}
        for name in ("lift", "decision_tree", "logistic", "xgboost"):
            ranked = [run["rankings"].get(name, []) for run in values]
            hits[name] = {"top1": sum(bool(r[:1]) and r[0] in expected for r in ranked) / len(ranked),
                          "top3": sum(bool(set(r[:3]) & expected) for r in ranked) / len(ranked)}
        per_fault[fault] = {
            "expected_features": sorted(expected),
            "residual_gaps": round(statistics.mean(run["residual_gaps"] for run in values), 1),
            "unexplained_attacks": round(statistics.mean(run["unexplained_attacks"] for run in values), 1),
            "seeds_with_evidence": sum(run["residual_gaps"] > 0 for run in values),
            "f1": f1,
            "localisation": hits,
            "top_feature_by_seed": [run["rankings"].get("xgboost", [None])[0] if run["rankings"].get("xgboost") else None for run in values],
        }
    faults = [fault for fault in per_fault if fault != CONTROL]
    nameable = [fault for fault in faults if per_fault[fault]["expected_features"]]
    overall = {
        "faults": len(faults),
        "faults_with_a_naming_feature": len(nameable),
        "detected_by_evidence_alone": sum(per_fault[f]["seeds_with_evidence"] == len(SEEDS) for f in faults),
        "mean_f1": {name: round(statistics.mean(per_fault[f]["f1"][name]["mean"] for f in faults if name in per_fault[f]["f1"]), 4)
                    for name in sorted(methods)},
        "localisation_over_all_faults": {
            name: {k: round(statistics.mean(per_fault[f]["localisation"][name][k] for f in faults), 4) for k in ("top1", "top3")}
            for name in ("lift", "decision_tree", "logistic", "xgboost")},
        "localisation_over_nameable_faults": {
            name: {k: round(statistics.mean(per_fault[f]["localisation"][name][k] for f in nameable), 4) for k in ("top1", "top3")}
            for name in ("lift", "decision_tree", "logistic", "xgboost")},
    }
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "seeds": SEEDS, "overall": overall, "faults": per_fault}


def analyse() -> None:
    runs: dict = {}
    for filename in sorted(os.listdir(RAW_DIR)):
        fault, seed = filename[:-5].split("__")
        with open(os.path.join(RAW_DIR, filename), encoding="utf-8") as handle:
            runs.setdefault(fault, {})[seed] = analyse_run(fault, int(seed), json.load(handle))
    result = summarise(runs)
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    print(json.dumps(result["overall"], indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--worker", nargs=2, metavar=("FAULT", "SEED"))
    parser.add_argument("--out")
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--analyse", action="store_true")
    args = parser.parse_args()
    if args.worker:
        collect(args.worker[0], int(args.worker[1]), args.count, args.out)
        return
    if not args.analyse:
        run_all(args.count, args.jobs)
    analyse()


if __name__ == "__main__":
    main()
