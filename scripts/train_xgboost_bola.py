from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
from graphql import (
    FieldNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    InlineFragmentNode,
    OperationDefinitionNode,
    parse,
)
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from xgboost import XGBClassifier

from app.benchmarks.dataset import read_jsonl


FEATURE_NAMES = [
    "query_length",
    "field_count",
    "max_field_depth",
    "alias_count",
    "identifier_argument_count",
    "variable_definition_count",
    "runtime_variable_count",
    "path_depth",
    "role_is_admin",
    "owner_matches_principal",
    "has_children_field",
    "has_user_field",
    "has_nested_resource_path",
    "has_relationship_path",
]


def extract_features(case: dict[str, Any]) -> dict[str, int]:
    """
    Extract per-request features.

    Deliberately excludes scenario, case_id, is_bola,
    expected_authorized, principal_name, and raw object IDs.
    """
    document = parse(case["query"])

    fields: list[str] = []
    alias_count = 0
    identifier_argument_count = 0
    variable_definition_count = 0
    max_field_depth = 0

    fragments = {
        definition.name.value: definition
        for definition in document.definitions
        if isinstance(definition, FragmentDefinitionNode)
    }

    def visit_selection_set(
        selection_set: Any,
        depth: int = 1,
        fragment_stack: frozenset[str] = frozenset(),
    ) -> None:
        nonlocal alias_count
        nonlocal identifier_argument_count
        nonlocal max_field_depth

        if selection_set is None:
            return

        for selection in selection_set.selections:
            if isinstance(selection, FieldNode):
                name = selection.name.value.lower()
                fields.append(name)
                max_field_depth = max(max_field_depth, depth)

                if selection.alias is not None:
                    alias_count += 1

                for argument in selection.arguments or ():
                    if argument.name.value.lower() in {
                        "id",
                        "userid",
                        "resourceid",
                        "objectid",
                        "parentid",
                        "childid",
                    }:
                        identifier_argument_count += 1

                visit_selection_set(
                    selection.selection_set,
                    depth + 1,
                    fragment_stack,
                )

            elif isinstance(selection, InlineFragmentNode):
                visit_selection_set(
                    selection.selection_set,
                    depth,
                    fragment_stack,
                )

            elif isinstance(selection, FragmentSpreadNode):
                fragment_name = selection.name.value
                fragment = fragments.get(fragment_name)

                if fragment and fragment_name not in fragment_stack:
                    visit_selection_set(
                        fragment.selection_set,
                        depth,
                        fragment_stack | {fragment_name},
                    )

    for definition in document.definitions:
        if isinstance(definition, OperationDefinitionNode):
            variable_definition_count += len(
                definition.variable_definitions or ()
            )
            visit_selection_set(definition.selection_set)

    role = str(case.get("role", "user")).lower()
    principal_id = case.get("principal_id")
    owner_id = case.get("target_owner_id")
    graphql_path = str(case.get("graphql_path", ""))

    return {
        "query_length": len(case["query"]),
        "field_count": len(fields),
        "max_field_depth": max_field_depth,
        "alias_count": alias_count,
        "identifier_argument_count": identifier_argument_count,
        "variable_definition_count": variable_definition_count,
        "runtime_variable_count": len(case.get("variables") or {}),
        "path_depth": graphql_path.count(".") + 1,
        "role_is_admin": int(role in {
            "admin",
            "administrator",
            "superuser",
        }),
        "owner_matches_principal": int(
            principal_id is not None
            and owner_id is not None
            and str(principal_id) == str(owner_id)
        ),
        "has_children_field": int("children" in fields),
        "has_user_field": int("user" in fields),
        "has_nested_resource_path": int(
            "user" in fields and "resource" in fields
        ),
        "has_relationship_path": int("children" in fields),
    }


def query_family(case: dict[str, Any]) -> str:
    """
    Assign the test family from query structure, not from its label.
    Relationship requests will form the held-out test family.
    """
    query = case["query"].lower()

    if "children" in query:
        return "relationship"

    if "user(" in query:
        return "nested"

    return "direct"


def metrics(
    y_true: list[int],
    predictions: list[int],
    scores: list[float],
) -> dict[str, Any]:
    tn, fp, fn, tp = confusion_matrix(
        y_true,
        predictions,
        labels=[0, 1],
    ).ravel()

    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0

    return {
        "accuracy": round(accuracy_score(y_true, predictions), 4),
        "precision": round(
            precision_score(y_true, predictions, zero_division=0), 4
        ),
        "recall": round(
            recall_score(y_true, predictions, zero_division=0), 4
        ),
        "f1_score": round(
            f1_score(y_true, predictions, zero_division=0), 4
        ),
        "pr_auc_average_precision": round(
            average_precision_score(y_true, scores), 4
        ),
        "false_positive_rate": round(false_positive_rate, 4),
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
    }


def rule_baseline_score(case: dict[str, Any]) -> float:
    """
    Offline deterministic baseline reflecting the existing core rules.

    A live recent-denial count is deliberately omitted because the
    synthetic benchmark cases do not contain request history.
    """
    role = str(case.get("role", "user")).lower()

    if role in {"admin", "administrator", "superuser"}:
        return 0.0

    principal_id = case.get("principal_id")
    owner_id = case.get("target_owner_id")

    score = 0.0

    if (
        principal_id is None
        or owner_id is None
        or str(principal_id) != str(owner_id)
    ):
        score += 80.0

    if "." in str(case.get("graphql_path", "")):
        score += 20.0

    return min(score, 100.0)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train and evaluate the GraphQL-Shield XGBoost model."
    )
    parser.add_argument(
        "--dataset",
        default="results/research_benchmark/benchmark_dataset.jsonl",
    )
    parser.add_argument(
        "--output-dir",
        default="results/research_benchmark/xgboost",
    )
    args = parser.parse_args()

    cases = read_jsonl(args.dataset)

    if not cases:
        raise SystemExit("Dataset is empty; generate it before training.")

    rows = []
    for case in cases:
        if "is_bola" not in case:
            raise SystemExit("Dataset is missing the is_bola label.")
        rows.append({
            **extract_features(case),
            "label": int(bool(case["is_bola"])),
            "family": query_family(case),
            "raw_case": case,
        })

    # Hold out the entire relationship-query family.
    # Do not use this family when fitting model parameters.
    train_rows = [row for row in rows if row["family"] != "relationship"]
    test_rows = [row for row in rows if row["family"] == "relationship"]

    if not train_rows or not test_rows:
        raise SystemExit(
            "Need direct/nested training cases and relationship test cases."
        )

    y_train = [row["label"] for row in train_rows]
    y_test = [row["label"] for row in test_rows]

    if len(set(y_train)) < 2 or len(set(y_test)) < 2:
        raise SystemExit(
            "Training and held-out relationship sets must each contain "
            "both normal and BOLA labels. Regenerate a larger dataset."
        )

    x_train = pd.DataFrame(
        [{key: row[key] for key in FEATURE_NAMES} for row in train_rows],
        columns=FEATURE_NAMES,
    )
    x_test = pd.DataFrame(
        [{key: row[key] for key in FEATURE_NAMES} for row in test_rows],
        columns=FEATURE_NAMES,
    )

    model = XGBClassifier(
        objective="binary:logistic",
        eval_metric="logloss",
        n_estimators=160,
        max_depth=3,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.9,
        random_state=20261011,
        n_jobs=1,
        tree_method="hist",
    )

    model.fit(x_train, y_train)

    start = time.perf_counter()
    repeats = 100
    for _ in range(repeats):
        probabilities = model.predict_proba(x_test)[:, 1]
    elapsed = time.perf_counter() - start

    predictions = (probabilities >= 0.5).astype(int).tolist()

    baseline_scores = [
        rule_baseline_score(row["raw_case"]) / 100.0
        for row in test_rows
    ]
    baseline_predictions = [
        int(score >= 0.6) for score in baseline_scores
    ]

    y_true = [int(value) for value in y_test]

    results = {
        "dataset": str(Path(args.dataset)),
        "total_cases": len(rows),
        "training_cases": len(train_rows),
        "held_out_cases": len(test_rows),
        "held_out_family": "relationship",
        "class_counts": {
            "all": dict(Counter(str(row["label"]) for row in rows)),
            "training": dict(Counter(str(value) for value in y_train)),
            "held_out": dict(Counter(str(value) for value in y_test)),
        },
        "xgboost": metrics(
            y_true,
            predictions,
            probabilities.tolist(),
        ),
        "rule_baseline": metrics(
            y_true,
            baseline_predictions,
            baseline_scores,
        ),
        "xgboost_inference_latency": {
            "average_ms_per_batch": round(
                (elapsed / repeats) * 1000, 4
            ),
            "average_ms_per_case": round(
                (elapsed / repeats / len(test_rows)) * 1000, 6
            ),
            "batch_size": len(test_rows),
            "repetitions": repeats,
        },
        "feature_names": FEATURE_NAMES,
        "note": (
            "Synthetic per-request benchmark. The rule baseline omits "
            "recent-denial history. Results do not establish superiority "
            "on real-world traffic."
        ),
    }

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    model_path = output_dir / "bola_xgboost_model.json"
    model.save_model(str(model_path))

    results["model_path"] = str(model_path)

    metrics_path = output_dir / "evaluation_metrics.json"
    metrics_path.write_text(
        json.dumps(results, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(results, indent=2))
    print(f"\nSaved model: {model_path}")
    print(f"Saved metrics: {metrics_path}")


if __name__ == "__main__":
    main()
