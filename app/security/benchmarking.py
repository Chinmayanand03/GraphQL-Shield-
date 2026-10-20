"""Synthetic GraphQL BOLA research benchmarking utilities."""
from __future__ import annotations

import hashlib
import json
import random
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

DATASET_VERSION = "1.0"

# Keep these values synchronized with app/seed.py.
OBJECTS: dict[int, dict[str, Any]] = {
    101: {
        "owner_id": 101,
        "object_type": "document",
        "name": "Balanilavan's Secret Note",
        "parent_id": None,
    },
    102: {
        "owner_id": 102,
        "object_type": "document",
        "name": "Kapilesh's Financial Record",
        "parent_id": None,
    },
    103: {
        "owner_id": 103,
        "object_type": "document",
        "name": "Sakthivel B's Research Note",
        "parent_id": None,
    },
    104: {
        "owner_id": 104,
        "object_type": "document",
        "name": "Chinmayanand's Admin Log",
        "parent_id": None,
    },
    201: {
        "owner_id": 101,
        "object_type": "folder",
        "name": "Balanilavan's Projects",
        "parent_id": None,
    },
    202: {
        "owner_id": 101,
        "object_type": "document",
        "name": "Project Alpha Plan",
        "parent_id": 201,
    },
    203: {
        "owner_id": 101,
        "object_type": "document",
        "name": "Project Beta Plan",
        "parent_id": 201,
    },
}

USERS: dict[int, dict[str, Any]] = {
    101: {"username": "balanilavan", "role": "user"},
    102: {"username": "kapilesh", "role": "user"},
    103: {"username": "sakthivel", "role": "user"},
    104: {"username": "chinmayanand", "role": "admin"},
}

SCENARIO_WEIGHTS: dict[str, int] = {
    "direct_legitimate": 30,
    "direct_bola": 30,
    "nested_legitimate": 15,
    "nested_bola": 15,
    "admin_access": 10,
}


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    scenario: str
    principal_id: int
    principal_name: str
    role: str
    query: str
    variables: dict[str, Any]
    operation_name: str
    target_type: str
    target_id: int
    target_owner_id: int
    graphql_path: str
    sensitive_sink_path: str
    is_bola: bool
    expected_authorized: bool
    dataset_version: str = DATASET_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _pick_direct_legitimate(
    rng: random.Random,
) -> tuple[int, int, str, int, bool]:
    principal_id = rng.choice([101, 102])
    owned_ids = [
        object_id
        for object_id, obj in OBJECTS.items()
        if obj["owner_id"] == principal_id
    ]
    target_id = rng.choice(owned_ids)

    return (
        principal_id,
        target_id,
        "direct_legitimate",
        OBJECTS[target_id]["owner_id"],
        True,
    )


def _pick_direct_bola(
    rng: random.Random,
) -> tuple[int, int, str, int, bool]:
    principal_id = rng.choice([101, 102])
    foreign_ids = [
        object_id
        for object_id, obj in OBJECTS.items()
        if obj["owner_id"] != principal_id
    ]
    target_id = rng.choice(foreign_ids)

    return (
        principal_id,
        target_id,
        "direct_bola",
        OBJECTS[target_id]["owner_id"],
        False,
    )


def _pick_nested_legitimate(
    rng: random.Random,
) -> tuple[int, int, int, str, int, bool]:
    target_id = rng.choice([202, 203])

    return (
        101,
        101,
        target_id,
        "nested_legitimate",
        OBJECTS[target_id]["owner_id"],
        True,
    )


def _pick_nested_bola(
    rng: random.Random,
) -> tuple[int, int, int, str, int, bool]:
    principal_id = rng.choice([101, 102])
    foreign_ids = [
        object_id
        for object_id, obj in OBJECTS.items()
        if obj["owner_id"] != principal_id
    ]
    target_id = rng.choice(foreign_ids)

    return (
        principal_id,
        principal_id,
        target_id,
        "nested_bola",
        OBJECTS[target_id]["owner_id"],
        False,
    )


def _build_case(
    index: int,
    scenario: str,
    rng: random.Random,
) -> BenchmarkCase:
    if scenario == "direct_legitimate":
        (
            principal_id,
            target_id,
            scenario,
            owner_id,
            expected,
        ) = _pick_direct_legitimate(rng)

        query = (
            "query BenchmarkDirect($id: Int!) { "
            "resource(id: $id) { id name } }"
        )
        variables = {"id": target_id}
        operation_name = "BenchmarkDirect"
        graphql_path = "resource"
        sink = "resource.name"

    elif scenario == "direct_bola":
        (
            principal_id,
            target_id,
            scenario,
            owner_id,
            expected,
        ) = _pick_direct_bola(rng)

        query = (
            "query BenchmarkDirect($id: Int!) { "
            "resource(id: $id) { id name } }"
        )
        variables = {"id": target_id}
        operation_name = "BenchmarkDirect"
        graphql_path = "resource"
        sink = "resource.name"

    elif scenario == "nested_legitimate":
        (
            principal_id,
            user_id,
            target_id,
            scenario,
            owner_id,
            expected,
        ) = _pick_nested_legitimate(rng)

        query = (
            "query BenchmarkNested($userId: Int!, "
            "$resourceId: Int!) { "
            "user(id: $userId) { id "
            "resource(id: $resourceId) { id name } } }"
        )
        variables = {
            "userId": user_id,
            "resourceId": target_id,
        }
        operation_name = "BenchmarkNested"
        graphql_path = "user.resource"
        sink = "user.resource.name"

    elif scenario == "nested_bola":
        (
            principal_id,
            user_id,
            target_id,
            scenario,
            owner_id,
            expected,
        ) = _pick_nested_bola(rng)

        query = (
            "query BenchmarkNested($userId: Int!, "
            "$resourceId: Int!) { "
            "user(id: $userId) { id "
            "resource(id: $resourceId) { id name } } }"
        )
        variables = {
            "userId": user_id,
            "resourceId": target_id,
        }
        operation_name = "BenchmarkNested"
        graphql_path = "user.resource"
        sink = "user.resource.name"

    elif scenario == "admin_access":
        principal_id = 103
        target_id = rng.choice(list(OBJECTS))
        owner_id = OBJECTS[target_id]["owner_id"]
        expected = True

        query = (
            "query BenchmarkAdmin($id: Int!) { "
            "resource(id: $id) { id name } }"
        )
        variables = {"id": target_id}
        operation_name = "BenchmarkAdmin"
        graphql_path = "resource"
        sink = "resource.name"

    else:
        raise ValueError(f"Unknown benchmark scenario: {scenario}")

    principal = USERS[principal_id]

    return BenchmarkCase(
        case_id=f"case-{index:06d}",
        scenario=scenario,
        principal_id=principal_id,
        principal_name=principal["username"],
        role=principal["role"],
        query=query,
        variables=variables,
        operation_name=operation_name,
        target_type="Resource",
        target_id=target_id,
        target_owner_id=owner_id,
        graphql_path=graphql_path,
        sensitive_sink_path=sink,
        is_bola=not expected,
        expected_authorized=expected,
    )


def generate_dataset(
    count: int = 1000,
    seed: int = 20261011,
) -> list[BenchmarkCase]:
    """Generate a reproducible synthetic BOLA benchmark dataset."""
    if not 1 <= count <= 5000:
        raise ValueError("count must be between 1 and 5000")

    rng = random.Random(seed)
    names = list(SCENARIO_WEIGHTS)
    weights = list(SCENARIO_WEIGHTS.values())
    scenarios = rng.choices(names, weights=weights, k=count)

    cases = [
        _build_case(index + 1, scenario, rng)
        for index, scenario in enumerate(scenarios)
    ]
    rng.shuffle(cases)

    # Assign stable, unique IDs after shuffling.
    return [
        BenchmarkCase(
            case_id=f"case-{index + 1:06d}",
            **{
                key: value
                for key, value in asdict(case).items()
                if key != "case_id"
            },
        )
        for index, case in enumerate(cases)
    ]


def write_jsonl(
    cases: Iterable[BenchmarkCase],
    path: str | Path,
) -> dict[str, Any]:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    digest = hashlib.sha256()
    scenarios: Counter[str] = Counter()
    bola_count = 0
    count = 0

    with destination.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:
        for case in cases:
            line = json.dumps(
                case.to_dict(),
                ensure_ascii=False,
                sort_keys=True,
            )
            file.write(line + "\n")
            digest.update((line + "\n").encode("utf-8"))

            scenarios[case.scenario] += 1
            bola_count += int(case.is_bola)
            count += 1

    return {
        "dataset_version": DATASET_VERSION,
        "count": count,
        "bola_count": bola_count,
        "legitimate_count": count - bola_count,
        "scenario_counts": dict(sorted(scenarios.items())),
        "sha256": digest.hexdigest(),
        "path": str(destination),
    }


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    with Path(path).open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            if not line.strip():
                continue

            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSONL at line {line_number}: {exc}"
                ) from exc

            required = {
                "case_id",
                "scenario",
                "principal_id",
                "role",
                "query",
                "variables",
                "operation_name",
                "target_id",
                "target_owner_id",
                "graphql_path",
                "sensitive_sink_path",
                "is_bola",
                "expected_authorized",
            }

            missing = required.difference(item)
            if missing:
                raise ValueError(
                    f"Dataset line {line_number} missing fields: "
                    f"{sorted(missing)}"
                )

            rows.append(item)

    return rows

from .benchmark_metrics import classification_metrics, latency_summary

from .response_classifier import resolve_response_path, exact_target_visible, classify_http_response

from .benchmark_runner import run_research_benchmark
