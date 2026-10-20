import json

import httpx
import pytest

from app.benchmarks.dataset import (
    generate_dataset,
    read_jsonl,
    write_jsonl,
)
from app.benchmarks.evaluator import (
    classify_http_response,
    exact_target_visible,
    resolve_response_path,
)
from app.benchmarks.metrics import (
    classification_metrics,
    latency_summary,
)


def test_dataset_is_reproducible():
    first = [
        case.to_dict()
        for case in generate_dataset(100, seed=17)
    ]
    second = [
        case.to_dict()
        for case in generate_dataset(100, seed=17)
    ]

    assert first == second


def test_dataset_count_and_unique_case_ids():
    cases = generate_dataset(250, seed=5)

    assert len(cases) == 250
    assert len({case.case_id for case in cases}) == 250


def test_dataset_has_legitimate_and_bola_cases():
    cases = generate_dataset(500, seed=5)

    assert any(case.is_bola for case in cases)
    assert any(not case.is_bola for case in cases)
    assert all(
        case.expected_authorized != case.is_bola
        for case in cases
    )


def test_dataset_targets_are_seeded_objects():
    cases = generate_dataset(250, seed=7)

    assert all(
        case.target_id in {101, 102, 103, 104, 201, 202, 203, 204, 205, 206}
        for case in cases
    )
    assert all(
        case.target_owner_id in {101, 102, 103, 104}
        for case in cases
    )



def test_dataset_rejects_count_over_limit():
    with pytest.raises(ValueError):
        generate_dataset(5001)


def test_jsonl_round_trip(tmp_path):
    cases = generate_dataset(50, seed=7)
    path = tmp_path / "dataset.jsonl"

    manifest = write_jsonl(cases, path)
    loaded = read_jsonl(path)

    assert len(loaded) == 50
    assert manifest["count"] == 50
    assert len(manifest["sha256"]) == 64
    assert loaded[0]["case_id"] == cases[0].case_id


def test_jsonl_reader_rejects_missing_fields(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text(
        json.dumps({"case_id": "missing"}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="missing fields"):
        read_jsonl(path)


def test_classification_metrics_known_example():
    result = classification_metrics(
        [True, True, False, False],
        [True, False, True, False],
    )

    assert result["tp"] == 1
    assert result["fn"] == 1
    assert result["fp"] == 1
    assert result["tn"] == 1
    assert result["precision"] == 0.5
    assert result["recall"] == 0.5
    assert result["f1"] == 0.5
    assert result["false_positive_rate"] == 0.5


def test_classification_metrics_reject_mismatched_lengths():
    with pytest.raises(ValueError):
        classification_metrics([True], [True, False])


def test_latency_summary_percentiles():
    result = latency_summary([1, 2, 3, 4, 100])

    assert result["count"] == 5
    assert result["mean_ms"] == 22.0
    assert result["p95_ms"] == 100.0
    assert result["max_ms"] == 100.0


def test_response_path_resolver():
    payload = {
        "user": {
            "resource": {
                "id": 202,
            }
        }
    }

    found, value = resolve_response_path(
        payload,
        "user.resource",
    )

    assert found is True
    assert value["id"] == 202


def test_exact_target_visibility():
    assert exact_target_visible({"id": 202}, 202)
    assert not exact_target_visible({"id": 201}, 202)
    assert not exact_target_visible({"name": "private"}, 202)


def test_http_response_classification_confirmed_exposure():
    response = httpx.Response(
        200,
        json={
            "data": {
                "resource": {
                    "id": 202,
                    "name": "Synthetic",
                }
            }
        },
    )

    result = classify_http_response(
        response,
        "resource",
        202,
    )

    assert result["outcome"] == "EXPOSED_CONFIRMED"
    assert result["target_confirmed"] is True


def test_http_response_classification_block():
    response = httpx.Response(
        403,
        json={"detail": "Denied"},
    )

    result = classify_http_response(
        response,
        "resource",
        202,
    )

    assert result["outcome"] == "BLOCKED"
    assert result["blocked"] is True


def test_http_response_classification_inconclusive_graphql_error():
    response = httpx.Response(
        200,
        json={
            "data": {"resource": None},
            "errors": [{"message": "Resolver error"}],
        },
    )

    result = classify_http_response(
        response,
        "resource",
        202,
    )

    assert result["outcome"] == "INCONCLUSIVE"
