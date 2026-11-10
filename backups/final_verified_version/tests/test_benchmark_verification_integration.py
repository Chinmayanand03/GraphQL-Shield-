from __future__ import annotations

import csv
import json
from pathlib import Path
import pytest

from app.benchmarks.dataset import generate_dataset, write_jsonl
from app.benchmarks.runner import run_research_benchmark
from app.config import settings


def test_end_to_end_research_benchmark_runs_and_verifies_replays(tmp_path: Path):
    report = run_research_benchmark(
        count=10,
        seed=20261011,
        output_dir=tmp_path,
    )

    assert report['report_version'] == '2.0'
    assert report['dataset']['actual_count'] == 10
    assert report['dataset']['loaded_from_existing_dataset'] is False

    dynamic = report['integrated_dynamic_verification']
    assert dynamic['method'] == 'labelled_attack_generation_and_dynamic_replay'
    assert dynamic['labelled_bola_cases'] == report['dataset']['bola_count']
    assert dynamic['attack_cases_generated_and_executed'] == dynamic['labelled_bola_cases']
    assert dynamic['baseline_confirmed_exposures'] == dynamic['labelled_bola_cases']
    assert dynamic['protected_blocks'] == dynamic['labelled_bola_cases']
    assert dynamic['protected_confirmed_exposures'] == 0
    assert dynamic['protection_verified_rate'] == 1.0
    assert dynamic['cases_skipped'] == 0

    perf = report['performance']
    assert perf['request_cases'] == 10
    assert perf['baseline_and_protected_http_calls'] == 20
    assert perf['dynamic_replay_http_calls'] == dynamic['http_requests_for_replays']
    assert perf['total_http_calls'] == 20 + dynamic['http_requests_for_replays'] + perf.get('research_hardening_replay_http_calls', 0)
    assert perf['elapsed_seconds_end_to_end'] > 0.0

    report_file = tmp_path / 'research_benchmark_report.json'
    raw_csv = tmp_path / 'research_benchmark_raw.csv'
    dataset_file = tmp_path / 'benchmark_dataset.jsonl'
    manifest_file = tmp_path / 'benchmark_dataset_manifest.json'
    dyn_json = tmp_path / 'integrated_dynamic_verification.json'
    dyn_csv = tmp_path / 'integrated_dynamic_verification_raw.csv'

    assert report_file.exists()
    assert raw_csv.exists()
    assert dataset_file.exists()
    assert manifest_file.exists()
    assert dyn_json.exists()
    assert dyn_csv.exists()

    with raw_csv.open(encoding='utf-8') as f:
        reader = list(csv.DictReader(f))
        assert len(reader) == 10
        assert 'authorization_aware_candidate' in reader[0]
        assert 'baseline_outcome' in reader[0]
        assert 'protected_outcome' in reader[0]

    with dyn_csv.open(encoding='utf-8') as f:
        dyn_reader = list(csv.DictReader(f))
        assert len(dyn_reader) == dynamic['attack_cases_generated_and_executed']
        if dyn_reader:
            assert dyn_reader[0]['verdict'] == 'PROTECTION_VERIFIED'


def test_benchmark_with_pre_existing_dataset(tmp_path: Path):
    cases = generate_dataset(15, seed=42)
    dataset_path = tmp_path / 'pre_existing.jsonl'
    write_jsonl(cases, dataset_path)

    out_dir = tmp_path / 'benchmark_results'
    report = run_research_benchmark(
        dataset_path=dataset_path,
        output_dir=out_dir,
    )

    assert report['dataset']['loaded_from_existing_dataset'] is True
    assert report['dataset']['actual_count'] == 15
    assert (out_dir / 'research_benchmark_report.json').exists()
    assert (out_dir / 'integrated_dynamic_verification.json').exists()


def test_benchmark_ablation_study_matches_detector_metrics(tmp_path: Path):
    report = run_research_benchmark(
        count=10,
        seed=20261011,
        output_dir=tmp_path,
    )

    overall = report['detection_metrics']['overall']
    ablation = report['ablation_study']['metrics']

    for candidate in ('taint_source_only', 'context_sensitive_taint_only', 'authorization_aware_candidate'):
        assert candidate in overall
        assert ablation[candidate] == overall[candidate]


def test_benchmark_rejects_invalid_count_bounds():
    with pytest.raises(ValueError, match='count must be between 1 and 5000'):
        run_research_benchmark(count=0)

    with pytest.raises(ValueError, match='count must be between 1 and 5000'):
        run_research_benchmark(count=5001)


def test_benchmark_restores_database_url_on_failure(tmp_path: Path):
    original_url = settings.DATABASE_URL

    bad_dataset = tmp_path / 'empty.jsonl'
    bad_dataset.write_text('', encoding='utf-8')

    with pytest.raises(ValueError, match='Provided benchmark dataset is empty'):
        run_research_benchmark(
            dataset_path=bad_dataset,
            output_dir=tmp_path / 'fail_out',
        )

    assert settings.DATABASE_URL == original_url
