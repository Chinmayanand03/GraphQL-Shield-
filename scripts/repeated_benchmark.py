from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.benchmarks.runner import run_research_benchmark


# Conservative approximate Student-t critical values for 95% intervals.
T_CRITICAL_95 = {
    1: 12.706,
    2: 4.303,
    3: 3.182,
    4: 2.776,
    5: 2.571,
    6: 2.447,
    7: 2.365,
    8: 2.306,
    9: 2.262,
    10: 2.228,
    11: 2.201,
    12: 2.179,
    13: 2.160,
    14: 2.145,
    15: 2.131,
    16: 2.120,
    17: 2.110,
    18: 2.101,
    19: 2.093,
    20: 2.086,
    24: 2.064,
    29: 2.045,
}


def flatten_numeric(
    value: Any,
    prefix: str = "",
) -> dict[str, float]:
    """Flatten nested report values, retaining numeric metrics only."""
    output: dict[str, float] = {}

    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            output.update(flatten_numeric(child, path))

    elif (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    ):
        output[prefix] = float(value)

    return output


def t_critical_95(degrees_of_freedom: int) -> float:
    eligible = [
        df for df in T_CRITICAL_95
        if df <= degrees_of_freedom
    ]

    if not eligible:
        return 12.706

    # Using the closest available lower df is conservative.
    return T_CRITICAL_95[max(eligible)]


def summarize_values(values: list[float]) -> dict:
    """Summarize independent run-level results with a 95% t interval."""
    if not values:
        raise ValueError("Cannot summarize an empty metric")

    mean = statistics.mean(values)
    minimum = min(values)
    maximum = max(values)

    if len(values) == 1:
        return {
            "n": 1,
            "mean": mean,
            "std_dev": None,
            "ci95_lower": None,
            "ci95_upper": None,
            "min": minimum,
            "max": maximum,
        }

    sd = statistics.stdev(values)
    df = len(values) - 1

    # For degrees of freedom > 29, 2.045 is conservative relative
    # to the 95% t critical value.
    critical = (
        t_critical_95(df)
        if df <= 29
        else 2.045
    )

    margin = critical * sd / math.sqrt(len(values))

    return {
        "n": len(values),
        "mean": mean,
        "std_dev": sd,
        "ci95_lower": mean - margin,
        "ci95_upper": mean + margin,
        "min": minimum,
        "max": maximum,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Repeat the GraphQL Shield research benchmark "
            "across independent dataset seeds."
        )
    )

    parser.add_argument(
        "--count",
        type=int,
        default=1000,
        help="Requests per run, from 1 to 5000.",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=5,
        help="Independent dataset seeds; at least 3.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=20261011,
        help="Initial random seed.",
    )
    parser.add_argument(
        "--output-root",
        default="results/repeated_benchmark",
    )

    args = parser.parse_args()

    if not 1 <= args.count <= 5000:
        parser.error("--count must be between 1 and 5000")

    if not 3 <= args.repeats <= 30:
        parser.error("--repeats must be between 3 and 30")

    root = Path(args.output_root)
    root.mkdir(parents=True, exist_ok=True)

    report_records: list[dict] = []
    metric_rows: list[dict] = []
    seed_list = []

    for run_index in range(args.repeats):
        seed = args.seed + run_index
        seed_list.append(seed)

        run_dir = root / f"seed_{seed}"

        print(
            f"[{run_index + 1}/{args.repeats}] "
            f"Running count={args.count}, seed={seed}"
        )

        report = run_research_benchmark(
            count=args.count,
            seed=seed,
            output_dir=run_dir,
        )

        report_records.append({
            "seed": seed,
            "output_dir": str(run_dir),
            "report": report,
        })

        # Keep detection, endpoint, latency, CPU, memory and
        # throughput metrics. Ignore timestamps and descriptive text.
        numeric_metrics: dict[str, float] = {}

        for section in (
            "endpoint_summary",
            "detection_metrics",
            "performance",
        ):
            numeric_metrics.update(
                flatten_numeric(
                    report.get(section, {}),
                    prefix=section,
                )
            )

        for metric, value in numeric_metrics.items():
            metric_rows.append({
                "seed": seed,
                "metric": metric,
                "value": value,
            })

    # Aggregate results from independent runs, not individual requests
    # treated as independent experiments.
    grouped: dict[str, list[float]] = {}

    for row in metric_rows:
        grouped.setdefault(row["metric"], []).append(
            row["value"]
        )

    summaries = {
        metric: summarize_values(values)
        for metric, values in sorted(grouped.items())
    }

    per_run_csv = root / "metrics_by_run.csv"

    with per_run_csv.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["seed", "metric", "value"],
        )
        writer.writeheader()
        writer.writerows(metric_rows)

    summary_csv = root / "metrics_summary.csv"

    with summary_csv.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        fields = [
            "metric",
            "n",
            "mean",
            "std_dev",
            "ci95_lower",
            "ci95_upper",
            "min",
            "max",
        ]
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        for metric, result in sorted(summaries.items()):
            writer.writerow({
                "metric": metric,
                **result,
            })

    summary_json = {
        "experiment": "GraphQL Shield multi-seed benchmark",
        "dataset_count_per_run": args.count,
        "repeats": args.repeats,
        "seeds": seed_list,
        "total_cases": args.count * args.repeats,
        "confidence_interval": (
            "Approximate 95% Student-t interval across independent "
            "run-level measurements. It is not a per-request interval."
        ),
        "metrics": summaries,
        "runs": [
            {
                "seed": item["seed"],
                "output_dir": item["output_dir"],
                "actual_cases": item["report"]["dataset"]["actual_count"],
            }
            for item in report_records
        ],
    }

    (root / "repeated_benchmark_summary.json").write_text(
        json.dumps(summary_json, indent=2),
        encoding="utf-8",
    )

    print("\nRepeated benchmark completed.")
    print(f"Cases per run: {args.count}")
    print(f"Runs: {args.repeats}")
    print(f"Total cases: {args.count * args.repeats}")
    print(f"Output: {root.resolve()}")
    print("\nReview metrics_summary.csv for mean, variation, and intervals.")


if __name__ == "__main__":
    main()
