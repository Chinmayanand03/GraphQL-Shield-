from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.benchmarks.runner import run_research_benchmark


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the local GraphQL Shield research benchmark."
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1000,
        help="Number of cases, from 1 to 5000.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=20261011,
    )
    parser.add_argument(
        "--output-dir",
        default="results/research_benchmark",
    )
    parser.add_argument(
        "--dataset",
        default=None,
        help="Existing JSONL dataset; generate one if omitted.",
    )

    args = parser.parse_args()

    report = run_research_benchmark(
        count=args.count,
        seed=args.seed,
        output_dir=args.output_dir,
        dataset_path=args.dataset,
    )

    print(
        json.dumps(
            {
                "dataset_count": report["dataset"]["actual_count"],
                "scenario_counts": report["dataset"]["scenario_counts"],
                "endpoint_summary": report["endpoint_summary"],
                "detection_metrics": report[
                    "detection_metrics"
                ]["overall"],
                "ablation_study": report[
                    "ablation_study"
                ]["metrics"],
                "performance": report["performance"],
                "output_dir": args.output_dir,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
