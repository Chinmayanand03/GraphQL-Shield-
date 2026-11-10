from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.benchmarks.dataset import generate_dataset, write_jsonl


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a synthetic GraphQL BOLA benchmark dataset."
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
        help="Deterministic random seed.",
    )
    parser.add_argument(
        "--output",
        default="results/research_benchmark/benchmark_dataset.jsonl",
    )
    args = parser.parse_args()

    cases = generate_dataset(args.count, args.seed)
    manifest = write_jsonl(cases, args.output)
    manifest["seed"] = args.seed

    manifest_path = Path(args.output).with_name(
        "benchmark_dataset_manifest.json"
    )
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
