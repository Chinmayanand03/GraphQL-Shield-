from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.benchmarks.behavioral_dataset import (
    FEATURE_NAMES,
    FEATURE_SCHEMA,
    SCENARIO_CONFIGS,
    generate_behavioral_dataset,
    write_csv_dataset,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a synthetic session-based behavioural BOLA dataset."
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1000,
        help="Number of session records (default: 1000).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=20261011,
        help="Deterministic random seed (default: 20261011).",
    )
    parser.add_argument(
        "--output",
        default="results/research_benchmark/behavioral_sessions.csv",
        help="Destination path for generated CSV dataset.",
    )
    parser.add_argument(
        "--manifest",
        default="results/research_benchmark/behavioral_dataset_manifest.json",
        help="Destination path for dataset manifest JSON.",
    )
    args = parser.parse_args()

    sessions = generate_behavioral_dataset(count=args.count, seed=args.seed)
    manifest = write_csv_dataset(sessions, destination=args.output)
    manifest["seed"] = args.seed

    manifest_path = Path(args.manifest)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(manifest, indent=2))
    print(f"\nSaved CSV dataset to: {args.output}")
    print(f"Saved manifest to: {args.manifest}")


if __name__ == "__main__":
    main()
