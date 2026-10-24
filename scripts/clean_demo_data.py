"""
Remove rows that unit tests wrote into the development database before the
test suite was isolated (tests/conftest.py). Backs the database up first.

Removed: audit and layer-event rows for object types this app does not have
(Order, Invoice, Customer: the portability test's fake schema) and rows whose
reason only arises in unit tests with a fake request (MISSING_USER,
MISSING_REQUEST, INTERNAL_ERROR). Real demo and clinic events are kept.

    python -m scripts.clean_demo_data [--dry-run]
"""
from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import sys
from datetime import datetime

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB = os.path.join(ROOT, "shield.db")
FAKE_TYPES = ("Order", "Invoice", "Customer")
TEST_ONLY_REASONS = ("MISSING_USER", "MISSING_REQUEST", "INTERNAL_ERROR")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if not os.path.exists(DB):
        sys.exit(f"No database at {DB}")

    types = ",".join("?" * len(FAKE_TYPES))
    reasons = ",".join("?" * len(TEST_ONLY_REASONS))
    queries = {
        "audit_logs": (f"object_type IN ({types}) OR reason IN ({reasons})", FAKE_TYPES + TEST_ONLY_REASONS),
        "layer_events": (f"object_type IN ({types}) OR detail IN ({reasons})", FAKE_TYPES + TEST_ONLY_REASONS),
    }
    conn = sqlite3.connect(DB)
    counts = {table: conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}", params).fetchone()[0]
              for table, (where, params) in queries.items()}
    print("Rows to remove:", counts)
    if args.dry_run or not any(counts.values()):
        conn.close()
        return

    conn.close()
    backup = os.path.join(ROOT, "backups", f"shield_before_cleanup_{datetime.now():%Y%m%d_%H%M%S}.db")
    os.makedirs(os.path.dirname(backup), exist_ok=True)
    shutil.copy2(DB, backup)
    print("Backup:", backup)
    conn = sqlite3.connect(DB)
    for table, (where, params) in queries.items():
        conn.execute(f"DELETE FROM {table} WHERE {where}", params)
    conn.commit()
    conn.close()
    print("Removed.")


if __name__ == "__main__":
    main()
