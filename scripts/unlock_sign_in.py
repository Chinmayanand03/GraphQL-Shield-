"""
Clear sign-in lockouts, for example after mistyping a demo password five times.

    python -m scripts.unlock_sign_in balanilavan     # one username
    python -m scripts.unlock_sign_in --all           # every username and address
"""
from __future__ import annotations

import argparse
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.database import get_db_connection, init_db


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("username", nargs="?")
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()
    if not args.username and not args.all:
        parser.error("give a username or --all")
    init_db()
    conn = get_db_connection()
    try:
        if args.all:
            removed = conn.execute("DELETE FROM login_attempts").rowcount
        else:
            removed = conn.execute("DELETE FROM login_attempts WHERE key = ?",
                                   (f"user:{args.username.strip().lower()}",)).rowcount
        conn.commit()
    finally:
        conn.close()
    print(f"Cleared {removed} lockout record(s).")


if __name__ == "__main__":
    main()
