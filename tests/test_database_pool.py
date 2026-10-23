import os
import sqlite3

import pytest

from app import database
from app.config import settings

DB_FILE = os.path.abspath("test_pool.db")


@pytest.fixture(autouse=True)
def pool_db():
    original = settings.DATABASE_URL
    settings.DATABASE_URL = f"sqlite:///{DB_FILE}"
    database.init_db()
    yield
    database.close_pooled_connections(DB_FILE)
    settings.DATABASE_URL = original
    for path in (DB_FILE, f"{DB_FILE}-wal", f"{DB_FILE}-shm"):
        if os.path.exists(path):
            os.remove(path)


def test_closed_connection_is_reused():
    first = database.get_db_connection()
    first.close()
    second = database.get_db_connection()
    assert second is first
    second.close()


def test_concurrent_borrowers_get_different_connections():
    a = database.get_db_connection()
    b = database.get_db_connection()
    assert a is not b
    a.close()
    b.close()


def test_failed_transaction_does_not_leave_a_lock():
    conn = database.get_db_connection()
    conn.execute("INSERT INTO layer_events (layer, event) VALUES ('L1', 'X')")
    conn.close()  # returned without commit, e.g. after an exception
    other = sqlite3.connect(DB_FILE, timeout=0.5)
    try:
        other.execute("INSERT INTO layer_events (layer, event) VALUES ('L1', 'Y')")  # would raise "locked"
        other.commit()
        assert [r[0] for r in other.execute("SELECT event FROM layer_events")] == ["Y"]
    finally:
        other.close()


def test_close_pooled_connections_releases_the_file():
    database.get_db_connection().close()
    database.close_pooled_connections(DB_FILE)
    os.replace(DB_FILE, DB_FILE + ".moved")  # fails on Windows while the file is open
    os.replace(DB_FILE + ".moved", DB_FILE)
