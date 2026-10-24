"""Dashboard evidence endpoints and the tamper-evident audit log."""
import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.core.security import create_access_token
from app.database import get_db_connection
from app.main import app
from app.security.audit import log_decision, verify_audit_chain
from app.seed import seed_database

client = TestClient(app)
DB_FILE = os.path.abspath("test_dashboard_api.db")


@pytest.fixture(autouse=True)
def fresh_db():
    original = settings.DATABASE_URL
    settings.DATABASE_URL = f"sqlite:///{DB_FILE}"
    seed_database()
    yield
    settings.DATABASE_URL = original


def headers(user_id=101, role="user"):
    return {"Authorization": f"Bearer {create_access_token(user_id=user_id, role=role)}"}


def write(n=3):
    for i in range(n):
        log_decision(101, "user", "query", "Resource", 100 + i, "resource", "ALLOW", "OWNER_MATCH", 5, "LOW", "L1")


# ---------------------------------------------------------------- tamper-evident audit log

def test_chain_is_intact_after_normal_writes():
    write(5)
    result = verify_audit_chain()
    assert result["intact"] and result["checked"] == 5 and result["legacy_rows"] == 0


def test_editing_a_row_breaks_the_chain():
    write(4)
    conn = sqlite3.connect(DB_FILE)
    second = conn.execute("SELECT id FROM audit_logs ORDER BY id LIMIT 1 OFFSET 1").fetchone()[0]
    conn.execute("UPDATE audit_logs SET decision = 'DENY' WHERE id = ?", (second,))
    conn.commit()
    conn.close()
    result = verify_audit_chain()
    assert result["intact"] is False and result["first_broken_id"] == second


def test_deleting_a_row_breaks_the_chain():
    write(4)
    conn = sqlite3.connect(DB_FILE)
    conn.execute("DELETE FROM audit_logs WHERE id = (SELECT id FROM audit_logs ORDER BY id LIMIT 1 OFFSET 1)")
    conn.commit()
    conn.close()
    assert verify_audit_chain()["intact"] is False


def test_numeric_string_ids_do_not_cause_false_alarms():
    log_decision("101", "user", "query", "Resource", "102", "resource", "DENY", "OWNERSHIP_MISMATCH", "80", "HIGH", "L1")
    assert verify_audit_chain()["intact"] is True


def test_integrity_endpoint_reports_real_requests():
    client.post("/graphql", json={"query": "{ resource(id: 102) { id } }"}, headers=headers())
    data = client.get("/api/v1/audit/integrity").json()
    assert data["intact"] is True and data["checked"] >= 1


# ---------------------------------------------------------------- audit log API

def test_audit_logs_are_admin_only():
    assert client.get("/api/v1/audit-logs", headers=headers()).status_code == 403


def test_audit_logs_filter_and_paginate():
    client.post("/graphql", json={"query": "{ resource(id: 102) { id } }"}, headers=headers())   # L1 deny
    client.post("/graphql", json={"query": "{ resource(id: 201) { id children { id } } }"}, headers=headers())  # L1 + L2
    admin = headers(104, "admin")
    everything = client.get("/api/v1/audit-logs", headers=admin).json()
    assert everything["total"] >= 4
    l2 = client.get("/api/v1/audit-logs?layer=L2", headers=admin).json()
    assert l2["logs"] and all(row["layer"] == "L2" for row in l2["logs"])
    denied = client.get("/api/v1/audit-logs?decision=DENY", headers=admin).json()
    assert all(row["decision"] == "DENY" for row in denied["logs"])
    page = client.get("/api/v1/audit-logs?limit=1&offset=1", headers=admin).json()
    assert len(page["logs"]) == 1 and page["logs"][0]["id"] == everything["logs"][1]["id"]
    assert everything["logs"][0]["actor_name"] == "B.V. Balanilavan"


def test_timeline_counts_decisions():
    client.post("/graphql", json={"query": "{ resource(id: 101) { id } }"}, headers=headers())
    client.post("/graphql", json={"query": "{ resource(id: 102) { id } }"}, headers=headers())
    points = client.get("/api/v1/audit/timeline?bucket=hour&span=2").json()["points"]
    assert sum(p["allowed"] for p in points) >= 1 and sum(p["denied"] for p in points) >= 1


# ---------------------------------------------------------------- evidence panels

def test_research_results_endpoint():
    data = client.get("/api/v1/research/results").json()
    assert {"ablation", "tool_comparison", "latency", "blind_spot_seeds"} <= set(data)


def test_live_predictor_recall_counts():
    client.post("/graphql", json={"query": "{ resource(id: 201) { id children { id } } }"}, headers=headers())
    data = client.get("/api/v1/security/blind-spot-live").json()
    assert "live_recall" in data and data["blind_spot_denials"] >= 0


def test_test_report_lists_every_property():
    data = client.get("/api/v1/verification/test-report").json()
    if data["available"]:
        assert len(data["properties"]) == 6
        assert all(p["status"] in ("PASS", "FAIL", "NOT RUN") for p in data["properties"])


def test_favicon_is_served():
    response = client.get("/favicon.ico")
    assert response.status_code == 200 and "svg" in response.headers["content-type"]
