"""
Read-only endpoints behind the dashboard's evidence panels.

Aggregate numbers (counts, research results, test outcomes, audit integrity)
are public, like the dashboard's other totals; per-request audit rows are
admin-only, like /api/v1/dashboard-stats.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse

from app.core.dependencies import get_current_user, is_admin
from app.database import get_db
from app.security.audit import verify_audit_chain

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESEARCH_RESULTS = os.path.join(PROJECT_ROOT, "app", "models", "research_results.json")
TEST_REPORT = os.path.join(PROJECT_ROOT, "results", "verification", "latest_test_run.json")
FAVICON = os.path.join(PROJECT_ROOT, "app", "static", "favicon.svg")

# Each non-interference card on the dashboard and the real tests that verify it.
NON_INTERFERENCE_FILE = "tests/test_non_interference.py"
PROPERTY_TESTS = {
    "Single Resource Access": ["test_legitimate_single_resource_access_not_interfered"],
    "Nested Hierarchy Access": ["test_legitimate_children_traversal_not_interfered"],
    "Insecure Endpoint Isolation": ["test_insecure_endpoint_not_interfered"],
    "High-to-Low Confidentiality": ["test_protected_response_is_independent_of_foreign_secret_change"],
    "Secret Mutation Independence": ["test_protected_response_is_independent_of_foreign_secret_change",
                                     "test_vulnerable_baseline_exposes_foreign_secret_change"],
    "Derived-Value Independence": ["test_protected_count_does_not_reveal_foreign_child",
                                   "test_insecure_count_reveals_foreign_child"],
}

router = APIRouter()


def _read_json(path: str):
    try:
        with open(path, encoding="utf-8") as file:
            return json.load(file)
    except (OSError, ValueError):
        return None


@router.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse(FAVICON, media_type="image/svg+xml")


@router.get("/api/v1/research/results")
def research_results():
    """Ablation, tool comparison, latency and multi-seed results
    (built by scripts/build_dashboard_results.py from the experiment outputs)."""
    data = _read_json(RESEARCH_RESULTS)
    if data is None:
        raise HTTPException(status_code=404, detail="Run `python -m scripts.build_dashboard_results` first")
    return data


@router.get("/api/v1/security/blind-spot-live")
def blind_spot_live(db: sqlite3.Connection = Depends(get_db)):
    """How the advisory predictor did on real traffic: every blind-spot denial
    Layer 2 records carries the prediction made before the request ran."""
    predicted = db.execute("SELECT COUNT(*) FROM layer_events WHERE event = 'BLIND_SPOT_PREDICTED'").fetchone()[0]
    caught = db.execute(
        "SELECT detail FROM layer_events WHERE event = 'L1_BLIND_SPOT_CAUGHT_BY_L2'"
    ).fetchall()
    flagged = missed = unscored = 0
    for (detail,) in caught:
        match = re.search(r"predicted p=([0-9.]+)", detail or "")
        if not match:
            unscored += 1
        elif float(match.group(1)) >= 0.5:
            flagged += 1
        else:
            missed += 1
    scored = flagged + missed
    return {
        "requests_predicted_as_blind_spots": predicted,
        "blind_spot_denials": len(caught),
        "denials_flagged_in_advance": flagged,
        "denials_missed": missed,
        "denials_without_prediction": unscored,
        "live_recall": round(flagged / scored, 4) if scored else None,
        "note": ("Recall = share of blind-spot denials the model had flagged before the request ran. "
                 "Precision is not shown: predictions are per request and denials per object, so they "
                 "cannot be paired exactly."),
    }


@router.get("/api/v1/verification/test-report")
def test_report():
    """Outcome of the last real `python -m pytest` run, and each non-interference
    property's status from the tests that verify it."""
    data = _read_json(TEST_REPORT)
    if data is None:
        return {"available": False, "reason": "No test run recorded yet. Run `python -m pytest -q`."}
    tests = data.get("tests", {})
    properties = []
    for name, functions in PROPERTY_TESTS.items():
        outcomes = [tests.get(f"{NON_INTERFERENCE_FILE}::{function}") for function in functions]
        if any(o == "failed" for o in outcomes):
            status = "FAIL"
        elif outcomes and all(o == "passed" for o in outcomes):
            status = "PASS"
        else:
            status = "NOT RUN"
        properties.append({"name": name, "status": status, "tests": functions})
    return {
        "available": True,
        "finished_at": data.get("finished_at"),
        "last_run": data.get("last_run", {}),
        "properties": properties,
    }


@router.get("/api/v1/audit/integrity")
def audit_integrity(db: sqlite3.Connection = Depends(get_db)):
    """Recompute the audit log's hash chain (tamper evidence)."""
    return verify_audit_chain(db)


@router.get("/api/v1/audit/timeline")
def audit_timeline(
    bucket: str = Query("day", pattern="^(day|hour)$"),
    span: int = Query(14, ge=1, le=90),
    db: sqlite3.Connection = Depends(get_db),
):
    """Allowed and denied decisions per day (or per hour) for the recent span."""
    if bucket == "day":
        key, window = "strftime('%Y-%m-%d', timestamp)", f"-{span} days"
    else:
        key, window = "strftime('%Y-%m-%d %H:00', timestamp)", f"-{span} hours"
    rows = db.execute(
        f"""
        SELECT {key} AS bucket,
               SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) AS allowed,
               SUM(CASE WHEN decision = 'DENY' THEN 1 ELSE 0 END) AS denied
        FROM audit_logs
        WHERE timestamp >= datetime('now', ?)
        GROUP BY bucket ORDER BY bucket
        """,
        (window,),
    ).fetchall()
    return {"bucket": bucket, "span": span, "timezone": "UTC", "points": [dict(row) for row in rows]}


@router.get("/api/v1/audit-logs")
def audit_logs(
    limit: int = Query(25, ge=1, le=200),
    offset: int = Query(0, ge=0),
    layer: str | None = Query(None, pattern="^(L1|L2)$"),
    user_id: int | None = None,
    decision: str | None = Query(None, pattern="^(ALLOW|DENY)$"),
    risk: str | None = Query(None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$"),
    db: sqlite3.Connection = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """ADMIN only: audit rows, newest first, filterable and paginated."""
    if not is_admin(current_user):
        raise HTTPException(status_code=403, detail="Admin access required")
    clauses, params = [], []
    for column, value in (("a.layer", layer), ("a.user_id", user_id), ("a.decision", decision), ("a.risk_level", risk)):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(value)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    total = db.execute(f"SELECT COUNT(*) FROM audit_logs AS a {where}", params).fetchone()[0]
    rows = db.execute(
        f"""
        SELECT a.id, a.timestamp, a.user_id, a.role, a.operation, a.object_type, a.object_id, a.path,
               a.decision, a.reason, a.risk_score, a.risk_level, a.layer,
               COALESCE(NULLIF(u.display_name, ''), u.username, CAST(a.user_id AS TEXT)) AS actor_name
        FROM audit_logs AS a LEFT JOIN users AS u ON u.id = a.user_id
        {where}
        ORDER BY a.id DESC LIMIT ? OFFSET ?
        """,
        (*params, limit, offset),
    ).fetchall()
    return {"total": total, "limit": limit, "offset": offset, "logs": [dict(row) for row in rows]}
