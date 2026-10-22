"""
Live behavioural telemetry: the behavioural model's session features, computed
from the gateway's own audit log instead of being typed in by hand.

Each audit row is one object-level authorization decision (Layer 1, or Layer 2
for objects Layer 1 never saw), so a "request" here is one such decision.
Window: the last WINDOW_MINUTES per user.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

WINDOW_MINUTES = 15
BURST_SECONDS = 60


def _enumeration_score(object_ids: list[int]) -> float:
    """Share of consecutive distinct object IDs that differ by exactly 1."""
    ids = sorted(set(object_ids))
    if len(ids) < 2:
        return 0.0
    return round(sum(1 for a, b in zip(ids, ids[1:]) if b - a == 1) / (len(ids) - 1), 4)


def _burst_rate(timestamps: list[datetime]) -> float:
    """Most decisions inside any BURST_SECONDS window, as decisions per minute."""
    times = sorted(timestamps)
    best, start = 0, 0
    for end, current in enumerate(times):
        while (current - times[start]).total_seconds() > BURST_SECONDS:
            start += 1
        best = max(best, end - start + 1)
    return round(best * 60 / BURST_SECONDS, 2)


def session_features(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """The 10 behavioural features (app.benchmarks.behavioral_dataset.FEATURE_NAMES)."""
    object_ids = [row["object_id"] for row in rows if row["object_id"] is not None]
    timestamps = [datetime.fromisoformat(str(row["timestamp"])) for row in rows if row["timestamp"]]
    total = len(rows)
    return {
        "requests_per_window": total,
        "distinct_objects_count": len(set(object_ids)),
        "requests_per_minute": round(total / WINDOW_MINUTES, 2),
        "repeated_target_count": total - len(set(object_ids)),
        "recent_denials_count": sum(1 for row in rows if row["decision"] == "DENY"),
        "cross_owner_attempts_count": sum(1 for row in rows if row["cross_owner"]),
        "nested_relationship_count": sum(1 for row in rows if "." in (row["path"] or "")),
        "max_query_depth": max((len((row["path"] or "").split(".")) for row in rows), default=0),
        "enumeration_score": _enumeration_score(object_ids),
        "request_burst_rate": _burst_rate(timestamps),
    }


def live_sessions(conn, window_minutes: int = WINDOW_MINUTES) -> list[dict[str, Any]]:
    """Per-user feature vectors for every user active in the window."""
    rows = conn.execute(
        """
        SELECT a.user_id, a.object_id, a.path, a.decision, a.timestamp,
               COALESCE(NULLIF(u.display_name, ''), u.username, CAST(a.user_id AS TEXT)) AS actor,
               CASE WHEN UPPER(COALESCE(a.role, '')) != 'ADMIN'
                         AND o.owner_id IS NOT NULL AND o.owner_id != a.user_id
                    THEN 1 ELSE 0 END AS cross_owner
        FROM audit_logs AS a
        LEFT JOIN users AS u ON u.id = a.user_id
        LEFT JOIN objects AS o ON o.id = a.object_id
        WHERE a.user_id IS NOT NULL AND a.timestamp >= datetime('now', ?)
        ORDER BY a.user_id, a.timestamp
        """,
        (f"-{int(window_minutes)} minutes",),
    ).fetchall()

    by_user: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        by_user.setdefault(row["user_id"], []).append(dict(row))

    blind_spots = {
        row[0]: row[1]
        for row in conn.execute(
            "SELECT user_id, COUNT(*) FROM layer_events WHERE event = 'L1_BLIND_SPOT_CAUGHT_BY_L2' "
            "AND timestamp >= datetime('now', ?) GROUP BY user_id",
            (f"-{int(window_minutes)} minutes",),
        )
    }
    return [
        {
            "user_id": user_id,
            "actor": user_rows[0]["actor"],
            "layer1_blind_spot_denials": blind_spots.get(user_id, 0),
            "features": session_features(user_rows),
        }
        for user_id, user_rows in by_user.items()
    ]
