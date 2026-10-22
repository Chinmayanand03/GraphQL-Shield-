"""
Dual-layer enforcement state and cross-layer evidence.

GraphQL-Shield enforces object-level authorization in two independent layers:

  Layer 1  (pre-execution gate, app/security/enforcement.py)
           Parses the request before any resolver runs and checks every object ID
           it can find in the query text. Blocks the whole request on a mismatch,
           so state-changing operations never start.

  Layer 2  (execution-time guard, app/security/runtime_object_guard.py)
           Runs inside the GraphQL engine. It checks the arguments the engine
           actually coerced before a mutation resolver runs, and the objects the
           resolvers actually produced before they are returned. It does not depend
           on Layer 1's parsing being correct.

When Layer 2 denies an object that Layer 1 never evaluated, the request exposed a
Layer 1 blind spot (relationship traversal, inline fragments, parser differences).
Those events are recorded here so the gateway audits its own pre-execution check.
"""
from typing import Any

from app.database import get_db_connection

LAYER_STATE = {"layer1": True, "layer2": True}

EVENT_L1_BLOCKED = "L1_BLOCKED"
EVENT_L2_FILTERED = "L2_FILTERED"
EVENT_L2_MUTATION_BLOCKED = "L2_MUTATION_BLOCKED"
EVENT_L1_BLIND_SPOT = "L1_BLIND_SPOT_CAUGHT_BY_L2"
# Advisory: the blind-spot predictor expects this allowed request to reach objects
# Layer 1 cannot see (app/security/blind_spot_model.py). Never changes a decision.
EVENT_BLIND_SPOT_PREDICTED = "BLIND_SPOT_PREDICTED"


def is_enabled(layer: str) -> bool:
    return bool(LAYER_STATE.get(layer, True))


def set_layers(layer1: bool | None = None, layer2: bool | None = None) -> dict:
    if layer1 is not None:
        LAYER_STATE["layer1"] = bool(layer1)
    if layer2 is not None:
        LAYER_STATE["layer2"] = bool(layer2)
    return dict(LAYER_STATE)


def mark_layer1_checked(request: Any, object_type: str, object_id: Any) -> None:
    """Remember which objects Layer 1 evaluated for this request."""
    state = getattr(request, "state", None)
    if state is None:
        return
    checked = getattr(state, "layer1_checked", None)
    if checked is None:
        checked = set()
        state.layer1_checked = checked
    checked.add((str(object_type).lower(), str(object_id)))


def layer1_saw(request: Any, object_type: str, object_id: Any) -> bool:
    checked = getattr(getattr(request, "state", None), "layer1_checked", None) or set()
    return (str(object_type).lower(), str(object_id)) in checked


def record_layer_event(user_id, layer: str, event: str, object_type=None, object_id=None, path=None, detail="") -> None:
    try:
        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO layer_events (user_id, layer, event, object_type, object_id, path, detail) VALUES (?,?,?,?,?,?,?)",
                (user_id, layer, event, object_type, object_id, path, detail),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        # Evidence recording must never change an enforcement decision.
        pass


def layer_summary(limit: int = 25) -> dict:
    conn = get_db_connection()
    try:
        counts = {row["event"]: row["n"] for row in conn.execute(
            "SELECT event, COUNT(*) AS n FROM layer_events GROUP BY event")}
        recent = [dict(row) for row in conn.execute(
            "SELECT * FROM layer_events ORDER BY id DESC LIMIT ?", (limit,))]
    finally:
        conn.close()
    return {"layers": dict(LAYER_STATE), "counts": counts, "recent": recent}
