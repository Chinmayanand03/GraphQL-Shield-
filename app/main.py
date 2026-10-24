import json
import logging
import os
import sqlite3
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from strawberry.fastapi import GraphQLRouter

from app.config import check_production_settings, settings
from app.database import init_db, get_db
from app.graphql.schema import schema
from app.core.security import create_access_token
from app.core.dependencies import get_current_user, get_optional_user, is_admin
from app.core.passwords import verify_password
from app.security.taint_request_explainer import router as taint_explainer_router
from app.security.enforcement import bola_enforcement_middleware
from app.security.layers import layer_summary, set_layers
from app.clinic.api import router as clinic_router
from app.clinic.data import init_clinic
from app.dashboard_api import router as dashboard_router

logger = logging.getLogger("graphql_shield.auth")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize application resources when FastAPI starts."""
    check_production_settings()
    init_db()
    init_clinic()
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "Schema-Aware Security Gateway for Preventing "
        "GraphQL BOLA Vulnerabilities"
    ),
    lifespan=lifespan,
)


# Basic REST health check
app.include_router(taint_explainer_router)
# Second evaluation application (schema-first graphql-core), protected by the same two layers.
app.include_router(clinic_router)
# Evidence panels: research results, live predictor recall, test report, audit integrity.
app.include_router(dashboard_router)

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "message": "FastAPI is running",
    }


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/v1/auth/login")
def login(request: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    """Development login endpoint. Demo passwords follow <username>123."""
    user = db.execute(
        "SELECT id, role, password_hash FROM users WHERE username = ?",
        (request.username.strip().lower(),),
    ).fetchone()

    if not user or not verify_password(request.password, user["password_hash"]):
        # The client gets one generic message; the server log says why, so a
        # failed sign-in can be diagnosed. The password itself is never logged.
        logger.warning(
            "Login failed for username %r: %s (password length %d%s)",
            request.username,
            "unknown username" if not user else "wrong password",
            len(request.password),
            ", has leading/trailing spaces" if request.password != request.password.strip() else "",
        )
        raise HTTPException(status_code=401, detail="Invalid username or password")

    access_token = create_access_token(user_id=user["id"], role=user["role"])
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/api/v1/protected")
def protected_route(
    current_user: dict = Depends(get_current_user),
):
    """Demonstrate successful JWT extraction."""
    return {
        "message": "You are successfully authenticated via JWT",
        "user": current_user,
    }


# /api/v1/audit-logs (admin, filterable, paginated) lives in app/dashboard_api.py.


# Static dashboard assets
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)

app.mount(
    "/static",
    StaticFiles(directory=STATIC_DIR),
    name="static",
)


@app.get("/api/v1/dashboard-stats")
def get_dashboard_stats(
    db: sqlite3.Connection = Depends(get_db),
    current_user: dict | None = Depends(get_optional_user),
):
    """Return dashboard metrics and demo-user metadata.

    The aggregate counters are public; the recent audit rows (who touched which
    object) are returned only to an ADMIN token, matching /api/v1/audit-logs.
    """
    cursor = db.cursor()

    cursor.execute("SELECT COUNT(*) FROM audit_logs")
    total_requests = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE decision = 'ALLOW'")
    allowed = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE decision = 'DENY'")
    blocked = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*) FROM audit_logs
        WHERE reason IN ('OWNERSHIP_MISMATCH', 'NESTED_AUTHORIZATION_VIOLATION')
        """
    )
    bola_attempts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE risk_level = 'HIGH'")
    high_risk = cursor.fetchone()[0]

    logs_visible = is_admin(current_user)
    recent_logs = []
    if logs_visible:
        cursor.execute(
            """
            SELECT a.*,
                   u.username AS username,
                   COALESCE(NULLIF(u.display_name, ''), u.username) AS display_name,
                   COALESCE(NULLIF(u.display_name, ''), u.username, CAST(a.user_id AS TEXT)) AS actor_name,
                   COALESCE(u.role, a.role) AS actor_role
            FROM audit_logs AS a
            LEFT JOIN users AS u ON u.id = a.user_id
            ORDER BY a.timestamp DESC
            LIMIT 15
            """
        )
        recent_logs = [dict(row) for row in cursor.fetchall()]

    cursor.execute(
        """
        SELECT id, username, UPPER(role) AS role,
               COALESCE(NULLIF(display_name, ''), username) AS display_name
        FROM users ORDER BY id
        """
    )
    demo_users = [dict(row) for row in cursor.fetchall()]

    return {
        "stats": {
            "total": total_requests,
            "allowed": allowed,
            "blocked": blocked,
            "bola": bola_attempts,
            "high_risk": high_risk,
        },
        "recent_logs": recent_logs,
        "recent_logs_restricted": not logs_visible,
        "demo_users": demo_users,
        "research_evaluation": _research_evaluation_or_unavailable(db, current_user),
    }


class SessionScoreRequest(BaseModel):
    requests_per_window: int = 20
    distinct_objects_count: int = 5
    requests_per_minute: float = 1.33
    repeated_target_count: int = 15
    recent_denials_count: int = 0
    cross_owner_attempts_count: int = 0
    nested_relationship_count: int = 2
    max_query_depth: int = 2
    enumeration_score: float = 0.05
    request_burst_rate: float = 2.5


def _model_service():
    """Import the ML service lazily so the security gateway starts even when the
    optional ML packages (pandas, scikit-learn, xgboost) are not installed."""
    try:
        from app.security import model_service
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Behavioral ML service unavailable: {exc}. Install requirements.txt to enable it.",
        )
    return model_service


def _research_evaluation(db, current_user: dict | None) -> dict:
    """Research metrics are public; provenance evidence and live per-user sessions
    are built from audit rows, so like the audit log they go only to an ADMIN token."""
    summary = _model_service().get_research_evaluation_summary(db)
    summary["provenance_evidence_restricted"] = not is_admin(current_user)
    if summary["provenance_evidence_restricted"]:
        summary["provenance_evidence"] = []
        if summary.get("behavioural_alerts_source") == "live":
            summary["behavioural_alerts"] = []
    return summary


def _research_evaluation_or_unavailable(db, current_user: dict | None):
    try:
        return _research_evaluation(db, current_user)
    except HTTPException as exc:
        return {"available": False, "reason": exc.detail}


@app.get("/api/v1/research-evaluation")
def get_research_evaluation(
    db: sqlite3.Connection = Depends(get_db),
    current_user: dict | None = Depends(get_optional_user),
):
    """Return empirical research evaluation metrics, provenance evidence, and model limits."""
    return _research_evaluation(db, current_user)


@app.post("/api/v1/telemetry/score-session")
def score_session(request: SessionScoreRequest):
    """Offline telemetry scoring for behavioural anomaly detection using rule baseline and XGBoost.

    Advisory only: this score never changes a Layer 1 / Layer 2 authorization decision."""
    return _model_service().score_session_telemetry(request.model_dump())


@app.get("/api/v1/telemetry/live-sessions")
def get_live_sessions(
    db: sqlite3.Connection = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """ADMIN only: behavioural features computed from the last 15 minutes of the
    audit log for each active user, scored by the rule baseline and XGBoost."""
    if not is_admin(current_user):
        raise HTTPException(status_code=403, detail="Admin access required")
    from app.security.live_telemetry import live_sessions

    service = _model_service()
    return {
        "sessions": [
            {**session, "score": service.score_session_telemetry(session["features"])}
            for session in live_sessions(db)
        ]
    }


class QueryScoreRequest(BaseModel):
    query: str
    variables: dict | None = None


@app.get("/api/v1/security/blind-spot-model")
def get_blind_spot_model():
    """Layer 1 blind-spot predictor: status, evaluation metrics and discovery run."""
    from app.security import blind_spot_model

    return blind_spot_model.summary()


@app.post("/api/v1/security/blind-spot-score")
def score_blind_spot(body: QueryScoreRequest, current_user: dict = Depends(get_current_user)):
    """Predict, without executing it, whether a query reaches objects Layer 1 cannot
    see, with per-feature explanations. Advisory only."""
    from app.security import blind_spot_model

    result = blind_spot_model.score_request(
        [{"query": body.query, "variables": body.variables}],
        caller_is_admin=is_admin(current_user),
        explain=True,
    )
    if result is None:
        raise HTTPException(status_code=400, detail="Query could not be parsed")
    return result


class LayerToggleRequest(BaseModel):
    layer1: bool | None = None
    layer2: bool | None = None


@app.get("/api/v1/security/layers")
def get_layers(current_user: dict | None = Depends(get_optional_user)):
    """Current Layer 1 / Layer 2 state and per-layer event counts. The recent
    per-object layer events are returned only to an ADMIN token."""
    summary = layer_summary()
    summary["toggle_enabled"] = settings.ENABLE_LAYER_TOGGLE
    summary["recent_restricted"] = not is_admin(current_user)
    if summary["recent_restricted"]:
        summary["recent"] = []
    return summary


@app.post("/api/v1/security/layers")
def toggle_layers(body: LayerToggleRequest, current_user: dict = Depends(get_current_user)):
    """ADMIN only: switch enforcement layers on/off to demonstrate the layer ablation live."""
    if not settings.ENABLE_LAYER_TOGGLE:
        raise HTTPException(status_code=403, detail="Layer toggling is disabled (ENABLE_LAYER_TOGGLE=false)")
    if not is_admin(current_user):
        raise HTTPException(status_code=403, detail="Admin access required")
    return {"layers": set_layers(body.layer1, body.layer2)}


@app.get("/api/v1/security/layer-ablation")
def get_layer_ablation():
    """Results of scripts/run_layer_ablation.py (the dual-layer ablation experiment)."""
    path = os.path.join(os.path.dirname(STATIC_DIR), "..", "results", "layer_ablation", "results.json")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Run `python -m scripts.run_layer_ablation` first")
    with open(path, encoding="utf-8") as file:
        return json.load(file)


@app.get("/dashboard", response_class=HTMLResponse)
def read_dashboard():
    """Serve the dashboard HTML."""
    html_path = os.path.join(STATIC_DIR, "dashboard.html")
    with open(html_path, "r", encoding="utf-8") as file:
        return file.read()


# Protected Strawberry GraphQL router.
# Queries over GET are disabled so every operation passes through the Layer 1 gate
# (Layer 2 would still filter foreign objects, but GET gives no reason to exist here).
graphql_app = GraphQLRouter(
    schema,
    context_getter=None,
    dependencies=[Depends(bola_enforcement_middleware)],
    allow_queries_via_get=False,
)
app.include_router(graphql_app, prefix="/graphql")


def require_insecure_baseline(current_user: dict = Depends(get_current_user)):
    """The vulnerable baseline is for benchmarking only: it needs a valid token and can be
    switched off completely with ENABLE_INSECURE_BASELINE=false."""
    if not settings.ENABLE_INSECURE_BASELINE:
        raise HTTPException(status_code=404, detail="Insecure benchmark baseline is disabled")
    return current_user


# Intentionally vulnerable endpoint for benchmark comparison
insecure_graphql_app = GraphQLRouter(
    schema,
    context_getter=None,
    dependencies=[Depends(require_insecure_baseline)],
    allow_queries_via_get=False,
)
app.include_router(
    insecure_graphql_app,
    prefix="/graphql-insecure",
)

