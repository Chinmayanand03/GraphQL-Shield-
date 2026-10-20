import json
import os
import sqlite3
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from strawberry.fastapi import GraphQLRouter

from app.config import settings
from app.database import init_db, get_db
from app.graphql.schema import schema
from app.core.security import create_access_token
from app.core.dependencies import get_current_user
from app.security.taint_request_explainer import router as taint_explainer_router
from app.security.enforcement import bola_enforcement_middleware
from app.security.layers import layer_summary, set_layers


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize application resources when FastAPI starts."""
    init_db()
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

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "message": "FastAPI is running",
    }


class LoginRequest(BaseModel):
    username: str
    password: str


LOGIN_USERNAME_ALIASES = {
    "balanilavan": ["bala"],
    "bala": ["balanilavan"],

    "kapilesh": ["kapil"],
    "kapil": ["kapilesh"],

    "chinmayanand": ["chinmay"],
    "chinmay": ["chinmayanand"],

    "sakthivel": ["sakthi"],
    "sakthi": ["sakthivel"],
}

PASSWORD_ALIASES = {
    "balanilavan123": ["bala123"],
    "bala123": ["balanilavan123"],

    "kapilesh123": ["kapil123"],
    "kapil123": ["kapilesh123"],

    "sakthivel123": ["sakthi123"],
    "sakthi123": ["sakthivel123"],

    "chinmay123": ["chinmayanand123"],
    "chinmayanand123": ["chinmay123"],
}



@app.post("/api/v1/auth/login")
def login(request: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    """Development login endpoint with friendly and legacy username aliases."""
    requested_username = request.username.strip().lower()
    candidates = [requested_username]
    aliases = LOGIN_USERNAME_ALIASES.get(requested_username, [])
    if isinstance(aliases, str):
        aliases = [aliases]
    for alias in aliases:
        if alias not in candidates:
            candidates.append(alias)

    expected_passwords = [request.password]
    for alt in PASSWORD_ALIASES.get(request.password, []):
        if alt not in expected_passwords:
            expected_passwords.append(alt)
    expected_hashes = [f"hash_{p}" for p in expected_passwords]

    cursor = db.cursor()
    user = None
    for candidate in candidates:
        placeholders = ", ".join("?" for _ in expected_hashes)
        cursor.execute(
            f"SELECT id, role FROM users WHERE username = ? AND password_hash IN ({placeholders})",
            (candidate, *expected_hashes),
        )
        user = cursor.fetchone()
        if user:
            break

    if not user:
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


@app.get("/api/v1/audit-logs")
def get_audit_logs(
    db: sqlite3.Connection = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Restrict audit log access to administrators."""
    if current_user.get("role", "").upper() != "ADMIN":
        raise HTTPException(
            status_code=403,
            detail="Admin access required",
        )

    cursor = db.cursor()
    cursor.execute(
        "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 50"
    )
    logs = [dict(row) for row in cursor.fetchall()]

    return {"logs": logs}


# Static dashboard assets
os.makedirs("app/static", exist_ok=True)

app.mount(
    "/static",
    StaticFiles(directory="app/static"),
    name="static",
)


@app.get("/api/v1/dashboard-stats")
def get_dashboard_stats(db: sqlite3.Connection = Depends(get_db)):
    """Return dashboard metrics, recent audit events, and safe demo-user metadata."""
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

    user_columns = {
        row[1] for row in cursor.execute("PRAGMA table_info(users)").fetchall()
    }
    if "display_name" in user_columns:
        cursor.execute(
            """
            SELECT a.*,
                   u.username AS username,
                   u.display_name AS display_name,
                   COALESCE(
                       NULLIF(u.display_name, ''),
                       CASE u.username
                           WHEN 'chinmayanand' THEN 'Admin Demo Account'
                           WHEN 'chinmay' THEN 'Admin Demo Account'
                           WHEN 'balanilavan' THEN 'B.V. Balanilavan'
                           WHEN 'bala' THEN 'B.V. Balanilavan'
                           WHEN 'kapilesh' THEN 'Kapilesh N'
                           WHEN 'kapil' THEN 'Kapilesh N'
                           WHEN 'sakthivel' THEN 'Sakthivel B'
                           WHEN 'sakthi' THEN 'Sakthivel B'
                           ELSE u.username
                       END,
                       CAST(a.user_id AS TEXT)
                    ) AS actor_name,
                   COALESCE(u.role, a.role) AS actor_role
            FROM audit_logs AS a
            LEFT JOIN users AS u ON u.id = a.user_id
            ORDER BY a.timestamp DESC
            LIMIT 15
            """
        )
    else:
        cursor.execute(
            """
            SELECT a.*,
                   u.username AS username,
                   CASE u.username
                       WHEN 'chinmayanand' THEN 'Admin Demo Account'
                       WHEN 'chinmay' THEN 'Admin Demo Account'
                       WHEN 'balanilavan' THEN 'B.V. Balanilavan'
                       WHEN 'bala' THEN 'B.V. Balanilavan'
                       WHEN 'kapilesh' THEN 'Kapilesh N'
                       WHEN 'kapil' THEN 'Kapilesh N'
                       WHEN 'sakthivel' THEN 'Sakthivel B'
                       WHEN 'sakthi' THEN 'Sakthivel B'
                       ELSE u.username
                   END AS display_name,
                   COALESCE(
                       CASE u.username
                           WHEN 'chinmayanand' THEN 'Admin Demo Account'
                           WHEN 'chinmay' THEN 'Admin Demo Account'
                           WHEN 'balanilavan' THEN 'B.V. Balanilavan'
                           WHEN 'bala' THEN 'B.V. Balanilavan'
                           WHEN 'kapilesh' THEN 'Kapilesh N'
                           WHEN 'kapil' THEN 'Kapilesh N'
                           WHEN 'sakthivel' THEN 'Sakthivel B'
                           WHEN 'sakthi' THEN 'Sakthivel B'
                           ELSE u.username
                       END,
                       CAST(a.user_id AS TEXT)
                   ) AS actor_name,
                   COALESCE(u.role, a.role) AS actor_role
            FROM audit_logs AS a
            LEFT JOIN users AS u ON u.id = a.user_id
            ORDER BY a.timestamp DESC
            LIMIT 15
            """
        )
    recent_logs = [dict(row) for row in cursor.fetchall()]

    demo_users = []
    for persona in (
        {
            "username": "balanilavan",
            "legacy_username": "bala",
            "display_name": "B.V. Balanilavan",
            "role": "USER",
            "id": 101,
        },
        {
            "username": "kapilesh",
            "legacy_username": "kapil",
            "display_name": "Kapilesh N",
            "role": "USER",
            "id": 102,
        },
        {
            "username": "sakthivel",
            "legacy_username": "sakthi",
            "display_name": "Sakthivel B",
            "role": "USER",
            "id": 103,
        },
        {
            "username": "chinmayanand",
            "legacy_username": "chinmay",
            "display_name": "Admin Demo Account",
            "role": "ADMIN",
            "id": 104,
        },
    ):
        candidates = [persona["username"]]
        if persona["legacy_username"]:
            candidates.append(persona["legacy_username"])
        legacy_lookup = {
            "balanilavan": ["bala"],
            "kapilesh": ["kapil"],
            "sakthivel": ["sakthi"],
            "chinmayanand": ["chinmay"],
        }
        for extra in legacy_lookup.get(persona["username"], []):
            if extra not in candidates:
                candidates.append(extra)
        placeholders = ", ".join("?" for _ in candidates)
        if "display_name" in user_columns:
            cursor.execute(
                f"SELECT id, username, role, display_name FROM users WHERE username IN ({placeholders}) ORDER BY CASE username WHEN ? THEN 0 ELSE 1 END LIMIT 1",
                (*candidates, persona["username"]),
            )
        else:
            cursor.execute(
                f"SELECT id, username, role FROM users WHERE username IN ({placeholders}) ORDER BY CASE username WHEN ? THEN 0 ELSE 1 END LIMIT 1",
                (*candidates, persona["username"]),
            )
        row = cursor.fetchone()
        if row is None and "id" in persona:
            cursor.execute(
                "SELECT id, username, role FROM users WHERE id = ?",
                (persona["id"],),
            )
            row = cursor.fetchone()
        if row is None:
            continue
        item = dict(row)
        # Expose canonical seeded identifiers and names on the dashboard
        item["id"] = persona["id"] if "id" in persona and persona["id"] else item.get("id")
        item["username"] = persona["username"]
        item["display_name"] = persona["display_name"]
        item["role"] = persona["role"]
        demo_users.append(item)

    return {
        "stats": {
            "total": total_requests,
            "allowed": allowed,
            "blocked": blocked,
            "bola": bola_attempts,
            "high_risk": high_risk,
        },
        "recent_logs": recent_logs,
        "demo_users": demo_users,
        "research_evaluation": _research_evaluation_or_unavailable(db),
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


def _research_evaluation_or_unavailable(db):
    try:
        return _model_service().get_research_evaluation_summary(db)
    except HTTPException as exc:
        return {"available": False, "reason": exc.detail}


@app.get("/api/v1/research-evaluation")
def get_research_evaluation(db: sqlite3.Connection = Depends(get_db)):
    """Return empirical research evaluation metrics, provenance evidence, and model limits."""
    return _model_service().get_research_evaluation_summary(db)


@app.post("/api/v1/telemetry/score-session")
def score_session(request: SessionScoreRequest):
    """Offline telemetry scoring for behavioural anomaly detection using rule baseline and XGBoost.

    Advisory only: this score never changes a Layer 1 / Layer 2 authorization decision."""
    return _model_service().score_session_telemetry(request.model_dump())


class LayerToggleRequest(BaseModel):
    layer1: bool | None = None
    layer2: bool | None = None


@app.get("/api/v1/security/layers")
def get_layers():
    """Current Layer 1 / Layer 2 state, per-layer event counts and recent layer events."""
    return layer_summary()


@app.post("/api/v1/security/layers")
def toggle_layers(body: LayerToggleRequest, current_user: dict = Depends(get_current_user)):
    """ADMIN only: switch enforcement layers on/off to demonstrate the layer ablation live."""
    if not settings.ENABLE_LAYER_TOGGLE:
        raise HTTPException(status_code=403, detail="Layer toggling is disabled (ENABLE_LAYER_TOGGLE=false)")
    if current_user.get("role", "").upper() != "ADMIN":
        raise HTTPException(status_code=403, detail="Admin access required")
    return {"layers": set_layers(body.layer1, body.layer2)}


@app.get("/api/v1/security/layer-ablation")
def get_layer_ablation():
    """Results of scripts/run_layer_ablation.py (the dual-layer ablation experiment)."""
    path = os.path.join("results", "layer_ablation", "results.json")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Run `python -m scripts.run_layer_ablation` first")
    with open(path, encoding="utf-8") as file:
        return json.load(file)


@app.get("/dashboard", response_class=HTMLResponse)
def read_dashboard():
    """Serve the dashboard HTML."""
    with open("app/static/dashboard.html", "r", encoding="utf-8") as file:
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

