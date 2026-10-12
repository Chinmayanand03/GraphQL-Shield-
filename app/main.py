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
    "alice": "bala",
    "bala": "alice",
    "bob": "kapilesh",
    "kapilesh": "bob",
    "charlie": "chinmay",
    "chinmay": "charlie",
}


@app.post("/api/v1/auth/login")
def login(request: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    """Development login endpoint with friendly and legacy username aliases."""
    expected_hash = f"hash_{request.password}"
    requested_username = request.username.strip().lower()
    candidates = [requested_username]
    alias = LOGIN_USERNAME_ALIASES.get(requested_username)
    if alias and alias not in candidates:
        candidates.append(alias)

    cursor = db.cursor()
    user = None
    for candidate in candidates:
        cursor.execute(
            "SELECT id, role FROM users WHERE username = ? AND password_hash = ?",
            (candidate, expected_hash),
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
                           WHEN 'chinmay' THEN 'Agnihotram Chinmayanand'
                           WHEN 'charlie' THEN 'Agnihotram Chinmayanand'
                           WHEN 'bala' THEN 'B.V. Balanilavan'
                           WHEN 'alice' THEN 'B.V. Balanilavan'
                           WHEN 'kapilesh' THEN 'Kapilesh N'
                           WHEN 'bob' THEN 'Kapilesh N'
                           WHEN 'sakthivel' THEN 'Sakthivel B'
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
                       WHEN 'chinmay' THEN 'Agnihotram Chinmayanand'
                       WHEN 'charlie' THEN 'Agnihotram Chinmayanand'
                       WHEN 'bala' THEN 'B.V. Balanilavan'
                       WHEN 'alice' THEN 'B.V. Balanilavan'
                       WHEN 'kapilesh' THEN 'Kapilesh N'
                       WHEN 'bob' THEN 'Kapilesh N'
                       WHEN 'sakthivel' THEN 'Sakthivel B'
                       ELSE u.username
                   END AS display_name,
                   COALESCE(
                       CASE u.username
                           WHEN 'chinmay' THEN 'Agnihotram Chinmayanand'
                           WHEN 'charlie' THEN 'Agnihotram Chinmayanand'
                           WHEN 'bala' THEN 'B.V. Balanilavan'
                           WHEN 'alice' THEN 'B.V. Balanilavan'
                           WHEN 'kapilesh' THEN 'Kapilesh N'
                           WHEN 'bob' THEN 'Kapilesh N'
                           WHEN 'sakthivel' THEN 'Sakthivel B'
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
        {"username": "chinmay", "legacy_username": "charlie", "display_name": "Agnihotram Chinmayanand", "role": "ADMIN"},
        {"username": "bala", "legacy_username": "alice", "display_name": "B.V. Balanilavan", "role": "USER"},
        {"username": "kapilesh", "legacy_username": "bob", "display_name": "Kapilesh N", "role": "USER"},
        {"username": "sakthivel", "legacy_username": None, "display_name": "Sakthivel B", "role": "USER"},
    ):
        candidates = [persona["username"]]
        if persona["legacy_username"]:
            candidates.append(persona["legacy_username"])
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
        if row is None:
            continue
        item = dict(row)
        # Expose the friendly login alias on the dashboard even when a test DB
        # was freshly seeded with legacy usernames for backwards compatibility.
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
    }


@app.get("/dashboard", response_class=HTMLResponse)
def read_dashboard():
    """Serve the dashboard HTML."""
    with open("app/static/dashboard.html", "r", encoding="utf-8") as file:
        return file.read()


# Protected Strawberry GraphQL router
graphql_app = GraphQLRouter(
    schema,
    context_getter=None,
    dependencies=[Depends(bola_enforcement_middleware)],
)
app.include_router(graphql_app, prefix="/graphql")


# Intentionally vulnerable endpoint for benchmark comparison
insecure_graphql_app = GraphQLRouter(
    schema,
    context_getter=None,
)
app.include_router(
    insecure_graphql_app,
    prefix="/graphql-insecure",
)

