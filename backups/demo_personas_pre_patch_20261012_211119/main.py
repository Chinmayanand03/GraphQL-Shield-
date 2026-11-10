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
def login(
    request: LoginRequest,
    db: sqlite3.Connection = Depends(get_db),
):
    """
    Development login endpoint.
    Expects seeded usernames such as alice and bob.
    """
    expected_hash = f"hash_{request.password}"

    cursor = db.cursor()
    cursor.execute(
        """
        SELECT id, role
        FROM users
        WHERE username = ? AND password_hash = ?
        """,
        (request.username, expected_hash),
    )
    user = cursor.fetchone()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    access_token = create_access_token(
        user_id=user["id"],
        role=user["role"],
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


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
def get_dashboard_stats(
    db: sqlite3.Connection = Depends(get_db),
):
    """Provide audit statistics for the demonstration dashboard."""
    cursor = db.cursor()

    cursor.execute("SELECT COUNT(*) FROM audit_logs")
    total_requests = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM audit_logs WHERE decision = 'ALLOW'"
    )
    allowed = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM audit_logs WHERE decision = 'DENY'"
    )
    blocked = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*) FROM audit_logs
        WHERE reason IN (
            'OWNERSHIP_MISMATCH',
            'NESTED_AUTHORIZATION_VIOLATION'
        )
        """
    )
    bola_attempts = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM audit_logs WHERE risk_level = 'HIGH'"
    )
    high_risk = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT a.*, u.username AS username, u.username AS actor_name
        FROM audit_logs AS a
        LEFT JOIN users AS u ON u.id = a.user_id
        ORDER BY a.timestamp DESC
        LIMIT 15
        """
    )
    recent_logs = [dict(row) for row in cursor.fetchall()]

    return {
        "stats": {
            "total": total_requests,
            "allowed": allowed,
            "blocked": blocked,
            "bola": bola_attempts,
            "high_risk": high_risk,
        },
        "recent_logs": recent_logs,
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

