from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import JSONResponse
from strawberry.fastapi import GraphQLRouter
from pydantic import BaseModel
import sqlite3

from app.config import settings
from app.database import init_db, get_db
from app.graphql.schema import schema
from app.core.security import create_access_token
from app.core.dependencies import get_current_user

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Schema-Aware Security Gateway for Preventing GraphQL BOLA Vulnerabilities"
)

# Initialize database on startup
@app.on_event("startup")
def startup_event():
    init_db()

# Basic REST health check
@app.get("/health")
def health_check():
    return {"status": "ok", "message": "FastAPI is running"}

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/v1/auth/login")
def login(request: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    """
    Development login endpoint.
    Expects seed usernames like 'alice', 'bob'.
    Seed passwords are structured as 'username123' matching 'hash_username123' in the DB.
    """
    expected_hash = f"hash_{request.password}"
    
    cursor = db.cursor()
    cursor.execute(
        "SELECT id, role FROM users WHERE username = ? AND password_hash = ?", 
        (request.username, expected_hash)
    )
    user = cursor.fetchone()
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
        
    access_token = create_access_token(user_id=user['id'], role=user['role'])
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/v1/protected")
def protected_route(current_user: dict = Depends(get_current_user)):
    """
    A protected route to demonstrate successful JWT extraction.
    """
    return {
        "message": "You are successfully authenticated via JWT",
        "user": current_user
    }

@app.get("/api/v1/audit-logs")
def get_audit_logs(db: sqlite3.Connection = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """
    Retrieve security audit logs. Restricted to ADMIN users only.
    """
    if current_user.get("role", "").upper() != "ADMIN":
        raise HTTPException(status_code=403, detail="Admin access required")
        
    cursor = db.cursor()
    cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 50")
    logs = [dict(row) for row in cursor.fetchall()]
    return {"logs": logs}

from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import os

# Create static dir if not exists
os.makedirs("app/static", exist_ok=True)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

@app.get("/api/v1/dashboard-stats")
def get_dashboard_stats(db: sqlite3.Connection = Depends(get_db)):
    """
    Open endpoint serving stats for the static dashboard purely for demonstration.
    """
    cursor = db.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM audit_logs")
    total_requests = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE decision = 'ALLOW'")
    allowed = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE decision = 'DENY'")
    blocked = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE reason IN ('OWNERSHIP_MISMATCH', 'NESTED_AUTHORIZATION_VIOLATION')")
    bola_attempts = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE risk_level = 'HIGH'")
    high_risk = cursor.fetchone()[0]
    
    cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 15")
    recent_logs = [dict(row) for row in cursor.fetchall()]
    
    return {
        "stats": {
            "total": total_requests,
            "allowed": allowed,
            "blocked": blocked,
            "bola": bola_attempts,
            "high_risk": high_risk
        },
        "recent_logs": recent_logs
    }

@app.get("/dashboard", response_class=HTMLResponse)
def read_dashboard():
    """Serves the simple HTML dashboard UI"""
    with open("app/static/dashboard.html", "r", encoding="utf-8") as f:
        return f.read()

from app.security.enforcement import bola_enforcement_middleware

# Secure Strawberry GraphQL router protected by the BOLA security gateway
graphql_app = GraphQLRouter(schema, context_getter=None, dependencies=[Depends(bola_enforcement_middleware)])
app.include_router(graphql_app, prefix="/graphql")

# Insecure Strawberry GraphQL router (Phase 11 Benchmark Baseline)
insecure_graphql_app = GraphQLRouter(schema, context_getter=None)
app.include_router(insecure_graphql_app, prefix="/graphql-insecure")
