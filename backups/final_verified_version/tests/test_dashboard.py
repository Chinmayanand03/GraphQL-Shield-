from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_dashboard_ui_loads():
    res = client.get("/dashboard")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "GraphQL Shield Dashboard" in res.text

def test_dashboard_stats_loads():
    res = client.get("/api/v1/dashboard-stats")
    assert res.status_code == 200
    data = res.json()
    assert "stats" in data
    assert "recent_logs" in data
