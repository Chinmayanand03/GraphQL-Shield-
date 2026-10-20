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
    assert "demo_users" in data


def test_dashboard_demo_users_display():
    res = client.get("/api/v1/dashboard-stats")
    assert res.status_code == 200
    data = res.json()
    demo_users = data["demo_users"]
    assert len(demo_users) == 4

    users_by_id = {u["id"]: u for u in demo_users}
    assert 101 in users_by_id
    assert users_by_id[101]["username"] == "balanilavan"
    assert users_by_id[101]["role"].upper() == "USER"
    assert users_by_id[101]["display_name"] == "B.V. Balanilavan"

    assert 102 in users_by_id
    assert users_by_id[102]["username"] == "kapilesh"
    assert users_by_id[102]["role"].upper() == "USER"
    assert users_by_id[102]["display_name"] == "Kapilesh N"

    assert 103 in users_by_id
    assert users_by_id[103]["username"] == "sakthivel"
    assert users_by_id[103]["role"].upper() == "USER"
    assert users_by_id[103]["display_name"] == "Sakthivel B"

    assert 104 in users_by_id
    assert users_by_id[104]["username"] == "chinmayanand"
    assert users_by_id[104]["role"].upper() == "ADMIN"
    assert users_by_id[104]["display_name"] == "Admin Demo Account"
    assert "Agnihotram" not in users_by_id[104]["display_name"]

