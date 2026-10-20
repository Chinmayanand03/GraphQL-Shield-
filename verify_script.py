import httpx
import json
import sqlite3
import sys

BASE_URL = "http://localhost:8000"

def verify():
    print("--- Starting Verification ---")
    
    # Check Server
    try:
        r = httpx.get(f"{BASE_URL}/health")
        if r.status_code == 200:
            print("Server: PASS")
        else:
            print("Server: FAIL")
            return
    except Exception as e:
        print("Server: FAIL", e)
        return

    # Check Login
    r = httpx.post(f"{BASE_URL}/api/v1/auth/login", json={"username": "balanilavan", "password": "balanilavan123"})
    if r.status_code == 200 and "access_token" in r.json():
        print("Login: PASS")
        token = r.json()["access_token"]
    else:
        print("Login: FAIL")
        return

    # Check Demo 1 (Legitimate)
    query1 = {"query": "{ resource(id: 101) { id name } }"}
    r1 = httpx.post(f"{BASE_URL}/graphql", json=query1, headers={"Authorization": f"Bearer {token}"})
    if r1.status_code == 200 and "data" in r1.json():
        print("Legitimate request: PASS")
    else:
        print("Legitimate request: FAIL", r1.status_code, r1.text)
        return

    # Check Demo 2 (Direct BOLA)
    query2 = {"query": "{ resource(id: 102) { id name } }"}
    r2 = httpx.post(f"{BASE_URL}/graphql", json=query2, headers={"Authorization": f"Bearer {token}"})
    if r2.status_code == 403 and r2.json()["detail"]["reason"] == "OWNERSHIP_MISMATCH":
        print("Direct BOLA: PASS")
    else:
        print("Direct BOLA: FAIL", r2.status_code, r2.text)
        return

    # Check Demo 3 (Nested BOLA)
    query3 = {"query": "{ user(id: 101) { username resource(id: 102) { name } } }"}
    r3 = httpx.post(f"{BASE_URL}/graphql", json=query3, headers={"Authorization": f"Bearer {token}"})
    if r3.status_code == 403 and r3.json()["detail"]["reason"] == "NESTED_AUTHORIZATION_VIOLATION":
        print("Nested BOLA: PASS")
    else:
        print("Nested BOLA: FAIL", r3.status_code, r3.text)
        return

    # Check Demo 4 (Invalid JWT)
    query4 = {"query": "{ resource(id: 101) { id name } }"}
    r4 = httpx.post(f"{BASE_URL}/graphql", json=query4, headers={"Authorization": "Bearer fake"})
    if r4.status_code == 401:
        print("Invalid JWT: PASS")
    else:
        print("Invalid JWT: FAIL", r4.status_code, r4.text)
        return

    # Check Audit Logs
    conn = sqlite3.connect("shield.db")
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM audit_logs")
    count = cur.fetchone()[0]
    if count >= 3:
        print("Audit logging: PASS")
    else:
        print("Audit logging: FAIL")
        return

    # Check Dashboard API
    r_dash = httpx.get(f"{BASE_URL}/api/v1/dashboard-stats")
    if r_dash.status_code == 200 and r_dash.json()["stats"]["total"] >= 3:
        print("Dashboard: PASS")
    else:
        print("Dashboard: FAIL", r_dash.status_code)
        return

if __name__ == "__main__":
    verify()
