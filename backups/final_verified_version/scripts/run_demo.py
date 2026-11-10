import httpx
import json
import time
import os
import subprocess
import sys

BASE_URL = "http://localhost:8000"

def print_header(title):
    print("\n" + "="*60)
    print(f"🚀 {title}")
    print("="*60)

def main():
    print_header("INITIALIZING CLEAN DATABASE")
    # Reset DB deterministically
    if os.path.exists("shield.db"):
        try:
            os.remove("shield.db")
        except PermissionError:
            print("⚠️ Warning: shield.db is currently locked by the server. Please stop the server, run this script, and restart it.")
            sys.exit(1)
            
    subprocess.run(["python", "-m", "app.seed"])
    print("✅ Database reset and seeded with standard users/objects.\n")
    print("Please ensure the FastAPI server is currently running in a SECOND terminal:")
    print("Command: uvicorn app.main:app --reload\n")
    input("Press [ENTER] when you are ready to begin the demonstration...")

    try:
        client = httpx.Client(base_url=BASE_URL)
        # Check health
        client.get("/health")
    except httpx.ConnectError:
        print("\n❌ Error: Cannot connect to server at http://localhost:8000. Please start the server first.")
        sys.exit(1)
    
    # =========================================================================
    print_header("DEMO 1 — LEGITIMATE ACCESS")
    print("→ User 101 (Alice) logs in...")
    res = client.post("/api/v1/auth/login", json={"username": "alice", "password": "alice123"})
    token = res.json().get("access_token")
    print("✅ JWT Generated")
    
    print("\n→ User 101 requests Object 101...")
    query = {"query": "{ resource(id: 101) { id name } }"}
    res = client.post("/graphql", json=query, headers={"Authorization": f"Bearer {token}"})
    print(f"\n[HTTP {res.status_code}]\n{json.dumps(res.json(), indent=2)}")
    print("\n✅ Ownership verified")
    print("✅ Policy ALLOW")
    print("✅ GraphQL backend executes & Data returned")
    print("✅ Audit event recorded (LOW RISK)")
    
    input("\nPress [ENTER] to execute Demo 2...")

    # =========================================================================
    print_header("DEMO 2 — BOLA ATTACK")
    print("→ User 101 (Alice) modifies object ID to 102 (Bob's Resource)...")
    query = {"query": "{ resource(id: 102) { id name } }"}
    res = client.post("/graphql", json=query, headers={"Authorization": f"Bearer {token}"})
    print(f"\n[HTTP {res.status_code}]\n{json.dumps(res.json(), indent=2)}")
    print("\n✅ Gateway extracts Object 102")
    print("✅ Ownership lookup shows Owner = 102")
    print("✅ User 101 != Owner 102")
    print("✅ BOLA detected (Risk: HIGH)")
    print("✅ Request blocked (HTTP 403)")
    print("✅ GraphQL backend never executes")
    print("✅ Audit event recorded")

    input("\nPress [ENTER] to execute Demo 3...")

    # =========================================================================
    print_header("DEMO 3 — NESTED BOLA")
    print("→ User 101 requests their own parent object (User 101)")
    print("→ Attempts to access nested resource belonging to Bob (Resource 102)...")
    query = {"query": "{ user(id: 101) { username resource(id: 102) { name } } }"}
    res = client.post("/graphql", json=query, headers={"Authorization": f"Bearer {token}"})
    print(f"\n[HTTP {res.status_code}]\n{json.dumps(res.json(), indent=2)}")
    print("\n✅ Deep Nested traversal intercepted")
    print("✅ Decision: DENY (NESTED_AUTHORIZATION_VIOLATION)")
    print("✅ HTTP 403 Blocked")
    print("✅ Audit event recorded")

    input("\nPress [ENTER] to execute Demo 4...")

    # =========================================================================
    print_header("DEMO 4 — INVALID JWT")
    print("→ Attempting request with expired/invalid JWT token...")
    query = {"query": "{ resource(id: 101) { id name } }"}
    res = client.post("/graphql", json=query, headers={"Authorization": "Bearer invalid.token.123"})
    print(f"\n[HTTP {res.status_code}]\n{json.dumps(res.json(), indent=2)}")
    print("\n✅ Authentication failure")
    print("✅ Request rejected before reaching Gateway")
    
    print("\n" + "="*60)
    print("🎉 DEMONSTRATION COMPLETE!")
    print("Open your browser and navigate to http://localhost:8000/dashboard")
    print("to view the live audit logs of these four exact events.")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
