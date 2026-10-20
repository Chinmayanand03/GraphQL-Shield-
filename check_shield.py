"""
check_shield.py - Verification for vectors outside dashboard UI capabilities:
  1. Inline Fragment BOLA & Authorized Inline Fragment
  2. Queries over HTTP GET rejection
  3. Batched GraphQL operations (legitimate batch, limit exceeded, mixed BOLA batch)
  4. Mutation BOLA protection (unauthorized write blocked, DB integrity preserved, authorized write allowed)
"""
from __future__ import annotations

import os
import sys
import sqlite3
import httpx

# Ensure project root is in sys.path and is the working directory
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
os.chdir(PROJECT_ROOT)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

BASE_URL = os.environ.get("SHIELD_URL", "http://localhost:8000")


def get_client() -> tuple[httpx.Client, bool]:
    """Return an HTTP client. Uses live server if reachable, else falls back to TestClient."""
    try:
        r = httpx.get(f"{BASE_URL}/health", timeout=1.0)
        if r.status_code == 200:
            return httpx.Client(base_url=BASE_URL, timeout=10.0), True
    except Exception:
        pass

    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app), False


def run_checks() -> bool:
    client, is_live = get_client()
    mode_str = f"Live Server ({BASE_URL})" if is_live else "In-Process TestClient"
    print("=" * 65)
    print(f"GraphQL Shield Advanced Security Checks [{mode_str}]")
    print("Testing vectors the dashboard UI cannot send:")
    print(" 1. Inline Fragments  2. GET Queries  3. Batching  4. Mutations")
    print("=" * 65)

    # Step 0: Authenticate as Balanilavan (id: 101)
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "balanilavan", "password": "balanilavan123"}
    )
    if login_res.status_code != 200 or "access_token" not in login_res.json():
        print(f"[FAIL] Login failed: {login_res.status_code} {login_res.text}")
        return False
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("[PASS] Authenticated as Balanilavan (User ID: 101)\n")

    all_passed = True

    # -------------------------------------------------------------
    # 1. Inline Fragment BOLA
    # -------------------------------------------------------------
    print("--- 1. INLINE FRAGMENTS ---")
    # 1a. Unauthorized Inline Fragment targeting Kapilesh's resource (id: 102)
    inline_bola_query = """
    query InlineFragmentBOLA {
        ... on Query {
            resource(id: 102) {
                id
                name
                ownerId
            }
        }
    }
    """
    res = client.post("/graphql", json={"query": inline_bola_query}, headers=headers)
    if res.status_code == 403:
        detail = res.json().get("detail", {})
        print(f" [PASS] 1a. Inline Fragment BOLA blocked: HTTP 403 ({detail.get('reason', 'BLOCKED')})")
    elif res.status_code == 200 and res.json().get("data", {}).get("resource") is None:
        print(" [PASS] 1a. Inline Fragment BOLA filtered by Layer 2: resource is null")
    else:
        print(f" [FAIL] 1a. Inline Fragment BOLA not blocked: {res.status_code} {res.text}")
        all_passed = False

    # 1b. Authorized Inline Fragment targeting own resource (id: 101)
    inline_auth_query = """
    query InlineFragmentLegit {
        ... on Query {
            resource(id: 101) {
                id
                name
            }
        }
    }
    """
    res = client.post("/graphql", json={"query": inline_auth_query}, headers=headers)
    if res.status_code == 200 and res.json().get("data", {}).get("resource", {}).get("id") == 101:
        print(" [PASS] 1b. Authorized Inline Fragment allowed: HTTP 200 with resource data")
    else:
        print(f" [FAIL] 1b. Authorized Inline Fragment failed: {res.status_code} {res.text}")
        all_passed = False

    # -------------------------------------------------------------
    # 2. Queries over HTTP GET
    # -------------------------------------------------------------
    print("\n--- 2. QUERIES OVER HTTP GET ---")
    res = client.get("/graphql?query={resource(id:101){id name}}", headers=headers)
    if res.status_code in (400, 405) and ("not allowed" in res.text.lower() or res.status_code == 405):
        print(f" [PASS] 2. Query over GET rejected: HTTP {res.status_code} ({res.text.strip()})")
    else:
        print(f" [FAIL] 2. Query over GET was not rejected: {res.status_code} {res.text}")
        all_passed = False

    # -------------------------------------------------------------
    # 3. Batched Operations
    # -------------------------------------------------------------
    print("\n--- 3. QUERY BATCHING ---")
    # 3a. Legitimate batch (<= 5 operations)
    batch_legit = [
        {"query": "{ resource(id: 101) { id name } }"},
        {"query": "{ user(id: 101) { id username } }"},
    ]
    res = client.post("/graphql", json=batch_legit, headers=headers)
    if res.status_code == 200 and isinstance(res.json(), list) and len(res.json()) == 2:
        print(" [PASS] 3a. Legitimate batch (2 ops) allowed: HTTP 200 with 2 responses")
    else:
        print(f" [FAIL] 3a. Legitimate batch failed: {res.status_code} {res.text}")
        all_passed = False

    # 3b. Batch size limit exceeded (> 5 operations, MAX_BATCH_OPERATIONS = 5)
    batch_excessive = [{"query": "{ resource(id: 101) { id } }"}] * 6
    res = client.post("/graphql", json=batch_excessive, headers=headers)
    if res.status_code == 400 and "BATCH_SIZE_EXCEEDED" in res.text:
        print(" [PASS] 3b. Excessive batch (>5 ops) blocked: HTTP 400 BATCH_SIZE_EXCEEDED")
    else:
        print(f" [FAIL] 3b. Excessive batch check failed: {res.status_code} {res.text}")
        all_passed = False

    # 3c. Mixed batch containing a BOLA attack in 2nd operation
    batch_bola = [
        {"query": "{ resource(id: 101) { id name } }"},
        {"query": "{ resource(id: 102) { id name } }"},
    ]
    res = client.post("/graphql", json=batch_bola, headers=headers)
    if res.status_code == 403:
        detail = res.json().get("detail", {})
        print(f" [PASS] 3c. Batch containing BOLA blocked: HTTP 403 (batch_index={detail.get('batch_index')}, {detail.get('reason')})")
    else:
        print(f" [FAIL] 3c. Batch BOLA not blocked: {res.status_code} {res.text}")
        all_passed = False

    # -------------------------------------------------------------
    # 4. Mutations (Write BOLA Protection)
    # -------------------------------------------------------------
    print("\n--- 4. MUTATIONS (WRITE BOLA) ---")
    db_path = os.path.join(PROJECT_ROOT, "shield.db")
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT name FROM objects WHERE id = 102")
    original_kapil_name = cur.fetchone()[0]

    # 4a. Unauthorized mutation: Balanilavan attempting to modify Kapilesh's resource
    mutation_bola = """
    mutation UnauthorizedUpdate {
        updateResource(id: 102, name: "ATTACKED_BY_BOLA") {
            id
            name
        }
    }
    """
    res = client.post("/graphql", json={"query": mutation_bola}, headers=headers)
    is_blocked = False
    if res.status_code == 403:
        is_blocked = True
        print(f" [PASS] 4a. Unauthorized mutation blocked at Layer 1: HTTP 403 ({res.json().get('detail', {}).get('reason')})")
    elif res.status_code == 200:
        errors = res.json().get("errors", [])
        if any("mutation blocked" in e.get("message", "").lower() or "MUTATION_AUTHORIZATION_DENIED" in str(e) for e in errors):
            is_blocked = True
            print(" [PASS] 4a. Unauthorized mutation blocked at Layer 2: GraphQLError MUTATION_AUTHORIZATION_DENIED")

    if not is_blocked:
        print(f" [FAIL] 4a. Unauthorized mutation was NOT blocked: {res.status_code} {res.text}")
        all_passed = False

    # 4b. Verify Database Integrity: Kapilesh's resource must NOT have changed
    cur.execute("SELECT name FROM objects WHERE id = 102")
    current_kapil_name = cur.fetchone()[0]
    if current_kapil_name == original_kapil_name:
        print(f" [PASS] 4b. Database integrity verified: Target object preserved as '{current_kapil_name}'")
    else:
        print(f" [FAIL] 4b. Database integrity compromised! Target modified to '{current_kapil_name}'")
        all_passed = False

    # 4c. Legitimate mutation on own resource (id 101)
    cur.execute("SELECT name FROM objects WHERE id = 101")
    original_bala_name = cur.fetchone()[0]

    mutation_legit = """
    mutation AuthorizedUpdate {
        updateResource(id: 101, name: "Balanilavan's Updated Note") {
            id
            name
        }
    }
    """
    res = client.post("/graphql", json={"query": mutation_legit}, headers=headers)
    if res.status_code == 200 and res.json().get("data", {}).get("updateResource", {}).get("name") == "Balanilavan's Updated Note":
        print(" [PASS] 4c. Legitimate mutation allowed: HTTP 200 with updated resource")
        # Restore original name to keep DB clean
        cur.execute("UPDATE objects SET name = ? WHERE id = 101", (original_bala_name,))
        conn.commit()
    else:
        print(f" [FAIL] 4c. Legitimate mutation failed: {res.status_code} {res.text}")
        all_passed = False

    conn.close()

    print("\n" + "=" * 65)
    if all_passed:
        print("ALL ADVANCED SHIELD CHECKS PASSED (100%)")
    else:
        print("SOME CHECKS FAILED - Check logs above")
    print("=" * 65)
    return all_passed


if __name__ == "__main__":
    success = run_checks()
    sys.exit(0 if success else 1)
