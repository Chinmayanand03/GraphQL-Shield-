import httpx
import json
import os
import sys

BASE_URL = "http://localhost:8000"
JWT_TOKEN = None

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    print("="*60)
    print("🛡️  GraphQL Shield: Live Interactive Demo Client")
    print("="*60)

def display_response(res):
    print("\n--- SERVER RESPONSE ---")
    print(f"HTTP Status: {res.status_code}")
    try:
        print(json.dumps(res.json(), indent=2))
    except Exception:
        print(res.text)
    print("-----------------------\n")
    input("Press [ENTER] to return to menu...")

def login():
    global JWT_TOKEN
    print("\n[Authenticating as User 101 (Alice)]...")
    try:
        res = httpx.post(f"{BASE_URL}/api/v1/auth/login", json={"username": "alice", "password": "alice123"})
        if res.status_code == 200:
            JWT_TOKEN = res.json().get("access_token")
            print(f"✅ Success! Received JWT Token: {JWT_TOKEN[:15]}...[TRUNCATED]")
        else:
            print("❌ Authentication failed. Is the server running?")
    except httpx.ConnectError:
        print("❌ Could not connect to server. Ensure it is running on port 8000.")
    input("\nPress [ENTER] to return to menu...")

def legitimate_request():
    if not JWT_TOKEN:
        print("\n❌ Please login first!")
        input("\nPress [ENTER] to return to menu...")
        return
        
    print("\n[Sending Legitimate Request] User 101 requests Object 101...")
    query = {"query": "{ resource(id: 101) { id name } }"}
    res = httpx.post(f"{BASE_URL}/graphql", json=query, headers={"Authorization": f"Bearer {JWT_TOKEN}"})
    display_response(res)

def direct_bola_attack():
    if not JWT_TOKEN:
        print("\n❌ Please login first!")
        input("\nPress [ENTER] to return to menu...")
        return
        
    print("\n[Sending BOLA Attack] User 101 requests Object 102 (Bob's Resource)...")
    query = {"query": "{ resource(id: 102) { id name } }"}
    res = httpx.post(f"{BASE_URL}/graphql", json=query, headers={"Authorization": f"Bearer {JWT_TOKEN}"})
    display_response(res)

def nested_bola_attack():
    if not JWT_TOKEN:
        print("\n❌ Please login first!")
        input("\nPress [ENTER] to return to menu...")
        return
        
    print("\n[Sending Nested BOLA] User 101 requests nested Object 102...")
    query = {"query": "{ user(id: 101) { username resource(id: 102) { name } } }"}
    res = httpx.post(f"{BASE_URL}/graphql", json=query, headers={"Authorization": f"Bearer {JWT_TOKEN}"})
    display_response(res)

def invalid_jwt_attack():
    print("\n[Sending Request with Forged JWT]...")
    query = {"query": "{ resource(id: 101) { id name } }"}
    res = httpx.post(f"{BASE_URL}/graphql", json=query, headers={"Authorization": "Bearer completely_fake_token"})
    display_response(res)

def main():
    while True:
        clear_screen()
        print_header()
        print(f"Current Status: {'Logged In (Token Active)' if JWT_TOKEN else 'Not Logged In'}")
        print("\n1. Login as User 101 (Alice)")
        print("2. Send Legitimate Resource Request")
        print("3. Send Direct BOLA Attack (Object ID Manipulation)")
        print("4. Send Nested BOLA Attack")
        print("5. Send Invalid JWT Request")
        print("0. Exit")
        
        choice = input("\nSelect an action (0-5): ")
        
        if choice == '1': login()
        elif choice == '2': legitimate_request()
        elif choice == '3': direct_bola_attack()
        elif choice == '4': nested_bola_attack()
        elif choice == '5': invalid_jwt_attack()
        elif choice == '0': sys.exit(0)

if __name__ == "__main__":
    main()
