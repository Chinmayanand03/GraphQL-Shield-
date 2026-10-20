# GraphQL Shield: Live Interactive Demonstration

This guide provides the exact `curl` commands to manually demonstrate the BOLA Security Gateway. 
By typing these commands into your terminal, you will send real HTTP traffic to the FastAPI server. 

Because we added **Live Console Logging**, the server's terminal will print a complete Security Trace (AUTH, GRAPHQL, OWNERSHIP, AUTHORIZATION, ENFORCEMENT) for every request you make!

---

### Step 0: Start the Server

Open your first terminal and start the server:
```bash
python -m app.seed
uvicorn app.main:app --reload
```
*(Leave this terminal visible on your screen. The security trace logs will print here.)*

---

### Step 1: Authenticate as User 101

Open a second terminal. We need to log in as Balanilavan (User 101) to get a JWT token.

**Run:**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
-H "Content-Type: application/json" \
-d "{\"username\":\"balanilavan\",\"password\":\"balanilavan123\"}"
```
**Expected:** The server will return a JSON object with your `access_token`. Copy this token. We will use it in the next steps (replace `<YOUR_TOKEN>` below).

---

### Demo 1: Legitimate Resource Request

Balanilavan legitimately requests his own Resource (Object ID: 101).

**Run:**
```bash
curl -X POST "http://localhost:8000/graphql" \
-H "Authorization: Bearer <YOUR_TOKEN>" \
-H "Content-Type: application/json" \
-d "{\"query\": \"{ resource(id: 101) { id name } }\"}"
```
**Look at the Server Terminal:** You will see the Live Security Trace showing `Decision: ALLOW`. The backend executes and returns HTTP 200 with Balanilavan's data.

---

### Demo 2: Direct BOLA Attack

Now, explain to your evaluator that you are keeping the *same user token*, but manually changing the requested object ID from `101` to `102` (which belongs to Kapilesh).

**Run:**
```bash
curl -X POST "http://localhost:8000/graphql" \
-H "Authorization: Bearer <YOUR_TOKEN>" \
-H "Content-Type: application/json" \
-d "{\"query\": \"{ resource(id: 102) { id name } }\"}"
```
**Look at the Server Terminal:** You will see:
- `Requesting User: 101`
- `True Owner ID: 102`
- `Decision: DENY`
- `Reason: OWNERSHIP_MISMATCH`
- `Enforcement: HTTP 403 Forbidden`

---

### Demo 3: Nested BOLA Attack

Attackers often hide BOLA attempts inside nested fields. Balanilavan requests his own user profile, but nests a request for Kapilesh's resource underneath it.

**Run:**
```bash
curl -X POST "http://localhost:8000/graphql" \
-H "Authorization: Bearer <YOUR_TOKEN>" \
-H "Content-Type: application/json" \
-d "{\"query\": \"{ user(id: 101) { username resource(id: 102) { name } } }\"}"
```
**Look at the Server Terminal:** The parser recursively extracts the nested `Resource (102)`, evaluates it against Balanilavan's identity, blocks it with `NESTED_AUTHORIZATION_VIOLATION`, and returns HTTP 403.

---

### Demo 4: Invalid / Expired JWT

Finally, demonstrate edge protection by using a forged or expired token.

**Run:**
```bash
curl -X POST "http://localhost:8000/graphql" \
-H "Authorization: Bearer fake_forged_token_here" \
-H "Content-Type: application/json" \
-d "{\"query\": \"{ resource(id: 101) { id name } }\"}"
```
**Expected:** The request is instantly rejected with HTTP 401 Unauthorized before it even reaches the GraphQL Gateway.

---

### Final Step: Live Security Dashboard

To prove that all decisions were permanently recorded:
1. Open your web browser.
2. Navigate to **http://localhost:8000/dashboard**
3. Show the evaluator the visual Audit Log, which now contains the exact `ALLOW` and `DENY` events you just triggered manually!
