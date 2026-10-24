# GraphQL-Shield Dashboard Guide

What every part of the dashboard shows, how it works, and how to present it, in plain words.

Open the dashboard at **http://127.0.0.1:8000/dashboard** after starting the server:

```
python -m uvicorn app.main:app --port 8000
```

---

## At a glance

```
+----------------------------------------------------------------------------+
| Dashboard page (one web page)                                              |
|  Top bar: API status, Refresh, Light or Dark mode, Export CSV              |
|                                                                            |
|  1. Security Testing      2. Research and ML         3. Audit and Verification
|  - Five summary cards     - Behavioural ML model     - Decision mix (ring chart)
|  - Demo users and roles   - Benchmark vs simple rule - Authorization overview
|  - GraphQL test console   - Suspicious sessions      - Non-interference properties
|  - Per-request flow       - Session scorer           - Decisions with real owners
|  - Dual-layer defense     - BLIND-SPOT PREDICTOR *   - Recent audit events + CSV
|  - Where taint fits       - Discovery: L1 bug found  |
+----------------------------------------------------------------------------+
        |  test requests and sign-in           ^  live data, every 30 s
        v                                      |
+----------------------------------------------------------------------------+
| GraphQL-Shield server: Layer 1 and Layer 2 log every decision to the audit log
+----------------------------------------------------------------------------+
```

The page has three tabs: **Security Testing** to run attacks live, **Research and ML** for the two models, and **Audit and Verification** for the evidence. All of it comes from the server's audit log. The blind-spot predictor (marked *) is the project's main research contribution.

---

## How the dashboard works behind the screen

The dashboard is a single web page that asks the GraphQL-Shield server for data and draws it. It never decides anything itself: every allow or deny decision happens on the server.

1. **The page loads** from `/dashboard` and immediately asks the server for statistics, layer counts and model results.
2. **It refreshes by itself every 30 seconds**, and again whenever you come back to the browser tab, so the numbers stay live.
3. **Every security decision is written to the audit log** in the database: who asked, for which object, allowed or denied, why, and which layer decided. Most panels are views of that log.
4. **Sensitive details are admin-only.** Anyone sees the totals; only someone signed in as admin sees who accessed which object. Without sign-in, those tables say "Admin only".
5. **When you run a test** in the test console, the page logs in with the account you typed, sends a real GraphQL request to the server, and shows exactly what came back.

**In one sentence for faculty:** "The dashboard is a live window onto the gateway's audit log; it shows every decision the two security layers made and lets us send real attacks to watch them being blocked."

---

## Top bar

| Item | What it does |
| --- | --- |
| **API connected** (green dot) | The page reached the server. Red means the server is not running: start it again. |
| **Light mode / Dark mode** | Switches the colours. The choice is remembered in your browser. |
| **Refresh** | Fetches the latest numbers now instead of waiting 30 seconds. |
| **Export CSV** | Downloads the recent audit events as a spreadsheet file (admin sign-in needed to include rows). |
| **Three tabs** | Security Testing, Research & ML, Audit & Verification. The left sidebar opens the same three. |

---

## Tab 1: Security Testing

This tab is where you show the protection working live: you send real requests and watch them get allowed or blocked.

### 1. Five summary cards

| Card | Meaning |
| --- | --- |
| Total requests | Every authorization decision recorded |
| Allowed | Decisions where the user owned the object, or was admin |
| Blocked | Decisions where access was denied |
| BOLA signals | Denials because the object belonged to someone else (directly or through nesting) |
| High risk | Decisions the risk score marked high |

### 2. Demo users and roles

Every password is the username followed by 123.

| Name | Username | Password | Role |
| --- | --- | --- | --- |
| B.V. Balanilavan | balanilavan | balanilavan123 | User, ID 101 |
| Kapilesh N | kapilesh | kapilesh123 | User, ID 102 |
| Sakthivel B | sakthivel | sakthivel123 | User, ID 103 |
| Admin Demo Account | chinmayanand | chinmayanand123 | Admin, ID 104 |

**Use account** copies the username into the test console below; you still type the password.

### 3. GraphQL test console

This sends a real GraphQL request as the user you choose and shows the answer.

- **Endpoint:** *Protected GraphQL Shield* (both layers on) or *Insecure baseline*, a deliberately unprotected copy used to show what happens without protection.
- **Scenario:** the kind of request to send.

| Scenario | What it tries | Expected on the protected endpoint |
| --- | --- | --- |
| Direct resource lookup | Ask for one object by ID | Blocked (403) if it belongs to someone else |
| Nested user → resource | Hide the foreign ID inside a user query | Blocked (403) |
| Implicit children relationship | List the documents inside a folder | Only your own documents come back |
| Inline fragment user lookup | Hide the request inside a fragment to dodge Layer 1 | Blocked (403) |
| Batched request | Send two queries at once, one foreign | Blocked (403) |
| Mutation: rename resource | Change someone else's object | Blocked, object unchanged |
| Mutation: delete resource | Delete someone else's object | Blocked, object not deleted |

The console clears the password after every run, so type it again for each test. **HTTP 403** means Layer 1 refused it before anything ran; **HTTP 200** means it ran, with foreign data removed.

### 4. Per-request taint → authorization flow

After each test, five boxes explain how that request was judged:

1. **Authenticated principal:** who sent it (user ID and role, from the login token).
2. **Taint source tracked:** where the object ID came from (typed directly, or a variable).
3. **Object / path analysis:** which object it targets, where in the query, and who owns it.
4. **Authorization reasoning:** the rule that decided, e.g. OWNER_MATCH (you own it) or OWNERSHIP_MISMATCH (you don't).
5. **Observed enforcement:** what actually happened (HTTP status, any errors).

The coloured label at the top sums it up, e.g. *DENIED · HTTP 403* or *ACCEPTED · POLICY ALLOWS*.

### 5. Dual-layer defense

The heart of the project: two independent checks.

- **Layer 1, before the query runs:** reads the query, finds every object ID written in it, and rejects the whole request if any is foreign.
- **Layer 2, while the query runs:** checks every object actually returned, and every object a change would touch, removing or blocking anything foreign. It catches what Layer 1 cannot see, such as documents reached through a folder's `children`.

| Counter | Meaning |
| --- | --- |
| Layer 1 blocked | Requests rejected before running |
| Layer 2 filtered | Foreign objects removed from answers |
| Layer 2 mutations blocked | Changes stopped before they happened |
| Layer 1 blind spots | Foreign objects only Layer 2 caught: proof that Layer 2 is needed |

**Admin sign-in** (chinmayanand / chinmayanand123) unlocks the event table, the audit details and the ML scoring. **Turn Layer 1/2 OFF** switches a layer off for a live demonstration: with Layer 2 off, the folder `children` attack leaks. These switches affect every user, so turn both back on afterwards.

### 6. Where taint analysis fits

A five-step picture of the research pipeline: untrusted inputs (taint sources) → how they travel through the query (propagation) → which object they reach (relationship graph) → the ownership rule (authorization reasoning) → the actual allow or deny (runtime enforcement). Finding an untrusted ID is not proof of an attack; the ownership check decides.

---

## Tab 2: Research & ML

Both models only advise: neither can allow or block a request; Layer 1 and Layer 2 make every decision.

### Model 1: Behavioural ML model (advisory)

It watches **how each user behaves over time** and gives a risk score, like a bank noticing unusual card activity.

- **Model loading status:** green means the trained model file was found.
- **Held-out family: nested_relational:** one type of behaviour was kept out of training and used only for testing, to check the model copes with patterns it never saw.
- **Benchmark metric comparison:** scores for the model and a simple hand-written rule on 1,000 test sessions. Honest result: the rule scored 100% and the model 99.2%, so the model is not claimed to be better.
- **Evaluation limitations and findings:** notes saying the model is not better than the rule, never overrides security decisions, and how the fair test was set up.
- **Suspicious behavioural sessions:** one row per user active in the last 15 minutes, from the audit log: requests per minute, denials, attempts on other people's objects, whether IDs were tried one after another (enumeration), and the alert level. Admin only. With no recent traffic it shows labelled sample sessions.
- **Interactive session telemetry scorer:** type numbers for an imaginary session (or click a preset such as *Rapid enumeration attack*) and see how the model and rule score it.

### Model 2: Layer 1 blind-spot predictor (the main research idea)

It predicts, **before a query runs**, whether the query will reach objects Layer 1 cannot see, so only Layer 2 can protect them.

Key idea in plain words: Layer 2 automatically writes down every object Layer 1 missed. Those notes become the training answers, so nobody had to label anything by hand.

- **Evaluation table:** how well the model and the simple rule ("flag queries containing children") find these gaps. Both now score 100%.
- **What drives the prediction:** which query features matter most. `relationship_field_count` (a `children`-style field) dominates.
- **Discovery run: gaps found in Layer 1:** the result to highlight. Before the fix, every query using a **default value for a variable** slipped past Layer 1. The simple rule missed all 585; the model found them. That was a real bug, now fixed, and attacks only Layer 2 could stop dropped by 66% (401 to 138 per 4,000 requests).
- **Score a query without running it:** paste a query and click **Predict blind spot** (admin sign-in needed). Example: *LIKELY BLIND SPOT · p=99.8% · relationship_field_count=1 (+6.69)* means 99.8% likely, mainly because of the `children` field.

---

## Tab 3: Audit & Verification

This tab is the evidence: the record of every decision, so anyone can check what the gateway did and why.

- **Request decision mix:** a ring chart of allowed versus denied decisions. It shows the mix, not a detection accuracy.
- **Authorization overview:** bars comparing allowed and denied counts, and how many records were high risk.
- **Verified non-interference property tests:** six cards, each a security property the automated tests check, e.g. *Single resource access* (owners are never wrongly blocked), *High-to-low confidentiality* (others' private records can't be reached through nesting), *Derived-value independence* (even a count of children does not reveal hidden documents). These cards are a fixed summary of tests that pass when you run `python -m pytest`; the dashboard does not run them.
- **Recent authorization decisions and runtime provenance evidence:** latest decisions with full context: who asked, their role, the object and its real owner (*Owned* or *Foreign*), where in the query it was reached, the parent object, decision, reason and risk. Admin only.
- **Recent audit events:** the raw audit log, newest first, with search, decision and risk filters, plus **Export CSV**. Times stored in UTC, shown in Indian time (IST). Admin only.

---

## 5-minute demo script

**Before you start:** run `python -m uvicorn app.main:app --port 8000` in the project folder, keep that window open, and open http://127.0.0.1:8000/dashboard.

1. **The problem (30 s).** "BOLA means a user reads or changes someone else's data just by changing an ID. It is the number one API risk on the OWASP list, and GraphQL makes it harder to stop."
2. **The attack works without protection (1 min).** In the test console, log in as `balanilavan` / `balanilavan123`, choose *Insecure baseline*, *Implicit children relationship*, folder 201, and run. Point at document 204, *Kapilesh's Shared Draft*: Balanilavan should not see it.
3. **The same attack with protection (30 s).** Switch to *Protected GraphQL Shield*, retype the password, run again. Only documents 202 and 203 (Balanilavan's own) come back.
4. **A direct attack is stopped at the door (30 s).** Choose *Direct resource lookup*, resource 102 (Kapilesh's), run. HTTP 403, and the five flow boxes explain: *OWNERSHIP_MISMATCH*.
5. **Why two layers (1 min).** Sign in as admin (`chinmayanand` / `chinmayanand123`). Show the counters, especially *Layer 1 blind spots*. Optional: click *Turn Layer 2 OFF*, rerun step 3 and document 204 leaks; then turn Layer 2 back ON.
6. **The research contribution (1 min).** Open Research & ML → *Layer 1 blind-spot predictor*. "Layer 2's records trained this model with no hand labelling. It found a real Layer 1 bug, variable default values, that our own rule missed; fixing it cut these attacks by 66%." Click *Predict blind spot*.
7. **The evidence (30 s).** Open Audit & Verification and show the decisions with real owners marked *Owned* or *Foreign*.

**After the demo:** make sure both layers are ON again.

---

## Questions faculty may ask

| Question | Answer |
| --- | --- |
| What is BOLA? | Broken Object Level Authorization: a user gets someone else's object by asking for its ID. First in the OWASP API Security Top 10 (2023). |
| Why is GraphQL harder than REST? | One request can reach many objects, nested deep, and even objects never named by ID, such as a folder's `children`. |
| Why not just Layer 1? | It only sees IDs written in the query, so objects reached through relationships slip past. Our ablation shows exactly that leak. |
| Why not just Layer 2? | It is enough for safety, but Layer 1 stops attacks before anything runs, so changes never start, and its misses tell us where to improve it. |
| Does the ML block attacks? | No. Both models only advise. Every allow or deny is decided by fixed ownership rules, so decisions stay predictable and auditable. |
| What is new in your work? | Using Layer 2's records of what Layer 1 missed as free training data. The model found a real Layer 1 bug that our own rule missed. |
| Is the ML better than a simple rule? | Not after the bug fix: both score 100%. Its value was the discovery, which we say openly. |
| How fast is it? | After database connection pooling, protection adds about 60–81% per request in lab tests (about 20–38 ms per request). |
| Does it work on other apps? | Yes for our second test app (clinic records), protected by configuration alone. Testing on a third-party app is the next step. |
| What are the limits? | Both test apps and attacks were built by us; policy is owner-or-admin only; numbers come from a laptop. |
| Is the 100% block rate real? | Yes on our test set: 2,267 of 2,267 attacks blocked, 0 legitimate requests blocked. It shows the design works on these attacks, not on every possible attack. |
