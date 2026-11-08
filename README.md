# GraphQL-Shield: Autonomous Dual-Layer Runtime Object Guard & Behavioral Defense Framework

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com)
[![Strawberry GraphQL](https://img.shields.io/badge/GraphQL-Strawberry-e535ab.svg?logo=graphql)](https://strawberry.rocks/)
[![Tests Passing](https://img.shields.io/badge/tests-414%20passed-brightgreen.svg)]()
[![Security Standard](https://img.shields.io/badge/OWASP-API1%3A2023%20BOLA-red.svg)](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **A production-grade dual-layer security framework providing pre-execution AST gating, execution-time runtime object & mutation interception, and XGBoost-driven behavioral anomaly detection to eliminate Broken Object Level Authorization (BOLA / IDOR) in GraphQL APIs.**

---

## Table of Contents

- [Overview & Motivation](#overview--motivation)
- [Key Features](#key-features)
- [Dual-Layer Defense Architecture](#dual-layer-defense-architecture)
  - [Layer 1: Centralized Pre-Execution Gate](#layer-1-centralized-pre-execution-gate)
  - [Layer 2: Execution-Time Object & Mutation Guard](#layer-2-execution-time-object--mutation-guard)
  - [Cross-Layer Evidence & Blind Spot Auditing](#cross-layer-evidence--blind-spot-auditing)
  - [Behavioral Machine Learning Engine (XGBoost)](#behavioral-machine-learning-engine-xgboost)
- [Interactive Research & Security Dashboard](#interactive-research--security-dashboard)
- [Quickstart Guide](#quickstart-guide)
  - [Prerequisites](#prerequisites)
  - [Installation & Setup](#installation--setup)
  - [Running the Server](#running-the-server)
- [Live Interactive Attack Demonstrations](#live-interactive-attack-demonstrations)
  - [Demo Personas](#demo-personas)
  - [Demo 1: Legitimate Resource Access (200 OK)](#demo-1-legitimate-resource-access)
  - [Demo 2: Direct Root BOLA Attack (403 Forbidden)](#demo-2-direct-root-bola-attack)
  - [Demo 3: Nested Object BOLA Attack (403 Forbidden)](#demo-3-nested-object-bola-attack)
  - [Demo 4: Unauthorized Mutation Blocked (Execution-Time Guard)](#demo-4-unauthorized-mutation-blocked)
  - [Demo 5: Implicit Relationship Traversal Probe](#demo-5-implicit-relationship-traversal-probe)
  - [Demo 6: Administrative Policy Override](#demo-6-administrative-policy-override)
- [Academic Research & Benchmarking Suite](#academic-research--benchmarking-suite)
  - [Comparative Dual-Endpoint Architecture](#comparative-dual-endpoint-architecture)
  - [Layer Ablation Experiments](#layer-ablation-experiments)
  - [Training the Behavioral XGBoost Model](#training-the-behavioral-xgboost-model)
- [Verification & Test Suite](#verification--test-suite)
- [API Reference](#api-reference)
- [Directory Structure](#directory-structure)
- [License](#license)

---

## Overview & Motivation

**Broken Object Level Authorization (BOLA / IDOR)** consistently ranks as the **#1 vulnerability in OWASP API Security Top 10 (API1:2023)**. 

While REST architectures feature rigid, predictable resource hierarchies (e.g. `/users/101/orders/501`), **GraphQL introduces unique, critical security challenges**:
1. **Dynamic Selection Sets & Unbounded Depth**: Clients construct custom queries with arbitrary nesting, fragments, and aliases.
2. **Disconnected Resolvers**: Field-level resolvers execute independently; parent authorization checks do not automatically protect child resolvers.
3. **Implicit Relationship Traversal**: Attackers traverse graph edges (e.g. `user -> organization -> projects -> sensitive_document`) to reach foreign objects without declaring their IDs directly.
4. **Mutations Without Ownership Checks**: Graph mutations (`update`, `delete`, `transfer`) can alter unauthorized data unless strictly intercepted before resolver execution.
5. **Perimeter Blindness**: Traditional Web Application Firewalls (WAFs) cannot inspect deep GraphQL ASTs or establish ownership boundaries before queries execute.

**GraphQL-Shield** addresses these challenges by embedding an autonomous **Dual-Layer Runtime Object Guard directly into the request and execution lifecycles**.

---

## Key Features

- **Layer 1 Pre-Execution Gate**:
  - Intercepts requests before any resolver runs.
  - Inspects AST nodes, inline fragments (`... on Query`), fragment spreads, and list IDs (`[101, 102]`).
  - Strict query batching enforcement (`MAX_BATCH_OPERATIONS`).
  - Fails closed on malformed or non-JSON payloads.
  - Blocks entire requests on direct BOLA attempts, preventing state mutation.
- **Layer 2 Execution-Time Guard**:
  - Embedded inside the GraphQL execution pipeline as a Strawberry schema extension.
  - **Mutation Argument Guard**: Inspects engine-coerced arguments before root mutations (`updateResource`, `deleteResource`, `transferOwnership`) execute.
  - **Guarded Types**: Secures both `ResourceType` and `UserType` models.
  - **Non-Interference Sanitization**: Filters collection fields item-by-item without leaking foreign object existence.
  - **Interfaces and unions**: resolves the concrete type of `node(id:)` and union results before deciding, so a foreign object cannot hide behind an abstract type.
  - **Aggregate fields**: declared counts (e.g. `childrenCount`) are answered by Layer 2 from the objects the caller may see.
  - **Batched checks**: a list is checked with one owner lookup and audited in one transaction.
- **Uniform denials**: a foreign object and a missing one get the same `ACCESS_DENIED` response; the exact reason stays in the hash-chained audit log.
- **Startup lint**: warns about schema types with owner-like fields (`ownerId`, `belongsTo`, `createdBy`, …) that the configuration leaves unprotected, about any type fetched by ID from a root query that is neither owned nor declared in `public_types`, and about undeclared aggregate fields.
- **No timing channel**: a missing object is checked and audited like a foreign one, so a denial takes the same time either way (`scripts/run_timing_channel.py`).
- **Framework support**: the same `OwnershipMiddleware` protects Strawberry, plain graphql-core, Graphene and Ariadne servers.
- **Layer 1 Blind Spot Auditing**:
  - Automatically identifies and logs when Layer 2 catches an unauthorized object that Layer 1 could not parse from raw query text.
  - Emits telemetry events to `layer_events` table for forensic analysis.
- **Runtime Layer Toggling & Ablation**:
  - Dedicated admin API (`/api/v1/security/layers`) to toggle Layer 1 and Layer 2 on/off for empirical ablation demonstrations.
- **Behavioral ML Anomaly Engine (XGBoost)**:
  - Evaluates traversal velocity, ID entropy, and role-resource vectors to detect horizontal privilege escalation.
- **Interactive Security Dashboard (`/dashboard`)**:
  - Real-time audit stream, visual taint tracer, layer event logs, and comparative evaluation metrics.

---

## Dual-Layer Defense Architecture

```mermaid
flowchart TD
    Client([HTTP Client / Attacker]) -->|POST /graphql + JWT| Gateway[FastAPI Security Gateway]
    
    subgraph Layer1 [Layer 1: Pre-Execution Gate]
        Gateway --> Auth[JWT Authentication & Principal Extraction]
        Auth --> L1Check{Layer 1 Enabled?}
        L1Check -->|Yes| AST[AST Parser: Inspect Inline Fragments, Lists & Batching]
        L1Check -->|No / Bypassed| Strawberry
        AST --> PolicyL1[Policy Conformance Engine]
        PolicyL1 -->|Mismatch on Known ID| L1Block[HTTP 403 Forbidden: L1_PRE_EXECUTION Block]
        PolicyL1 -->|Clean Query| Strawberry[Strawberry GraphQL Engine]
    end

    subgraph Layer2 [Layer 2: Execution-Time Guard]
        Strawberry --> MutGuard{Mutation Resolver?}
        MutGuard -->|Yes| ArgGuard[Engine-Coerced ID Ownership Check]
        ArgGuard -->|Unauthorized Target| L2MutBlock[GraphQLError: MUTATION_AUTHORIZATION_DENIED]
        ArgGuard -->|Authorized Target| ExecMut[Execute Mutation Resolver]
        
        MutGuard -->|No (Query)| Resolvers[Object Resolvers]
        Resolvers --> TypeFilter{Guarded Type? User/Resource}
        TypeFilter -->|Yes| ItemGuard[Per-Item DB Ownership Oracle]
        ItemGuard -->|Owned by Principal| Emit[Emit Object]
        ItemGuard -->|Foreign Object| Scrub[Scrub & Log L1 Blind Spot]
    end
    
    Emit --> Response([HTTP 200 OK Sanitized Response])
```

### Layer 1: Centralized Pre-Execution Gate
- Evaluates raw POST requests before GraphQL execution starts.
- Handles operation batches (JSON arrays up to `MAX_BATCH_OPERATIONS`).
- Recursively expands inline fragments (`InlineFragmentNode`) and fragment spreads (`FragmentSpreadNode`), with recursion loop guards.
- Inspects both scalar IDs (`id: 101`) and list arguments (`id: [101, 102]`).
- Records every evaluated object ID on `request.state.layer1_checked`.

### Layer 2: Execution-Time Object & Mutation Guard
- Operates inside the GraphQL engine via `RuntimeObjectAuthorizationExtension`.
- Intercepts root mutations **before** execution: checks the coerced `id` argument against the database ownership oracle. If unauthorized, raises `MUTATION_AUTHORIZATION_DENIED` and prevents database writes.
- Sanitizes query responses: protects `ResourceType` and `UserType` instances, scrubbing foreign objects from lists and returning `None` for single object violations.

### Cross-Layer Evidence & Blind Spot Auditing
When Layer 2 denies an object that Layer 1 never checked (e.g. an object reached through complex relationship traversal or unparsed dynamic syntax), it logs an `L1_BLIND_SPOT_CAUGHT_BY_L2` event into `layer_events`. This provides verifiable evidence of defense-in-depth efficacy.

---

## Quickstart Guide

### Prerequisites
- **Python 3.10+** (tested on Python 3.13)
- **Git**

### Installation & Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Chinmayanand03/GraphQL-Shield-.git
   cd GraphQL-Shield-
   ```

2. **Create and activate a virtual environment**:
   ```bash
   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate

   # Windows (PowerShell)
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize & Seed the Database**:
   ```bash
   # Standard seed
   python -m app.seed

   # Or seed with the relationship-BOLA shared folder scenario
   python -m app.seed --with-shared-folder
   ```

### Running the Server

Start FastAPI with Uvicorn:
```bash
uvicorn app.main:app --reload --port 8000
```

- **Protected GraphQL Gateway**: `http://localhost:8000/graphql`
- **Insecure Benchmark Baseline**: `http://localhost:8000/graphql-insecure`
- **Interactive Security Dashboard**: `http://localhost:8000/dashboard`
- **Swagger API Documentation**: `http://localhost:8000/docs`

---

## Live Interactive Attack Demonstrations

Open two terminal windows:
- **Terminal 1**: Running the server (`uvicorn app.main:app --reload`).
- **Terminal 2**: Execute the commands below.

### Demo Personas
| User ID | Username | Password | Role | Description |
| :--- | :--- | :--- | :--- | :--- |
| `101` | `balanilavan` | `balanilavan123` | `user` | Standard User (Resource 101, Folder 201) |
| `102` | `kapilesh` | `kapilesh123` | `user` | Standard User (Resource 102) |
| `103` | `sakthivel` | `sakthivel123` | `user` | Standard User (Resource 103) |
| `104` | `chinmayanand` | `chinmayanand123` | `admin` | System Administrator (Global access) |

Every demo password follows the same format, `<username>123`. Passwords are stored as salted PBKDF2-SHA256 hashes; older databases holding `hash_<password>` values are upgraded automatically on startup.

### Configuration
Copy `.env.example` to `.env` and set `JWT_SECRET`. With `ENVIRONMENT=production` the server refuses to start on the built-in development secret.

The insecure baseline and the dashboard's layer switches are **off by default**. The layer switch is process-wide (it changes enforcement for every user), so enable both only for local demos:

```env
ENABLE_INSECURE_BASELINE=true
ENABLE_LAYER_TOGGLE=true
```

Every GraphQL operation is also limited by `MAX_QUERY_DEPTH` (10), `MAX_QUERY_ALIASES` (15), `MAX_QUERY_TOKENS` (2000) and `MAX_BATCH_OPERATIONS` (5). Set `ENABLE_INTROSPECTION=false` to disable schema introspection.

### Account protection
GraphQL-Shield stops one user reaching another user's objects. `app/core/accounts.py` also stops someone taking over the account itself:

| Attack | Protection |
| :--- | :--- |
| Guessing a password | 5 wrong passwords for a username within 15 minutes lock it for 15 minutes (HTTP 429, even for the right password). 20 failures from one address block that address. Unknown usernames are locked the same way. |
| Finding out which usernames exist | Wrong password and unknown username get the same reply, and take the same time (an unknown username is checked against a dummy hash). |
| Editing a token (another user ID, or `admin`) | The signature check rejects it. |
| A token that should no longer work | Every request checks the database: the account must still exist, and the token must not be logged out or from before a password change. The role is read from the database, never from the token, so removing a role takes effect at once. |
| A stolen session | `POST /api/v1/auth/logout` ends that token; `POST /api/v1/auth/logout-all` ends every session of the account. |
| Weak passwords | `POST /api/v1/auth/change-password` needs the current password and refuses passwords under 12 characters, containing the username, common ones, or with too few different characters. It ends every other session. Wrong current passwords count towards the lockout. |
| Demo passwords in production | With `ENVIRONMENT=production` the server refuses to start while any account still has its demo password. |

Limits are set by `LOGIN_MAX_FAILURES`, `LOGIN_IP_MAX_FAILURES`, `LOGIN_WINDOW_SECONDS`, `LOGIN_LOCK_SECONDS` and `ACCESS_TOKEN_MINUTES`. Locked yourself out during a demo? Run `python -m scripts.unlock_sign_in <username>` (or `--all`). Tested in `tests/test_account_security.py`. Not included: two-factor authentication, and HTTPS, which a real deployment must add in front of the server.

---

### Step 1: Obtain JWT Token (User 101)

```bash
curl -s -X POST "http://localhost:8000/api/v1/auth/login"   -H "Content-Type: application/json"   -d '{"username":"balanilavan","password":"balanilavan123"}'
```
*Save the `access_token` to variable `TOKEN`.*

---

### Demo 1: Legitimate Resource Access (200 OK)
User `101` queries their own document (`id: 101`).

```bash
curl -X POST "http://localhost:8000/graphql"   -H "Authorization: Bearer $TOKEN"   -H "Content-Type: application/json"   -d '{"query": "{ resource(id: 101) { id name } }"}'
```
**Outcome**: `200 OK` | `[AUTHORIZATION] Decision: ALLOW | Reason: OWNER_MATCH`

---

### Demo 2: Direct Root BOLA Attack (403 Forbidden)
User `101` attempts to read Kapilesh's document (`id: 102`).

```bash
curl -X POST "http://localhost:8000/graphql"   -H "Authorization: Bearer $TOKEN"   -H "Content-Type: application/json"   -d '{"query": "{ resource(id: 102) { id name } }"}'
```
**Outcome**: `403 Forbidden` | Blocked at **Layer 1 Pre-Execution Gate**. The response says `ACCESS_DENIED`, the same as for an ID that does not exist; the audit log records `OWNERSHIP_MISMATCH`.

---

### Demo 3: Nested Object BOLA Attack (403 Forbidden)
User `101` queries their own profile but nests a foreign resource request inside it.

```bash
curl -X POST "http://localhost:8000/graphql"   -H "Authorization: Bearer $TOKEN"   -H "Content-Type: application/json"   -d '{"query": "{ user(id: 101) { username resource(id: 102) { name } } }"}'
```
**Outcome**: `403 Forbidden` | Blocked at **Layer 1** (`ACCESS_DENIED`; the exact reason is in the audit log).

---

### Demo 4: Unauthorized Mutation Blocked (Execution-Time Guard)
User `101` attempts to modify Kapilesh's resource (`id: 102`) using the `updateResource` mutation.

```bash
curl -X POST "http://localhost:8000/graphql"   -H "Authorization: Bearer $TOKEN"   -H "Content-Type: application/json"   -d '{"query": "mutation { updateResource(id: 102, name: "Hacked Note") { id name } }"}'
```
**Outcome**: Blocked before the resolver runs (by Layer 1, or by the **Layer 2 Mutation Guard** when Layer 1 is off). The error says `ACCESS_DENIED`; the database is unchanged.

---

### Demo 5: Implicit Relationship Traversal Probe
User `101` queries folder `201` with child records (when seeded with `--with-shared-folder`, child `204` belongs to Kapilesh).

```bash
curl -X POST "http://localhost:8000/graphql"   -H "Authorization: Bearer $TOKEN"   -H "Content-Type: application/json"   -d '{"query": "{ resource(id: 201) { id name children { id name } childrenCount } }"}'
```
**Outcome**: `200 OK` | **Layer 2** filters out Kapilesh's document `204`. Balanilavan only receives documents `202` and `203`, and `childrenCount` is 2, not 3.

---

### Demo 6: Administrative Policy Override
Admin (`chinmayanand` / `chinmayanand123`) accesses any object:

```bash
ADMIN_TOKEN=$(curl -s -X POST "http://localhost:8000/api/v1/auth/login"   -H "Content-Type: application/json"   -d '{"username":"chinmayanand","password":"chinmayanand123"}' | jq -r .access_token)

curl -X POST "http://localhost:8000/graphql"   -H "Authorization: Bearer $ADMIN_TOKEN"   -H "Content-Type: application/json"   -d '{"query": "{ resource(id: 102) { id name } }"}'
```
**Outcome**: `200 OK` | `[AUTHORIZATION] Decision: ALLOW | Reason: ADMIN_OVERRIDE`

---

## Academic Research & Benchmarking Suite

### Comparative Dual-Endpoint Architecture
GraphQL-Shield hosts dual endpoints for scientific rigor:
- **`/graphql`**: Hardened with dual-layer defense.
- **`/graphql-insecure`**: Vulnerable baseline for comparative metrics (requires authenticated token; off unless `ENABLE_INSECURE_BASELINE=true`).

### Layer Ablation Experiments
Run every Layer 1 / Layer 2 combination against the same attacks (uses a temporary database, so `shield.db` is untouched):

```bash
python -m scripts.run_layer_ablation
```

This writes `results/layer_ablation/results.json`, served at `GET /api/v1/security/layer-ablation`. Each cell shows the layer that stopped the attack:

| Scenario | L1 on, L2 on | L1 on, L2 off | L1 off, L2 on | L1 off, L2 off |
| :--- | :--- | :--- | :--- | :--- |
| direct | L1 | L1 | L2 | LEAKED |
| nested | L1 | L1 | L2 | LEAKED |
| inline_fragment | L1 | L1 | L2 | LEAKED |
| relationship | L2 | **LEAKED** | L2 | LEAKED |
| batch | L1 | L1 | L2 | LEAKED |
| mutation_update | L1 | L1 | L2 | LEAKED |

Relationship traversal is invisible to Layer 1, which is why Layer 2 is required.

With `ENABLE_LAYER_TOGGLE=true`, admins can also switch layers live: `POST /api/v1/security/layers` with `{"layer1": false, "layer2": true}`.

### Mutation Ownership Registry
Layer 2 checks each root mutation's target using `MUTATION_TARGETS` in `app/graphql/mutations.py` (mutation name → target argument and object type). A mutation missing from the registry is denied, and `tests/test_hardening.py` fails if a new mutation is added without an entry.

### Layer 1 Blind-Spot Predictor (self-supervised from cross-layer disagreement)

Layer 2 writes an audit row (`layer='L2'`) only for owned objects Layer 1 never evaluated. Every such row is a Layer 1 coverage gap, recorded by the gateway itself. The blind-spot predictor uses these rows as training labels, so no request is labelled by hand:

1. `scripts/train_blind_spot_model.py` generates 4,000 varied requests (literals, variables, variable defaults, aliases, directives, named/inline fragments, relationships, batches, mutations) from different callers against a test world with mixed-owner folders, and runs each through the real gateway.
2. Each request Layer 1 allows is labelled by whether Layer 2 then audited an object Layer 1 missed (a coverage gap), and whether Layer 2 denied it (an attack only Layer 2 stopped).
3. XGBoost is trained on 17 **pre-execution** query features (`app/security/query_features.py`): structure, how IDs are supplied, and how many IDs Layer 1 resolved. It never sees ownership data or enforcement outcomes.
4. It is compared with the hand-written rule for Layer 1's documented blind spot (relationship traversal), on a random split and on a query family held out from training (relationships wrapped in fragments).

```bash
python -m scripts.train_blind_spot_model --discovery   # analyse the current Layer 1
python -m scripts.train_blind_spot_model               # train and deploy the model
```

**Discovery run (before the fix).** The model learned a Layer 1 gap that the hand-written rule did not encode: `query($id: Int = 102)` with no variables sent. Layer 1 ignored variable defaults, so every such request (585 of them, queries and mutations) reached objects Layer 1 never checked. 263 of them were attacks stopped only by Layer 2.

| Random test split (discovery) | XGBoost | Rule baseline |
| :--- | :--- | :--- |
| F1 (coverage gaps) | **1.000** | 0.639 |
| Attack recall | **100%** | 22.8% |

**After fixing Layer 1** (`object_extractor.py` now reads variable defaults), attacks reaching only Layer 2 fell from 401 to 138 (−66%), and Layer 1 blocks 1,678 instead of 1,415 of the 4,000 requests. The remaining gaps are relationship traversal only; there the model and the rule tie (F1 0.996 on the random split, 1.000 on the held-out family).

**At runtime** the model scores every request Layer 1 allows (about 1.2 ms). A positive prediction is recorded as a `BLIND_SPOT_PREDICTED` layer event, and each `L1_BLIND_SPOT_CAUGHT_BY_L2` event carries the earlier prediction (`predicted p=…`), so predictions can be checked against live traffic. It is advisory only and never changes an allow/deny decision.

- `GET /api/v1/security/blind-spot-model`: metrics, SHAP feature importance, discovery run
- `POST /api/v1/security/blind-spot-score`: score a query without executing it, with per-feature SHAP explanations

**Limits.** The test world is small and synthetic, and coverage gaps are largely a deterministic function of query structure, so F1 1.000 shows the method recovers the gap causes, not real-world accuracy. The contribution is the method: the gateway labels its own blind spots, and the model turns those labels into causes an engineer can fix.

### Behavioural Session Model (live telemetry)
The behavioural XGBoost model's 10 session features are now computed from the audit log (last 15 minutes per user, `app/security/live_telemetry.py`) instead of being typed in. Admins get them at `GET /api/v1/telemetry/live-sessions`, and the dashboard's session table shows live sessions when there is recent traffic.

```bash
python scripts/generate_behavioral_dataset.py
python scripts/train_behavioral_xgboost.py
```

The trained model is stored in `app/models/behavioral/` (tracked in git), so the dashboard can load it on a fresh clone.

---

## Research Evaluation

### Schema-aware, portable enforcement
Both layers are configured per application by a `ShieldConfig` (`app/security/shield_config.py`): the GraphQL schema, which object types are owned, an owner-lookup callable, ID arguments and an ID decoder (e.g. Relay global IDs), and targets for mutations whose return type does not reveal what they change.

- **Layer 1** takes each ID's object type from the schema (the type the field returns, or the mutation's target), not from the field name. A global ID naming a different type than the field expects (type confusion, the pattern behind Saleor's CVE-2022-39275) is checked as both types.
- **Layer 2** decides what to guard from each field's GraphQL return type (`info.return_type`) and reads IDs from objects or dicts. It runs as a Strawberry extension or as plain graphql-core middleware (`OwnershipMiddleware(config)`), so it also fits Graphene and Ariadne servers.
- A mutation with no known target is denied unless the config lists it as unguarded.

### Second application: clinic records
`app/clinic` is a second target that shares no code with the demo app: a schema-first SDL on plain graphql-core, dict resolvers, Relay global IDs, and patients, records and prescriptions with independent owners (a colleague's record on another doctor's patient). Its resolvers have no ownership checks; `/clinic/graphql` is protected only by `CLINIC_CONFIG`. `tests/test_clinic_app.py` covers direct, nested, two-level relationship, reverse relationship, type-confused IDs, create/update mutations, Layer 2 alone, admin, and the insecure baseline.

### Comparison with graphql-shield (Node)
`comparison/graphql-shield` protects the same schema (`comparison/schema.graphql`), seed data and unchecked resolvers with graphql-shield 7.6.5 rules (argument rules, type-wide rules, mutation rules). `scripts/run_tool_comparison.py` runs the same 13 attack and 5 benign scenarios against both and judges every response with one oracle (an attack leaks if a non-owned object is returned or the victim object changes).

```bash
cd comparison/graphql-shield && npm install && cd ../..
python -m scripts.run_tool_comparison
```

| Complete configuration | Attacks leaked | Legitimate requests failed | Configuration written |
| :--- | :--- | :--- | :--- |
| GraphQL Shield | 0 / 13 | 0 / 5 | 2 owned types, 1 mutation entry not derivable from the schema, 1 aggregate field, and the owner-lookup function |
| graphql-shield | 0 / 13 | **1 / 5** | 8 permission entries + 4 rule functions |

graphql-shield's failure is GraphQL null propagation: in `children: [ResourceType!]!`, denying the one foreign child raises an error that cannot null a non-null item, so it nulls the whole folder and the owner loses their own documents. Layer 2 removes the foreign item before nullability is enforced.

**Configuration mistakes** (one entry removed at a time):

| System | Effect of a missing entry |
| :--- | :--- |
| GraphQL Shield | Missing mutation entry: **0 leaks** (derived from the schema, or denied). Missing owned type: that type is unprotected (Resource: 9/13 leak; User: 1/13). |
| graphql-shield, `fallbackRule: allow` (default) | Missing mutation rule: the write executes (1 leak each). Missing `ResourceType.*`: relationship leaks. Overlapping rules cover the rest. |
| graphql-shield, `fallbackRule: deny` | 0 leaks, but each missing rule blocks legitimate requests (1 to 4 of 5). |

Neither approach dominates: GraphQL Shield needs far less configuration and fails closed on mutations, but a missing owned type is a single point of failure; graphql-shield's overlapping per-field rules tolerate one missing read rule but need much more configuration, and cost availability under null propagation.

### Latency
`scripts/run_latency_benchmark.py` measures in-process (FastAPI TestClient, no network). All configurations are interleaved: after 30 warm-up requests, each of 10 repeats times 100 requests of every configuration in a fresh random order. Drift on the machine then affects them all alike, and the overhead is the per-repeat difference to the unprotected endpoint, with a 95% confidence interval.

| Request | Unprotected | Both layers, no pooling | Both layers, pooled | Paired overhead [95% CI] |
| :--- | :--- | :--- | :--- | :--- |
| Own lookup | 9.4 ms | 32.6 ms | 10.4 ms | +0.99 ms [−0.36, +2.35] |
| Relationship (`children`) | 10.2 ms | 66.1 ms | 11.0 ms | +0.86 ms [+0.32, +1.40] |
| Own update | 10.4 ms | 35.5 ms | 10.4 ms | +0.00 ms [−1.28, +1.29] |

Protection costs about 1 ms per request (at most 2.4 ms). Three fixes found by profiling got it there:

- SQLite connections are pooled (`--no-pool` reproduces the old behaviour): 3.1–6.0× faster.
- The risk engine's recent-denial check uses an index and an existence probe, instead of counting the whole audit log for every checked object, which had made latency grow with the log.
- The advisory blind-spot predictor cost about 4.4 ms of Layer 1's 5.3 ms, mostly starting XGBoost's thread pool for one row. It now scores on one thread and caches the probability per feature vector, and parsed queries are cached.

**Scaling** (`python -m scripts.run_scaling_benchmark`, `evaluation/latency_scaling.json`, also interleaved): a folder with N children, 10% foreign.

| Children | Unprotected | Layer 2 one by one | Layer 2 batched |
| :--- | :--- | :--- | :--- |
| 1 | 6.9 ms | 8.8 ms | 7.8 ms |
| 10 | 8.5 ms | 9.9 ms | 9.2 ms |
| 50 | 9.2 ms | 18.1 ms | 12.8 ms |
| 200 | 11.7 ms | 44.6 ms | 26.3 ms |

Numbers come from a Windows laptop and vary between runs; compare configurations within a run, not across runs.

### Determinism
The ablation, the tool comparison and the security test suite are deterministic: the same code and data always give the same outcome, so they are reported as counts, not with confidence intervals. Latency and the blind-spot predictor (new request sets per seed, `scripts/run_blind_spot_seeds.py`) are repeated.

Blind-spot predictor on the fixed Layer 1, 5 seeds × 2,000 requests (mean ± std):

| Measure | XGBoost | Rule baseline |
| :--- | :--- | :--- |
| F1, random test split | 0.992 ± 0.006 | 0.992 ± 0.006 |
| Attack recall | 1.000 ± 0.000 | 1.000 ± 0.000 |
| F1, held-out family | 1.000 ± 0.000 | 1.000 ± 0.000 |

Coverage-gap rate among allowed requests: 0.289 ± 0.015; attacks stopped only by Layer 2 per 2,000 requests: 75.6 ± 8.8; top feature in every seed: `relationship_field_count`. Once the variable-default gap is fixed, the remaining blind spot is relationship traversal and the rule matches the model: the predictor's value is the discovery run, not ongoing accuracy.

### Fault injection: does the cross-layer evidence find Layer 1 bugs?
One discovered bypass is an anecdote, so `scripts/run_fault_injection.py` measures it. It patches 17 realistic bugs into Layer 1 at load time (files on disk never change): ignored variables or defaults, skipped fragments, aliases, directives, nested lookups, batch operations, mutation targets, and more. Each fault and an unmodified control run on 5 seeds of 1,000 requests composed from independent constructs.

```bash
python -m scripts.run_fault_injection            # about 1.5 h on a laptop
python -m scripts.run_fault_injection --analyse  # recompute from raw rows
```

Results (`evaluation/fault_injection.json`):

| Measure | Result |
| :--- | :--- |
| Faults detected from the evidence alone | **17 / 17** (every seed); 0 false alarms on the unmodified Layer 1 |
| Mean F1 predicting affected requests | relationship rule 0.661, evidence rule 0.966, decision tree 0.957, logistic regression 0.968, XGBoost 0.967 (0.978 with Layer 1's resolution count) |
| Broken construct ranked first (14 faults a feature can name) | logistic regression 1.000, XGBoost 1.000, decision tree 0.957, lift 0.929 |

The evidence rule is "a relationship field, or an ID argument Layer 1 did not resolve". The value is in the evidence, not the model: XGBoost is no better than logistic regression.

### Security properties (property-based tests)
`tests/test_properties.py` checks four properties with Hypothesis on generated owners, folder contents and composed requests (120 examples each):

- **P1 Safety**: no response contains an object the caller does not own.
- **P2 Non-interference**: changing only other users' objects cannot change the response.
- **P3 Write safety**: no request changes an object the caller does not own.
- **P4 Availability**: a request naming only the caller's objects returns them.

With protection off, all four fail, which shows the tests can catch a violation. Writing P2 exposed four leak channels, now fixed and covered by `tests/test_leak_channels.py` and `tests/test_properties.py`:

- different denial reasons for foreign and missing objects (plus owner IDs in the explainer);
- foreign objects returned through interfaces and unions;
- `childrenCount` counting foreign children;
- deleting a folder that held a hidden foreign child failed on the foreign-key constraint, revealing the child. A deleted folder's children now move to the top level (they keep their owner and content), so the result no longer depends on them.

**Timing.** `python -m scripts.run_timing_channel` sends 1,500 interleaved pairs of requests for a foreign and a missing object and compares their medians (`evaluation/timing_channel.json`). With Layer 2 alone, a foreign read used to take 0.352 ms longer (95% CI 0.193–0.554 ms, p = 2×10⁻⁸), because a lookup that found nothing skipped the check (`--without-missing-check` reproduces it, `evaluation/timing_channel_before_fix.json`). Layer 2 now checks those lookups too, and no setting shows a difference: every 95% interval contains zero and every p ≥ 0.68. The measurement is in-process, with a resolution of about 0.1 ms.

### Other frameworks
`tests/test_frameworks.py` protects a Graphene app (Relay `Node`, lists, mutations) and an Ariadne app with the same middleware. Graphene needs graphql-core < 3.3, so run it in a separate environment:

```bash
python -m venv venv-graphene && venv-graphene/Scripts/pip install -r requirements-frameworks.txt
venv-graphene/Scripts/python -m pytest tests/test_frameworks.py
```

### Docker and CI
`Dockerfile` runs the server and `.github/workflows/tests.yml` runs the test suite on push. Neither was run on the development machine (no Docker there).

---

## Verification & Test Suite

Run the complete test suite:
```bash
python -m pytest -v
```

Expected output:
```text
410 passed, 4 skipped   (the 4 Graphene tests run in their own environment, see "Other frameworks")
```

---

## API Reference

| Endpoint | Method | Auth | Description |
| :--- | :--- | :--- | :--- |
| `/graphql` | `POST` | Bearer JWT | **Protected GraphQL Gateway** with Dual-Layer AST & Mutation Guard |
| `/graphql-insecure` | `POST` | Bearer JWT | **Vulnerable Baseline Endpoint** for comparative evaluation |
| `/dashboard` | `GET` | Public | Real-time Interactive Research & Security Console |
| `/api/v1/auth/login` | `POST` | Public | User authentication and JWT issuance |
| `/api/v1/security/layers` | `GET/POST` | Public counts; Admin for recent events and POST | Inspect or toggle Layer 1 / Layer 2 state |
| `/api/v1/security/layer-ablation` | `GET` | Public | View results from empirical layer ablation experiments |
| `/api/v1/taint-explain` | `POST` | Bearer JWT | Read-only Taint & Policy evaluation explainer |
| `/api/v1/audit-logs` | `GET` | Admin | Fetch recent authorization audit logs |
| `/api/v1/dashboard-stats` | `GET` | Public counts; Admin for `recent_logs` | Aggregated security and telemetry metrics |
| `/api/v1/research-evaluation` | `GET` | Public metrics; Admin for `provenance_evidence` | Empirical comparison stats (Protected vs Insecure) |
| `/api/v1/telemetry/score-session` | `POST` | Public | Offline behavioral scoring using XGBoost (no stored data) |
| `/health` | `GET` | Public | Service health and readiness probe |

---

## Directory Structure

```text
GraphQL-Shield/
├── app/
│   ├── benchmarks/           # Ground truth oracles & evaluation datasets
│   ├── clinic/               # Second, unrelated application (schema-first, Relay IDs)
│   ├── core/                 # JWT security primitives & FastAPI dependencies
│   ├── graphql/              # Schema, queries, mutations, and types
│   │   ├── mutations.py      # Resource write operations (update, delete, transfer)
│   │   ├── queries.py
│   │   ├── schema.py         # Strawberry schema with BatchingConfig
│   │   └── types.py          # ResourceType & UserType resolvers
│   ├── security/             # Dual-layer defense implementation
│   │   ├── enforcement.py    # Layer 1: Centralized pre-execution gate
│   │   ├── runtime_object_guard.py  # Layer 2: Execution-time object & mutation guard
│   │   ├── layers.py         # Dual-layer state, layer events & blind-spot recorder
│   │   ├── object_extractor.py # AST traversal with inline fragments & list IDs
│   │   ├── shield_config.py  # Per-application configuration and startup lint
│   │   ├── audit.py          # Hash-chained audit log
│   │   └── model_service.py  # Lazy-loaded XGBoost ML behavioral service
│   ├── static/
│   │   └── dashboard.html    # Interactive research console UI
│   ├── database.py           # SQLite connection & layer_events table
│   ├── main.py               # FastAPI entrypoint, layer APIs, and routers
│   └── seed.py               # Database seeder with optional shared-folder scenario
├── comparison/               # graphql-shield (Node) on the same schema
├── evaluation/               # Tracked results: fault injection, latency, scaling
├── paper/                    # IEEE paper source (LaTeX)
├── scripts/                  # Benchmarking, training, and fault-injection scripts
├── tests/                    # 414 unit, integration, property and security tests
├── requirements.txt
└── README.md
```

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
