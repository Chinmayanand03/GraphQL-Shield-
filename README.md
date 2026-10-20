# GraphQL-Shield: Autonomous Dual-Layer Runtime Object Guard & Behavioral Defense Framework

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com)
[![Strawberry GraphQL](https://img.shields.io/badge/GraphQL-Strawberry-e535ab.svg?logo=graphql)](https://strawberry.rocks/)
[![Tests Passing](https://img.shields.io/badge/tests-238%20passed-brightgreen.svg)]()
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
- **Python 3.10+** (Tested on Python 3.10, 3.11, 3.12)
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
**Outcome**: `403 Forbidden` | Blocked at **Layer 1 Pre-Execution Gate** (`OWNERSHIP_MISMATCH`).

---

### Demo 3: Nested Object BOLA Attack (403 Forbidden)
User `101` queries their own profile but nests a foreign resource request inside it.

```bash
curl -X POST "http://localhost:8000/graphql"   -H "Authorization: Bearer $TOKEN"   -H "Content-Type: application/json"   -d '{"query": "{ user(id: 101) { username resource(id: 102) { name } } }"}'
```
**Outcome**: `403 Forbidden` | Blocked at **Layer 1** (`NESTED_AUTHORIZATION_VIOLATION`).

---

### Demo 4: Unauthorized Mutation Blocked (Execution-Time Guard)
User `101` attempts to modify Kapilesh's resource (`id: 102`) using the `updateResource` mutation.

```bash
curl -X POST "http://localhost:8000/graphql"   -H "Authorization: Bearer $TOKEN"   -H "Content-Type: application/json"   -d '{"query": "mutation { updateResource(id: 102, name: "Hacked Note") { id name } }"}'
```
**Outcome**: Blocked by **Layer 2 Mutation Guard** (`MUTATION_AUTHORIZATION_DENIED`). Resolver never executes; database remains unmodified.

---

### Demo 5: Implicit Relationship Traversal Probe
User `101` queries folder `201` with child records (when seeded with `--with-shared-folder`, child `204` belongs to Kapilesh).

```bash
curl -X POST "http://localhost:8000/graphql"   -H "Authorization: Bearer $TOKEN"   -H "Content-Type: application/json"   -d '{"query": "{ resource(id: 201) { id name children { id name } childrenCount } }"}'
```
**Outcome**: `200 OK` | **Layer 2** transparently filters out Kapilesh's document `204`. Balanilavan only receives documents `202` and `203`. Zero information leak.

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
- **`/graphql-insecure`**: Vulnerable baseline for comparative metrics (requires authenticated token; can be toggled via `ENABLE_INSECURE_BASELINE`).

### Layer Ablation Experiments
Admins can evaluate Layer 1 vs Layer 2 independently:
- Check current layer status: `GET /api/v1/security/layers`
- Toggle layers dynamically: `POST /api/v1/security/layers` with `{"layer1": false, "layer2": true}`
- View empirical ablation results: `GET /api/v1/security/layer-ablation`

### Training the Behavioral XGBoost Model
```bash
python scripts/generate_behavioral_dataset.py
python scripts/train_behavioral_xgboost.py
```

---

## Verification & Test Suite

Run the complete test suite:
```bash
python -m pytest -v
```

Expected output:
```text
======================= 238 passed in 43.60s =======================
```

---

## API Reference

| Endpoint | Method | Auth | Description |
| :--- | :--- | :--- | :--- |
| `/graphql` | `POST` | Bearer JWT | **Protected GraphQL Gateway** with Dual-Layer AST & Mutation Guard |
| `/graphql-insecure` | `POST` | Bearer JWT | **Vulnerable Baseline Endpoint** for comparative evaluation |
| `/dashboard` | `GET` | Public | Real-time Interactive Research & Security Console |
| `/api/v1/auth/login` | `POST` | Public | User authentication and JWT issuance |
| `/api/v1/security/layers` | `GET/POST` | Admin for POST | Inspect or toggle Layer 1 / Layer 2 state |
| `/api/v1/security/layer-ablation` | `GET` | Public | View results from empirical layer ablation experiments |
| `/api/v1/taint-explain` | `POST` | Bearer JWT | Read-only Taint & Policy evaluation explainer |
| `/api/v1/audit-logs` | `GET` | Bearer JWT | Fetch recent authorization audit logs |
| `/api/v1/dashboard-stats` | `GET` | Public | Aggregated security and telemetry metrics |
| `/api/v1/research-evaluation` | `GET` | Public | Empirical comparison stats (Protected vs Insecure) |
| `/api/v1/telemetry/score-session` | `POST` | Bearer JWT | Offline behavioral scoring using XGBoost |
| `/health` | `GET` | Public | Service health and readiness probe |

---

## Directory Structure

```text
GraphQL-Shield/
├── app/
│   ├── benchmarks/           # Ground truth oracles & evaluation datasets
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
│   │   ├── model_service.py  # Lazy-loaded XGBoost ML behavioral service
│   │   └── policy_rules.py   # Formal authorization policy rules
│   ├── static/
│   │   └── dashboard.html    # Interactive research console UI
│   ├── database.py           # SQLite connection & layer_events table
│   ├── main.py               # FastAPI entrypoint, layer APIs, and routers
│   └── seed.py               # Database seeder with optional shared-folder scenario
├── scripts/                  # Benchmarking, training, and demo scripts
├── tests/                    # 238 unit, integration, and security tests
├── requirements.txt
└── README.md
```

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
