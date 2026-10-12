# Per-request Taint & Authorization Flow

This patch replaces the static-only explanation with a request-specific flow. After each dashboard test it displays:

1. The authenticated principal and role from the validated JWT.
2. Actual ID taint sources returned by `app.security.taint_sources.track_sources()`.
3. Parsed GraphQL object paths and ownership lookups.
4. A read-only re-evaluation by the project's existing `PolicyEngine`.
5. The actual HTTP / GraphQL outcome, distinguished from the policy replay.

For successful requests, the flow explains `OWNER_MATCH` or `ADMIN_OVERRIDE` from the configured engine. For HTTP 403, it shows the observed denial reason and risk data. For the intentionally vulnerable baseline, it warns if the same policy replay says DENY and the response visibly contains the target ID.

Relationship queries additionally show parsed nested selection paths and owner fields visible in the response. The tool does NOT invent hidden child IDs or claim that all internal propagation edges were dynamically observed. The API explicitly labels its policy check as a read-only replay, not the enforcement event itself.

## Install

1. Extract this ZIP into the GraphQL-Shield project root; `apply_taint_trace_dashboard.py`, `payload/`, and `tests/` should sit beside the project's `app/` folder.
2. From a PowerShell terminal in the project root, run:

   ```powershell
   python .\apply_taint_trace_dashboard.py
   ```

3. Run `python -m pytest -q`.
4. Restart FastAPI if needed and hard-refresh `/dashboard` with Ctrl+F5.
5. Try a foreign object ID on `/graphql` (expected 403) and an owned object ID. Inspect the new per-request flow panel.

The installer creates timestamped backups of `app/main.py` and `app/static/dashboard.html` to `backups/taint_request_trace_before_patch_<timestamp>/` before writing. It is idempotent and stops if required source anchors are absent. If a test file or module with the same name already exists, it backs it up first.

The new authenticated route `POST /api/v1/taint-explain` invokes the existing `track_sources`, `normalize_query`, `get_object_owner`, and `PolicyEngine`. It does not execute the GraphQL query or make an enforcement decision. It is a read-only explanation endpoint using the same policy engine to explain the request.

For implicit relationship queries, the flow displays nested selection paths and owner fields actually visible in the response. It does not claim to know hidden child IDs unless a resolver/analysis API explicitly exposes that evidence.

The added regression tests cover foreign-owner denial, legitimate owner access, and administrator access under the configured policy.
