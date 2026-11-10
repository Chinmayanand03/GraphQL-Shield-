# GraphQL Shield Dashboard Enhancement

## Adds
- Joins `users.username` into recent audit records so the Actor column can display a username instead of only a numeric user ID.
- Shows operation plus path/object details in the audit table.
- Adds a local test console with direct-resource, nested user-resource, and implicit child-relationship scenarios.
- Lets the user select `/graphql` (protected) or `/graphql-insecure` (intentionally vulnerable baseline), enter seeded demo login credentials, and inspect the response without manually running test commands in a terminal.
- Adds an explanatory taint-analysis pipeline diagram and explicitly labels it as an explanation, not a live taint trace feed.

## Install
1. Unzip this archive into the project root, preserving its folders. It contains `apply_dashboard_enhancement.ps1` and `payload/app/static/dashboard.html`.
2. Open PowerShell in the project root.
3. Run `./apply_dashboard_enhancement.ps1`.
4. Run `python -m pytest -q`.
5. Restart FastAPI if needed and open `/dashboard`; press Ctrl+F5.

The installer backs up `app/main.py` and `app/static/dashboard.html` under `backups/dashboard_test_console_before_patch/` before changing anything. It makes a targeted change to the dashboard-stats recent-log SQL join. If your current `main.py` uses a different query, the script stops rather than guessing.

## Using the test console
- Use only local seeded demo accounts (for example Balanilavan/Kapilesh) and test IDs from your synthetic database.
- Enter username and password. The page requests a JWT from `/api/v1/auth/login`; it keeps the token only in JavaScript memory, never in localStorage.
- Select direct resource, nested user-to-resource, or implicit `children` traversal; fill in the corresponding IDs; click **Run selected test**.
- The response appears in the dashboard, then the dashboard refreshes audit metrics.
- The `/graphql-insecure` endpoint is intentionally vulnerable and should only be used on a local isolated research environment.

## Important security note
The project's `/api/v1/dashboard-stats` route is open in the current code shared earlier. Do not deploy the dashboard or its statistics endpoint publicly as-is. Restrict them to administrators before any non-local deployment. Do not put real credentials into the test console.

## Taint analysis note
The diagram explains the existing analysis concepts: taint sources, propagation, transfer/graph/path reasoning, authorization context, and enforcement. It does not fabricate live taint findings. A live trace viewer would require storing or exposing analyzer findings through a dedicated API endpoint.
