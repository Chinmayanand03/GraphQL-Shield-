# GraphQL Shield Interactive Dashboard Patch

This patch replaces `app/static/dashboard.html` with a responsive, dependency-free dashboard that uses the existing API endpoints:

- `GET /api/v1/dashboard-stats` must return `{ "stats": { "total": ..., "allowed": ..., "blocked": ..., "bola": ..., "high_risk": ... }, "recent_logs": [...] }`.
- `GET /health` is used for the API health indicator.
- The existing `/dashboard` route in `app/main.py` serves this file.

## Features

- KPI cards for total requests, allowed, blocked, BOLA-related signals, and high-risk records.
- SVG decision-mix chart and aggregate authorization bars.
- Auto-refresh every 30 seconds, manual refresh, API connectivity indicator.
- Client-side search and filters over the recent records returned by the API.
- CSV export of currently visible audit rows.
- Light/dark theme toggle, responsive layout, loading and empty states.
- No new Python packages, CDN, or external JavaScript dependency.

## Installation

1. Back up the current dashboard:

   ```powershell
   Copy-Item app/static/dashboard.html app/static/dashboard.html.bak -Force
   ```

2. Copy `app/static/dashboard.html` from this patch into the same path in your project, replacing the old file.
3. Start or restart the app as you normally do.
4. Open `http://127.0.0.1:8000/dashboard` (adjust host/port if yours differs).
5. Confirm aggregate cards populate, refresh works, and search/filters/export work.

No changes to `app/main.py` should be necessary because the current route already serves `app/static/dashboard.html` and exposes `/api/v1/dashboard-stats`.

## Notes

- Filters operate on the recent log rows returned by the API, currently limited by the backend to the latest 15 entries. KPI cards come from the aggregate counters.
- The dashboard is a visualization layer, not an authorization control. Do not expose audit information publicly in production. Protect `/api/v1/dashboard-stats` with admin authorization before deploying outside a local demo environment.
- Dashboard data uses text-safe DOM rendering for audit fields.
