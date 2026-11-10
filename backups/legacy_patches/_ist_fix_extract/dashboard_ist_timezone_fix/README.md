# GraphQL Shield dashboard IST timestamp fix

This patch fixes display-time conversion only. The database values remain unchanged.

## Why this patch is needed

The `audit_logs.timestamp` values shared by the project are strings such as `2026-10-12 15:58:41` that represent UTC but have no timezone suffix. `new Date(value)` can interpret that kind of string as the browser's local time. That causes the table to display UTC clock values without converting them to India Standard Time.

## Install

1. Stop before running if your project layout differs; this script requires `app/static/dashboard.html` under the current project root.
2. Open PowerShell in `C:\Users\CHINMAYANAND\Downloads\GraphQL-Shield`.
3. Extract this ZIP into the project root, preserving the script filename.
4. Run:

```powershell
.\apply_ist_timestamp_fix.ps1
```

The script checks that the relevant dashboard code exists, creates a timestamped backup beside `dashboard.html`, then changes only the display code. It does not update database timestamps or change authorization logic.

5. Refresh the browser with Ctrl+F5.

## Expected display

A stored UTC timestamp `2026-10-12 15:58:41` should display in IST as approximately `12 Oct 2026, 09:28:41 PM` (subject to locale punctuation). The table header and last-updated clock explicitly say IST. CSV data retains the raw UTC timestamp and names that column `timestamp_utc`.

The script is intended for the dashboard version containing a `formatTime(value)` function, a `Time` table header, and the existing `lastUpdated` clock code. If those signatures differ, the script stops before modifying the file.
