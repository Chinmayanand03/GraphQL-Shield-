$ErrorActionPreference = "Stop"
$projectRoot = (Get-Location).Path
$mainPath = Join-Path $projectRoot "app/main.py"
$dashboardPath = Join-Path $projectRoot "app/static/dashboard.html"
$sourceDashboard = Join-Path $PSScriptRoot "payload/app/static/dashboard.html"
$backupDir = Join-Path $projectRoot "backups/dashboard_test_console_before_patch"

if (-not (Test-Path $mainPath)) { throw "app/main.py not found. Run this script from the project root." }
if (-not (Test-Path $dashboardPath)) { throw "app/static/dashboard.html not found." }
if (-not (Test-Path $sourceDashboard)) { throw "Patch dashboard HTML is missing: $sourceDashboard" }

$mainText = Get-Content -LiteralPath $mainPath -Raw
$oldPattern = '(?s)cursor\.execute\(\s*"SELECT \* FROM audit_logs ORDER BY timestamp DESC LIMIT 15"\s*\)'
$newQuery = @'
cursor.execute(
        """
        SELECT a.*, u.username AS username, u.username AS actor_name
        FROM audit_logs AS a
        LEFT JOIN users AS u ON u.id = a.user_id
        ORDER BY a.timestamp DESC
        LIMIT 15
        """
    )
'@
$alreadyJoined = $mainText.Contains('u.username AS actor_name')
if (-not $alreadyJoined -and -not [regex]::IsMatch($mainText, $oldPattern)) {
    throw "Expected dashboard-stats recent_logs query was not found. No files were changed. Inspect app/main.py and adapt the query manually."
}

New-Item -ItemType Directory -Force $backupDir | Out-Null
Copy-Item -LiteralPath $mainPath -Destination (Join-Path $backupDir "main.py") -Force
Copy-Item -LiteralPath $dashboardPath -Destination (Join-Path $backupDir "dashboard.html") -Force

if (-not $alreadyJoined) {
    $mainText = [regex]::Replace($mainText, $oldPattern, $newQuery.TrimEnd(), 1)
    Set-Content -LiteralPath $mainPath -Value $mainText -Encoding utf8
}
Copy-Item -LiteralPath $sourceDashboard -Destination $dashboardPath -Force
Write-Host "Dashboard enhanced. Backups: $backupDir"
Write-Host "New features: username in audit table, richer path/details, local GraphQL test console, taint pipeline explainer."
Write-Host "Test console is for local demonstration only. The dashboard statistics endpoint remains unauthenticated in the current project; do not expose it publicly without restricting it to administrators."
