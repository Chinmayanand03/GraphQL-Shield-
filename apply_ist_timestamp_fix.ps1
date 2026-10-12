$ErrorActionPreference = 'Stop'

$projectRoot = (Get-Location).Path
$dashboardPath = Join-Path $projectRoot 'app\static\dashboard.html'

if (-not (Test-Path -LiteralPath $dashboardPath)) {
    throw "Dashboard not found at '$dashboardPath'. Run this script from the GraphQL-Shield project root. No files changed."
}

$html = Get-Content -LiteralPath $dashboardPath -Raw -Encoding UTF8
$formatPattern = '(?ms)^[ \t]*function formatTime\(value\)\s*\{.*?^[ \t]*\}'
$formatMatches = [regex]::Matches($html, $formatPattern)
if ($formatMatches.Count -ne 1) {
    throw "Expected exactly one function formatTime(value) in dashboard.html; found $($formatMatches.Count). No files changed."
}

$newFormatFunction = @'
      function formatTime(value) {
        if (!value || value === '—') return '—';
        const raw = String(value).trim();
        let date;
        // SQLite audit timestamps are stored as UTC strings without a zone suffix,
        // for example: 2026-10-12 15:58:41. Interpret those strings as UTC explicitly.
        const naiveUtc = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?$/.test(raw);
        if (naiveUtc) {
          date = new Date(raw.replace(' ', 'T') + 'Z');
        } else {
          // ISO values with Z or an explicit offset already identify their timezone.
          date = new Date(raw);
        }
        if (Number.isNaN(date.getTime())) return raw;
        return new Intl.DateTimeFormat('en-IN', {
          timeZone: 'Asia/Kolkata',
          day: '2-digit', month: 'short', year: 'numeric',
          hour: '2-digit', minute: '2-digit', second: '2-digit',
          hour12: true
        }).format(date);
      }
'@

$formatRegex = [regex]::new($formatPattern)
$newHtml = $formatRegex.Replace(
    $html,
    [System.Text.RegularExpressions.MatchEvaluator]{ param($match) $newFormatFunction.TrimEnd() },
    1
)

# Make the UI timezone explicit instead of leaving the column ambiguous.
if ($newHtml.Contains('<th>Time</th>')) {
    $newHtml = $newHtml.Replace('<th>Time</th>', '<th>Time (IST)</th>')
} elseif (-not $newHtml.Contains('<th>Time (IST)</th>')) {
    throw "Could not find the audit table time header. No files changed."
}

# Show the 'Last updated' clock in IST too.
$oldUpdated = "state.lastUpdate = new Date(); setText('lastUpdated', 'Last updated: ' + state.lastUpdate.toLocaleTimeString());"
$newUpdated = @'
state.lastUpdate = new Date();
          const istNow = new Intl.DateTimeFormat('en-IN', { timeZone: 'Asia/Kolkata', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true }).format(state.lastUpdate);
          setText('lastUpdated', 'Last updated (IST): ' + istNow);
'@
$newUpdated = $newUpdated.Trim()
if ($newHtml.Contains($oldUpdated)) {
    $newHtml = $newHtml.Replace($oldUpdated, $newUpdated)
} elseif (-not $newHtml.Contains('Last updated (IST):')) {
    throw "Could not find the last-updated clock code. No files changed."
}

# Keep CSV's raw stored timestamp clearly labelled UTC; don't alter the audit evidence.
$newHtml = $newHtml.Replace("const headers = ['timestamp','actor'", "const headers = ['timestamp_utc','actor'")

# Ensure that the visible dashboard will indicate the timestamp display convention.
$subtitleOld = 'Search and filter the latest records returned by the API.'
$subtitleNew = 'Search and filter the latest records returned by the API. Timestamps are stored in UTC and displayed in IST (Asia/Kolkata).'
if ($newHtml.Contains($subtitleOld) -and -not $newHtml.Contains($subtitleNew)) {
    $newHtml = $newHtml.Replace($subtitleOld, $subtitleNew)
}

if ($newHtml -eq $html) {
    throw "No changes were made: the dashboard may already have the IST fix."
}

$backupPath = "$dashboardPath.bak_ist_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
Copy-Item -LiteralPath $dashboardPath -Destination $backupPath
Set-Content -LiteralPath $dashboardPath -Value $newHtml -Encoding UTF8

Write-Host "IST timestamp fix applied successfully." -ForegroundColor Green
Write-Host "Dashboard: $dashboardPath"
Write-Host "Backup:    $backupPath"
Write-Host "Audit timestamps are interpreted as UTC and displayed in Asia/Kolkata (IST)."
Write-Host "CSV keeps original database timestamps labelled timestamp_utc."
