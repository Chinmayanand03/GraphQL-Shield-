$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$required = @(
    "payload\app\graphql\types.py",
    "payload\app\security\dynamic_verifier.py",
    "payload\tests\test_relationship_authorization_regression.py",
    "app\graphql\types.py",
    "app\security\dynamic_verifier.py",
    "app\security\enforcement.py"
)
foreach ($path in $required) {
    if (-not (Test-Path (Join-Path $root $path))) {
        throw "Required file not found: $path. Extract the entire patch ZIP into the project root before running this script."
    }
}

$enforcementPath = Join-Path $root "app\security\enforcement.py"
$enforcementContent = Get-Content $enforcementPath -Raw
$alreadyWired = $enforcementContent -match 'request\.state\.current_user\s*=\s*current_user'
$signature = [regex]::Match(
    $enforcementContent,
    '(?m)^[ \t]*async[ \t]+def[ \t]+bola_enforcement_middleware[^\r\n]*:[ \t]*$'
)
if (-not $alreadyWired -and -not $signature.Success) {
    throw "Could not safely locate the one-line bola_enforcement_middleware signature. No files were changed. Add 'request.state.current_user = current_user' as the first statement in that function, then rerun the tests."
}

$backupRoot = Join-Path $root "backups\relationship_bola_fix_pre_patch"
$backupFiles = @(
    "app\graphql\types.py",
    "app\security\dynamic_verifier.py",
    "app\security\enforcement.py"
)
if (Test-Path "tests\test_relationship_authorization_regression.py") {
    $backupFiles += "tests\test_relationship_authorization_regression.py"
}
foreach ($relative in $backupFiles) {
    $source = Join-Path $root $relative
    if (Test-Path $source) {
        $destination = Join-Path $backupRoot $relative
        New-Item -ItemType Directory -Force (Split-Path $destination) | Out-Null
        Copy-Item $source $destination -Force
    }
}

Copy-Item (Join-Path $root "payload\app\graphql\types.py") (Join-Path $root "app\graphql\types.py") -Force
Copy-Item (Join-Path $root "payload\app\security\dynamic_verifier.py") (Join-Path $root "app\security\dynamic_verifier.py") -Force

if (-not $alreadyWired) {
    $lineFeedIndex = $enforcementContent.IndexOf("`n", $signature.Index + $signature.Length)
    if ($lineFeedIndex -lt 0) {
        throw "Could not locate the end of bola_enforcement_middleware signature line. Restoring from the backup may be required."
    }
    $updated = $enforcementContent.Insert($lineFeedIndex + 1, "    request.state.current_user = current_user`r`n")
    [System.IO.File]::WriteAllText($enforcementPath, $updated, [System.Text.UTF8Encoding]::new($false))
}

New-Item -ItemType Directory -Force (Join-Path $root "tests") | Out-Null
Copy-Item (Join-Path $root "payload\tests\test_relationship_authorization_regression.py") (Join-Path $root "tests\test_relationship_authorization_regression.py") -Force

Write-Host "Relationship BOLA fix applied. Backups: $backupRoot" -ForegroundColor Green
Write-Host "Next: python -m pytest -q" -ForegroundColor Cyan
