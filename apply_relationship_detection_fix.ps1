$ErrorActionPreference = 'Stop'

$projectRoot = $PSScriptRoot
$payloadRoot = Join-Path $projectRoot 'payload'

$files = @(
    @{ Source = 'app/benchmarks/runner.py'; Destination = 'app/benchmarks/runner.py'; BackupName = 'runner.py' },
    @{ Source = 'app/benchmarks/dataset.py'; Destination = 'app/benchmarks/dataset.py'; BackupName = 'dataset.py' },
    @{ Source = 'tests/test_research_hardening_integration.py'; Destination = 'tests/test_research_hardening_integration.py'; BackupName = 'test_research_hardening_integration.py' },
    @{ Source = 'app/benchmarks/relationship_detector.py'; Destination = 'app/benchmarks/relationship_detector.py'; BackupName = 'relationship_detector.py' },
    @{ Source = 'tests/test_relationship_detector.py'; Destination = 'tests/test_relationship_detector.py'; BackupName = 'test_relationship_detector.py' }
)

if (-not (Test-Path $payloadRoot -PathType Container)) {
    throw "Patch payload folder not found: $payloadRoot. Extract the ZIP into your project root first."
}

# Validate every source before changing any project file.
foreach ($item in $files) {
    $sourcePath = Join-Path $payloadRoot $item.Source
    if (-not (Test-Path $sourcePath -PathType Leaf)) {
        throw "Required patch file is missing: $sourcePath. No project files have been changed."
    }
}

$requiredProjectFiles = @(
    'app/benchmarks/runner.py',
    'app/benchmarks/dataset.py',
    'app/benchmarks/research_hardening_integration.py',
    'app/security/relationship_extractor.py',
    'tests/test_research_hardening_integration.py'
)
foreach ($relativePath in $requiredProjectFiles) {
    if (-not (Test-Path (Join-Path $projectRoot $relativePath) -PathType Leaf)) {
        throw "Expected existing project file not found: $relativePath. Confirm you are in the correct GraphQL-Shield project folder. No project files have been changed."
    }
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$backupRoot = Join-Path $projectRoot "backups/relationship_detection_pre_patch_$timestamp"
New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null

try {
    # Back up existing files which will be replaced.
    foreach ($item in $files) {
        $destinationPath = Join-Path $projectRoot $item.Destination
        if (Test-Path $destinationPath -PathType Leaf) {
            $backupPath = Join-Path $backupRoot $item.BackupName
            New-Item -ItemType Directory -Path (Split-Path $backupPath -Parent) -Force | Out-Null
            Copy-Item -LiteralPath $destinationPath -Destination $backupPath -Force
        }
    }

    # Apply patch only after every source and prerequisite passed validation.
    foreach ($item in $files) {
        $sourcePath = Join-Path $payloadRoot $item.Source
        $destinationPath = Join-Path $projectRoot $item.Destination
        New-Item -ItemType Directory -Path (Split-Path $destinationPath -Parent) -Force | Out-Null
        Copy-Item -LiteralPath $sourcePath -Destination $destinationPath -Force
        Write-Host "Updated $($item.Destination)"
    }

    Write-Host ''
    Write-Host 'Relationship-aware detection patch applied.' -ForegroundColor Green
    Write-Host "Backup location: $backupRoot"
    Write-Host 'Next: python -m pytest -q'
}
catch {
    Write-Error "Patch application stopped: $($_.Exception.Message)"
    Write-Error "Existing-file backups, when created, are in: $backupRoot"
    throw
}
