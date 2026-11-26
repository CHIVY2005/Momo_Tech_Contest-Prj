$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Write-Host "==> [VeriShield Verify] Repo root: $RepoRoot" -ForegroundColor Cyan

$BackendDir = Join-Path $RepoRoot "backend"
$VenvBin = Join-Path $BackendDir ".venv\Scripts"
$RuffExe = Join-Path $VenvBin "ruff.exe"
$MypyExe = Join-Path $VenvBin "mypy.exe"
$PytestExe = Join-Path $VenvBin "pytest.exe"

if (-not (Test-Path $PytestExe)) {
    Write-Error "Backend virtualenv not found at $VenvBin. Create backend/.venv first."
    exit 1
}

Push-Location $BackendDir
try {
    Write-Host "==> [1/3] Running Ruff linter..." -ForegroundColor Yellow
    & $RuffExe check app tests ../scripts ../evaluation ../submission ../training
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Host "==> [2/3] Running Mypy strict typecheck..." -ForegroundColor Yellow
    & $MypyExe --config-file pyproject.toml app
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Host "==> [3/3] Running Pytest suite..." -ForegroundColor Yellow
    & $PytestExe -c pyproject.toml
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}

$FrontendPkg = Join-Path $RepoRoot "frontend\package.json"
if (Test-Path $FrontendPkg) {
    Push-Location (Join-Path $RepoRoot "frontend")
    try {
        Write-Host "==> [Frontend] Running TypeScript strict check, tests & build..." -ForegroundColor Yellow
        & npx tsc --noEmit
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

        & npm test
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

        & npm run build
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    finally {
        Pop-Location
    }
}

Write-Host "==> [VeriShield Verify] ALL CHECKS PASSED!" -ForegroundColor Green
