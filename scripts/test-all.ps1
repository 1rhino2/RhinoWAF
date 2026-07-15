# RhinoWAF local verification (Windows)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host '== go test ==' -ForegroundColor Cyan
go test ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host '== go build ==' -ForegroundColor Cyan
go build -o rhinowaf.exe ./cmd/rhinowaf
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host '== version ==' -ForegroundColor Cyan
& .\rhinowaf.exe -version
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (Get-Command golangci-lint -ErrorAction SilentlyContinue) {
    Write-Host '== golangci-lint ==' -ForegroundColor Cyan
    golangci-lint run --timeout=5m
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} else {
    Write-Host 'golangci-lint not installed, skipping lint' -ForegroundColor Yellow
}

Write-Host 'All checks passed.' -ForegroundColor Green
