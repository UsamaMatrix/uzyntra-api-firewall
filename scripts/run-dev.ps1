#Requires -Version 5.1
$ErrorActionPreference = "Stop"

# ─── Colors ───────────────────────────────────────────────────────────────────
function Write-Header  { param($msg) Write-Host "`n  $msg" -ForegroundColor Cyan }
function Write-Step    { param($msg) Write-Host "  › $msg" -ForegroundColor White }
function Write-Success { param($msg) Write-Host "  ✔ $msg" -ForegroundColor Green }
function Write-Warn    { param($msg) Write-Host "  ⚠ $msg" -ForegroundColor Yellow }
function Write-Fail    { param($msg) Write-Host "  ✘ $msg" -ForegroundColor Red }
function Write-Divider { Write-Host "  $('─' * 54)" -ForegroundColor DarkGray }

# ─── Banner ───────────────────────────────────────────────────────────────────
Clear-Host
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║           API FIREWALL  —  Dev Runner                ║" -ForegroundColor Cyan
Write-Host "  ║                                                      ║" -ForegroundColor Cyan
Write-Host "  ║  GitHub   : github.com/UZYNTRA-Security/uzyntra-api-firewall ║" -ForegroundColor DarkGray
Write-Host "  ║  LinkedIn : linkedin.com/in/usamamatrix              ║" -ForegroundColor DarkGray
Write-Host "  ╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Divider

# ─── Paths ────────────────────────────────────────────────────────────────────
$ProjectRoot = Resolve-Path "$PSScriptRoot\.."
$ConfigPath  = "config/development.yaml"
$ConfigFull  = Join-Path $ProjectRoot $ConfigPath
$CargoToml   = Join-Path $ProjectRoot "Cargo.toml"

# ─── Requirement Checks ───────────────────────────────────────────────────────
Write-Header "Checking Requirements"

# Rust / Cargo
Write-Step "Rust toolchain (cargo)..."
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Fail "cargo not found. Install Rust from https://rustup.rs"
    exit 1
}
$rustVersion = (rustc --version 2>&1)
Write-Success "Rust  : $rustVersion"

# Cargo.toml
Write-Step "Cargo.toml..."
if (-not (Test-Path $CargoToml)) {
    Write-Fail "Cargo.toml not found at: $CargoToml"
    exit 1
}
Write-Success "Cargo.toml found"

# Config file
Write-Step "Config file ($ConfigPath)..."
if (-not (Test-Path $ConfigFull)) {
    Write-Fail "Config not found at: $ConfigFull"
    exit 1
}
Write-Success "Config found"

Write-Divider

# ─── Environment ──────────────────────────────────────────────────────────────
Write-Header "Setting Environment"

Set-Location $ProjectRoot

$env:APP_CONFIG_PATH = $ConfigPath
$env:RUST_LOG        = "info"

Write-Step "APP_CONFIG_PATH = $env:APP_CONFIG_PATH"
Write-Step "RUST_LOG        = $env:RUST_LOG"
Write-Step "Working dir     = $ProjectRoot"

Write-Divider

# ─── Build & Run ──────────────────────────────────────────────────────────────
Write-Header "Starting API Firewall"
Write-Step "Running: cargo run"
Write-Host ""

try {
    cargo run
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Process exited with code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
} catch {
    Write-Fail "Unexpected error: $_"
    exit 1
}
