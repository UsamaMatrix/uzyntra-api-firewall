#!/usr/bin/env bash
# API Firewall — Dev Runner (Bash)
set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────────────────────
RESET="\033[0m"
BOLD="\033[1m"
CYAN="\033[96m"
GREEN="\033[92m"
YELLOW="\033[93m"
RED="\033[91m"
WHITE="\033[97m"
GRAY="\033[90m"

header()  { echo -e "\n  ${CYAN}${BOLD}${1}${RESET}"; }
step()    { echo -e "  ${WHITE}› ${1}${RESET}"; }
success() { echo -e "  ${GREEN}✔ ${1}${RESET}"; }
warn()    { echo -e "  ${YELLOW}⚠ ${1}${RESET}"; }
fail()    { echo -e "  ${RED}✘ ${1}${RESET}"; }
divider() { echo -e "  ${GRAY}──────────────────────────────────────────────────────${RESET}"; }

# ─── Banner ───────────────────────────────────────────────────────────────────
clear
echo ""
echo -e "  ${CYAN}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "  ${CYAN}║           API FIREWALL  —  Dev Runner                ║${RESET}"
echo -e "  ${CYAN}║                                                      ║${RESET}"
echo -e "  ${GRAY}║  GitHub   : github.com/UZYNTRA-Security/uzyntra-api-firewall ║${RESET}"
echo -e "  ${GRAY}║  LinkedIn : linkedin.com/in/usamamatrix              ║${RESET}"
echo -e "  ${CYAN}╚══════════════════════════════════════════════════════╝${RESET}"
divider

# ─── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_PATH="config/development.yaml"
CONFIG_FULL="$PROJECT_ROOT/$CONFIG_PATH"
CARGO_TOML="$PROJECT_ROOT/Cargo.toml"

# ─── Trap for clean exit ──────────────────────────────────────────────────────
trap 'echo ""; warn "Interrupted by user."; exit 0' INT

# ─── Requirement Checks ───────────────────────────────────────────────────────
header "Checking Requirements"

# Bash version
step "Bash version..."
success "Bash   : ${BASH_VERSION}"

# Rust / Cargo
step "Rust toolchain (cargo)..."
if ! command -v cargo &>/dev/null; then
    fail "cargo not found. Install Rust from https://rustup.rs"
    exit 1
fi
RUST_VER="$(rustc --version 2>&1)"
success "Rust   : ${RUST_VER}"

# Cargo.toml
step "Cargo.toml..."
if [[ ! -f "$CARGO_TOML" ]]; then
    fail "Cargo.toml not found at: $CARGO_TOML"
    exit 1
fi
success "Cargo.toml found"

# Config file
step "Config file ($CONFIG_PATH)..."
if [[ ! -f "$CONFIG_FULL" ]]; then
    fail "Config not found at: $CONFIG_FULL"
    exit 1
fi
success "Config found"

divider

# ─── Environment ──────────────────────────────────────────────────────────────
header "Setting Environment"

cd "$PROJECT_ROOT"
export APP_CONFIG_PATH="$CONFIG_PATH"
export RUST_LOG="info"

step "APP_CONFIG_PATH = $APP_CONFIG_PATH"
step "RUST_LOG        = $RUST_LOG"
step "Working dir     = $PROJECT_ROOT"

divider

# ─── Build & Run ──────────────────────────────────────────────────────────────
header "Starting API Firewall"
step "Running: cargo run"
echo ""

if ! cargo run; then
    fail "cargo run failed with exit code $?"
    exit 1
fi
