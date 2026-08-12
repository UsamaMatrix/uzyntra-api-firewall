#!/usr/bin/env python3
"""API Firewall — Dev Runner (Python)"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

# ─── ANSI Colors ──────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
WHITE  = "\033[97m"
GRAY   = "\033[90m"

def header(msg):  print(f"\n  {CYAN}{BOLD}{msg}{RESET}")
def step(msg):    print(f"  {WHITE}› {msg}{RESET}")
def success(msg): print(f"  {GREEN}✔ {msg}{RESET}")
def warn(msg):    print(f"  {YELLOW}⚠ {msg}{RESET}")
def fail(msg):    print(f"  {RED}✘ {msg}{RESET}")
def divider():    print(f"  {GRAY}{'─' * 54}{RESET}")

def banner():
    print()
    print(f"  {CYAN}╔══════════════════════════════════════════════════════╗{RESET}")
    print(f"  {CYAN}║           API FIREWALL  —  Dev Runner                ║{RESET}")
    print(f"  {CYAN}║                                                      ║{RESET}")
    print(f"  {GRAY}║  GitHub   : github.com/UZYNTRA-Security/uzyntra-api-firewall ║{RESET}")
    print(f"  {GRAY}║  LinkedIn : linkedin.com/in/usamamatrix              ║{RESET}")
    print(f"  {CYAN}╚══════════════════════════════════════════════════════╝{RESET}")
    divider()

# ─── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
CONFIG_PATH  = "config/development.yaml"
CONFIG_FULL  = PROJECT_ROOT / CONFIG_PATH
CARGO_TOML   = PROJECT_ROOT / "Cargo.toml"

# ─── Requirement Checks ───────────────────────────────────────────────────────
def check_requirements():
    header("Checking Requirements")

    # Python version
    step("Python version...")
    if sys.version_info < (3, 7):
        fail(f"Python 3.7+ required, found {sys.version}")
        sys.exit(1)
    success(f"Python : {sys.version.split()[0]}")

    # Rust / Cargo
    step("Rust toolchain (cargo)...")
    if not shutil.which("cargo"):
        fail("cargo not found. Install Rust from https://rustup.rs")
        sys.exit(1)
    result = subprocess.run(["rustc", "--version"], capture_output=True, text=True)
    success(f"Rust   : {result.stdout.strip()}")

    # Cargo.toml
    step("Cargo.toml...")
    if not CARGO_TOML.exists():
        fail(f"Cargo.toml not found at: {CARGO_TOML}")
        sys.exit(1)
    success("Cargo.toml found")

    # Config file
    step(f"Config file ({CONFIG_PATH})...")
    if not CONFIG_FULL.exists():
        fail(f"Config not found at: {CONFIG_FULL}")
        sys.exit(1)
    success("Config found")

    divider()

# ─── Environment ──────────────────────────────────────────────────────────────
def setup_environment():
    header("Setting Environment")

    os.chdir(PROJECT_ROOT)
    os.environ["APP_CONFIG_PATH"] = CONFIG_PATH
    os.environ["RUST_LOG"]        = "info"

    step(f"APP_CONFIG_PATH = {CONFIG_PATH}")
    step(f"RUST_LOG        = info")
    step(f"Working dir     = {PROJECT_ROOT}")

    divider()

# ─── Build & Run ──────────────────────────────────────────────────────────────
def run():
    header("Starting API Firewall")
    step("Running: cargo run")
    print()

    try:
        result = subprocess.run(["cargo", "run"], cwd=PROJECT_ROOT)
        if result.returncode != 0:
            fail(f"Process exited with code {result.returncode}")
            sys.exit(result.returncode)
    except FileNotFoundError:
        fail("cargo executable not found during run.")
        sys.exit(1)
    except KeyboardInterrupt:
        print()
        warn("Interrupted by user.")
        sys.exit(0)

# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Enable ANSI on Windows
    if sys.platform == "win32":
        os.system("")

    banner()
    check_requirements()
    setup_environment()
    run()
