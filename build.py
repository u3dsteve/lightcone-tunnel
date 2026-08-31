#!/usr/bin/env python3
"""
Lightcone Tunnel GUI Packaging Script
Usage: python build.py
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

# ============================================================================
# Configuration
# ============================================================================
APP_NAME = "LightconeManager"
MAIN_SCRIPT = "lightcone-manager.py"
ICON_FILE = "icon.ico"  # Windows icon (optional)
OUTPUT_DIR = "dist"

# ============================================================================
# Clean Old Builds
# ============================================================================
def clean():
    print("🧹 Cleaning old builds...")
    dirs_to_clean = ["build", "dist", "__pycache__"]
    for d in dirs_to_clean:
        if os.path.exists(d):
            shutil.rmtree(d)
    for f in Path(".").glob("*.spec"):
        f.unlink()

# ============================================================================
# PyInstaller Command Generator
# ============================================================================
def get_base_cmd():
    return [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",
        "--name", APP_NAME,
        "--collect-all", "nicegui",
        "--collect-all", "webencodings",
        "--collect-all", "tinycss2",
        "--add-data", f"lightcone-tunnel.py{os.pathsep}.",
        "--hidden-import", "cryptography",
        "--hidden-import", "cryptography.hazmat.primitives.ciphers.aead",
        "--hidden-import", "zfec",
        MAIN_SCRIPT
    ]

# ============================================================================
# Windows Packaging
# ============================================================================
def build_windows():
    print("📦 Building Windows executable...")
    cmd = get_base_cmd()
    if os.path.exists(ICON_FILE):
        cmd.insert(-1, "--icon")
        cmd.insert(-1, ICON_FILE)

    subprocess.run(cmd, check=True)
    print(f"✅ Windows executable: {OUTPUT_DIR}/{APP_NAME}.exe")

# ============================================================================
# Linux Packaging
# ============================================================================
def build_linux():
    print("📦 Building Linux executable...")
    cmd = get_base_cmd()
    subprocess.run(cmd, check=True)
    print(f"✅ Linux executable: {OUTPUT_DIR}/{APP_NAME}")

# ============================================================================
# Main Entry Point
# ============================================================================
if __name__ == "__main__":
    try:
        import PyInstaller
    except ImportError:
        print("❌ PyInstaller is not installed. Run: pip install pyinstaller")
        sys.exit(1)

    clean()

    if sys.platform == "win32":
        build_windows()
    elif sys.platform.startswith("linux"):
        build_linux()
    else:
        print("⚠️ Unsupported platform. Only Windows and Linux are supported.")
        sys.exit(1)

    print("\n✅ Build complete!")
