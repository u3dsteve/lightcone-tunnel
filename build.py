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
# Windows Packaging
# ============================================================================
def build_windows():
    print("📦 Building Windows executable...")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",
        "--name", APP_NAME,
        "--add-data", f"lightcone-tunnel.py{os.pathsep}.",
        MAIN_SCRIPT
    ]
    if os.path.exists(ICON_FILE):
        cmd.extend(["--icon", ICON_FILE])

    subprocess.run(cmd, check=True)
    print(f"✅ Windows executable: {OUTPUT_DIR}/{APP_NAME}.exe")

# ============================================================================
# Linux Packaging
# ============================================================================
def build_linux():
    print("📦 Building Linux executable...")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",  # 抑制终端窗口，提供桌面应用体验
        "--name", APP_NAME,
        "--add-data", f"lightcone-tunnel.py{os.pathsep}.",
        MAIN_SCRIPT
    ]
    subprocess.run(cmd, check=True)
    print(f"✅ Linux executable: {OUTPUT_DIR}/{APP_NAME}")

# ============================================================================
# Main Entry Point
# ============================================================================
if __name__ == "__main__":
    # Check dependencies
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
