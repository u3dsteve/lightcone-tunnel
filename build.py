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
ICON_FILE = "icon.ico"
OUTPUT_DIR = "dist"


# ============================================================================
# Clean Old Builds
# ============================================================================
def clean():
    print("Cleaning old builds...")
    for d in ("build", "dist"):
        if os.path.exists(d):
            shutil.rmtree(d)
    for f in Path(".").glob("*.spec"):
        f.unlink()


# ============================================================================
# PyInstaller Command Generator
# ============================================================================
def get_base_cmd():
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",
        "--name", APP_NAME,
        "--collect-all", "nicegui",
        "--add-data", f"lightcone-tunnel.py{os.pathsep}.",
        MAIN_SCRIPT,
    ]
    # zfec is optional in lightcone-tunnel.py; only bundle it when installed,
    # otherwise PyInstaller aborts on the missing hidden import.
    try:
        import zfec  # noqa: F401
        cmd.insert(-1, "--hidden-import")
        cmd.insert(-1, "zfec")
    except ImportError:
        print("Note: zfec not installed; building without it.")
    return cmd


# ============================================================================
# Windows Packaging
# ============================================================================
def build_windows():
    print("Building Windows executable...")
    cmd = get_base_cmd()
    if os.path.exists(ICON_FILE):
        cmd.insert(-1, "--icon")
        cmd.insert(-1, ICON_FILE)
    subprocess.run(cmd, check=True)
    print(f"Windows executable: {OUTPUT_DIR}/{APP_NAME}.exe")


# ============================================================================
# Linux Packaging
# ============================================================================
def build_linux():
    print("Building Linux executable...")
    subprocess.run(get_base_cmd(), check=True)
    print(f"Linux executable: {OUTPUT_DIR}/{APP_NAME}")


# ============================================================================
# Main Entry Point
# ============================================================================
if __name__ == "__main__":
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller is not installed. Run: pip install pyinstaller")
        sys.exit(1)

    clean()

    if sys.platform == "win32":
        build_windows()
    elif sys.platform.startswith("linux"):
        build_linux()
    else:
        print("Unsupported platform. Only Windows and Linux are supported.")
        sys.exit(1)

    print("\nBuild complete!")
