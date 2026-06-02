"""
build.py — one-command installer build for Container Probe GUI

Usage
-----
  python build.py              # auto-detect platform
  python build.py --windows    # force Windows build (on Windows runner)
  python build.py --macos      # force macOS  build (on macOS  runner)

Outputs
-------
  dist/ContainerProbe.exe          (Windows)
  dist/ContainerProbe.app          (macOS app bundle)
  ContainerProbe-<version>.dmg     (macOS DMG, if create-dmg is installed)
  Output/ContainerProbeSetup.exe   (Windows installer, if Inno Setup is installed)
"""

from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
import sys
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────
APP_NAME    = "ContainerProbe"
APP_VERSION = "1.0.0"
ENTRY_POINT = "gui.py"
ICON_WIN    = "assets/icon.ico"
ICON_MAC    = "assets/icon.icns"
INNO_SCRIPT = "installer/windows.iss"


def run(cmd: list[str], **kw) -> None:
    print(f"\n▶  {' '.join(cmd)}\n")
    subprocess.run(cmd, check=True, **kw)


def pyinstaller_base() -> list[str]:
    return [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--name", APP_NAME,
        "--windowed",                # no terminal window
        "--onefile",                 # single executable
        "--add-data", f"src{sep()}src",   # bundle the package source
    ]


def sep() -> str:
    """PyInstaller path separator: ; on Windows, : elsewhere."""
    return ";" if platform.system() == "Windows" else ":"


def build_windows() -> None:
    icon = Path(ICON_WIN)
    cmd = pyinstaller_base()
    if icon.exists():
        cmd += ["--icon", str(icon)]
    cmd.append(ENTRY_POINT)
    run(cmd)

    exe = Path("dist") / f"{APP_NAME}.exe"
    print(f"\n✅  Executable: {exe}")

    # Build Inno Setup installer if iscc is available
    iscc = shutil.which("iscc")
    if iscc and Path(INNO_SCRIPT).exists():
        run([iscc, INNO_SCRIPT])
        print("✅  Installer created in Output/")
    else:
        print("ℹ   Inno Setup not found — skipping installer. "
              "Install from https://jrsoftware.org/isinfo.php")


def build_macos() -> None:
    icon = Path(ICON_MAC)
    cmd = pyinstaller_base()
    if icon.exists():
        cmd += ["--icon", str(icon)]
    cmd.append(ENTRY_POINT)
    run(cmd)

    app = Path("dist") / f"{APP_NAME}.app"
    print(f"\n✅  App bundle: {app}")

    # Build DMG if create-dmg is available
    create_dmg = shutil.which("create-dmg")
    if create_dmg and app.exists():
        dmg_name = f"{APP_NAME}-{APP_VERSION}.dmg"
        run([
            "create-dmg",
            "--volname", "Container Probe",
            "--window-size", "600", "400",
            "--icon-size", "128",
            "--icon", f"{APP_NAME}.app", "150", "200",
            "--hide-extension", f"{APP_NAME}.app",
            "--app-drop-link", "450", "200",
            dmg_name,
            str(app),
        ])
        print(f"✅  DMG: {dmg_name}")
    else:
        print("ℹ   create-dmg not found — skipping DMG. "
              "Install with: brew install create-dmg")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build Container Probe GUI installer")
    parser.add_argument("--windows", action="store_true")
    parser.add_argument("--macos",   action="store_true")
    args = parser.parse_args()

    system = platform.system()
    if args.windows or system == "Windows":
        build_windows()
    elif args.macos or system == "Darwin":
        build_macos()
    else:
        print(f"Unsupported platform: {system}. Use --windows or --macos.")
        sys.exit(1)


if __name__ == "__main__":
    main()
