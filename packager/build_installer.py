"""Automated Windows Installer Build Pipeline for VeilSetup.exe."""
import os
import sys
import shutil
import subprocess
from pathlib import Path

# Ensure packaging directory is in sys.path
packaging_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(packaging_dir))

from build_exe import build_standalone_exe

INNO_SEARCH_PATHS = [
    r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    r"C:\Program Files\Inno Setup 6\ISCC.exe",
    r"C:\Program Files (x86)\Inno Setup 5\ISCC.exe",
    r"C:\Program Files\Inno Setup 5\ISCC.exe",
]


def find_iscc() -> Path | None:
    """Locate the Inno Setup compiler executable (ISCC.exe)."""
    # 1. Check PATH
    which_iscc = shutil.which("iscc") or shutil.which("ISCC.exe")
    if which_iscc:
        return Path(which_iscc)

    # 2. Check standard Windows installation directories
    for path_str in INNO_SEARCH_PATHS:
        p = Path(path_str)
        if p.exists():
            return p

    # 3. Check LOCALAPPDATA / ProgramData
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        p = Path(local_app_data) / "Programs" / "Inno Setup 6" / "ISCC.exe"
        if p.exists():
            return p

    return None


def build_installer(build_exe_if_missing: bool = True) -> Path | None:
    """Builds the Inno Setup installer VeilSetup.exe."""
    print("=" * 60)
    print("Veil Windows Installer Build Pipeline (VeilSetup.exe)")
    print("=" * 60)

    root_dir = packaging_dir.parent
    exe_path = root_dir / "dist" / "Veil.exe"
    iss_path = packaging_dir / "installer.iss"

    # Step 1: Ensure Veil.exe exists
    if not exe_path.exists():
        if build_exe_if_missing:
            print("[1/2] Standalone binary dist/Veil.exe missing. Building binary first...")
            build_standalone_exe()
        else:
            raise FileNotFoundError(f"Missing required binary at {exe_path}")
    else:
        print("[1/2] Standalone binary verified at:", exe_path)

    # Step 2: Locate Inno Setup Compiler
    iscc_path = find_iscc()
    if not iscc_path:
        print("\n[NOTE] Inno Setup compiler (ISCC.exe) not detected on this system.")
        print(f"Verified installer specification: {iss_path}")
        print("To compile VeilSetup.exe locally:")
        print("  1. Install Inno Setup: winget install JRSoftware.InnoSetup")
        print("  2. Re-run: python packager/build_installer.py")
        return None

    print(f"[2/2] Compiling Windows Installer via {iscc_path}...")
    cmd = [str(iscc_path), str(iss_path)]
    subprocess.check_call(cmd, cwd=str(packaging_dir))

    setup_exe = root_dir / "dist" / "VeilSetup.exe"
    if setup_exe.exists():
        size_mb = setup_exe.stat().st_size / (1024 * 1024)
        print(f"\nSUCCESS: Generated Windows Installer: {setup_exe} ({size_mb:.1f} MB)")
        return setup_exe

    return None


if __name__ == "__main__":
    build_installer()
