"""Automated Build Pipeline for Standalone Veil.exe."""
import sys
import subprocess
from pathlib import Path

# Ensure project root is in sys.path
root_dir = Path(__file__).resolve().parent.parent
# Ensure packaging dir is in sys.path
packaging_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(packaging_dir))

from generate_ico import generate_veil_ico


def build_standalone_exe() -> Path:
    """Builds dist/Veil.exe using PyInstaller and executes smoke testing."""
    print("=" * 60)
    print("Veil Windows Standalone Packaging Pipeline")
    print("=" * 60)

    # 1. Ensure icon exists
    ico_path = packaging_dir / "veil.ico"
    if not ico_path.exists():
        print("[1/3] Generating multi-resolution Windows icon...")
        generate_veil_ico(ico_path)
    else:
        print("[1/3] Multi-resolution icon found at:", ico_path)

    # 2. Run PyInstaller
    spec_path = packaging_dir / "veil.spec"
    print(f"[2/3] Compiling standalone binary via PyInstaller ({spec_path})...")

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        str(spec_path)
    ]

    subprocess.check_call(cmd, cwd=str(root_dir))

    exe_path = root_dir / "dist" / "Veil.exe"
    if not exe_path.exists():
        raise FileNotFoundError(f"Expected binary not found at {exe_path}")

    size_mb = exe_path.stat().st_size / (1024 * 1024)
    print(f"\nSUCCESS: Generated standalone executable: {exe_path} ({size_mb:.1f} MB)")

    # 3. Smoke Test
    print("[3/3] Executing smoke test on dist/Veil.exe --help...")
    smoke_cmd = [str(exe_path), "--help"]
    out = subprocess.check_output(smoke_cmd, text=True)
    assert "Veil" in out, "Smoke test failed: Veil help string missing"
    print("Smoke test passed: Executable responds to CLI commands.")

    return exe_path


if __name__ == "__main__":
    try:
        build_standalone_exe()
    except Exception as exc:
        print(f"\nBUILD FAILED: {exc}")
        sys.exit(1)
