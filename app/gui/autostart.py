"""Windows Auto-Start Manager using HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run."""
import sys
import os
from pathlib import Path

RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_NAME = "Veil"


def _get_target_command(custom_path: str = None) -> str:
    """Determine the command string to register in Windows Run key."""
    if custom_path:
        return f'"{custom_path}" --gui'

    # If running inside a PyInstaller frozen bundle
    if getattr(sys, "frozen", False) and hasattr(sys, "executable"):
        return f'"{sys.executable}" --gui'

    # If running from source code
    python_exe = sys.executable
    entrypoint = Path(__file__).resolve().parent.parent / "entrypoint.py"
    return f'"{python_exe}" "{entrypoint}" --gui'


def is_autostart_enabled() -> bool:
    """Check if Veil is registered to run on Windows startup for the current user."""
    if sys.platform != "win32":
        return False

    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, APP_NAME)
            return bool(val)
    except FileNotFoundError:
        return False
    except OSError:
        return False


def enable_autostart(custom_path: str = None) -> bool:
    """Register Veil in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run."""
    if sys.platform != "win32":
        return False

    import winreg
    cmd = _get_target_command(custom_path)
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, cmd)
            return True
    except OSError as e:
        print(f"Failed to enable autostart in registry: {e}")
        return False


def disable_autostart() -> bool:
    """Remove Veil from HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run."""
    if sys.platform != "win32":
        return False

    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_SET_VALUE) as key:
            try:
                winreg.DeleteValue(key, APP_NAME)
            except FileNotFoundError:
                pass
            return True
    except OSError as e:
        print(f"Failed to disable autostart in registry: {e}")
        return False
