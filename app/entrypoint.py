"""Veil Application Main Entrypoint.

Unified binary runner:
- If invoked directly (double-click in Windows Explorer, desktop shortcut, or with `--gui`), launches the native desktop window and system tray.
- If invoked with CLI arguments in a terminal (e.g. `veil scan ...`, `veil clients`, `veil doctor`), executes the command-line interface.
"""
import sys
import multiprocessing
from pathlib import Path

# MUST be called first to prevent Windows PyInstaller subprocess explosions
multiprocessing.freeze_support()

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.cli import cli


def main():
    # If no arguments provided, or explicitly requested via flag, launch native desktop app
    if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] in ("--gui", "-g")):
        try:
            from app.gui.runner import launch_gui
            launch_gui()
        except KeyboardInterrupt:
            sys.exit(0)
        except Exception as e:
            import traceback
            err_msg = traceback.format_exc()
            if sys.platform == "win32":
                try:
                    import ctypes
                    ctypes.windll.user32.MessageBoxW(
                        0,
                        f"Veil encountered an error while starting the desktop interface:\n\n{err_msg}",
                        "Veil AI Privacy Gateway - Startup Error",
                        0x10  # MB_ICONERROR
                    )
                except Exception:
                    pass
            sys.exit(1)
    else:
        # CLI mode: Attach to parent console on Windows so stdout/stderr print cleanly in terminal
        if sys.platform == "win32":
            try:
                import ctypes
                # Only attach and open CONOUT$ if stdout is None (standard PyInstaller GUI mode in terminal)
                if sys.stdout is None:
                    if ctypes.windll.kernel32.AttachConsole(-1):
                        sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace")
                        sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="replace")
            except Exception:
                pass

        cli()


if __name__ == "__main__":
    main()
