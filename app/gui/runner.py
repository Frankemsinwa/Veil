"""Veil Desktop Application Orchestrator & Runner."""
import sys
import time
import threading
import urllib.request
import urllib.error
import uvicorn

from app.core.config import settings
from app.gui.tray import VeilSystemTray
from app.gui.window import VeilDesktopWindow


class VeilAppRunner:
    """Coordinates the background Uvicorn daemon, system tray, and native GUI window."""

    def __init__(self, host: str = None, port: int = None, debug: bool = False):
        self.host = host or settings.HOST
        self.port = port or settings.PORT
        self.debug = debug

        self.server: uvicorn.Server = None
        self.server_thread: threading.Thread = None
        self.tray: VeilSystemTray = None
        self.window: VeilDesktopWindow = None
        self._shutdown_event = threading.Event()

    def _start_uvicorn(self):
        """Starts the FastAPI backend inside a background daemon thread."""
        from app.main import app as fastapi_app
        config = uvicorn.Config(
            app=fastapi_app,
            host=self.host,
            port=self.port,
            log_level="warning" if not self.debug else "info",
            access_log=self.debug
        )
        self.server = uvicorn.Server(config)
        self.server_thread = threading.Thread(target=self.server.run, daemon=True)
        self.server_thread.start()

    def _wait_for_gateway(self, timeout_sec: float = 8.0) -> bool:
        """Poll the local loopback health endpoint until ready."""
        url = f"http://{self.host}:{self.port}/health"
        deadline = time.time() + timeout_sec

        while time.time() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=1.0) as resp:
                    if resp.status == 200:
                        return True
            except Exception:
                time.sleep(0.15)
        return False

    def _on_close_to_tray(self):
        """Notify user that Veil is minimized to the system tray."""
        if self.tray:
            self.tray.notify(
                "Veil Privacy Shield Active",
                "Veil is running in the background. Right-click the shield tray icon to open or exit."
            )

    def _on_exit_requested(self):
        """Triggered from system tray exit or window exit."""
        self._shutdown_event.set()
        if self.window:
            self.window.force_close()
        if self.tray:
            self.tray.stop()
        if self.server:
            self.server.should_exit = True

    def _on_toggle_pause(self):
        """Toggle gateway pause state via HTTP API."""
        url = f"http://{self.host}:{self.port}/api/gateway/toggle"
        try:
            req = urllib.request.Request(url, data=b"", method="POST")
            urllib.request.urlopen(req, timeout=2.0)
        except Exception as e:
            print(f"Error toggling gateway from tray: {e}")

    def run(self):
        """Main launch entrypoint."""
        print(f"Starting Veil Privacy Gateway daemon on {self.host}:{self.port}...")
        self._start_uvicorn()

        # Wait for uvicorn to initialize
        if not self._wait_for_gateway():
            print("Error: Gateway daemon failed to start within timeout.")
            if self.server:
                self.server.should_exit = True
            sys.exit(1)

        print(f"Gateway active at http://{self.host}:{self.port}. Launching desktop window and tray...")

        # Initialize window
        dashboard_url = f"http://{self.host}:{self.port}/dashboard"
        self.window = VeilDesktopWindow(
            url=dashboard_url,
            title="Veil | Enterprise AI Privacy Gateway",
            on_close_to_tray=self._on_close_to_tray
        )
        self.window.create()

        # Initialize system tray
        self.tray = VeilSystemTray(
            on_show_window=self.window.show,
            on_exit=self._on_exit_requested,
            on_toggle_pause=self._on_toggle_pause
        )
        self.tray.start()

        try:
            # Blocks main thread until window is closed or app exits
            self.window.start(debug=self.debug)
        except KeyboardInterrupt:
            pass
        finally:
            self._on_exit_requested()
            if self.server_thread and self.server_thread.is_alive():
                self.server_thread.join(timeout=2.0)
            print("Veil shut down cleanly.")


def launch_gui(host: str = None, port: int = None, debug: bool = False):
    """Convenience helper to launch the desktop application."""
    runner = VeilAppRunner(host=host, port=port, debug=debug)
    runner.run()
