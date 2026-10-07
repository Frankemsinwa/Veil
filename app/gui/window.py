"""Veil Native Desktop Window via pywebview."""
import sys
from typing import Optional, Callable

try:
    import webview
except ImportError:
    webview = None


class VeilDesktopWindow:
    """Manages the native Edge Chromium WebView2 desktop window."""

    def __init__(
        self,
        url: str = "http://127.0.0.1:8080/dashboard",
        title: str = "Veil | Enterprise AI Privacy Gateway",
        width: int = 1180,
        height: int = 780,
        on_close_to_tray: Optional[Callable[[], None]] = None,
    ):
        self.url = url
        self.title = title
        self.width = width
        self.height = height
        self.on_close_to_tray = on_close_to_tray
        self._window = None
        self._is_closing = False

    def create(self):
        """Creates the pywebview window instance."""
        if webview is None:
            raise RuntimeError("pywebview is not installed in the environment.")

        self._window = webview.create_window(
            title=self.title,
            url=self.url,
            width=self.width,
            height=self.height,
            min_size=(960, 640),
            background_color="#080a0f",
            text_select=True,
            confirm_close=False,
        )

        # Hook closing event to intercept window X and minimize to tray
        self._window.events.closing += self._on_window_closing
        return self._window

    def _on_window_closing(self):
        """Called when user clicks X on the window."""
        if self._is_closing:
            return True  # Allow true close

        # If minimize to tray is enabled, hide window and cancel closure
        if self.on_close_to_tray:
            self.hide()
            self.on_close_to_tray()
            return False  # Prevent window destruction
        return True

    def show(self):
        """Restore and focus the window."""
        if self._window:
            self._window.show()
            self._window.restore()

    def hide(self):
        """Hide the window into background tray."""
        if self._window:
            self._window.hide()

    def force_close(self):
        """Perform true exit and close the window."""
        self._is_closing = True
        if self._window:
            self._window.destroy()

    def start(self, debug: bool = False):
        """Start the pywebview event loop (blocks main thread until exit)."""
        if webview is None:
            raise RuntimeError("pywebview is not installed.")
        # On Windows, pywebview defaults to Edge Chromium WebView2
        webview.start(debug=debug, gui="edgechromium" if sys.platform == "win32" else None)
