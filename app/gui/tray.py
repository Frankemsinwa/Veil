"""Veil Native System Tray Daemon via pystray."""
import threading
import time
from typing import Optional, Callable
from PIL import Image, ImageDraw

try:
    import pystray
    from pystray import MenuItem as item, Menu
except ImportError:
    pystray = None
    item = None
    Menu = None

from app.core.config import settings, PolicyLevel
from app.core.events import privacy_event_bus
from app.clients import client_manager
from app.gui.autostart import is_autostart_enabled, enable_autostart, disable_autostart


def create_shield_icon(color_hex: str = "#00f5a0", size: int = 64) -> Image.Image:
    """Generate a crisp, anti-aliased shield icon dynamically in memory.
    
    Colors:
      - Active: #00f5a0 (Emerald)
      - Paused: #ffb703 (Amber)
      - Alert:  #ff3366 (Crimson)
    """
    scale = 4
    canvas_size = size * scale
    image = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    # Convert hex to RGB
    h = color_hex.lstrip("#")
    rgb = tuple(int(h[i:i+2], 16) for i in (0, 2, 4))
    fill_rgba = (*rgb, 235)
    border_rgba = (*rgb, 255)

    # Shield polygon points
    # (top-left, top-right, right-mid, bottom-center, left-mid)
    points = [
        (canvas_size * 0.20, canvas_size * 0.15),
        (canvas_size * 0.80, canvas_size * 0.15),
        (canvas_size * 0.85, canvas_size * 0.50),
        (canvas_size * 0.50, canvas_size * 0.90),
        (canvas_size * 0.15, canvas_size * 0.50),
    ]

    # Draw outer shield border
    draw.polygon(points, fill=fill_rgba, outline=border_rgba)

    # Inner checkmark / glyph
    # (P1 -> P2 -> P3)
    p1 = (canvas_size * 0.35, canvas_size * 0.48)
    p2 = (canvas_size * 0.47, canvas_size * 0.62)
    p3 = (canvas_size * 0.68, canvas_size * 0.35)
    line_color = (8, 10, 15, 255)
    line_width = int(canvas_size * 0.08)
    draw.line([p1, p2, p3], fill=line_color, width=line_width, joint="curve")

    # Downscale for smooth anti-aliased edges
    return image.resize((size, size), Image.Resampling.LANCZOS)


class VeilSystemTray:
    """Manages the background system tray icon, context menu, and desktop notifications."""

    def __init__(
        self,
        on_show_window: Optional[Callable[[], None]] = None,
        on_exit: Optional[Callable[[], None]] = None,
        on_toggle_pause: Optional[Callable[[], None]] = None,
    ):
        self.on_show_window = on_show_window
        self.on_exit = on_exit
        self.on_toggle_pause = on_toggle_pause

        self.icon_active = create_shield_icon("#00f5a0", size=64)
        self.icon_paused = create_shield_icon("#ffb703", size=64)
        self.icon_alert = create_shield_icon("#ff3366", size=64)

        self._is_paused = False
        self._running = False
        self._icon: Optional["pystray.Icon"] = None
        self._bus_thread: Optional[threading.Thread] = None

    def _build_menu(self):
        """Constructs the native right-click tray context menu."""
        def _get_status_text(item):
            return "Veil Status: PAUSED" if self._is_paused else "Veil Status: ACTIVE"

        def _get_toggle_text(item):
            return "Resume Privacy Gateway" if self._is_paused else "Pause Privacy Gateway"

        def _toggle_action(icon, item):
            self.toggle_pause()

        def _show_action(icon, item):
            if self.on_show_window:
                self.on_show_window()

        def _rescan_action(icon, item):
            client_manager.scan_all()
            if self._icon:
                self._icon.notify("Scanned system for IDEs and CLI agents.", "Clients Rescanned")

        def _exit_action(icon, item):
            self.stop()
            if self.on_exit:
                self.on_exit()

        def _set_policy(policy_name: str):
            def handler(icon, item):
                try:
                    settings.POLICY = PolicyLevel(policy_name)
                    privacy_event_bus.publish_sync("metric", {
                        "action": "policy_change",
                        "policy": settings.POLICY.value
                    })
                    if self._icon:
                        self._icon.notify(f"Enforcement mode set to {policy_name}", "Policy Updated")
                except Exception as e:
                    print(f"Policy update error: {e}")
            return handler

        menu_items = [
            item("Open Veil Cockpit", _show_action, default=True),
            item(_get_status_text, None, enabled=False),
            item(_get_toggle_text, _toggle_action),
            Menu.SEPARATOR,
            item(
                "Enforcement Policy",
                Menu(
                    item("Strict (Fail-Closed)", _set_policy("STRICT")),
                    item("Balanced (Heuristic)", _set_policy("BALANCED")),
                    item("Permissive (Audit Only)", _set_policy("PERMISSIVE")),
                )
            ),
            item("Rescan AI Clients", _rescan_action),
            item(
                "Start with Windows",
                lambda icon, item: self._toggle_autostart(),
                checked=lambda item: is_autostart_enabled()
            ),
            Menu.SEPARATOR,
            item("Exit Veil", _exit_action)
        ]

        return Menu(*menu_items)

    def _toggle_autostart(self):
        """Toggle Windows startup registration."""
        if is_autostart_enabled():
            disable_autostart()
            self.notify("Auto-Start Disabled", "Veil will not launch automatically on Windows boot.")
        else:
            enable_autostart()
            self.notify("Auto-Start Enabled", "Veil will launch minimized in the system tray on Windows boot.")

    def toggle_pause(self):
        """Toggle paused / active status."""
        self._is_paused = not self._is_paused
        if self._icon:
            self._icon.icon = self.icon_paused if self._is_paused else self.icon_active
            self._icon.title = f"Veil Gateway ({'Paused' if self._is_paused else 'Active'})"
        if self.on_toggle_pause:
            self.on_toggle_pause()

    def notify(self, title: str, message: str):
        """Dispatch a native desktop balloon notification."""
        if self._icon:
            try:
                self._icon.notify(message, title)
            except Exception as e:
                print(f"Notification error: {e}")

    def flash_alert(self, title: str, message: str):
        """Flash alert icon and notify on credential blocks."""
        if not self._icon:
            return

        def _worker():
            self._icon.icon = self.icon_alert
            self.notify(title, message)
            time.sleep(3.5)
            if self._icon and self._running:
                self._icon.icon = self.icon_paused if self._is_paused else self.icon_active

        threading.Thread(target=_worker, daemon=True).start()

    def _event_bus_listener(self):
        """Listen to privacy bus events in background to trigger desktop alerts."""
        import asyncio

        async def _run():
            queue = await privacy_event_bus.subscribe()
            try:
                while self._running:
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=1.0)
                        etype = event.get("type")
                        data = event.get("data", {})
                        if etype == "blocked":
                            reason = data.get("reason", "Outbound secret blocked")
                            violations = ", ".join(data.get("violations", ["Secret"]))
                            self.flash_alert("Veil Security Block", f"Fail-closed block: {violations}\n{reason}")
                    except asyncio.TimeoutError:
                        continue
            finally:
                await privacy_event_bus.unsubscribe(queue)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_run())
        finally:
            loop.close()

    def start(self):
        """Start the system tray icon in a dedicated daemon thread."""
        if pystray is None:
            print("Warning: pystray not available; system tray disabled.")
            return

        self._running = True
        self._icon = pystray.Icon(
            name="Veil",
            icon=self.icon_active,
            title="Veil AI Privacy Gateway (Active)",
            menu=self._build_menu()
        )

        # Start event bus listener
        self._bus_thread = threading.Thread(target=self._event_bus_listener, daemon=True)
        self._bus_thread.start()

        # Run tray loop in thread
        tray_thread = threading.Thread(target=self._icon.run, daemon=True)
        tray_thread.start()

    def stop(self):
        """Stop tray resident and clean up icon."""
        self._running = False
        if self._icon:
            try:
                self._icon.stop()
            except Exception:
                pass
            self._icon = None
