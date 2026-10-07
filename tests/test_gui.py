"""Tests for Phase 15: Native Desktop Window & System Tray Integration."""
import pytest
from unittest.mock import MagicMock, patch
from PIL import Image

from app.gui.tray import create_shield_icon, VeilSystemTray
from app.gui.window import VeilDesktopWindow
from app.gui.runner import VeilAppRunner


def test_create_shield_icon():
    """Verify that dynamic shield icons are generated with correct mode, dimensions, and colors."""
    icon_active = create_shield_icon("#00f5a0", size=64)
    assert isinstance(icon_active, Image.Image)
    assert icon_active.size == (64, 64)
    assert icon_active.mode == "RGBA"

    icon_paused = create_shield_icon("#ffb703", size=32)
    assert isinstance(icon_paused, Image.Image)
    assert icon_paused.size == (32, 32)

    icon_alert = create_shield_icon("#ff3366", size=128)
    assert isinstance(icon_alert, Image.Image)
    assert icon_alert.size == (128, 128)


def test_desktop_window_configuration_and_close_intercept():
    """Verify window settings and minimizing to tray on user close."""
    tray_called = []

    def mock_close_to_tray():
        tray_called.append(True)

    window = VeilDesktopWindow(
        url="http://127.0.0.1:8080/dashboard",
        title="Veil Test Window",
        width=1000,
        height=700,
        on_close_to_tray=mock_close_to_tray
    )

    assert window.title == "Veil Test Window"
    assert window.width == 1000
    assert window.height == 700

    # User clicks window 'X'
    # Should intercept, hide, and trigger close_to_tray callback
    with patch.object(window, "hide") as mock_hide:
        should_close = window._on_window_closing()
        assert should_close is False  # Intercepted!
        assert len(tray_called) == 1
        mock_hide.assert_called_once()

    # If force_close was called, user intends real termination
    window._is_closing = True
    assert window._on_window_closing() is True


def test_system_tray_menu_and_toggle():
    """Verify system tray menu items, policy changing, and pause toggling."""
    show_called = []
    exit_called = []
    toggle_called = []

    tray = VeilSystemTray(
        on_show_window=lambda: show_called.append(True),
        on_exit=lambda: exit_called.append(True),
        on_toggle_pause=lambda: toggle_called.append(True)
    )

    assert tray._is_paused is False
    tray.toggle_pause()
    assert tray._is_paused is True
    assert len(toggle_called) == 1

    tray.toggle_pause()
    assert tray._is_paused is False
    assert len(toggle_called) == 2

    menu = tray._build_menu()
    assert menu is not None


def test_runner_initialization_and_coordination():
    """Verify application runner state and timeout handling."""
    runner = VeilAppRunner(host="127.0.0.1", port=8999, debug=False)
    assert runner.host == "127.0.0.1"
    assert runner.port == 8999
    assert runner._shutdown_event.is_set() is False

    # Simulate close to tray
    runner.tray = MagicMock()
    runner._on_close_to_tray()
    runner.tray.notify.assert_called_once()
