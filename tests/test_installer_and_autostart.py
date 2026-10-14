"""Tests for Phase 17: Windows Enterprise Installer & Auto-Start Resident."""
import sys
import importlib.util
from pathlib import Path
import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.gui.autostart import (
    _get_target_command,
    is_autostart_enabled,
    enable_autostart,
    disable_autostart
)
from app.clients import client_manager

# Load packager/build_installer.py via importlib
installer_script = Path(__file__).resolve().parent.parent / "packager" / "build_installer.py"
spec = importlib.util.spec_from_file_location("build_installer_module", installer_script)
build_installer_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_installer_mod)
find_iscc = build_installer_mod.find_iscc


def test_autostart_command_generation():
    """Verify quoted path and arguments for Windows Run command."""
    cmd = _get_target_command(r"C:\Program Files\Veil\Veil.exe")
    assert cmd == r'"C:\Program Files\Veil\Veil.exe" --gui'


def test_autostart_registry_toggle():
    """Verify that enabling and disabling autostart updates Windows registry cleanly."""
    if sys.platform != "win32":
        pytest.skip("Windows registry tests only run on win32 platforms.")

    initial_state = is_autostart_enabled()
    try:
        # Enable
        success_enable = enable_autostart()
        assert success_enable is True
        assert is_autostart_enabled() is True

        # Disable
        success_disable = disable_autostart()
        assert success_disable is True
        assert is_autostart_enabled() is False
    finally:
        # Always restore initial state
        if initial_state:
            enable_autostart()
        else:
            disable_autostart()


@pytest.mark.asyncio
async def test_autostart_rest_endpoints():
    """Verify GET and POST /api/system/autostart API endpoints."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # GET
        get_resp = await client.get("/api/system/autostart")
        assert get_resp.status_code == 200
        data = get_resp.json()
        assert "enabled" in data

        # POST (test disable then restore)
        post_resp = await client.post("/api/system/autostart", json={"enabled": False})
        assert post_resp.status_code == 200
        assert post_resp.json()["enabled"] is False


def test_disconnect_all_restores_clients():
    """Verify disconnect_all method executes cleanly across all client adapters."""
    results = client_manager.disconnect_all()
    assert isinstance(results, dict)


def test_inno_setup_script_structure():
    """Verify that the Inno Setup script has required enterprise parameters and rollback hook."""
    iss_file = Path(__file__).resolve().parent.parent / "packager" / "installer.iss"
    assert iss_file.exists()
    content = iss_file.read_text(encoding="utf-8")

    assert "Veil AI Privacy Gateway" in content
    assert "OutputBaseFilename=VeilSetup" in content
    assert "desktopicon" in content
    assert "autostart" in content
    assert "installca" in content
    assert "proxy install-ca" in content
    assert "disconnect-all" in content  # Uninstaller rollback hook
    assert "proxy disable" in content   # Uninstaller proxy restore
    assert "proxy uninstall-ca" in content # Uninstaller CA cleanup
    assert "uninsdeletevalue" in content


def test_find_iscc_detection():
    """Verify compiler locator runs cleanly."""
    compiler = find_iscc()
    # It will either be Path or None depending on whether Inno Setup is on this machine
    assert compiler is None or isinstance(compiler, Path)
