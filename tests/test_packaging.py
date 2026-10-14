import sys
import importlib.util
from pathlib import Path
from PIL import Image

ico_script = Path(__file__).resolve().parent.parent / "packager" / "generate_ico.py"
spec = importlib.util.spec_from_file_location("packager_generate_ico", ico_script)
generate_ico_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generate_ico_mod)
generate_veil_ico = generate_ico_mod.generate_veil_ico

from app.entrypoint import main as entrypoint_main


def test_ico_generation(tmp_path):
    """Verify that multi-resolution Windows ICO generation succeeds."""
    target_ico = tmp_path / "test_veil.ico"
    generate_veil_ico(target_ico)

    assert target_ico.exists()
    assert target_ico.stat().st_size > 0

    with Image.open(target_ico) as img:
        assert img.format == "ICO"


def test_spec_file_syntax_and_paths():
    """Verify that the PyInstaller spec file exists and can be parsed."""
    spec_path = Path(__file__).resolve().parent.parent / "packager" / "veil.spec"
    assert spec_path.exists()
    content = spec_path.read_text(encoding="utf-8")
    assert "entrypoint.py" in content
    assert "app/ui" in content
    assert "veil.ico" in content
    assert "Analysis" in content
    assert "EXE" in content


def test_spec_file_hidden_imports():
    """Verify that all core Phase 1-5 modules are included in PyInstaller hidden_imports."""
    spec_path = Path(__file__).resolve().parent.parent / "packager" / "veil.spec"
    content = spec_path.read_text(encoding="utf-8")

    expected_modules = [
        "app.proxy",
        "app.proxy.ca",
        "app.proxy.interceptor",
        "app.proxy.wininet",
        "app.licensing",
        "app.licensing.manager",
        "app.licensing.enforcer",
        "app.billing",
        "app.billing.paystack",
        "app.mcp_server",
        "app.engine.custom_dictionary",
        "app.engine.knowledge_vault",
        "app.engine.models",
        "app.clients.antigravity",
        "app.clients.opencode",
        "onnxruntime",
        "tokenizers",
        "cryptography",
    ]
    for mod in expected_modules:
        assert f"'{mod}'" in content or f'"{mod}"' in content, f"Module {mod} missing from hidden_imports in veil.spec"


def test_msi_builder_metadata():
    """Verify MSI builder script metadata and structure."""
    msi_script = Path(__file__).resolve().parent.parent / "packager" / "build_msi.py"
    assert msi_script.exists()
    content = msi_script.read_text(encoding="utf-8")

    assert "PRODUCT_NAME = \"Veil Privacy Gateway\"" in content
    assert "MANUFACTURER = \"Veil Security\"" in content
    assert "UPGRADE_CODE" in content
    assert "def build_msi()" in content


def test_entrypoint_delegates_to_cli(monkeypatch):
    """Verify that CLI commands are delegated to Typer."""
    called = []

    def mock_cli():
        called.append(True)

    monkeypatch.setattr("app.entrypoint.cli", mock_cli)
    monkeypatch.setattr(sys, "argv", ["veil", "doctor"])

    entrypoint_main()
    assert len(called) == 1

