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


def test_entrypoint_delegates_to_cli(monkeypatch):
    """Verify that CLI commands are delegated to Typer."""
    called = []

    def mock_cli():
        called.append(True)

    monkeypatch.setattr("app.entrypoint.cli", mock_cli)
    monkeypatch.setattr(sys, "argv", ["veil", "doctor"])

    entrypoint_main()
    assert len(called) == 1
