import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PIL import Image
from app.gui.tray import create_shield_icon


def generate_veil_ico(output_path: Path = None) -> Path:
    """Generate a multi-resolution .ico containing 16, 32, 48, 64, 128, and 256 pixel sizes."""
    if output_path is None:
        output_path = Path(__file__).resolve().parent / "veil.ico"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    sizes = [16, 32, 48, 64, 128, 256]
    images = [create_shield_icon("#00f5a0", size=s) for s in sizes]

    # Save as multi-resolution ICO file
    primary = images[-1]
    primary.save(
        output_path,
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=images[:-1]
    )
    print(f"Generated multi-resolution icon at: {output_path}")
    return output_path


if __name__ == "__main__":
    generate_veil_ico()
