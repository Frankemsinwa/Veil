"""Top-level forwarder to packaging/build_exe.py."""
import sys
from pathlib import Path

root_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(root_dir))

from packager.build_exe import build_standalone_exe

if __name__ == "__main__":
    build_standalone_exe()
