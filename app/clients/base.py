"""Base adapter interface and atomic filesystem utilities for client injectors."""
import os
import re
import json
import shutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Dict, Any

from app.clients.models import ClientInfo, ClientStatus, ClientType, MutationResult


def strip_json_comments(text: str) -> str:
    """Removes single-line and multi-line comments from JSON with comments (e.g. VS Code settings.json)."""
    # Remove single-line comments //...
    pattern = r"//.*?$|/\*.*?\*/"
    clean_text = re.sub(pattern, "", text, flags=re.MULTILINE | re.DOTALL)
    # Remove trailing commas before closing braces/brackets
    clean_text = re.sub(r",(\s*[}\]])", r"\1", clean_text)
    return clean_text


class BaseClientAdapter(ABC):
    """Abstract base class for discovering, connecting, and disconnecting AI clients."""

    def __init__(self, client_id: str, name: str, client_type: ClientType, icon: str, description: str):
        self.client_id = client_id
        self.name = name
        self.client_type = client_type
        self.icon = icon
        self.description = description

    @abstractmethod
    def detect(self) -> bool:
        """Returns True if the client is installed or configuration is detected on the host system."""
        pass

    @abstractmethod
    def get_status(self) -> ClientInfo:
        """Returns the current ClientInfo and connection state."""
        pass

    @abstractmethod
    def connect(self, gateway_url: str = "http://127.0.0.1:8080/v1") -> MutationResult:
        """Safely mutates the client configuration to route through the Veil gateway."""
        pass

    @abstractmethod
    def disconnect(self) -> MutationResult:
        """Safely rolls back configuration to remove Veil routing or restore backup."""
        pass

    # --- Atomic File System Utilities ---

    @staticmethod
    def get_backup_path(file_path: Path) -> Path:
        return file_path.with_name(f"{file_path.name}.veil.bak")

    def has_backup(self, file_path: Path) -> bool:
        return self.get_backup_path(file_path).exists()

    def create_backup(self, file_path: Path) -> Optional[Path]:
        """Creates an immutable backup of the original config file.
        
        Does not overwrite an existing backup to ensure the pristine original is preserved.
        """
        if not file_path.exists():
            return None
        backup_path = self.get_backup_path(file_path)
        if not backup_path.exists():
            shutil.copy2(file_path, backup_path)
        return backup_path

    def restore_backup(self, file_path: Path) -> bool:
        """Restores file from its .veil.bak backup if present."""
        backup_path = self.get_backup_path(file_path)
        if backup_path.exists():
            shutil.copy2(backup_path, file_path)
            backup_path.unlink()
            return True
        return False

    def atomic_write_text(self, file_path: Path, content: str):
        """Atomically writes content to file using a temporary file and atomic replace."""
        file_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = file_path.with_name(f"{file_path.name}.tmp")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(content)
            # Atomic replacement on Windows and POSIX
            os.replace(tmp_path, file_path)
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink()
            raise

    def atomic_write_json(self, file_path: Path, data: Dict[str, Any], indent: int = 2):
        """Atomically writes a dictionary as formatted JSON."""
        content = json.dumps(data, indent=indent)
        self.atomic_write_text(file_path, content)

    def load_json_safely(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Safely reads and parses a JSON file, stripping comments if needed."""
        if not file_path.exists():
            return None
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                raw_text = f.read()
            try:
                return json.loads(raw_text)
            except json.JSONDecodeError:
                clean_text = strip_json_comments(raw_text)
                return json.loads(clean_text)
        except Exception:
            return None
