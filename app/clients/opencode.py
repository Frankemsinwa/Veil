"""OpenCode IDE configuration discoverer and 1-click proxy injector."""
import os
import sys
import shutil
from pathlib import Path
from typing import Optional, Dict, Any, List

from app.clients.base import BaseClientAdapter
from app.clients.models import ClientInfo, ClientStatus, ClientType, MutationResult


class OpenCodeAdapter(BaseClientAdapter):
    """Detects OpenCode IDE / CLI installation and configures OpenAI base URL routing."""

    PROXY_KEYS = [
        "opencode.apiBase",
        "openai.baseURL",
        "openai.api_base",
        "api_base"
    ]

    def __init__(self, config_path_override: Optional[Path] = None):
        super().__init__(
            client_id="opencode",
            name="OpenCode IDE",
            client_type=ClientType.OPENCODE,
            icon="opencode",
            description="Open-Source AI Code Editor & Environment (Config Proxy)"
        )
        self.config_path_override = config_path_override

    def get_candidate_paths(self) -> List[Path]:
        """Returns candidate configuration paths in order of preference."""
        if self.config_path_override:
            return [self.config_path_override]

        paths: List[Path] = []
        if sys.platform == "win32":
            appdata = os.environ.get("APPDATA")
            if appdata:
                paths.append(Path(appdata) / "OpenCode" / "User" / "settings.json")
            paths.append(Path.home() / "AppData" / "Roaming" / "OpenCode" / "User" / "settings.json")
            paths.append(Path.home() / ".opencode" / "config.json")
        elif sys.platform == "darwin":
            paths.append(Path.home() / "Library" / "Application Support" / "OpenCode" / "User" / "settings.json")
            paths.append(Path.home() / ".opencode" / "config.json")
        else:
            paths.append(Path.home() / ".config" / "opencode" / "User" / "settings.json")
            paths.append(Path.home() / ".config" / "opencode" / "config.json")
            paths.append(Path.home() / ".opencode" / "config.json")

        return paths

    def get_config_path(self) -> Path:
        """Resolves the active or primary configuration path."""
        candidates = self.get_candidate_paths()
        # Return first existing path
        for p in candidates:
            if p.exists():
                return p
        # Check if parent directory exists
        for p in candidates:
            if p.parent.exists():
                return p
        # Default to first candidate
        return candidates[0]

    def detect(self) -> bool:
        """Checks if OpenCode configuration, directories, or executable exist on the system."""
        for p in self.get_candidate_paths():
            if p.exists() or p.parent.exists():
                return True
        return bool(shutil.which("opencode"))

    def get_status(self) -> ClientInfo:
        config_path = self.get_config_path()
        if not self.detect():
            return ClientInfo(
                id=self.client_id,
                name=self.name,
                client_type=self.client_type,
                status=ClientStatus.NOT_INSTALLED,
                icon=self.icon,
                description=self.description,
                config_path=str(config_path),
                has_backup=False
            )

        if not config_path.exists():
            return ClientInfo(
                id=self.client_id,
                name=self.name,
                client_type=self.client_type,
                status=ClientStatus.DETECTED,
                icon=self.icon,
                description=self.description,
                config_path=str(config_path),
                has_backup=False,
                current_base_url=None
            )

        settings_data = self.load_json_safely(config_path)
        if settings_data is None:
            return ClientInfo(
                id=self.client_id,
                name=self.name,
                client_type=self.client_type,
                status=ClientStatus.ERROR,
                icon=self.icon,
                description=self.description,
                config_path=str(config_path),
                has_backup=self.has_backup(config_path)
            )

        # Inspect proxy keys
        current_url = None
        for key in self.PROXY_KEYS:
            val = settings_data.get(key)
            if val:
                current_url = str(val)
                break

        is_connected = bool(current_url and "127.0.0.1" in current_url)

        return ClientInfo(
            id=self.client_id,
            name=self.name,
            client_type=self.client_type,
            status=ClientStatus.CONNECTED if is_connected else ClientStatus.DETECTED,
            icon=self.icon,
            description=self.description,
            config_path=str(config_path),
            has_backup=self.has_backup(config_path),
            current_base_url=current_url,
            details={"keys_checked": self.PROXY_KEYS}
        )

    def connect(self, gateway_url: str = "http://127.0.0.1:8080/v1") -> MutationResult:
        config_path = self.get_config_path()
        backup_created = None

        try:
            settings_data: Dict[str, Any] = {}
            if config_path.exists():
                backup_created = self.create_backup(config_path)
                loaded = self.load_json_safely(config_path)
                if loaded is not None:
                    settings_data = loaded
                else:
                    return MutationResult(
                        success=False,
                        message=f"Cannot connect OpenCode: settings file at {config_path} contains invalid JSON syntax.",
                        client_id=self.client_id
                    )

            previous_url = None
            for key in self.PROXY_KEYS:
                if key in settings_data:
                    previous_url = str(settings_data[key])
                    break

            # Apply proxy configuration
            settings_data["opencode.apiBase"] = gateway_url
            settings_data["openai.baseURL"] = gateway_url
            settings_data["api_base"] = gateway_url

            self.atomic_write_json(config_path, settings_data)

            return MutationResult(
                success=True,
                message=f"OpenCode successfully configured to route through Veil at {gateway_url}.",
                client_id=self.client_id,
                previous_url=previous_url,
                new_url=gateway_url,
                backup_path=str(backup_created) if backup_created else None
            )
        except Exception as e:
            return MutationResult(
                success=False,
                message=f"Failed to configure OpenCode: {e}",
                client_id=self.client_id
            )

    def disconnect(self) -> MutationResult:
        config_path = self.get_config_path()
        if not config_path.exists():
            return MutationResult(
                success=True,
                message="OpenCode is already disconnected (no settings file found).",
                client_id=self.client_id
            )

        try:
            if self.has_backup(config_path):
                self.restore_backup(config_path)
                return MutationResult(
                    success=True,
                    message="OpenCode restored to original configuration from backup.",
                    client_id=self.client_id
                )

            # Manual removal if no backup exists
            settings_data = self.load_json_safely(config_path)
            if settings_data is not None:
                for key in self.PROXY_KEYS:
                    settings_data.pop(key, None)
                self.atomic_write_json(config_path, settings_data)

            return MutationResult(
                success=True,
                message="OpenCode disconnected: removed Veil proxy routing.",
                client_id=self.client_id
            )
        except Exception as e:
            return MutationResult(
                success=False,
                message=f"Failed to disconnect OpenCode: {e}",
                client_id=self.client_id
            )
