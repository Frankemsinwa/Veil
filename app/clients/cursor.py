"""Cursor IDE configuration discoverer and 1-click proxy injector."""
import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any

from app.clients.base import BaseClientAdapter
from app.clients.models import ClientInfo, ClientStatus, ClientType, MutationResult


class CursorAdapter(BaseClientAdapter):
    """Detects Cursor IDE installation and configures OpenAI base URL routing."""

    def __init__(self, config_path_override: Optional[Path] = None):
        super().__init__(
            client_id="cursor",
            name="Cursor IDE",
            client_type=ClientType.CURSOR,
            icon="cursor",
            description="AI-first Code Editor (User Settings Proxy)"
        )
        self.config_path_override = config_path_override

    def get_config_path(self) -> Path:
        """Resolves active settings.json for Cursor on the host operating system."""
        if self.config_path_override:
            return self.config_path_override

        if sys.platform == "win32":
            appdata = os.environ.get("APPDATA")
            if appdata:
                return Path(appdata) / "Cursor" / "User" / "settings.json"
            return Path.home() / "AppData" / "Roaming" / "Cursor" / "User" / "settings.json"
        elif sys.platform == "darwin":
            return Path.home() / "Library" / "Application Support" / "Cursor" / "User" / "settings.json"
        else:
            return Path.home() / ".config" / "Cursor" / "User" / "settings.json"

    def detect(self) -> bool:
        """Checks if Cursor installation or user configuration exists."""
        config_path = self.get_config_path()
        if config_path.exists():
            return True
        # Check if parent user directory exists even if settings.json hasn't been created yet
        return config_path.parent.exists()

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

        current_url = (
            settings_data.get("openai.baseURL") or
            settings_data.get("cursor.general.customOpenAIBaseUrl")
        )
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
            details={"keys_checked": ["openai.baseURL", "cursor.general.customOpenAIBaseUrl"]}
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
                        message=f"Cannot connect Cursor: settings.json at {config_path} contains unparseable syntax.",
                        client_id=self.client_id
                    )

            previous_url = settings_data.get("openai.baseURL")

            # Apply proxy keys
            settings_data["openai.baseURL"] = gateway_url
            settings_data["cursor.general.customOpenAIBaseUrl"] = gateway_url

            self.atomic_write_json(config_path, settings_data)

            return MutationResult(
                success=True,
                message=f"Cursor successfully configured to route through Veil at {gateway_url}.",
                client_id=self.client_id,
                previous_url=previous_url,
                new_url=gateway_url,
                backup_path=str(backup_created) if backup_created else None
            )
        except Exception as e:
            return MutationResult(
                success=False,
                message=f"Failed to configure Cursor: {e}",
                client_id=self.client_id
            )

    def disconnect(self) -> MutationResult:
        config_path = self.get_config_path()
        if not config_path.exists():
            return MutationResult(
                success=True,
                message="Cursor is already disconnected (no settings.json found).",
                client_id=self.client_id
            )

        try:
            if self.has_backup(config_path):
                self.restore_backup(config_path)
                return MutationResult(
                    success=True,
                    message="Cursor restored to original configuration from backup.",
                    client_id=self.client_id
                )

            # Manual removal if no backup exists
            settings_data = self.load_json_safely(config_path)
            if settings_data is not None:
                settings_data.pop("openai.baseURL", None)
                settings_data.pop("cursor.general.customOpenAIBaseUrl", None)
                self.atomic_write_json(config_path, settings_data)

            return MutationResult(
                success=True,
                message="Cursor disconnected: removed Veil proxy routing.",
                client_id=self.client_id
            )
        except Exception as e:
            return MutationResult(
                success=False,
                message=f"Failed to disconnect Cursor: {e}",
                client_id=self.client_id
            )
