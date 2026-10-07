"""Claude Code CLI configuration and environment adapter."""
import os
import shutil
from pathlib import Path
from typing import Optional, Dict, Any

from app.clients.base import BaseClientAdapter
from app.clients.models import ClientInfo, ClientStatus, ClientType, MutationResult


class ClaudeCodeAdapter(BaseClientAdapter):
    """Detects Claude Code CLI tool and routes requests through Veil gateway."""

    def __init__(self, config_path_override: Optional[Path] = None):
        super().__init__(
            client_id="claude_code",
            name="Claude Code CLI",
            client_type=ClientType.CLAUDE_CODE,
            icon="claude",
            description="Anthropic Claude Agentic Command Line Interface"
        )
        self.config_path_override = config_path_override

    def get_config_path(self) -> Path:
        if self.config_path_override:
            return self.config_path_override
        # Claude Code primary configuration file
        primary = Path.home() / ".claude.json"
        if primary.exists():
            return primary
        secondary = Path.home() / ".claude" / "config.json"
        if secondary.exists():
            return secondary
        return primary

    def detect(self) -> bool:
        if self.get_config_path().exists():
            return True
        # Check PATH for claude executable
        return bool(shutil.which("claude"))

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
                has_backup=False
            )

        data = self.load_json_safely(config_path)
        if data is None:
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

        current_url = data.get("anthropicBaseUrl") or data.get("primaryApiKeyBaseUrl")
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
            current_base_url=current_url
        )

    def connect(self, gateway_url: str = "http://127.0.0.1:8080/v1") -> MutationResult:
        config_path = self.get_config_path()
        backup_created = None

        try:
            data: Dict[str, Any] = {}
            if config_path.exists():
                backup_created = self.create_backup(config_path)
                loaded = self.load_json_safely(config_path)
                if loaded is not None:
                    data = loaded

            previous_url = data.get("anthropicBaseUrl")
            data["anthropicBaseUrl"] = gateway_url

            self.atomic_write_json(config_path, data)

            return MutationResult(
                success=True,
                message=f"Claude Code successfully routed through Veil at {gateway_url}.",
                client_id=self.client_id,
                previous_url=previous_url,
                new_url=gateway_url,
                backup_path=str(backup_created) if backup_created else None
            )
        except Exception as e:
            return MutationResult(
                success=False,
                message=f"Failed to configure Claude Code: {e}",
                client_id=self.client_id
            )

    def disconnect(self) -> MutationResult:
        config_path = self.get_config_path()
        if not config_path.exists():
            return MutationResult(
                success=True,
                message="Claude Code is already disconnected.",
                client_id=self.client_id
            )

        try:
            if self.has_backup(config_path):
                self.restore_backup(config_path)
                return MutationResult(
                    success=True,
                    message="Claude Code restored to original configuration from backup.",
                    client_id=self.client_id
                )

            data = self.load_json_safely(config_path)
            if data is not None:
                data.pop("anthropicBaseUrl", None)
                self.atomic_write_json(config_path, data)

            return MutationResult(
                success=True,
                message="Claude Code disconnected from Veil gateway.",
                client_id=self.client_id
            )
        except Exception as e:
            return MutationResult(
                success=False,
                message=f"Failed to disconnect Claude Code: {e}",
                client_id=self.client_id
            )
