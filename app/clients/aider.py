"""Aider CLI AI pair programmer configuration adapter."""
import re
import shutil
from pathlib import Path
from typing import Optional, Dict, Any

from app.clients.base import BaseClientAdapter
from app.clients.models import ClientInfo, ClientStatus, ClientType, MutationResult


class AiderAdapter(BaseClientAdapter):
    """Detects Aider CLI (~/.aider.conf.yml) and configures openai-api-base routing."""

    def __init__(self, config_path_override: Optional[Path] = None):
        super().__init__(
            client_id="aider",
            name="Aider CLI",
            client_type=ClientType.AIDER,
            icon="aider",
            description="Terminal-based AI Pair Programming Agent"
        )
        self.config_path_override = config_path_override

    def get_config_path(self) -> Path:
        if self.config_path_override:
            return self.config_path_override
        return Path.home() / ".aider.conf.yml"

    def detect(self) -> bool:
        if self.get_config_path().exists():
            return True
        return bool(shutil.which("aider"))

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

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                content = f.read()
            match = re.search(r"^openai-api-base:\s*([^\s#]+)", content, flags=re.MULTILINE)
            current_url = match.group(1).strip() if match else None
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
        except Exception:
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

    def connect(self, gateway_url: str = "http://127.0.0.1:8080/v1") -> MutationResult:
        config_path = self.get_config_path()
        backup_created = None

        try:
            content = ""
            previous_url = None
            if config_path.exists():
                backup_created = self.create_backup(config_path)
                with open(config_path, "r", encoding="utf-8") as f:
                    content = f.read()

                match = re.search(r"^openai-api-base:\s*([^\s#]+)", content, flags=re.MULTILINE)
                if match:
                    previous_url = match.group(1).strip()
                    # Replace existing
                    new_content = re.sub(
                        r"^openai-api-base:.*$",
                        f"openai-api-base: {gateway_url}",
                        content,
                        flags=re.MULTILINE
                    )
                else:
                    new_content = content.rstrip() + f"\nopenai-api-base: {gateway_url}\n"
            else:
                new_content = f"# Aider configuration managed by Veil Privacy Gateway\nopenai-api-base: {gateway_url}\n"

            self.atomic_write_text(config_path, new_content)

            return MutationResult(
                success=True,
                message=f"Aider CLI successfully routed through Veil at {gateway_url}.",
                client_id=self.client_id,
                previous_url=previous_url,
                new_url=gateway_url,
                backup_path=str(backup_created) if backup_created else None
            )
        except Exception as e:
            return MutationResult(
                success=False,
                message=f"Failed to configure Aider: {e}",
                client_id=self.client_id
            )

    def disconnect(self) -> MutationResult:
        config_path = self.get_config_path()
        if not config_path.exists():
            return MutationResult(
                success=True,
                message="Aider CLI is already disconnected.",
                client_id=self.client_id
            )

        try:
            if self.has_backup(config_path):
                self.restore_backup(config_path)
                return MutationResult(
                    success=True,
                    message="Aider restored to original configuration from backup.",
                    client_id=self.client_id
                )

            with open(config_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Remove openai-api-base line
            new_content = re.sub(r"^openai-api-base:.*$\n?", "", content, flags=re.MULTILINE)
            self.atomic_write_text(config_path, new_content)

            return MutationResult(
                success=True,
                message="Aider disconnected from Veil gateway.",
                client_id=self.client_id
            )
        except Exception as e:
            return MutationResult(
                success=False,
                message=f"Failed to disconnect Aider: {e}",
                client_id=self.client_id
            )
