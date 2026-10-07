"""VS Code & JetBrains Continue.dev extension configuration adapter."""
from pathlib import Path
from typing import Optional, Dict, Any, List

from app.clients.base import BaseClientAdapter
from app.clients.models import ClientInfo, ClientStatus, ClientType, MutationResult


class ContinueAdapter(BaseClientAdapter):
    """Detects Continue.dev configuration (~/.continue/config.json) and routes models through Veil."""

    def __init__(self, config_path_override: Optional[Path] = None):
        super().__init__(
            client_id="continue",
            name="VS Code Continue.dev",
            client_type=ClientType.CONTINUE,
            icon="continue",
            description="Open-Source AI Code Assistant (VS Code / JetBrains)"
        )
        self.config_path_override = config_path_override

    def get_config_path(self) -> Path:
        if self.config_path_override:
            return self.config_path_override
        return Path.home() / ".continue" / "config.json"

    def detect(self) -> bool:
        config_path = self.get_config_path()
        return config_path.exists() or config_path.parent.exists()

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

        models: List[Dict[str, Any]] = data.get("models", [])
        connected_models = [m.get("title", "unnamed") for m in models if "127.0.0.1" in str(m.get("apiBase", ""))]
        is_connected = len(connected_models) > 0

        first_base_url = next((m.get("apiBase") for m in models if m.get("apiBase")), None)

        return ClientInfo(
            id=self.client_id,
            name=self.name,
            client_type=self.client_type,
            status=ClientStatus.CONNECTED if is_connected else ClientStatus.DETECTED,
            icon=self.icon,
            description=self.description,
            config_path=str(config_path),
            has_backup=self.has_backup(config_path),
            current_base_url=first_base_url,
            details={"total_models": len(models), "routed_models": connected_models}
        )

    def connect(self, gateway_url: str = "http://127.0.0.1:8080/v1") -> MutationResult:
        config_path = self.get_config_path()
        backup_created = None

        try:
            data: Dict[str, Any] = {"models": []}
            if config_path.exists():
                backup_created = self.create_backup(config_path)
                loaded = self.load_json_safely(config_path)
                if loaded is not None:
                    data = loaded
                else:
                    return MutationResult(
                        success=False,
                        message=f"Cannot connect Continue: config.json at {config_path} contains invalid syntax.",
                        client_id=self.client_id
                    )

            models = data.get("models", [])
            previous_url = None
            if models:
                previous_url = models[0].get("apiBase")
                for m in models:
                    m["apiBase"] = gateway_url
            else:
                # Add default Veil-protected model entry
                models.append({
                    "title": "Veil Protected Model",
                    "provider": "openai",
                    "model": "gpt-4o",
                    "apiBase": gateway_url
                })
                data["models"] = models

            self.atomic_write_json(config_path, data)

            return MutationResult(
                success=True,
                message=f"Continue.dev successfully configured to route through Veil at {gateway_url}.",
                client_id=self.client_id,
                previous_url=previous_url,
                new_url=gateway_url,
                backup_path=str(backup_created) if backup_created else None
            )
        except Exception as e:
            return MutationResult(
                success=False,
                message=f"Failed to configure Continue.dev: {e}",
                client_id=self.client_id
            )

    def disconnect(self) -> MutationResult:
        config_path = self.get_config_path()
        if not config_path.exists():
            return MutationResult(
                success=True,
                message="Continue.dev is already disconnected.",
                client_id=self.client_id
            )

        try:
            if self.has_backup(config_path):
                self.restore_backup(config_path)
                return MutationResult(
                    success=True,
                    message="Continue.dev restored to original configuration from backup.",
                    client_id=self.client_id
                )

            data = self.load_json_safely(config_path)
            if data is not None:
                for m in data.get("models", []):
                    if "127.0.0.1" in str(m.get("apiBase", "")):
                        m.pop("apiBase", None)
                self.atomic_write_json(config_path, data)

            return MutationResult(
                success=True,
                message="Continue.dev disconnected from Veil gateway.",
                client_id=self.client_id
            )
        except Exception as e:
            return MutationResult(
                success=False,
                message=f"Failed to disconnect Continue.dev: {e}",
                client_id=self.client_id
            )
