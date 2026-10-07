"""Antigravity IDE AI Adapter with Model Context Protocol (MCP) & Settings Injection."""
import os
import sys
import json
import shutil
from pathlib import Path
from typing import Optional, Dict, Any

from app.clients.base import BaseClientAdapter
from app.clients.models import ClientInfo, ClientStatus, ClientType, MutationResult


class AntigravityAdapter(BaseClientAdapter):
    """Detects Antigravity IDE and configures native MCP Privacy Server & API routing."""

    def __init__(self, config_path_override: Optional[Path] = None):
        super().__init__(
            client_id="antigravity",
            name="Antigravity IDE",
            client_type=ClientType.ANTIGRAVITY,
            icon="antigravity",
            description="Google DeepMind Agentic IDE (Native MCP & Gateway Routing)"
        )
        self.config_path_override = config_path_override

    def get_config_path(self) -> Path:
        """Returns the primary MCP configuration path for Antigravity."""
        if self.config_path_override:
            return self.config_path_override
        return Path.home() / ".gemini" / "config" / "mcp_config.json"

    def get_settings_path(self) -> Path:
        """Returns the Antigravity IDE User settings.json path."""
        if sys.platform == "win32":
            appdata = os.environ.get("APPDATA")
            if appdata:
                return Path(appdata) / "Antigravity IDE" / "User" / "settings.json"
            return Path.home() / "AppData" / "Roaming" / "Antigravity IDE" / "User" / "settings.json"
        elif sys.platform == "darwin":
            return Path.home() / "Library" / "Application Support" / "Antigravity IDE" / "User" / "settings.json"
        else:
            return Path.home() / ".config" / "Antigravity IDE" / "User" / "settings.json"

    def detect(self) -> bool:
        """Detects if Antigravity IDE or its configuration directory exists."""
        gemini_dir = Path.home() / ".gemini"
        settings_dir = self.get_settings_path().parent
        return gemini_dir.exists() or settings_dir.exists()

    def get_status(self) -> ClientInfo:
        if not self.detect():
            return ClientInfo(
                id=self.client_id,
                name=self.name,
                client_type=self.client_type,
                status=ClientStatus.NOT_INSTALLED,
                icon=self.icon,
                description=self.description,
                config_path=str(self.get_config_path()),
                has_backup=False
            )

        mcp_path = self.get_config_path()
        settings_path = self.get_settings_path()
        has_backup = self.has_backup(mcp_path) or self.has_backup(settings_path)

        # Check if Veil MCP server is registered
        is_mcp_connected = False
        if mcp_path.exists():
            try:
                data = self.load_json_safely(mcp_path)
                if data and "mcpServers" in data and "veil-privacy-guard" in data["mcpServers"]:
                    is_mcp_connected = True
            except Exception:
                pass

        # Check if settings.json has OpenAI / Proxy base URL
        is_settings_connected = False
        current_url = None
        if settings_path.exists():
            try:
                sdata = self.load_json_safely(settings_path)
                if sdata:
                    current_url = sdata.get("openai.baseURL") or sdata.get("http.proxy")
                    if current_url and "127.0.0.1" in current_url:
                        is_settings_connected = True
            except Exception:
                pass

        # Legacy fallback check in ~/.gemini/config.json
        legacy_path = Path.home() / ".gemini" / "config.json"
        if not is_mcp_connected and legacy_path.exists():
            try:
                ldata = self.load_json_safely(legacy_path)
                if ldata and "127.0.0.1" in ldata.get("api_base", ""):
                    is_mcp_connected = True
            except Exception:
                pass

        is_connected = is_mcp_connected or is_settings_connected
        status = ClientStatus.CONNECTED if is_connected else ClientStatus.DETECTED

        return ClientInfo(
            id=self.client_id,
            name=self.name,
            client_type=self.client_type,
            status=status,
            icon=self.icon,
            description=self.description,
            config_path=str(mcp_path),
            has_backup=has_backup,
            current_base_url=current_url or "MCP: veil-privacy-guard",
            details={
                "mcp_config": str(mcp_path),
                "settings_path": str(settings_path),
                "mcp_active": is_mcp_connected
            }
        )

    def connect(self, gateway_url: str = "http://127.0.0.1:8080/v1") -> MutationResult:
        """Injects Veil MCP server into mcp_config.json and updates Antigravity settings."""
        mcp_path = self.get_config_path()
        settings_path = self.get_settings_path()
        mcp_backup = None

        try:
            # 1. Configure MCP server in ~/.gemini/config/mcp_config.json
            mcp_path.parent.mkdir(parents=True, exist_ok=True)
            mcp_data: Dict[str, Any] = {"mcpServers": {}}
            if mcp_path.exists() and mcp_path.stat().st_size > 0:
                mcp_backup = self.create_backup(mcp_path)
                loaded = self.load_json_safely(mcp_path)
                if loaded and isinstance(loaded, dict):
                    mcp_data = loaded

            if "mcpServers" not in mcp_data or not isinstance(mcp_data["mcpServers"], dict):
                mcp_data["mcpServers"] = {}

            # Project root for python module execution
            project_root = str(Path(__file__).resolve().parent.parent.parent)
            python_bin = sys.executable

            mcp_data["mcpServers"]["veil-privacy-guard"] = {
                "command": python_bin,
                "args": ["-m", "app.mcp_server"],
                "env": {
                    "PYTHONPATH": project_root
                }
            }
            self.atomic_write_text(mcp_path, json.dumps(mcp_data, indent=2))

            # 2. Configure Antigravity User settings.json if directory exists
            if settings_path.parent.exists():
                s_data: Dict[str, Any] = {}
                if settings_path.exists() and settings_path.stat().st_size > 0:
                    self.create_backup(settings_path)
                    loaded_s = self.load_json_safely(settings_path)
                    if loaded_s and isinstance(loaded_s, dict):
                        s_data = loaded_s

                s_data["openai.baseURL"] = gateway_url
                self.atomic_write_text(settings_path, json.dumps(s_data, indent=2))

            # 3. Write legacy ~/.gemini/config.json for compatibility
            legacy_path = Path.home() / ".gemini" / "config.json"
            legacy_data = {}
            if legacy_path.exists():
                l_loaded = self.load_json_safely(legacy_path)
                if l_loaded and isinstance(l_loaded, dict):
                    legacy_data = l_loaded
            legacy_data["api_base"] = gateway_url
            self.atomic_write_text(legacy_path, json.dumps(legacy_data, indent=2))

            return MutationResult(
                success=True,
                message=f"Antigravity IDE successfully wired with native Veil MCP Server & gateway at {gateway_url}.",
                client_id=self.client_id,
                new_url=gateway_url,
                backup_path=str(mcp_backup) if mcp_backup else None
            )

        except Exception as e:
            return MutationResult(
                success=False,
                message=f"Failed to configure Antigravity MCP integration: {e}",
                client_id=self.client_id
            )

    def disconnect(self) -> MutationResult:
        """Restores Antigravity mcp_config.json and settings.json from backups."""
        mcp_path = self.get_config_path()
        settings_path = self.get_settings_path()
        legacy_path = Path.home() / ".gemini" / "config.json"

        try:
            # Restore or remove MCP server
            if self.has_backup(mcp_path):
                self.restore_backup(mcp_path)
            elif mcp_path.exists():
                mcp_data = self.load_json_safely(mcp_path)
                if mcp_data and "mcpServers" in mcp_data and "veil-privacy-guard" in mcp_data["mcpServers"]:
                    del mcp_data["mcpServers"]["veil-privacy-guard"]
                    self.atomic_write_text(mcp_path, json.dumps(mcp_data, indent=2))

            # Restore or remove settings.json keys
            if self.has_backup(settings_path):
                self.restore_backup(settings_path)
            elif settings_path.exists():
                s_data = self.load_json_safely(settings_path)
                if s_data and "openai.baseURL" in s_data:
                    del s_data["openai.baseURL"]
                    self.atomic_write_text(settings_path, json.dumps(s_data, indent=2))

            # Remove legacy
            if legacy_path.exists():
                ldata = self.load_json_safely(legacy_path)
                if ldata and "api_base" in ldata:
                    del ldata["api_base"]
                    self.atomic_write_text(legacy_path, json.dumps(ldata, indent=2))

            return MutationResult(
                success=True,
                message="Antigravity IDE disconnected. MCP servers and settings restored.",
                client_id=self.client_id
            )
        except Exception as e:
            return MutationResult(
                success=False,
                message=f"Failed to disconnect Antigravity: {e}",
                client_id=self.client_id
            )
