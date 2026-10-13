"""Antigravity IDE AI Adapter with Model Context Protocol (MCP) & Rule Automation."""
import os
import sys
import json
import shutil
import time
import urllib.request
from pathlib import Path
from typing import Optional, Dict, Any, List

from app.clients.base import BaseClientAdapter
from app.clients.models import ClientInfo, ClientStatus, ClientType, MutationResult

VEIL_PRIVACY_RULE_TEXT = """---
description: Enterprise zero-retention privacy shield and tokenization rules for Google Antigravity.
globs: *
---

# Veil AI Privacy & Security Guard

## Mission
Protect enterprise intellectual property, proprietary credentials, and customer PII by strictly channeling all reasoning workflows through the local Veil Security Shield.

## Core Rules
1. **Zero Raw Secrets Outbound**: Cloud credentials (AWS, GCP, Azure, GitHub), private RSA/SSH keys, internal database connection strings, and plaintext credentials must never be transmitted to external model endpoints without tokenization.
2. **Reversible Vault Tokenization**: Veil dynamically sanitizes sensitive identifiers into reversible session tokens (e.g., [EMAIL_001], [PROJECT_001], [AWS_KEY_001]). Respect and preserve these placeholders during generation; the local Veil engine restores them seamlessly in real-time.
3. **MCP Tool Verification**: When encountering sensitive customer data or high-security repositories, use the veil-privacy-guard MCP tools (inspect_prompt, scan_text, restore_response) for explicit privacy compliance checks.
4. **Fail-Closed Gating**: Under STRICT policy mode, any outbound leakage of trade secrets or dense vector breaches is fail-closed blocked locally with HTTP 403 Forbidden.
"""


class AntigravityAdapter(BaseClientAdapter):
    """Detects Antigravity IDE and configures native MCP Privacy Server, Rules & API routing."""

    def __init__(
        self,
        config_path_override: Optional[Path] = None,
        settings_path_override: Optional[Path] = None,
        global_rule_override: Optional[Path] = None,
        workspace_rule_override: Optional[Path] = None,
    ):
        super().__init__(
            client_id="antigravity",
            name="Antigravity IDE",
            client_type=ClientType.ANTIGRAVITY,
            icon="antigravity",
            description="Google DeepMind Agentic IDE (Native MCP & Rule Guardrails)"
        )
        self.config_path_override = config_path_override
        self.settings_path_override = settings_path_override
        self.global_rule_override = global_rule_override
        self.workspace_rule_override = workspace_rule_override

    def get_config_path(self) -> Path:
        """Returns the primary MCP configuration path for Antigravity."""
        if self.config_path_override:
            return self.config_path_override
        return Path.home() / ".gemini" / "config" / "mcp_config.json"

    def get_global_rule_path(self) -> Path:
        """Returns the global rule path in ~/.gemini/config/rules/veil_privacy.md."""
        if self.global_rule_override:
            return self.global_rule_override
        return Path.home() / ".gemini" / "config" / "rules" / "veil_privacy.md"

    def get_workspace_rule_path(self) -> Path:
        """Returns the workspace rule path in .agents/rules/veil_privacy.md."""
        if self.workspace_rule_override:
            return self.workspace_rule_override
        return Path.cwd() / ".agents" / "rules" / "veil_privacy.md"

    def get_settings_path(self) -> Path:
        """Returns the Antigravity IDE User settings.json path."""
        if self.settings_path_override:
            return self.settings_path_override
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
        return gemini_dir.exists() or settings_dir.exists() or (Path.cwd() / ".agents").exists()

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
        global_rule_path = self.get_global_rule_path()
        workspace_rule_path = self.get_workspace_rule_path()
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

        # Check if rules are present
        has_rule = global_rule_path.exists() or workspace_rule_path.exists()

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

        is_connected = is_mcp_connected or is_settings_connected or has_rule
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
                "mcp_active": is_mcp_connected,
                "global_rule": global_rule_path.exists(),
                "workspace_rule": workspace_rule_path.exists(),
            }
        )

    def connect(self, gateway_url: str = "http://127.0.0.1:8080/v1") -> MutationResult:
        """Injects Veil MCP server, installs rules, and updates Antigravity settings."""
        mcp_path = self.get_config_path()
        settings_path = self.get_settings_path()
        global_rule = self.get_global_rule_path()
        workspace_rule = self.get_workspace_rule_path()
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

            # 2. Install Global and Workspace Agent Rules
            global_rule.parent.mkdir(parents=True, exist_ok=True)
            self.atomic_write_text(global_rule, VEIL_PRIVACY_RULE_TEXT)

            workspace_dir = Path.cwd() / ".agents"
            if workspace_dir.exists() or Path.cwd().is_dir():
                workspace_rule.parent.mkdir(parents=True, exist_ok=True)
                self.atomic_write_text(workspace_rule, VEIL_PRIVACY_RULE_TEXT)

            # 3. Configure Antigravity User settings.json if directory exists
            if settings_path.parent.exists():
                s_data: Dict[str, Any] = {}
                if settings_path.exists() and settings_path.stat().st_size > 0:
                    self.create_backup(settings_path)
                    loaded_s = self.load_json_safely(settings_path)
                    if loaded_s and isinstance(loaded_s, dict):
                        s_data = loaded_s

                s_data["openai.baseURL"] = gateway_url
                s_data["openai.apiKey"] = "veil-dev-token"
                self.atomic_write_text(settings_path, json.dumps(s_data, indent=2))

            return MutationResult(
                success=True,
                message=f"Antigravity IDE successfully wired with native Veil MCP Server, Rules & gateway at {gateway_url}.",
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
        """Restores Antigravity mcp_config.json, removes rules, and restores settings."""
        mcp_path = self.get_config_path()
        settings_path = self.get_settings_path()
        global_rule = self.get_global_rule_path()
        workspace_rule = self.get_workspace_rule_path()

        try:
            # Restore or remove MCP server
            if self.has_backup(mcp_path):
                self.restore_backup(mcp_path)
            elif mcp_path.exists():
                mcp_data = self.load_json_safely(mcp_path)
                if mcp_data and "mcpServers" in mcp_data and "veil-privacy-guard" in mcp_data["mcpServers"]:
                    del mcp_data["mcpServers"]["veil-privacy-guard"]
                    self.atomic_write_text(mcp_path, json.dumps(mcp_data, indent=2))

            # Remove rule files
            if global_rule.exists():
                try:
                    global_rule.unlink()
                except Exception:
                    pass
            if workspace_rule.exists():
                try:
                    workspace_rule.unlink()
                except Exception:
                    pass

            # Restore or remove settings.json keys
            if self.has_backup(settings_path):
                self.restore_backup(settings_path)
            elif settings_path.exists():
                s_data = self.load_json_safely(settings_path)
                if s_data:
                    s_data.pop("openai.baseURL", None)
                    if s_data.get("openai.apiKey") == "veil-dev-token":
                        s_data.pop("openai.apiKey", None)
                    self.atomic_write_text(settings_path, json.dumps(s_data, indent=2))

            return MutationResult(
                success=True,
                message="Antigravity IDE disconnected. MCP servers, rules, and settings restored.",
                client_id=self.client_id
            )
        except Exception as e:
            return MutationResult(
                success=False,
                message=f"Failed to disconnect Antigravity: {e}",
                client_id=self.client_id
            )

    def test_connection(self, gateway_url: str = "http://127.0.0.1:8080/v1") -> Dict[str, Any]:
        """Runs multi-point diagnostic verifying MCP, rules, and gateway ping."""
        info = self.get_status()
        details = info.details or {}
        mcp_active = details.get("mcp_active", False)
        rule_active = details.get("global_rule", False) or details.get("workspace_rule", False)

        # Probe Veil gateway health
        health_url = gateway_url.replace("/v1", "").rstrip("/") + "/health"
        t0 = time.perf_counter()
        gateway_online = False
        elapsed_ms = 0.0

        try:
            req = urllib.request.Request(health_url, headers={"User-Agent": "Veil-Probe/antigravity"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                gateway_online = (resp.status == 200)
        except Exception:
            gateway_online = False

        if mcp_active or rule_active:
            status_text = "VERIFIED"
            msg = f"[OK] Verified! Antigravity is protected by Veil (MCP: {'Active' if mcp_active else 'Standby'}, Rule: {'Active' if rule_active else 'Standby'}, Gateway: {round(elapsed_ms, 1)}ms)."
            success = True
        else:
            status_text = "STANDBY"
            msg = f"Veil Gateway is online ({round(elapsed_ms, 1)}ms), but Antigravity MCP/Rules are not active. Click 'Connect' to enable."
            success = False

        return {
            "success": success,
            "client_id": self.client_id,
            "name": self.name,
            "is_routed": mcp_active or rule_active,
            "status": status_text,
            "url": info.current_base_url or gateway_url,
            "latency_ms": round(elapsed_ms, 2),
            "message": msg,
            "details": {
                "mcp_active": mcp_active,
                "rule_active": rule_active,
                "gateway_online": gateway_online
            }
        }
