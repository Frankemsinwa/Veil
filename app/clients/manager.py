"""Unified Client Manager discovering and controlling all client adapters."""
from typing import Dict, List, Optional

from app.core.config import settings
from app.clients.base import BaseClientAdapter
from app.clients.models import ClientInfo, MutationResult
from app.clients.cursor import CursorAdapter
from app.clients.continue_ext import ContinueAdapter
from app.clients.claude_code import ClaudeCodeAdapter
from app.clients.aider import AiderAdapter
from app.clients.system_env import SystemEnvAdapter
from app.clients.antigravity import AntigravityAdapter
from app.clients.opencode import OpenCodeAdapter


class ClientManager:
    """Central registry and controller for discovering, connecting, and disconnecting AI clients."""

    def __init__(self, adapters: Optional[List[BaseClientAdapter]] = None):
        if adapters is not None:
            self._adapters: Dict[str, BaseClientAdapter] = {a.client_id: a for a in adapters}
        else:
            default_adapters = [
                CursorAdapter(),
                ContinueAdapter(),
                ClaudeCodeAdapter(),
                AiderAdapter(),
                SystemEnvAdapter(),
                AntigravityAdapter(),
                OpenCodeAdapter(),
            ]
            self._adapters = {a.client_id: a for a in default_adapters}

    def get_all_clients(self) -> List[ClientInfo]:
        """Scans all registered adapters and returns their active detection status."""
        return [adapter.get_status() for adapter in self._adapters.values()]

    def get_client(self, client_id: str) -> Optional[BaseClientAdapter]:
        """Retrieves a specific client adapter by identifier."""
        return self._adapters.get(client_id)

    def connect_client(self, client_id: str, gateway_url: Optional[str] = None) -> MutationResult:
        """Connects a specific client to the Veil gateway URL."""
        adapter = self.get_client(client_id)
        if not adapter:
            return MutationResult(
                success=False,
                message=f"Client '{client_id}' is not recognized by Veil.",
                client_id=client_id
            )

        # Enforce licensing connection limits (Free tier = 1 client max)
        from app.licensing.enforcer import check_client_connection_limit
        connected_count = sum(1 for a in self._adapters.values() if a.get_status().status.value == "CONNECTED")
        current_status = adapter.get_status().status.value

        if current_status != "CONNECTED":
            allowed, limit_msg = check_client_connection_limit(connected_count, client_id)
            if not allowed:
                return MutationResult(
                    success=False,
                    message=limit_msg,
                    client_id=client_id
                )

        target_url = gateway_url or f"http://{settings.HOST}:{settings.PORT}/v1"
        return adapter.connect(target_url)

    def disconnect_client(self, client_id: str) -> MutationResult:
        """Rolls back and disconnects a specific client from the Veil gateway."""
        adapter = self.get_client(client_id)
        if not adapter:
            return MutationResult(
                success=False,
                message=f"Client '{client_id}' is not recognized by Veil.",
                client_id=client_id
            )
        return adapter.disconnect()

    def disconnect_all(self) -> Dict[str, MutationResult]:
        """Rolls back all connected clients (useful on gateway termination or pause)."""
        results = {}
        for cid, adapter in self._adapters.items():
            status = adapter.get_status()
            if status.status.value == "CONNECTED":
                results[cid] = adapter.disconnect()
        return results


# Global client manager singleton
client_manager = ClientManager()
