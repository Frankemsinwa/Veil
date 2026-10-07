"""Veil Client Auto-Discovery and Configuration Injection package."""
from app.clients.models import ClientStatus, ClientType, ClientInfo, MutationResult
from app.clients.base import BaseClientAdapter
from app.clients.cursor import CursorAdapter
from app.clients.continue_ext import ContinueAdapter
from app.clients.claude_code import ClaudeCodeAdapter
from app.clients.aider import AiderAdapter
from app.clients.antigravity import AntigravityAdapter
from app.clients.opencode import OpenCodeAdapter
from app.clients.manager import ClientManager, client_manager

__all__ = [
    "ClientStatus",
    "ClientType",
    "ClientInfo",
    "MutationResult",
    "BaseClientAdapter",
    "CursorAdapter",
    "ContinueAdapter",
    "ClaudeCodeAdapter",
    "AiderAdapter",
    "SystemEnvAdapter",
    "AntigravityAdapter",
    "OpenCodeAdapter",
    "ClientManager",
    "client_manager",
]
