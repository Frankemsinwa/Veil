"""Data models for Veil Client Discovery and Configuration Injection."""
from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class ClientStatus(str, Enum):
    """Current connection state of an AI client."""
    CONNECTED = "CONNECTED"          # Configured to route through Veil gateway
    DETECTED = "DETECTED"            # Installed / config found, currently pointing elsewhere
    NOT_INSTALLED = "NOT_INSTALLED"  # Client configuration or executable not found
    ERROR = "ERROR"                  # Config exists but syntax error or permission denied


class ClientType(str, Enum):
    """Supported AI client and IDE categories."""
    CURSOR = "cursor"
    CONTINUE = "continue"
    CLAUDE_CODE = "claude_code"
    AIDER = "aider"
    SYSTEM_ENV = "system_env"
    ANTIGRAVITY = "antigravity"
    OPENCODE = "opencode"


class ClientInfo(BaseModel):
    """Detailed telemetry and connection state for an AI client."""
    id: str = Field(description="Unique client identifier, e.g. 'cursor', 'continue'")
    name: str = Field(description="Display name of the client")
    client_type: ClientType
    status: ClientStatus
    icon: str = Field(description="Icon identifier or emoji for cockpit UI")
    description: str = Field(description="Human-readable description of client and config target")
    config_path: Optional[str] = Field(default=None, description="Path to active configuration file")
    has_backup: bool = Field(default=False, description="Whether a .veil.bak backup file exists")
    current_base_url: Optional[str] = Field(default=None, description="Active upstream base URL in client config")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional adapter-specific metadata")


class MutationResult(BaseModel):
    """Result of a 1-click connect or disconnect configuration operation."""
    success: bool
    message: str
    client_id: str
    previous_url: Optional[str] = None
    new_url: Optional[str] = None
    backup_path: Optional[str] = None
