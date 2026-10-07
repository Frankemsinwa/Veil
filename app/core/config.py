"""Core configuration for Veil Gateway."""
from enum import Enum
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class PolicyLevel(str, Enum):
    STRICT = "STRICT"        # Block all secrets, redact all PII, fail-closed
    BALANCED = "BALANCED"    # Block critical secrets, redact PII, allow dev/local IPs
    PERMISSIVE = "PERMISSIVE" # Audit-only mode, warn without blocking


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="VEIL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Gateway Server
    HOST: str = Field(default="127.0.0.1", description="Bind address for local gateway")
    PORT: int = Field(default=8080, description="Listening port for Veil")
    DEBUG: bool = Field(default=False, description="Enable verbose local debug mode")

    # Security Policy
    POLICY: PolicyLevel = Field(default=PolicyLevel.STRICT, description="Active privacy policy")
    FAIL_CLOSED: bool = Field(default=True, description="Strictly block requests on engine errors")

    # Upstream Provider Defaults
    DEFAULT_PROVIDER: str = Field(default="openai", description="Default upstream provider")
    UPSTREAM_OPENAI_BASE_URL: str = Field(
        default="https://api.openai.com/v1",
        description="Target OpenAI API base URL"
    )
    UPSTREAM_API_KEY: Optional[str] = Field(
        default=None,
        description="Optional upstream provider API key (fallback if not passed in client request)"
    )
    UPSTREAM_ANTHROPIC_BASE_URL: str = Field(
        default="https://api.anthropic.com/v1",
        description="Target Anthropic API base URL"
    )
    UPSTREAM_ANTHROPIC_API_KEY: Optional[str] = Field(
        default=None,
        description="Optional upstream Anthropic API key"
    )
    UPSTREAM_OLLAMA_BASE_URL: str = Field(
        default="http://127.0.0.1:11434",
        description="Local or remote Ollama instance base URL"
    )

    # Session & Vault Security
    SESSION_TTL_SECONDS: int = Field(
        default=1800,
        description="TTL for in-memory token mapping vaults (default: 30 minutes)"
    )
    VAULT_SECRET_KEY: Optional[str] = Field(
        default=None,
        description="Master encryption key (hex). Generated automatically if omitted."
    )

    # Semantic ML Classifier (Phase 10)
    SEMANTIC_CLASSIFIER_ENABLED: bool = Field(
        default=True,
        description="Enable local ML semantic classifier for contextual privacy"
    )
    SEMANTIC_BACKEND: str = Field(
        default="embedded",
        description="Semantic classifier backend: 'embedded', 'ollama', or 'onnx'"
    )
    SEMANTIC_CONFIDENCE_THRESHOLD: float = Field(
        default=0.70,
        description="Confidence threshold to flag contextual sensitivity"
    )
    SEMANTIC_BLOCK_THRESHOLD: float = Field(
        default=0.85,
        description="Confidence threshold to trigger BLOCK in STRICT mode for proprietary data"
    )
    OLLAMA_BASE_URL: str = Field(
        default="http://127.0.0.1:11434",
        description="Local Ollama endpoint URL"
    )
    OLLAMA_MODEL: str = Field(
        default="llama3.2:1b",
        description="Ollama model tag to use for semantic classification"
    )
    ONNX_MODEL_PATH: Optional[Path] = Field(
        default=None,
        description="Path to quantized ONNX classification model file"
    )

    # Audit & Ledger
    AUDIT_ENABLED: bool = Field(default=True, description="Enable local SQLite audit logging")
    DATA_DIR: Path = Field(
        default=Path.home() / ".veil",
        description="Local directory for encrypted audit ledgers and configs"
    )



settings = Settings()
