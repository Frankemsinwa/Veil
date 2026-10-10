"""Veil Detection Engine Data Models."""
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class EntityCategory(str, Enum):
    # High-severity secrets (Target: BLOCK)
    SECRET = "SECRET"
    
    # Personal identifiable information (Target: REDACT)
    PII = "PII"
    
    # Infrastructure & Networking (Target: REDACT / ALLOW depending on policy)
    INFRASTRUCTURE = "INFRASTRUCTURE"

    # Contextual Proprietary Knowledge & Vector Guardrails
    PROPRIETARY = "PROPRIETARY"


class EntityType(str, Enum):
    # Secrets
    OPENAI_API_KEY = "OPENAI_API_KEY"
    ANTHROPIC_API_KEY = "ANTHROPIC_API_KEY"
    GITHUB_PAT = "GITHUB_PAT"
    AWS_ACCESS_KEY = "AWS_ACCESS_KEY"
    AWS_SECRET_KEY = "AWS_SECRET_KEY"
    GOOGLE_API_KEY = "GOOGLE_API_KEY"
    SLACK_TOKEN = "SLACK_TOKEN"
    PRIVATE_KEY_PEM = "PRIVATE_KEY_PEM"
    JWT_TOKEN = "JWT_TOKEN"
    GENERIC_SECRET_ENTROPY = "GENERIC_SECRET_ENTROPY"

    # PII
    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    PHONE_NUMBER = "PHONE_NUMBER"
    IPV4_ADDRESS = "IPV4_ADDRESS"
    CREDIT_CARD = "CREDIT_CARD"
    SSN = "SSN"

    # Custom Enterprise Dictionary
    CUSTOM_ENTITY = "CUSTOM_ENTITY"

    # Vector Semantic Guardrail
    VECTOR_GUARDRAIL = "VECTOR_GUARDRAIL"


class DetectedSpan(BaseModel):
    """Represents a discrete sensitive token detected within text."""
    entity_type: EntityType
    category: EntityCategory
    start: int = Field(description="0-based start character index")
    end: int = Field(description="0-based end character index (exclusive)")
    matched_text: str = Field(description="Exact sensitive string slice")
    confidence: float = Field(ge=0.0, le=1.0, description="Detection confidence score")
    is_whitelisted: bool = Field(default=False, description="Whether entity matched RFC test data")
    metadata: Optional[dict] = Field(default_factory=dict)

    @property
    def length(self) -> int:
        return self.end - self.start
