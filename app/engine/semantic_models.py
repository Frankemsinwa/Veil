"""Data models for Phase 10 Semantic Classifier."""
from enum import Enum
from typing import List, Tuple, Optional
from pydantic import BaseModel, Field


class SemanticCategory(str, Enum):
    """Contextual sensitivity categories evaluated by the ML semantic classifier."""
    PROPRIETARY_BUSINESS_DATA = "PROPRIETARY_BUSINESS_DATA"  # Revenue forecasts, margins, pricing, internal financials
    NDA_CONFIDENTIAL = "NDA_CONFIDENTIAL"                    # M&A memos, trade secrets, confidential partnership terms
    LEGAL_PRIVILEGED = "LEGAL_PRIVILEGED"                    # Attorney-client communications, litigation defense
    INTERNAL_INFRASTRUCTURE = "INTERNAL_INFRASTRUCTURE"      # Bastion topologies, failover runbooks, network maps
    SAFE_PUBLIC = "SAFE_PUBLIC"                              # Benign queries, open coding questions, public knowledge


class SemanticClassificationResult(BaseModel):
    """Structured result returned by the semantic classifier sensor."""
    category: SemanticCategory = Field(description="Detected contextual category")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0")
    is_sensitive: bool = Field(description="Whether the category represents sensitive/protected content")
    matched_indicators: List[str] = Field(default_factory=list, description="Keywords or contextual indicators detected")
    rationale: str = Field(default="", description="Human-readable explanation of the classification")
    flagged_spans: List[Tuple[int, int]] = Field(default_factory=list, description="Character offsets of sensitive zones")
    backend_used: str = Field(default="embedded", description="Classifier backend that generated this result")
