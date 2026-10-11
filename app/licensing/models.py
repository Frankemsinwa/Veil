"""Data models and enums for Veil Licensing and Feature Gating."""
from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field


class LicenseTier(str, Enum):
    """Available commercial license tiers."""
    FREE = "FREE"              # Community / Solo Developer
    PRO = "PRO"                # Team / Professional Developer
    ENTERPRISE = "ENTERPRISE"  # Enterprise Fleet & Centralized Compliance


class FeatureFlag(str, Enum):
    """Individual features that can be gated by license tier."""
    BASIC_REGEX = "basic_regex"                   # High-speed deterministic regex scanning
    SHANNON_ENTROPY = "shannon_entropy"           # High-entropy credential detection
    LOCAL_UI = "local_ui"                         # Native desktop & web cockpit
    SSE_RING_RESTORE = "sse_ring_restore"         # Sliding-window streaming restoration
    VECTOR_GUARDRAILS = "vector_guardrails"       # Local ONNX INT8 dense vector defense
    CUSTOM_DICTIONARY = "custom_dictionary"       # Custom corporate keyword/NDA scanner
    UNLIMITED_CLIENTS = "unlimited_clients"       # Simultaneous routing across all IDEs
    AUDIT_EXPORT = "audit_export"                 # CSV / JSON export of HMAC audit receipts
    ENTERPRISE_FLEET = "enterprise_fleet"         # Centralized fleet sync & SIEM forwarders


# Default feature allocations per tier
TIER_ENTITLEMENTS: dict[LicenseTier, list[FeatureFlag]] = {
    LicenseTier.FREE: [
        FeatureFlag.BASIC_REGEX,
        FeatureFlag.SHANNON_ENTROPY,
        FeatureFlag.LOCAL_UI,
        FeatureFlag.SSE_RING_RESTORE,
    ],
    LicenseTier.PRO: [
        FeatureFlag.BASIC_REGEX,
        FeatureFlag.SHANNON_ENTROPY,
        FeatureFlag.LOCAL_UI,
        FeatureFlag.SSE_RING_RESTORE,
        FeatureFlag.VECTOR_GUARDRAILS,
        FeatureFlag.CUSTOM_DICTIONARY,
        FeatureFlag.UNLIMITED_CLIENTS,
        FeatureFlag.AUDIT_EXPORT,
    ],
    LicenseTier.ENTERPRISE: [
        FeatureFlag.BASIC_REGEX,
        FeatureFlag.SHANNON_ENTROPY,
        FeatureFlag.LOCAL_UI,
        FeatureFlag.SSE_RING_RESTORE,
        FeatureFlag.VECTOR_GUARDRAILS,
        FeatureFlag.CUSTOM_DICTIONARY,
        FeatureFlag.UNLIMITED_CLIENTS,
        FeatureFlag.AUDIT_EXPORT,
        FeatureFlag.ENTERPRISE_FLEET,
    ],
}

# Maximum simultaneous connected IDE clients
TIER_CLIENT_LIMITS: dict[LicenseTier, int] = {
    LicenseTier.FREE: 1,
    LicenseTier.PRO: 999,
    LicenseTier.ENTERPRISE: 999,
}


class LicensePayload(BaseModel):
    """Cryptographic payload encapsulated inside a signed Veil license key."""
    license_id: str = Field(..., description="Unique license identifier, e.g. VL-PRO-XXXXX")
    tier: LicenseTier = Field(default=LicenseTier.FREE, description="License tier level")
    customer_email: str = Field(default="community@veil.local", description="Licensed user email")
    issued_at: float = Field(..., description="UNIX timestamp of issuance")
    expires_at: Optional[float] = Field(None, description="UNIX timestamp of expiration (None = perpetual)")
    features: List[FeatureFlag] = Field(default_factory=list, description="Explicit feature flags enabled")
    max_clients: int = Field(default=1, description="Maximum simultaneous connected IDE clients")
    signature: Optional[str] = Field(None, description="HMAC-SHA256 signature over license metadata")

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        """Check if the license has expired."""
        if self.expires_at is None:
            return False
        import time
        now = current_time if current_time is not None else time.time()
        return now > self.expires_at

    def has_feature(self, feature: FeatureFlag) -> bool:
        """Check if this license grants access to a specific feature flag."""
        return feature in self.features


class PlanDetails(BaseModel):
    """Public representation of pricing plans for the Web UI and CLI."""
    tier: LicenseTier
    name: str
    price_usd_monthly: float
    price_ngn_monthly: int
    features: List[str]
    max_clients: int
    is_active: bool = False
    badge: Optional[str] = None
