"""Cryptographic License Key Management & Offline Verification Engine."""
import base64
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Optional, Tuple, List

from app.core.config import settings
from app.licensing.models import (
    LicenseTier,
    FeatureFlag,
    LicensePayload,
    PlanDetails,
    TIER_ENTITLEMENTS,
    TIER_CLIENT_LIMITS,
)

logger = logging.getLogger(__name__)

# System-level license signing master salt
DEFAULT_SIGNING_SALT = b"veil-enterprise-license-master-secret-2026-auth"


class LicenseManager:
    """Manages cryptographic license verification, storage, and feature checks."""

    def __init__(self, license_file_path: Optional[Path] = None):
        self.data_dir = settings.DATA_DIR
        self.license_path = license_file_path or (self.data_dir / "license.json")
        self._cached_license: Optional[LicensePayload] = None
        self._signing_key = self._derive_signing_key()
        self.reload_license()

    def _derive_signing_key(self) -> bytes:
        """Derives HMAC signing key from configuration or cryptographic salt."""
        base_seed = settings.VAULT_SECRET_KEY.encode() if settings.VAULT_SECRET_KEY else DEFAULT_SIGNING_SALT
        return hashlib.sha256(base_seed + b"::VEIL_LICENSING_HMAC_V1").digest()

    def _generate_default_free_license(self) -> LicensePayload:
        """Generates the standard unencumbered Community / Solo Free license."""
        return LicensePayload(
            license_id="VL-FREE-COMMUNITY",
            tier=LicenseTier.FREE,
            customer_email="developer@community.veil",
            issued_at=time.time(),
            expires_at=None,
            features=TIER_ENTITLEMENTS[LicenseTier.FREE],
            max_clients=TIER_CLIENT_LIMITS[LicenseTier.FREE],
            signature=None,
        )

    def reload_license(self) -> LicensePayload:
        """Loads and verifies license from disk or environment variable."""
        # 1. Check environment variable first
        env_key = os.environ.get("VEIL_LICENSE_KEY")
        if env_key:
            valid, payload, _ = self.verify_license_key(env_key)
            if valid and payload:
                self._cached_license = payload
                return payload

        # 2. Check license file on disk
        if self.license_path.exists():
            try:
                raw_json = self.license_path.read_text(encoding="utf-8")
                data = json.loads(raw_json)
                key_str = data.get("raw_key")
                if key_str:
                    valid, payload, err = self.verify_license_key(key_str)
                    if valid and payload:
                        self._cached_license = payload
                        return payload
                    logger.warning(f"Saved license key failed validation: {err}")
            except Exception as e:
                logger.error(f"Failed to read license file at {self.license_path}: {e}")

        # 3. Fallback to Free / Solo tier
        self._cached_license = self._generate_default_free_license()
        return self._cached_license

    def issue_license(
        self,
        tier: LicenseTier,
        customer_email: str,
        duration_days: Optional[int] = 30,
        custom_features: Optional[List[FeatureFlag]] = None,
        custom_max_clients: Optional[int] = None,
    ) -> Tuple[str, LicensePayload]:
        """Issues a cryptographically signed license key string for a customer."""
        issued_at = time.time()
        expires_at = (issued_at + (duration_days * 86400)) if duration_days else None
        features = custom_features if custom_features is not None else TIER_ENTITLEMENTS[tier]
        max_clients = custom_max_clients if custom_max_clients is not None else TIER_CLIENT_LIMITS[tier]

        unique_id = f"VL-{tier.value}-{uuid.uuid4().hex[:10].upper()}"

        payload_dict = {
            "license_id": unique_id,
            "tier": tier.value,
            "customer_email": customer_email,
            "issued_at": round(issued_at, 2),
            "expires_at": round(expires_at, 2) if expires_at else None,
            "features": [f.value for f in features],
            "max_clients": max_clients,
        }

        # Canonical JSON string for HMAC
        canonical_bytes = json.dumps(payload_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig = hmac.new(self._signing_key, canonical_bytes, hashlib.sha256).hexdigest()
        payload_dict["signature"] = sig

        # Base64url encode payload
        encoded_payload = base64.urlsafe_b64encode(canonical_bytes).decode("ascii").rstrip("=")
        license_key = f"VL-{tier.value}-{encoded_payload}.{sig}"

        created_payload = LicensePayload(
            license_id=unique_id,
            tier=tier,
            customer_email=customer_email,
            issued_at=issued_at,
            expires_at=expires_at,
            features=features,
            max_clients=max_clients,
            signature=sig,
        )

        return license_key, created_payload

    def verify_license_key(self, key_str: str) -> Tuple[bool, Optional[LicensePayload], str]:
        """Validates a license key string against signature and expiration."""
        if not key_str or not isinstance(key_str, str):
            return False, None, "License key cannot be empty"

        parts = key_str.strip().split(".")
        if len(parts) != 2:
            return False, None, "Invalid license key format (missing signature segment)"

        header_and_payload, signature = parts[0], parts[1]

        # Extract tier prefix and base64 body: VL-<TIER>-<BASE64>
        if not header_and_payload.startswith("VL-"):
            return False, None, "Invalid license prefix"

        sub_parts = header_and_payload.split("-", 2)
        if len(sub_parts) != 3:
            return False, None, "Malformed license key structure"

        tier_str, b64_payload = sub_parts[1], sub_parts[2]

        # Decode base64 payload
        try:
            # Re-add padding
            padding = 4 - (len(b64_payload) % 4)
            if padding != 4:
                b64_payload += "=" * padding
            payload_bytes = base64.urlsafe_b64decode(b64_payload)
            payload_dict = json.loads(payload_bytes.decode("utf-8"))
        except Exception as e:
            return False, None, f"Failed to decode license payload: {e}"

        # Verify HMAC-SHA256 signature
        canonical_bytes = json.dumps(payload_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected_sig = hmac.new(self._signing_key, canonical_bytes, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected_sig, signature):
            return False, None, "Cryptographic license signature verification failed (tampered key)"

        try:
            tier_enum = LicenseTier(payload_dict["tier"])
            features_enum = [FeatureFlag(f) for f in payload_dict.get("features", [])]
            payload = LicensePayload(
                license_id=payload_dict["license_id"],
                tier=tier_enum,
                customer_email=payload_dict.get("customer_email", "unknown"),
                issued_at=payload_dict["issued_at"],
                expires_at=payload_dict.get("expires_at"),
                features=features_enum,
                max_clients=payload_dict.get("max_clients", 1),
                signature=signature,
            )
        except Exception as e:
            return False, None, f"Failed to instantiate license model: {e}"

        # Verify expiration
        if payload.is_expired():
            return False, payload, f"License expired on {time.ctime(payload.expires_at)}"

        return True, payload, "Valid license key"

    def activate_license(self, key_str: str) -> Tuple[bool, str, Optional[LicensePayload]]:
        """Activates and saves a license key string to persistent storage."""
        valid, payload, message = self.verify_license_key(key_str)
        if not valid or not payload:
            return False, message, None

        # Persist to disk
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            storage_data = {
                "raw_key": key_str.strip(),
                "license_id": payload.license_id,
                "tier": payload.tier.value,
                "customer_email": payload.customer_email,
                "activated_at": time.time(),
                "expires_at": payload.expires_at,
            }
            self.license_path.write_text(json.dumps(storage_data, indent=2), encoding="utf-8")
            self._cached_license = payload
            logger.info(f"Successfully activated Veil {payload.tier.value} license for {payload.customer_email}")
            return True, f"Successfully activated {payload.tier.value} plan!", payload
        except Exception as e:
            logger.error(f"Failed to persist activated license: {e}")
            return False, f"Failed to save license to disk: {e}", None

    def clear_license(self) -> None:
        """Removes the persistent license and reverts to the Free tier."""
        if self.license_path.exists():
            try:
                self.license_path.unlink()
            except Exception:
                pass
        self._cached_license = self._generate_default_free_license()

    def get_active_license(self) -> LicensePayload:
        """Returns the currently active license, reloading if expired."""
        if self._cached_license is None or self._cached_license.is_expired():
            return self.reload_license()
        return self._cached_license

    def has_feature(self, feature: FeatureFlag) -> bool:
        """Returns whether the active license permits the specified feature."""
        license_obj = self.get_active_license()
        return license_obj.has_feature(feature)

    def get_max_clients(self) -> int:
        """Returns maximum simultaneous connected clients allowed for active tier."""
        license_obj = self.get_active_license()
        return license_obj.max_clients

    def get_all_plans(self) -> List[PlanDetails]:
        """Returns structured pricing plans for display in the Cockpit UI and CLI."""
        active_tier = self.get_active_license().tier

        return [
            PlanDetails(
                tier=LicenseTier.FREE,
                name="Community / Solo",
                price_usd_monthly=0.0,
                price_ngn_monthly=0,
                features=[
                    "High-speed ReDoS-safe Regex scanner (PII, API keys)",
                    "Shannon Entropy anomaly detection (H >= 4.2)",
                    "1 connected IDE client at a time (e.g. Cursor or Continue)",
                    "Sliding-window SSE stream restoration",
                    "Local Web UI Cockpit & System Tray resident",
                    "Tamper-evident HMAC-SHA256 compliance ledger",
                ],
                max_clients=1,
                is_active=(active_tier == LicenseTier.FREE),
                badge="Community Default",
            ),
            PlanDetails(
                tier=LicenseTier.PRO,
                name="Pro / Team",
                price_usd_monthly=20.0,
                price_ngn_monthly=30000,
                features=[
                    "All Community / Solo features included",
                    "Local ONNX INT8 Quantized Vector Guardrails (Offline ML)",
                    "Corporate Knowledge Vault embedding indexing",
                    "Custom Corporate Dictionary (NDA / Code Name defense)",
                    "Unlimited simultaneous IDE connections (Cursor, Continue, Claude Code, Aider, Antigravity, OpenCode)",
                    "Full CSV/JSON compliance audit export",
                    "Priority security updates",
                ],
                max_clients=999,
                is_active=(active_tier == LicenseTier.PRO),
                badge="Most Popular",
            ),
            PlanDetails(
                tier=LicenseTier.ENTERPRISE,
                name="Enterprise Fleet",
                price_usd_monthly=60.0,
                price_ngn_monthly=90000,
                features=[
                    "All Pro / Team features included",
                    "Pre-packaged Windows MSI installer for silent GPO / Intune fleet deployment",
                    "Centralized fleet policy sync (Coming in V2)",
                    "SIEM log forwarder (Splunk, Microsoft Sentinel, Datadog)",
                    "Dedicated SLA & custom model fine-tuning support",
                    "SOC 2 Type II & NDPA 2023 compliance audit report generation",
                ],
                max_clients=999,
                is_active=(active_tier == LicenseTier.ENTERPRISE),
                badge="Enterprise Ready",
            ),
        ]


# Global singleton instance
license_manager = LicenseManager()
