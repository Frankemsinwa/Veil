"""Veil Licensing & Feature Gating System."""
from app.licensing.models import LicenseTier, FeatureFlag, LicensePayload
from app.licensing.manager import license_manager
from app.licensing.enforcer import is_feature_allowed, check_client_connection_limit

__all__ = [
    "LicenseTier",
    "FeatureFlag",
    "LicensePayload",
    "license_manager",
    "is_feature_allowed",
    "check_client_connection_limit",
]
