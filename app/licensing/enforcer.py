"""Runtime feature gating and license entitlement enforcement helpers."""
import logging
from typing import Tuple

from app.licensing.models import FeatureFlag, LicenseTier
from app.licensing.manager import license_manager

logger = logging.getLogger(__name__)


class LicenseRestrictionException(Exception):
    """Raised when an operation is disallowed by the active license tier."""
    def __init__(self, message: str, required_tier: LicenseTier = LicenseTier.PRO):
        super().__init__(message)
        self.message = message
        self.required_tier = required_tier


def is_feature_allowed(feature: FeatureFlag) -> bool:
    """Checks whether the specified feature is entitled under the active license."""
    return license_manager.has_feature(feature)


def check_client_connection_limit(
    current_connected_count: int,
    connecting_client_id: str
) -> Tuple[bool, str]:
    """
    Enforces simultaneous client connection limits.
    Free tier allows 1 client connected at a time.
    Pro and Enterprise allow unlimited simultaneous connections.
    """
    max_allowed = license_manager.get_max_clients()
    active_license = license_manager.get_active_license()

    if current_connected_count >= max_allowed:
        return (
            False,
            f"The Community/Free tier permits a maximum of {max_allowed} active client connection at a time. "
            f"Please disconnect an existing client or upgrade to Pro to connect '{connecting_client_id}' simultaneously."
        )

    return True, "Connection permitted by license entitlement."
