"""Pytest global configuration and fixtures for Veil test suites."""
import pytest
from app.licensing.manager import license_manager
from app.licensing.models import LicenseTier


@pytest.fixture(autouse=True)
def ensure_pro_license_for_integration_tests():
    """
    Default test execution to a valid Pro tier license so all core privacy
    engines (regex, entropy, custom dict, vector guardrails, semantic classifier)
    are fully exercised in end-to-end integration tests.
    Individual licensing and gating tests explicitly clear and toggle license state.
    """
    key_str, _ = license_manager.issue_license(
        tier=LicenseTier.PRO,
        customer_email="test-suite@veil.local",
        duration_days=365,
    )
    license_manager.activate_license(key_str)
    yield
    license_manager.clear_license()
