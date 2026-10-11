"""Tests for feature gating based on active commercial license tiers."""
import pytest
from unittest.mock import patch, MagicMock
from app.licensing.models import LicenseTier, FeatureFlag
from app.licensing.manager import license_manager
from app.licensing.enforcer import is_feature_allowed, check_client_connection_limit
from app.engine.pipeline import InspectionPipeline
from app.clients.manager import ClientManager
from app.clients.base import BaseClientAdapter, ClientInfo, ClientStatus, MutationResult


def test_feature_allowed_checks():
    """Verify is_feature_allowed reflects active license entitlements."""
    # When Free:
    license_manager.clear_license()
    assert is_feature_allowed(FeatureFlag.BASIC_REGEX) is True
    assert is_feature_allowed(FeatureFlag.SHANNON_ENTROPY) is True
    assert is_feature_allowed(FeatureFlag.VECTOR_GUARDRAILS) is False
    assert is_feature_allowed(FeatureFlag.CUSTOM_DICTIONARY) is False
    assert is_feature_allowed(FeatureFlag.UNLIMITED_CLIENTS) is False

    # Issue and activate Pro key:
    pro_key, _ = license_manager.issue_license(LicenseTier.PRO, "tester@pro.com")
    license_manager.activate_license(pro_key)
    try:
        assert is_feature_allowed(FeatureFlag.VECTOR_GUARDRAILS) is True
        assert is_feature_allowed(FeatureFlag.CUSTOM_DICTIONARY) is True
        assert is_feature_allowed(FeatureFlag.UNLIMITED_CLIENTS) is True
    finally:
        license_manager.clear_license()


def test_client_connection_limit_free_vs_pro():
    """Verify Free tier restricts connected clients to 1, while Pro unlocks unlimited."""
    license_manager.clear_license()

    # Free tier limit check (0 connected -> allowed)
    allowed, msg = check_client_connection_limit(current_connected_count=0, connecting_client_id="cursor")
    assert allowed is True

    # Free tier limit check (1 connected -> blocked)
    allowed, msg = check_client_connection_limit(current_connected_count=1, connecting_client_id="continue")
    assert allowed is False
    assert "upgrade to pro" in msg.lower()

    # Pro tier unlocks unlimited connections
    pro_key, _ = license_manager.issue_license(LicenseTier.PRO, "dev@team.com")
    license_manager.activate_license(pro_key)
    try:
        allowed, msg = check_client_connection_limit(current_connected_count=1, connecting_client_id="continue")
        assert allowed is True
        allowed, msg = check_client_connection_limit(current_connected_count=5, connecting_client_id="claude_code")
        assert allowed is True
    finally:
        license_manager.clear_license()


def test_pipeline_gating_free_skips_vector():
    """Verify that under Free license, pipeline does not execute vector guardrails."""
    license_manager.clear_license()
    pipeline = InspectionPipeline()

    with patch.object(pipeline, "_scan_vector_guardrails") as mock_vec_scan:
        pipeline.inspect_semantic("Hello world clean prompt")
        # Should NOT call vector guardrails because user is on Free tier
        mock_vec_scan.assert_not_called()

    # When upgraded to Pro:
    pro_key, _ = license_manager.issue_license(LicenseTier.PRO, "pro@corp.com")
    license_manager.activate_license(pro_key)
    try:
        with patch.object(pipeline, "_scan_vector_guardrails", return_value=[]) as mock_vec_scan:
            pipeline.inspect_semantic("Hello world clean prompt")
            mock_vec_scan.assert_called_once()
    finally:
        license_manager.clear_license()
