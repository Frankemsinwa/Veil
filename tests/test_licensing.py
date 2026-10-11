"""Unit and cryptographic integrity tests for Veil Licensing Engine."""
import time
import pytest
from pathlib import Path
from app.licensing.models import LicenseTier, FeatureFlag, LicensePayload
from app.licensing.manager import LicenseManager


@pytest.fixture
def temp_license_manager(tmp_path):
    """Provides an isolated LicenseManager instance using a temporary directory."""
    lic_file = tmp_path / "test_license.json"
    mgr = LicenseManager(license_file_path=lic_file)
    mgr.data_dir = tmp_path
    return mgr


def test_default_free_license(temp_license_manager):
    """Verify that by default, the license manager issues a clean Free Community license."""
    lic = temp_license_manager.get_active_license()
    assert lic.tier == LicenseTier.FREE
    assert lic.is_expired() is False
    assert lic.max_clients == 1
    assert temp_license_manager.has_feature(FeatureFlag.BASIC_REGEX) is True
    assert temp_license_manager.has_feature(FeatureFlag.SHANNON_ENTROPY) is True
    assert temp_license_manager.has_feature(FeatureFlag.VECTOR_GUARDRAILS) is False
    assert temp_license_manager.has_feature(FeatureFlag.CUSTOM_DICTIONARY) is False


def test_issue_and_verify_pro_license(temp_license_manager):
    """Verify cryptographic signing and verification of a Pro license key."""
    key_str, payload = temp_license_manager.issue_license(
        tier=LicenseTier.PRO,
        customer_email="alice@company.com",
        duration_days=30,
    )

    assert key_str.startswith("VL-PRO-")
    assert "." in key_str
    assert payload.tier == LicenseTier.PRO
    assert payload.customer_email == "alice@company.com"

    # Verify the issued key
    valid, verified_payload, msg = temp_license_manager.verify_license_key(key_str)
    assert valid is True
    assert verified_payload is not None
    assert verified_payload.license_id == payload.license_id
    assert verified_payload.tier == LicenseTier.PRO
    assert FeatureFlag.VECTOR_GUARDRAILS in verified_payload.features
    assert FeatureFlag.CUSTOM_DICTIONARY in verified_payload.features


def test_tampered_license_rejection(temp_license_manager):
    """Ensure that modifying any part of the payload or signature fails cryptographic verification."""
    key_str, _ = temp_license_manager.issue_license(
        tier=LicenseTier.PRO,
        customer_email="bob@company.com",
        duration_days=30,
    )

    body, sig = key_str.split(".")
    # Tamper with the signature
    tampered_sig = "a" * len(sig)
    tampered_key = f"{body}.{tampered_sig}"

    valid, payload, err = temp_license_manager.verify_license_key(tampered_key)
    assert valid is False
    assert payload is None
    assert "verification failed" in err.lower()


def test_expired_license_detection(temp_license_manager):
    """Verify that expired licenses are identified and rejected."""
    # Issue a license with negative duration (already expired)
    key_str, payload = temp_license_manager.issue_license(
        tier=LicenseTier.PRO,
        customer_email="expired@company.com",
        duration_days=-1,
    )

    valid, verified_payload, err = temp_license_manager.verify_license_key(key_str)
    assert valid is False
    assert "expired" in err.lower()


def test_activate_and_persist_license(temp_license_manager):
    """Verify license activation and reloading from disk."""
    key_str, payload = temp_license_manager.issue_license(
        tier=LicenseTier.PRO,
        customer_email="carol@firm.com",
        duration_days=60,
    )

    success, msg, act_payload = temp_license_manager.activate_license(key_str)
    assert success is True
    assert act_payload.tier == LicenseTier.PRO
    assert temp_license_manager.license_path.exists()

    # Re-instantiate manager to simulate restart
    new_mgr = LicenseManager(license_file_path=temp_license_manager.license_path)
    loaded_lic = new_mgr.get_active_license()
    assert loaded_lic.tier == LicenseTier.PRO
    assert loaded_lic.customer_email == "carol@firm.com"
    assert new_mgr.has_feature(FeatureFlag.VECTOR_GUARDRAILS) is True

    # Clear license reverts to Free
    new_mgr.clear_license()
    cleared_lic = new_mgr.get_active_license()
    assert cleared_lic.tier == LicenseTier.FREE
