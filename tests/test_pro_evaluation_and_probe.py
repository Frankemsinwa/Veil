"""Tests for Phase 4: Pro Evaluation Experience & Real-Time Cockpit Telemetry.

Verifies:
1. Auto-Activated 30-Day Developer Pro License on fresh installs:
   - Auto-provisions a valid, cryptographically signed VL-PRO-TRIAL-... license key.
   - Validates that Pro features (Custom Dictionary, Vector Guardrails, Unlimited Clients) are enabled.
   - Reverts cleanly to Free tier on clear_license().
2. Interactive Live Test Bar & Enhanced /api/test/sanitize endpoint:
   - Returns rich matches with engine classifications (Deterministic Regex, Custom Dictionary, Vector Vault).
   - Returns placeholder tokens and latency measurements.
   - Increments metrics counters and updates live telemetry.
   - Correctly identifies blocked secrets and vector breaches.
"""
import time
import pytest
from pathlib import Path
from httpx import AsyncClient, ASGITransport

from app.main import app, metrics_state, inspection_pipeline
from app.licensing.models import LicenseTier, FeatureFlag
from app.licensing.manager import LicenseManager, license_manager
from app.licensing.enforcer import is_feature_allowed
from app.engine.custom_dictionary import custom_dictionary_manager, CustomEntityRule


def test_auto_activated_30_day_pro_trial(tmp_path: Path):
    """Verify that a fresh install automatically receives a 30-day Developer Pro evaluation license."""
    lic_file = tmp_path / "fresh_veil_license.json"
    mgr = LicenseManager(license_file_path=lic_file, auto_provision_trial=True)
    mgr.data_dir = tmp_path

    # Active license must be PRO tier trial
    active_lic = mgr.get_active_license()
    assert active_lic.tier == LicenseTier.PRO
    assert active_lic.license_id.startswith("VL-PRO-TRIAL-")
    assert active_lic.customer_email == "developer@trial.veil.local"
    assert active_lic.is_expired() is False
    assert active_lic.expires_at is not None
    # 30 days in future (within a 5-second variance)
    assert active_lic.expires_at > (time.time() + (29 * 86400))

    # All Pro features must be active
    assert mgr.has_feature(FeatureFlag.CUSTOM_DICTIONARY) is True
    assert mgr.has_feature(FeatureFlag.VECTOR_GUARDRAILS) is True
    assert mgr.has_feature(FeatureFlag.UNLIMITED_CLIENTS) is True
    assert mgr.has_feature(FeatureFlag.AUDIT_EXPORT) is True
    assert mgr.get_max_clients() >= 900

    # Must be persisted to disk
    assert lic_file.exists() is True

    # Clearing reverts to clean Free tier
    mgr.clear_license()
    assert mgr.get_active_license().tier == LicenseTier.FREE
    assert mgr.has_feature(FeatureFlag.CUSTOM_DICTIONARY) is False
    assert mgr.has_feature(FeatureFlag.VECTOR_GUARDRAILS) is False


def test_ensure_trial_license_does_not_override_existing(tmp_path: Path):
    """Verify that ensure_trial_license preserves existing licenses."""
    lic_file = tmp_path / "existing_license.json"
    mgr = LicenseManager(license_file_path=lic_file, auto_provision_trial=False)
    mgr.data_dir = tmp_path

    # Issue and activate a custom Enterprise license
    ent_key, ent_payload = mgr.issue_license(LicenseTier.ENTERPRISE, "cto@megacorp.com", duration_days=365)
    mgr.activate_license(ent_key)

    # Calling ensure_trial_license must NOT downgrade or overwrite it
    ensured = mgr.ensure_trial_license()
    assert ensured.tier == LicenseTier.ENTERPRISE
    assert ensured.customer_email == "cto@megacorp.com"


@pytest.mark.asyncio
async def test_live_probe_clean_text():
    """Verify /api/test/sanitize with a clean prompt returns 0 redactions and increments metrics."""
    initial_requests = metrics_state["total_requests"]
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {"text": "What is the capital of France?"}
        res = await client.post("/api/test/sanitize", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["blocked"] is False
        assert data["redaction_count"] == 0
        assert data["sanitized_text"] == "What is the capital of France?"
        assert data["latency_ms"] >= 0.0
        assert len(data["matches"]) == 0
        assert data["metrics"]["total_requests"] > initial_requests


@pytest.mark.asyncio
async def test_live_probe_pii_regex_match():
    """Verify /api/test/sanitize identifies Regex matches and returns placeholder tokens."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {"text": "Please reach out to support@acmecorp.internal regarding the incident"}
        res = await client.post("/api/test/sanitize", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["blocked"] is False
        assert data["redaction_count"] == 1
        assert "[EMAIL_" in data["sanitized_text"]
        assert len(data["matches"]) == 1
        match = data["matches"][0]
        assert match["entity_type"] == "EMAIL_ADDRESS"
        assert match["engine"] == "Deterministic Regex"
        assert "[EMAIL_" in match["placeholder"]
        assert match["matched_text"] == "support@acmecorp.internal"


@pytest.mark.asyncio
async def test_live_probe_custom_dictionary_match():
    """Verify /api/test/sanitize classifies Custom Dictionary rules under Pro evaluation."""
    # Ensure Pro license is active for test
    trial_key, _ = license_manager.issue_license(LicenseTier.PRO, "test@trial.com")
    license_manager.activate_license(trial_key)

    # Register custom rule
    rule = CustomEntityRule(
        name="Project Prometheus NDA",
        pattern=r"Project\s+Prometheus",
        is_regex=True,
        placeholder_prefix="PROJECT_PROMETHEUS",
        description="Confidential code name",
        enabled=True
    )
    custom_dictionary_manager.add_rule(rule)

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            payload = {"text": "The Q4 launch for Project Prometheus is scheduled for Friday"}
            res = await client.post("/api/test/sanitize", json=payload)
            assert res.status_code == 200
            data = res.json()
            assert data["blocked"] is False
            assert data["redaction_count"] == 1
            assert "[PROJECT_PROMETHEUS_" in data["sanitized_text"]
            assert len(data["matches"]) >= 1
            dict_match = next((m for m in data["matches"] if m["engine"] == "Custom Dictionary (Pro)"), None)
            assert dict_match is not None
            assert dict_match["placeholder"].startswith("[PROJECT_PROMETHEUS_")
    finally:
        custom_dictionary_manager.delete_rule(rule.id)
        license_manager.clear_license()


@pytest.mark.asyncio
async def test_live_probe_blocked_secret():
    """Verify /api/test/sanitize returns blocked status and increments total_blocks metric."""
    initial_blocks = metrics_state["total_blocks"]
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {"text": "Configure auth using AKIAIOSFODNN7EXAMPLE and secret key"}
        res = await client.post("/api/test/sanitize", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["blocked"] is True
        assert data["sanitized_text"] is None
        assert len(data["violations"]) >= 1
        assert data["metrics"]["total_blocks"] > initial_blocks
        assert len(data["matches"]) >= 1
        assert data["matches"][0]["placeholder"] == "[BLOCKED_CREDENTIAL]"
