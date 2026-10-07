"""Tests for Phase 4 & 5: Regex, Entropy, AST Whitelisting, and Policy Enforcement."""
import pytest
from app.engine.pipeline import InspectionPipeline
from app.engine.regex_scanner import RegexScanner, luhn_checksum_valid
from app.engine.entropy_scanner import calculate_shannon_entropy, EntropyScanner
from app.engine.ast_filter import AstFilter, is_rfc_mock_email, is_safe_test_ip
from app.engine.models import EntityType, EntityCategory
from app.core.exceptions import SecretDetectedException


def test_luhn_algorithm():
    # Valid test card (Visa sample)
    assert luhn_checksum_valid("4532015112830366") is True
    # Invalid card
    assert luhn_checksum_valid("4532015112830367") is False


def test_shannon_entropy():
    # Low entropy (repetitive)
    low_entropy = calculate_shannon_entropy("aaaaaaaaaaaaaaaaaaaa")
    assert low_entropy == 0.0

    # High entropy (random key-like string)
    high_entropy = calculate_shannon_entropy("7K9#mQx!vL2$pWz&tR5*")
    assert high_entropy > 4.0


def test_rfc_whitelists():
    assert is_rfc_mock_email("john.doe@example.com") is True
    assert is_rfc_mock_email("real_user@gmail.com") is False
    assert is_safe_test_ip("127.0.0.1") is True
    assert is_safe_test_ip("192.0.2.1") is True
    assert is_safe_test_ip("8.8.8.8") is False


def test_secret_detection_blocks_prompt():
    pipeline = InspectionPipeline()
    # Prompt containing an OpenAI secret key
    leak_prompt = "Here is my key: sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_SECRETKEY"

    with pytest.raises(SecretDetectedException) as exc_info:
        pipeline.inspect(leak_prompt)

    err = exc_info.value.to_dict()
    assert err["error"]["code"] == "OUTBOUND_SECRET_BLOCKED"
    violations = err["error"]["details"]
    assert any(v["entity_type"] == "OPENAI_API_KEY" for v in violations)


def test_entropy_scanner_detects_unclassified_secret():
    pipeline = InspectionPipeline()
    # High entropy arbitrary password/secret
    prompt_with_secret = 'db_password = "K9#xL2$vWz&tR5*pQ1!mZ8^b"'

    with pytest.raises(SecretDetectedException) as exc_info:
        pipeline.inspect(prompt_with_secret)

    err = exc_info.value.to_dict()
    assert err["error"]["code"] == "OUTBOUND_SECRET_BLOCKED"
    violations = err["error"]["details"]
    assert any(v["entity_type"] == "GENERIC_SECRET_ENTROPY" for v in violations)


def test_pii_marked_for_redaction():
    pipeline = InspectionPipeline()
    # Prompt with personal email and phone
    clean_prompt = "Contact Sarah at sarah.connor@cyberdyne.net or call +1-555-837-2918"

    decisions, redact_spans = pipeline.inspect(clean_prompt)
    assert len(redact_spans) >= 2
    types = {s.entity_type for s in redact_spans}
    assert EntityType.EMAIL_ADDRESS in types
    assert EntityType.PHONE_NUMBER in types


def test_rfc_mock_data_allowed_through():
    pipeline = InspectionPipeline()
    # Mock data inside code example
    mock_prompt = "In tests, connect to user@example.com at host 127.0.0.1"

    decisions, redact_spans = pipeline.inspect(mock_prompt)
    # Whitelisted items are not marked for redaction
    assert len(redact_spans) == 0
    assert all(d.action.value == "ALLOW" for d in decisions)
