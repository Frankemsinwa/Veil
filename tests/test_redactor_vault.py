"""Tests for Phase 6 & 7: Reversible Redactor, Ephemeral Vault, and End-to-End Gateway Inspection."""
import json
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app, openai_adapter
from app.vault.crypto import VaultCrypto
from app.vault.session_vault import SessionVault, VaultManager
from app.engine.pipeline import InspectionPipeline
from app.engine.redactor import Redactor
from app.restoration.restorer import ResponseRestorer


def test_vault_crypto_aes_gcm():
    crypto = VaultCrypto()
    secret_text = "super_confidential_token_12345"
    nonce, ciphertext = crypto.encrypt(secret_text)
    assert ciphertext != secret_text.encode("utf-8")

    decrypted = crypto.decrypt(nonce, ciphertext)
    assert decrypted == secret_text


def test_session_vault_consistent_placeholders():
    vault = SessionVault(session_id="test_sess_01")
    email = "ceo@corporation.com"
    p1 = vault.get_or_create_placeholder("EMAIL_ADDRESS", email)
    assert p1 == "[EMAIL_001]"

    # Second call with identical email must return the identical placeholder
    p2 = vault.get_or_create_placeholder("EMAIL_ADDRESS", email)
    assert p2 == "[EMAIL_001]"

    # Restoration must return the original
    assert vault.restore_placeholder("[EMAIL_001]") == email

    # Memory zeroization
    vault.zeroize()
    assert vault.restore_placeholder("[EMAIL_001]") is None


def test_redactor_and_restorer_roundtrip():
    pipeline = InspectionPipeline()
    vault = SessionVault(session_id="test_roundtrip")
    redactor = Redactor()
    restorer = ResponseRestorer()

    original_prompt = "Send the quarterly numbers to CFO Alice at alice@finance.corp or call +1-555-902-1829 immediately."
    _, spans = pipeline.inspect(original_prompt)

    redacted_text, count = redactor.redact_text(original_prompt, spans, vault)
    assert count >= 2
    assert "alice@finance.corp" not in redacted_text
    assert "+1-555-902-1829" not in redacted_text
    assert "[EMAIL_001]" in redacted_text

    # Restoration
    restored_text = restorer.restore_text(redacted_text, vault)
    assert restored_text == original_prompt


@pytest.mark.asyncio
async def test_gateway_blocks_secret_inbound(monkeypatch):
    """End-to-end test: gateway must reject a request containing an OpenAI key with HTTP 422."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "Deploy using sk-proj-1234567890abcdef1234567890abcdef12 please"}
            ]
        }
        response = await client.post("/v1/chat/completions", json=payload)
        assert response.status_code == 422
        data = response.json()
        assert data["error"]["code"] == "OUTBOUND_SECRET_BLOCKED"


@pytest.mark.asyncio
async def test_gateway_redacts_pii_outbound_and_restores_inbound(monkeypatch):
    """End-to-end test: outbound request sent to LLM has placeholders, returned response restores them."""
    captured_payload = {}

    async def mock_forward_request(endpoint, headers, payload):
        nonlocal captured_payload
        captured_payload = payload
        # Simulate LLM repeating the placeholder back in its answer
        simulated_assistant_reply = {
            "id": "chatcmpl-mock",
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": f"Confirmed! I have scheduled an email to {payload['messages'][0]['content'].split()[-1]}."
                }
            }]
        }
        return 200, {"content-type": "application/json"}, json.dumps(simulated_assistant_reply).encode("utf-8")

    monkeypatch.setattr(openai_adapter, "forward_request", mock_forward_request)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "Send report to frank@enterprise.com"}
            ],
            "stream": False
        }
        response = await client.post("/v1/chat/completions", json=payload)
        assert response.status_code == 200

        # Verify what was sent upstream to the LLM was sanitized!
        upstream_sent_content = captured_payload["messages"][0]["content"]
        assert "frank@enterprise.com" not in upstream_sent_content
        assert "[EMAIL_001]" in upstream_sent_content

        # Verify what was returned to the client user was seamlessly restored!
        client_response_data = response.json()
        restored_answer = client_response_data["choices"][0]["message"]["content"]
        assert "frank@enterprise.com" in restored_answer
        assert "[EMAIL_001]" not in restored_answer
