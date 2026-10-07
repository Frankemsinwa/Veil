"""Tests for Phase 8 & 9: Stream Restoration Buffer and Tamper-Evident Audit Ledger."""
import json
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app, openai_adapter
from app.restoration.buffer import StreamBuffer
from app.audit.ledger import AuditLedger
from app.vault.session_vault import SessionVault


def test_stream_buffer_reconstructs_split_tokens():
    vault = SessionVault(session_id="test_stream_split")
    email = "ceo@enterprise.com"
    placeholder = vault.get_or_create_placeholder("EMAIL_ADDRESS", email)
    assert placeholder == "[EMAIL_001]"

    buffer = StreamBuffer(restore_func=vault.restore_placeholder)

    # Simulate chunk deltas splitting the placeholder across 3 chunks:
    # chunk 1: "The recipient is [EM"
    # chunk 2: "AIL_"
    # chunk 3: "001]. Please confirm."
    chunk1_out = buffer.process_chunk("The recipient is [EM")
    assert chunk1_out == "The recipient is "  # Held back '[EM' in accumulator

    chunk2_out = buffer.process_chunk("AIL_")
    assert chunk2_out == ""  # Still incomplete, held back

    chunk3_out = buffer.process_chunk("001]. Please confirm.")
    # Now completed! Must output the decrypted original email + rest of sentence
    assert chunk3_out == f"{email}. Please confirm."


def test_stream_buffer_handles_false_brackets():
    buffer = StreamBuffer(restore_func=lambda x: None)

    # Markdown links like "[GitHub](https://github.com)"
    out = buffer.process_chunk("Check out [GitHub](https://github.com)")
    assert out == "Check out [GitHub](https://github.com)"


def test_audit_ledger_integrity_and_tamper_detection(tmp_path):
    db_file = tmp_path / "test_audit.db"
    ledger = AuditLedger(db_path=db_file)

    # Insert 3 receipts
    ledger.record_receipt(
        session_id="sess_1", provider="openai", model="gpt-4o",
        policy="STRICT", action_taken="ALLOWED_CLEAN",
        redaction_count=0, secret_blocked_count=0,
        entities_detected=[], latency_ms=12.5
    )
    ledger.record_receipt(
        session_id="sess_2", provider="openai", model="gpt-4o",
        policy="STRICT", action_taken="ALLOWED_REDACTED",
        redaction_count=2, secret_blocked_count=0,
        entities_detected=["EMAIL_ADDRESS"], latency_ms=24.1
    )
    ledger.record_receipt(
        session_id="sess_3", provider="openai", model="gpt-4o",
        policy="STRICT", action_taken="BLOCKED",
        redaction_count=0, secret_blocked_count=1,
        entities_detected=["OPENAI_API_KEY"], latency_ms=8.0
    )

    # Verify integrity passes
    is_valid, count, err = ledger.verify_integrity()
    assert is_valid is True
    assert count == 3
    assert err is None

    # Simulate malicious tampering: corrupt record #2 action in SQLite
    with ledger._get_connection() as conn:
        conn.execute("UPDATE audit_receipts SET action_taken = 'FORGED' WHERE id = 2")
        conn.commit()

    # Integrity verification must catch the tamper!
    tamper_valid, bad_id, tamper_err = ledger.verify_integrity()
    assert tamper_valid is False
    assert bad_id == 2
    assert "HMAC signature mismatch" in tamper_err


@pytest.mark.asyncio
async def test_end_to_end_streaming_restoration(monkeypatch):
    """Verify that proxy's SSE stream restores chunked placeholders in real-time."""
    async def mock_forward_stream(endpoint, headers, payload):
        yield b'data: {"choices":[{"delta":{"content":"Send it to [EM"}}]}\n\n'
        yield b'data: {"choices":[{"delta":{"content":"AIL_"}}]}\n\n'
        yield b'data: {"choices":[{"delta":{"content":"001] asap"}}]}\n\n'
        yield b'data: [DONE]\n\n'

    monkeypatch.setattr(openai_adapter, "forward_stream", mock_forward_stream)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "Send notification to alice@corp.com"}
            ],
            "stream": True
        }
        headers = {"x-session-id": "test_streaming_session"}
        response = await client.post("/v1/chat/completions", json=payload, headers=headers)
        assert response.status_code == 200
        text = response.text
        # Must restore alice@corp.com across the stream chunks
        assert "alice@corp.com" in text
