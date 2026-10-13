"""Tests for Phase 18: Multi-Provider Ingress (Anthropic /v1/messages & Ollama)."""
import json
import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch

from app.main import app, anthropic_adapter, ollama_adapter
from app.vault.session_vault import vault_manager
from app.restoration.restorer import ResponseRestorer


@pytest.mark.asyncio
async def test_anthropic_messages_blocks_credentials():
    """Verify fail-closed credential blocking on /v1/messages."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 1024,
            "messages": [
                {
                    "role": "user",
                    "content": "Deploy using AWS key: AKIAIOSFODNN7EXAMPLE and secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                }
            ]
        }
        resp = await client.post("/v1/messages", json=payload)
        assert resp.status_code in (403, 422)
        err = resp.json()
        assert err["error"]["code"] == "OUTBOUND_SECRET_BLOCKED"


@pytest.mark.asyncio
async def test_anthropic_messages_redacts_and_restores():
    """Verify inbound PII redaction and outbound response restoration for Anthropic."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Mock upstream Anthropic response returning placeholder
        mock_response = {
            "id": "msg_01X9y",
            "type": "message",
            "role": "assistant",
            "model": "claude-3-5-sonnet-20241022",
            "content": [
                {"type": "text", "text": "Contacting [EMAIL_001] right away."}
            ]
        }
        mock_forward = AsyncMock(return_value=(200, {"content-type": "application/json"}, json.dumps(mock_response).encode("utf-8")))

        with patch.object(anthropic_adapter, "forward_request", mock_forward):
            payload = {
                "model": "claude-3-5-sonnet-20241022",
                "max_tokens": 512,
                "system": "System instructions for claude",
                "messages": [
                    {"role": "user", "content": "Please send report to security@megacorp.internal"}
                ]
            }
            resp = await client.post("/v1/messages", json=payload, headers={"x-session-id": "anthropic_test_sess"})
            assert resp.status_code == 200

            # Verify forward_request received the sanitized prompt (no plaintext email)
            called_payload = mock_forward.call_args[1]["payload"]
            assert "security@megacorp.internal" not in called_payload["messages"][0]["content"]
            assert "[EMAIL_" in called_payload["messages"][0]["content"]

            # Verify response was restored with the original email
            resp_data = resp.json()
            assert "Contacting security@megacorp.internal right away." in resp_data["content"][0]["text"]


@pytest.mark.asyncio
async def test_ollama_generate_blocks_secrets():
    """Verify fail-closed secret blocking on Ollama /api/generate."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "model": "llama3",
            "prompt": "AWS secret: AKIAIOSFODNN7EXAMPLE",
            "stream": False
        }
        resp = await client.post("/api/generate", json=payload)
        assert resp.status_code in (403, 422)


@pytest.mark.asyncio
async def test_ollama_chat_redacts_and_restores():
    """Verify inbound PII redaction and outbound response restoration for Ollama /api/chat."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        mock_response = {
            "model": "llama3",
            "message": {"role": "assistant", "content": "Acknowledged [EMAIL_001]."},
            "done": True
        }
        mock_forward = AsyncMock(return_value=(200, {"content-type": "application/json"}, json.dumps(mock_response).encode("utf-8")))

        with patch.object(ollama_adapter, "forward_request", mock_forward):
            payload = {
                "model": "llama3",
                "messages": [{"role": "user", "content": "Email me at dev@internal.net"}],
                "stream": False
            }
            resp = await client.post("/api/chat", json=payload, headers={"x-session-id": "ollama_test_sess"})
            assert resp.status_code == 200

            # Upstream received redacted token
            called_payload = mock_forward.call_args[1]["payload"]
            assert "dev@internal.net" not in called_payload["messages"][0]["content"]
            assert "[EMAIL_" in called_payload["messages"][0]["content"]

            # Client received restored content
            resp_data = resp.json()
            assert "Acknowledged dev@internal.net." in resp_data["message"]["content"]


@pytest.mark.asyncio
async def test_anthropic_sse_stream_restorer():
    """Verify streaming token reconstruction for Anthropic SSE events."""
    restorer = ResponseRestorer()
    vault = vault_manager.get_session("stream_anthropic_test")
    placeholder = vault.get_or_create_placeholder("EMAIL", "lead.architect@company.com")

    # Simulate split placeholder across SSE events: "[EMA" then "IL_001]"
    async def mock_stream():
        yield f'event: content_block_delta\ndata: {{"type": "content_block_delta", "index": 0, "delta": {{"type": "text_delta", "text": "Contact {placeholder[:4]}"}}}}\n\n'.encode("utf-8")
        yield f'event: content_block_delta\ndata: {{"type": "content_block_delta", "index": 0, "delta": {{"type": "text_delta", "text": "{placeholder[4:]} now."}}}}\n\n'.encode("utf-8")
        yield b'event: message_stop\ndata: {"type": "message_stop"}\n\n'

    restored_chunks = []
    async for chunk in restorer.restore_anthropic_sse_stream(mock_stream(), vault):
        restored_chunks.append(chunk.decode("utf-8"))

    combined = "".join(restored_chunks)
    assert "lead.architect@company.com" in combined
    assert placeholder not in combined


@pytest.mark.asyncio
async def test_ollama_ndjson_stream_restorer():
    """Verify streaming token reconstruction for Ollama newline-delimited JSON."""
    restorer = ResponseRestorer()
    vault = vault_manager.get_session("stream_ollama_test")
    placeholder = vault.get_or_create_placeholder("EMAIL", "support@cloud.io")

    async def mock_stream():
        chunk1 = json.dumps({"model": "llama3", "message": {"content": f"Hello {placeholder[:4]}"}, "done": False}) + "\n"
        chunk2 = json.dumps({"model": "llama3", "message": {"content": f"{placeholder[4:]}!"}, "done": True}) + "\n"
        yield chunk1.encode("utf-8")
        yield chunk2.encode("utf-8")

    restored_chunks = []
    async for chunk in restorer.restore_ollama_stream(mock_stream(), vault):
        restored_chunks.append(chunk.decode("utf-8"))

    combined = "".join(restored_chunks)
    assert "support@cloud.io" in combined
    assert placeholder not in combined
