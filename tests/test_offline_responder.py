"""Tests for Phase 3: Intelligent Offline & Demo Responder (The Never-Crash Pillar).

Verifies that Veil never crashes or shows a network disconnect screen:
- Returns standard HTTP 403 Forbidden with OpenAI error format on secret / vector blocks.
- Serves OpenAI-compatible mock assistant completion and streaming SSE when offline or using veil-dev-token.
- Serves Anthropic-compatible message response and streaming SSE events when offline.
- Handles legacy /v1/completions endpoint smoothly.
"""
import json
import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.core.config import PolicyLevel, settings


@pytest.mark.asyncio
async def test_standard_http_403_on_secret_block():
    """Verify that credentials blocked by policy return standard HTTP 403 Forbidden."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "Deploy using AWS key AKIAIOSFODNN7EXAMPLE and secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
            ]
        }
        response = await client.post("/v1/chat/completions", json=payload)
        assert response.status_code == 403
        data = response.json()
        assert "error" in data
        assert data["error"]["type"] == "privacy_violation_error"
        assert "🛡️ BLOCKED BY VEIL" in data["error"]["message"]
        assert data["error"]["code"] == "OUTBOUND_SECRET_BLOCKED"
        assert len(data["error"]["details"]) >= 1


@pytest.mark.asyncio
async def test_standard_http_403_on_semantic_vector_block():
    """Verify that contextual trade secrets blocked in STRICT mode return HTTP 403 Forbidden."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        original_policy = settings.POLICY
        settings.POLICY = PolicyLevel.STRICT
        try:
            payload = {
                "model": "gpt-4o",
                "messages": [
                    {"role": "user", "content": "Our unreleased Q3 EBITDA forecast shows $12.5M with 28% gross margin. Do not distribute outside board."}
                ]
            }
            response = await client.post(
                "/v1/chat/completions",
                json=payload,
                headers={"x-session-id": "phase3_semantic_test"}
            )
            assert response.status_code == 403
            data = response.json()
            assert data["error"]["type"] == "privacy_violation_error"
            assert "🛡️ BLOCKED BY VEIL" in data["error"]["message"]
            assert data["error"]["code"] == "OUTBOUND_PROPRIETARY_DATA_BLOCKED"
        finally:
            settings.POLICY = original_policy


@pytest.mark.asyncio
async def test_offline_shield_responder_openai_chat_with_mock_token():
    """Verify non-streaming chat completions with veil-dev-token returns mock shield completion."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "Please contact user at alice.developer@megacorp.com regarding bug"}
            ]
        }
        headers = {"Authorization": "Bearer veil-dev-token"}
        response = await client.post("/v1/chat/completions", json=payload, headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["object"] == "chat.completion"
        assert len(data["choices"]) == 1
        msg = data["choices"][0]["message"]
        assert msg["role"] == "assistant"
        assert "🛡️ **[Veil Privacy Gateway]**" in msg["content"]
        assert "Protected 1 sensitive token(s)" in msg["content"]
        assert "[EMAIL_" in msg["content"]
        assert "usage" in data


@pytest.mark.asyncio
async def test_offline_shield_responder_openai_streaming():
    """Verify streaming chat completions with veil-dev-token streams SSE chunks smoothly."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "model": "gpt-4o",
            "stream": True,
            "messages": [
                {"role": "user", "content": "Tell me about privacy preservation."}
            ]
        }
        headers = {"Authorization": "Bearer veil-dev-token"}
        response = await client.post("/v1/chat/completions", json=payload, headers=headers)
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]

        body_text = response.text
        assert "data: " in body_text
        assert "data: [DONE]" in body_text

        # Parse first chunk
        lines = [line for line in body_text.splitlines() if line.startswith("data: ") and not line.startswith("data: [DONE]")]
        assert len(lines) > 2
        first_chunk = json.loads(lines[0][6:])
        assert first_chunk["object"] == "chat.completion.chunk"
        assert "delta" in first_chunk["choices"][0]


@pytest.mark.asyncio
async def test_offline_shield_responder_anthropic_messages():
    """Verify Anthropic /v1/messages with veil-dev-token returns Anthropic-compatible JSON."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "model": "claude-3-5-sonnet-20241022",
            "messages": [
                {"role": "user", "content": "Please send report to executive@fintech.io immediately."}
            ]
        }
        headers = {"x-api-key": "veil-dev-token"}
        response = await client.post("/v1/messages", json=payload, headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["type"] == "message"
        assert data["role"] == "assistant"
        assert len(data["content"]) == 1
        assert data["content"][0]["type"] == "text"
        assert "🛡️ **[Veil Privacy Gateway — Anthropic Claude Shield]**" in data["content"][0]["text"]
        assert "Protected 1 sensitive token(s)" in data["content"][0]["text"]
        assert data["stop_reason"] == "end_turn"
        assert "usage" in data


@pytest.mark.asyncio
async def test_offline_shield_responder_anthropic_streaming():
    """Verify Anthropic /v1/messages streaming returns valid Anthropic SSE events."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "model": "claude-3-5-sonnet-20241022",
            "stream": True,
            "messages": [
                {"role": "user", "content": "Draft an executive summary."}
            ]
        }
        headers = {"x-api-key": "veil-dev-token"}
        response = await client.post("/v1/messages", json=payload, headers=headers)
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]

        body_text = response.text
        assert "event: message_start" in body_text
        assert "event: content_block_start" in body_text
        assert "event: content_block_delta" in body_text
        assert "event: content_block_stop" in body_text
        assert "event: message_delta" in body_text
        assert "event: message_stop" in body_text


@pytest.mark.asyncio
async def test_legacy_completions_endpoint():
    """Verify legacy /v1/completions endpoint works cleanly in offline mode."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "model": "gpt-3.5-turbo-instruct",
            "prompt": "Summarize user history for contact john.doe@cyberdyne.systems"
        }
        headers = {"Authorization": "Bearer veil-dev-token"}
        response = await client.post("/v1/completions", json=payload, headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["object"] == "text_completion"
        assert len(data["choices"]) == 1
        assert "🛡️ [Veil Privacy Gateway]" in data["choices"][0]["text"]
        assert "Protected 1 sensitive token(s)" in data["choices"][0]["text"]


@pytest.mark.asyncio
async def test_clean_prompt_offline_shield_message():
    """Verify clean prompts show zero confidential leaks detected in shield message."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "def calculate_fibonacci(n: int) -> int: pass"}
            ]
        }
        headers = {"Authorization": "Bearer veil-dev-token"}
        response = await client.post("/v1/chat/completions", json=payload, headers=headers)
        assert response.status_code == 200
        data = response.json()
        text = data["choices"][0]["message"]["content"]
        assert "Zero confidential leaks detected" in text
