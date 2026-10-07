"""Unit and integration tests for Veil Gateway Phase 2 & 3."""
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.config import settings, PolicyLevel


@pytest.mark.asyncio
async def test_health_check_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "HEALTHY"
        assert data["service"] == "Veil Privacy Gateway"
        assert data["policy"] == PolicyLevel.STRICT.value
        assert data["fail_closed"] is True


@pytest.mark.asyncio
async def test_openai_pass_through_mock(monkeypatch):
    """Verify that /v1/chat/completions accepts OpenAI request and forwards correctly."""
    from app.main import openai_adapter

    # Mock the adapter's forward_request method
    async def mock_forward_request(endpoint, headers, payload):
        return 200, {"content-type": "application/json"}, b'{"id":"mock-123","choices":[{"message":{"role":"assistant","content":"Mocked safe response"}}]}'

    monkeypatch.setattr(openai_adapter, "forward_request", mock_forward_request)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "Hello world!"}
            ],
            "stream": False
        }
        response = await client.post("/v1/chat/completions", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "mock-123"
        assert data["choices"][0]["message"]["content"] == "Mocked safe response"


@pytest.mark.asyncio
async def test_openai_stream_pass_through_mock(monkeypatch):
    """Verify that streaming requests flow through SSE properly."""
    from app.main import openai_adapter

    async def mock_forward_stream(endpoint, headers, payload):
        yield b'data: {"choices":[{"delta":{"content":"Hello"}}]}\n\n'
        yield b'data: {"choices":[{"delta":{"content":" world" comma}}\n\n'
        yield b'data: [DONE]\n\n'

    monkeypatch.setattr(openai_adapter, "forward_stream", mock_forward_stream)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "Stream me a response"}
            ],
            "stream": True
        }
        response = await client.post("/v1/chat/completions", json=payload)
        assert response.status_code == 200
        assert "text/event-stream" in response.headers.get("content-type", "")
        content = response.text
        assert "data: [DONE]" in content
