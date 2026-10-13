"""Tests for Phase 13: Real-Time Event Bus & Live Telemetry WebSocket / REST Control API."""
import pytest
from httpx import AsyncClient, ASGITransport
from starlette.testclient import TestClient

from app.main import app, metrics_state
from app.core.config import settings, PolicyLevel
from app.core.events import PrivacyEventBus, privacy_event_bus


@pytest.mark.asyncio
async def test_event_bus_lifecycle():
    bus = PrivacyEventBus(history_size=5)
    queue = await bus.subscribe()

    await bus.publish("test_event", {"message": "hello veil"})
    received = await queue.get()

    assert received["type"] == "test_event"
    assert received["data"]["message"] == "hello veil"
    assert "timestamp" in received

    history = bus.get_recent_history()
    assert len(history) == 1
    assert history[0]["type"] == "test_event"

    await bus.unsubscribe(queue)


@pytest.mark.asyncio
async def test_get_clients_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/clients")
        assert response.status_code == 200
        clients = response.json()
        assert isinstance(clients, list)
        client_ids = {c["id"] for c in clients}
        assert "cursor" in client_ids
        assert "system_env" in client_ids


@pytest.mark.asyncio
async def test_client_connect_and_disconnect_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Connect system_env
        conn_resp = await client.post("/api/clients/system_env/connect")
        assert conn_resp.status_code == 200
        conn_data = conn_resp.json()
        assert conn_data["client_id"] == "system_env"
        assert conn_data["success"] is True

        # Disconnect system_env
        disc_resp = await client.post("/api/clients/system_env/disconnect")
        assert disc_resp.status_code == 200
        disc_data = disc_resp.json()
        assert disc_data["client_id"] == "system_env"
        assert disc_data["success"] is True


@pytest.mark.asyncio
async def test_gateway_metrics_and_policy_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Get metrics
        resp = await client.get("/api/metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert "metrics" in data
        assert "policy" in data

        # Change policy
        pol_resp = await client.post("/api/gateway/policy", json={"policy": "BALANCED"})
        assert pol_resp.status_code == 200
        assert pol_resp.json()["policy"] == "BALANCED"
        assert settings.POLICY == PolicyLevel.BALANCED

        # Restore to STRICT
        await client.post("/api/gateway/policy", json={"policy": "STRICT"})
        assert settings.POLICY == PolicyLevel.STRICT


@pytest.mark.asyncio
async def test_gateway_toggle_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Toggle pause
        resp1 = await client.post("/api/gateway/toggle")
        assert resp1.status_code == 200
        assert resp1.json()["is_paused"] is True

        # Toggle unpause
        resp2 = await client.post("/api/gateway/toggle")
        assert resp2.status_code == 200
        assert resp2.json()["is_paused"] is False


def test_websocket_telemetry_stream():
    client = TestClient(app)
    with client.websocket_connect("/ws/telemetry") as websocket:
        # Initial snapshot
        init_data = websocket.receive_json()
        assert init_data["type"] == "init"
        assert "clients" in init_data["data"]
        assert "metrics" in init_data["data"]

        # Publish event and verify receipt
        privacy_event_bus.publish_sync("telemetry_ping", {"ping": "pong"})
        event = websocket.receive_json()
        assert event["type"] == "telemetry_ping"
        assert event["data"]["ping"] == "pong"


@pytest.mark.asyncio
async def test_blocked_prompt_increments_metrics_and_emits_event():
    initial_blocks = metrics_state["total_blocks"]
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "My key is sk-proj-1234567890abcdef1234567890abcdef1234567890"}
            ]
        }
        resp = await client.post("/v1/chat/completions", json=payload)
        assert resp.status_code in (403, 422)
        assert metrics_state["total_blocks"] == initial_blocks + 1
