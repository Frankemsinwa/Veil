"""Tests for Cockpit UI Semantic Guardrails & Knowledge Vector Vault (Phase 4)."""
import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app


@pytest.mark.asyncio
async def test_vector_vault_html_components_rendered():
    """Verify that cockpit HTML includes the Semantic Vault navigation and view elements."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/")
        assert response.status_code == 200
        html = response.text
        
        # Navigation & Topbar
        assert 'id="nav-vector-vault"' in html
        assert 'id="vector-health-pill"' in html
        assert 'id="nav-vectors-count"' in html
        
        # View Section
        assert 'id="view-vector-vault"' in html
        assert 'id="form-add-vector"' in html
        assert 'id="vector-input-title"' in html
        assert 'id="vector-input-threshold"' in html
        assert 'id="vector-live-test-input"' in html
        assert 'id="btn-test-vector-sim"' in html
        assert 'id="vector-rules-list"' in html


@pytest.mark.asyncio
async def test_vector_vault_cockpit_lifecycle():
    """Verify complete CRUD & similarity test workflow through Cockpit endpoints."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Fetch initial vault state
        res_list = await client.get("/api/knowledge-vault")
        assert res_list.status_code == 200
        data = res_list.json()
        assert data["stats"]["vector_dimensions"] == 384
        assert data["stats"]["is_onnx_active"] is True

        # 2. Add confidential entry
        res_create = await client.post("/api/knowledge-vault/entry", json={
            "title": "Cockpit Test IP Key",
            "text": "Internal supercomputer cluster authentication secret token 99482-XZ",
            "category": "INFRASTRUCTURE",
            "action": "BLOCK",
            "threshold_override": 0.60
        })
        assert res_create.status_code == 200
        entry_id = res_create.json()["entry"]["id"]

        try:
            # 3. Test interactive similarity endpoint
            res_sim = await client.post("/api/knowledge-vault/test-similarity", json={
                "text": "The supercomputer cluster authentication secret token is needed",
                "top_k": 3
            })
            assert res_sim.status_code == 200
            sim_data = res_sim.json()
            assert len(sim_data["matches"]) >= 1
            assert sim_data["search_latency_ms"] < 150.0

            # 4. Toggle entry status
            res_toggle = await client.post(f"/api/knowledge-vault/{entry_id}/toggle")
            assert res_toggle.status_code == 200
            assert res_toggle.json()["entry"]["enabled"] is False

        finally:
            # 5. Clean up entry
            res_del = await client.delete(f"/api/knowledge-vault/{entry_id}")
            assert res_del.status_code == 200
