import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.core.events import privacy_event_bus


@pytest.mark.asyncio
async def test_dashboard_html_served():
    """Verify that root / and /dashboard serve the cockpit HTML document."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for path in ["/", "/dashboard"]:
            response = await client.get(path)
            assert response.status_code == 200
            assert "text/html" in response.headers["content-type"]
            html = response.text
            assert "VEIL" in html
            assert "Enterprise AI Privacy Gateway" in html
            assert "/static/style.css" in html
            assert "/static/app.js" in html
            assert 'id="clients-container"' in html
            assert 'id="telemetry-terminal"' in html
            assert 'id="btn-run-sandbox"' in html


@pytest.mark.asyncio
async def test_static_assets_served():
    """Verify that style.css and app.js are served properly."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # CSS test
        css_resp = await client.get("/static/style.css")
        assert css_resp.status_code == 200
        assert "--bg-canvas" in css_resp.text
        assert "--emerald" in css_resp.text

        # JS test
        js_resp = await client.get("/static/app.js")
        assert js_resp.status_code == 200
        assert "connectWebSocket" in js_resp.text
        assert "renderClientCards" in js_resp.text


@pytest.mark.asyncio
async def test_sandbox_detects_and_blocks_secrets():
    """Verify that the test playground detects and blocks secrets with fail-closed behavior."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "text": "AWS key: AKIAIOSFODNN7EXAMPLE and secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        }
        resp = await client.post("/api/test/sanitize", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["blocked"] is True
        assert data["sanitized_text"] is None
        assert len(data["violations"]) > 0


@pytest.mark.asyncio
async def test_sandbox_redacts_pii():
    """Verify that the test playground redacts PII and returns sanitized output."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "text": "Contact user at john.doe@cyberdyne.systems for details."
        }
        resp = await client.post("/api/test/sanitize", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["blocked"] is False
        assert data["redaction_count"] >= 1
        assert "john.doe@cyberdyne.systems" not in data["sanitized_text"]
        assert "[EMAIL_" in data["sanitized_text"]


@pytest.mark.asyncio
async def test_sandbox_clean_text_passes():
    """Verify that harmless clean text passes through without modification."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        clean_prompt = "def add(a: int, b: int) -> int: return a + b"
        payload = {"text": clean_prompt}
        resp = await client.post("/api/test/sanitize", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["blocked"] is False
        assert data["redaction_count"] == 0
        assert data["sanitized_text"] == clean_prompt
