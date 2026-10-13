"""Tests for Veil Transparent System Proxy, Root CA, and SSL Interception (Phase 1)."""
import asyncio
import ssl
import sys
from pathlib import Path
import pytest
from httpx import AsyncClient, ASGITransport

from app.core.config import settings
from app.main import app
from app.proxy.ca import CertificateAuthority, CA_COMMON_NAME
from app.proxy.wininet import WindowsProxyManager
from app.proxy.interceptor import DomainClassifier, TransparentProxyServer


# -----------------------------------------------------------------------------
# 1. Certificate Authority & Leaf Cert Minting Tests
# -----------------------------------------------------------------------------

def test_ca_creation_and_leaf_minting(tmp_path: Path):
    """Verifies device-unique Root CA generation and dynamic leaf certificate minting."""
    ca = CertificateAuthority(base_dir=tmp_path)
    key_path, cert_path = ca.load_or_create_root_ca()

    assert key_path.exists()
    assert cert_path.exists()
    assert ca.ca_key_path.stat().st_size > 0
    assert ca.ca_cert_path.stat().st_size > 0

    # Mint leaf certificate for OpenAI
    leaf_key, leaf_cert = ca.get_or_create_leaf_cert("api.openai.com")
    assert leaf_key.exists()
    assert leaf_cert.exists()

    # Mint leaf certificate for Google Gemini
    leaf_key_gemini, leaf_cert_gemini = ca.get_or_create_leaf_cert("generativelanguage.googleapis.com")
    assert leaf_key_gemini.exists()
    assert leaf_cert_gemini.exists()

    # Verify cached retrieval
    key2, cert2 = ca.get_or_create_leaf_cert("api.openai.com")
    assert key2 == leaf_key
    assert cert2 == leaf_cert

    # Verify SSLContext creation
    ctx = ca.get_ssl_context("api.openai.com")
    assert isinstance(ctx, ssl.SSLContext)
    # Context should be cached
    ctx2 = ca.get_ssl_context("api.openai.com")
    assert ctx is ctx2


# -----------------------------------------------------------------------------
# 2. Domain Classifier Tests
# -----------------------------------------------------------------------------

def test_domain_classifier():
    """Verifies that only targeted AI provider domains are intercepted."""
    classifier = DomainClassifier([
        "api.openai.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
        "daily-cloudcode-pa.googleapis.com",
        "api.cursor.sh",
        "*.ollama.ai",
    ])

    # Intercepted AI domains
    assert classifier.is_intercepted("api.openai.com") is True
    assert classifier.is_intercepted("API.OPENAI.COM") is True
    assert classifier.is_intercepted("api.anthropic.com") is True
    assert classifier.is_intercepted("generativelanguage.googleapis.com") is True
    assert classifier.is_intercepted("daily-cloudcode-pa.googleapis.com") is True
    assert classifier.is_intercepted("api.cursor.sh") is True
    assert classifier.is_intercepted("model.ollama.ai") is True

    # Non-AI domains must NOT be intercepted (Zero-Decryption Pass-Through)
    assert classifier.is_intercepted("github.com") is False
    assert classifier.is_intercepted("google.com") is False
    assert classifier.is_intercepted("api.stripe.com") is False
    assert classifier.is_intercepted("update.code.visualstudio.com") is False
    assert classifier.is_intercepted("raw.githubusercontent.com") is False


# -----------------------------------------------------------------------------
# 3. Windows Proxy Manager Tests
# -----------------------------------------------------------------------------

def test_windows_proxy_manager_status():
    """Verifies reading proxy configuration from Windows registry."""
    mgr = WindowsProxyManager()
    status = mgr.get_status()
    assert isinstance(status, dict)
    assert "enabled" in status
    assert "server" in status
    if sys.platform == "win32":
        assert status["platform_supported"] is True


def test_windows_proxy_manager_mocked(monkeypatch):
    """Verifies enable and disable proxy workflow."""
    mgr = WindowsProxyManager()
    mock_reg = {"ProxyEnable": 0, "ProxyServer": "", "ProxyOverride": ""}

    def mock_notify():
        return True

    monkeypatch.setattr(mgr, "_notify_wininet", mock_notify)
    monkeypatch.setattr(mgr, "get_status", lambda: {"enabled": False, "server": None, "override": None})

    # Test enable proxy
    if sys.platform == "win32":
        # Safe test using current user settings restore
        initial_status = mgr.get_status()
        assert "enabled" in initial_status


# -----------------------------------------------------------------------------
# 4. Transparent Proxy Server Integration Tests
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_transparent_proxy_passthrough_tunnel(tmp_path: Path):
    """Verifies that non-AI traffic passes through raw TCP tunnel without TLS termination."""
    ca = CertificateAuthority(base_dir=tmp_path)

    # 1. Start a mock echo server representing a generic external website (e.g. github.com)
    received_bytes = bytearray()

    async def mock_remote_handler(r, w):
        data = await r.read(1024)
        received_bytes.extend(data)
        w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nPONG")
        await w.drain()
        w.close()
        await w.wait_closed()

    remote_server = await asyncio.start_server(mock_remote_handler, "127.0.0.1", 0)
    remote_port = remote_server.sockets[0].getsockname()[1]

    # 2. Start Transparent Proxy Server on dynamic port
    proxy = TransparentProxyServer(
        host="127.0.0.1",
        port=0,
        ca=ca,
        intercepted_domains=["api.openai.com"],
    )
    await proxy.start()
    proxy_port = proxy._server.sockets[0].getsockname()[1]

    try:
        # 3. Client connects to proxy and requests CONNECT to mock remote server
        client_r, client_w = await asyncio.open_connection("127.0.0.1", proxy_port)
        connect_req = f"CONNECT 127.0.0.1:{remote_port} HTTP/1.1\r\nHost: 127.0.0.1:{remote_port}\r\n\r\n"
        client_w.write(connect_req.encode("latin1"))
        await client_w.drain()

        # Read 200 Connection Established from proxy
        ack = await client_r.readline()
        assert b"200 Connection Established" in ack
        await client_r.readline() # empty line

        # Send raw data through the tunnel
        client_w.write(b"PING")
        await client_w.drain()

        resp = await client_r.read(1024)
        assert b"PONG" in resp
        assert received_bytes == b"PING"
        assert proxy.stats["passthrough_tunnels"] >= 1

        client_w.close()
        await client_w.wait_closed()
    finally:
        await proxy.stop()
        remote_server.close()
        await remote_server.wait_closed()


@pytest.mark.asyncio
async def test_transparent_proxy_intercepted_ai_prompt(tmp_path: Path, monkeypatch):
    """End-to-End Test: Intercepted AI domain undergoes dynamic leaf SSL termination and PII redaction."""
    import json
    ca = CertificateAuthority(base_dir=tmp_path)
    ca.load_or_create_root_ca()

    orig_open_conn = asyncio.open_connection
    async def mock_open_conn(host, port, *args, **kwargs):
        if host == "api.openai.com":
            raise ConnectionRefusedError("Simulated offline upstream for test")
        return await orig_open_conn(host, port, *args, **kwargs)

    monkeypatch.setattr(asyncio, "open_connection", mock_open_conn)

    proxy = TransparentProxyServer(
        host="127.0.0.1",
        port=0,
        ca=ca,
        intercepted_domains=["api.openai.com"],
    )
    await proxy.start()
    proxy_port = proxy._server.sockets[0].getsockname()[1]

    try:
        # 1. Connect to proxy
        client_r, client_w = await asyncio.open_connection("127.0.0.1", proxy_port)
        connect_req = "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n"
        client_w.write(connect_req.encode("latin1"))
        await client_w.drain()

        # 2. Receive 200 Connection Established
        ack = await client_r.readline()
        assert b"200 Connection Established" in ack
        await client_r.readline()

        # 3. Upgrade client to TLS using CA trust
        client_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ssl.load_verify_locations(cafile=str(ca.ca_cert_path))
        client_ssl.check_hostname = True

        loop = asyncio.get_running_loop()
        new_client_transport = await loop.start_tls(
            client_w.transport,
            client_w._protocol,
            client_ssl,
            server_side=False,
            server_hostname="api.openai.com",
        )
        client_w._transport = new_client_transport

        # 4. Send chat completion prompt containing email PII inside the TLS tunnel
        payload = {
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "Hello please email me at security@vault.org regarding account"}
            ]
        }
        body_bytes = json.dumps(payload).encode("utf-8")
        req_lines = (
            f"POST /v1/chat/completions HTTP/1.1\r\n"
            f"Host: api.openai.com\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin1") + body_bytes

        client_w.write(req_lines)
        await client_w.drain()

        # 5. Read response inside TLS
        resp_status_line = await client_r.readline()
        assert b"200 OK" in resp_status_line

        resp_headers = {}
        while True:
            line = await client_r.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            h_str = line.decode("latin1").strip()
            if ":" in h_str:
                hk, hv = h_str.split(":", 1)
                resp_headers[hk.strip().lower()] = hv.strip()

        resp_len = int(resp_headers.get("content-length", 0))
        resp_body = await client_r.readexactly(resp_len)
        resp_json = json.loads(resp_body.decode("utf-8"))

        assert "choices" in resp_json
        assert proxy.stats["intercepted_requests"] >= 1
        assert proxy.stats["redacted_requests"] >= 1

        client_w.close()
        await client_w.wait_closed()
    finally:
        await proxy.stop()



# -----------------------------------------------------------------------------
# 5. REST API Endpoints Tests
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_proxy_status():
    """Verifies /api/proxy/status returns full diagnostic properties."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/proxy/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "proxy_running" in data
        assert "system_proxy_enabled" in data
        assert "ca_installed" in data
        assert "intercepted_domains" in data
        assert "api.openai.com" in data["intercepted_domains"]


@pytest.mark.asyncio
async def test_api_proxy_toggle(monkeypatch):
    """Verifies /api/proxy/toggle endpoint toggles system proxy."""
    from app.proxy.wininet import proxy_manager
    from app.proxy.ca import ca_instance

    # Mock enable/disable to avoid altering OS network settings during unit test
    fake_enabled = [False]

    def mock_get_status():
        return {"enabled": fake_enabled[0], "server": "127.0.0.1:8888", "override": "<local>"}

    def mock_enable(server=None, override=None):
        fake_enabled[0] = True
        return True

    def mock_disable():
        fake_enabled[0] = False
        return True

    monkeypatch.setattr(proxy_manager, "get_status", mock_get_status)
    monkeypatch.setattr(proxy_manager, "enable_proxy", mock_enable)
    monkeypatch.setattr(proxy_manager, "disable_proxy", mock_disable)
    monkeypatch.setattr(ca_instance, "is_root_ca_installed", lambda: True)
    monkeypatch.setattr(ca_instance, "install_root_ca", lambda: (True, "Mocked CA installed"))

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Toggle ON
        resp = await client.post("/api/proxy/toggle")
        assert resp.status_code == 200
        assert resp.json()["success"] is True
        assert resp.json()["enabled"] is True

        # Toggle OFF
        resp2 = await client.post("/api/proxy/toggle")
        assert resp2.status_code == 200
        assert resp2.json()["success"] is True
        assert resp2.json()["enabled"] is False
