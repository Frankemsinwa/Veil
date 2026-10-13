"""Transparent AI HTTP/HTTPS Proxy Interception Engine.

Intercepts outbound developer traffic via HTTP CONNECT tunnels:
- Non-AI domains pass through as raw TCP byte tunnels with zero decryption.
- Configured AI provider domains (api.openai.com, api.anthropic.com, etc.)
  undergo dynamic SSL termination, prompt privacy scanning/redaction,
  and response restoration.
"""
from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
import re
import ssl
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from app.audit.ledger import audit_ledger
from app.core.config import settings
from app.core.events import privacy_event_bus
from app.core.exceptions import SecretDetectedException, SemanticViolationException
from app.engine.pipeline import InspectionPipeline
from app.engine.redactor import Redactor
from app.proxy.ca import CertificateAuthority, ca_instance
from app.restoration.restorer import ResponseRestorer
from app.vault.session_vault import vault_manager

logger = logging.getLogger("veil.proxy.interceptor")


class DomainClassifier:
    """Classifies hostnames to determine whether SSL interception is required."""

    def __init__(self, intercepted_domains: Optional[List[str]] = None):
        self.intercepted_domains = intercepted_domains or list(settings.INTERCEPT_DOMAINS)

    def is_intercepted(self, hostname: str) -> bool:
        """Returns True if the hostname matches an intercepted AI provider domain."""
        host = hostname.lower().strip()
        for pattern in self.intercepted_domains:
            pat = pattern.lower().strip()
            if host == pat or fnmatch.fnmatch(host, pat) or fnmatch.fnmatch(host, f"*.{pat}"):
                return True
        return False


class TransparentProxyServer:
    """Asyncio HTTP CONNECT transparent proxy with dynamic SSL interception."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        ca: Optional[CertificateAuthority] = None,
        intercepted_domains: Optional[List[str]] = None,
    ):
        self.host = host if host is not None else settings.PROXY_HOST
        self.port = port if port is not None else settings.PROXY_PORT
        self.ca = ca or ca_instance
        self.classifier = DomainClassifier(intercepted_domains)
        self.pipeline = InspectionPipeline()
        self.redactor = Redactor()
        self.restorer = ResponseRestorer()

        self._server: Optional[asyncio.Server] = None
        self._active_tasks: Set[asyncio.Task] = set()
        self._is_running = False
        self._stats = {
            "total_connections": 0,
            "intercepted_requests": 0,
            "passthrough_tunnels": 0,
            "blocked_requests": 0,
            "redacted_requests": 0,
        }

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "is_running": self._is_running,
            "host": self.host,
            "port": self.port,
            "active_connections": len(self._active_tasks),
        }

    async def start(self) -> None:
        """Starts the transparent proxy server."""
        if self._is_running:
            return

        # Ensure CA certificate exists
        self.ca.load_or_create_root_ca()

        self._server = await asyncio.start_server(
            self._handle_client_connection,
            host=self.host,
            port=self.port,
        )
        if self._server and self._server.sockets:
            self.port = self._server.sockets[0].getsockname()[1]
        self._is_running = True
        logger.info(
            "Veil Transparent Proxy listening on %s:%d (Intercepting %s)",
            self.host,
            self.port,
            self.classifier.intercepted_domains,
        )

    async def stop(self) -> None:
        """Gracefully stops the proxy server and cancels active tasks."""
        self._is_running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        # Cancel remaining client connection tasks
        for task in list(self._active_tasks):
            task.cancel()
        if self._active_tasks:
            await asyncio.gather(*self._active_tasks, return_exceptions=True)
            self._active_tasks.clear()

        logger.info("Veil Transparent Proxy stopped.")

    def _handle_client_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Callback for incoming TCP connections; tracked in active task set."""
        task = asyncio.create_task(self._process_connection(reader, writer))
        self._active_tasks.add(task)
        task.add_done_callback(self._active_tasks.discard)

    async def _process_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Processes an incoming connection from client."""
        self._stats["total_connections"] += 1
        try:
            # Read first HTTP line
            line = await asyncio.wait_for(reader.readline(), timeout=30.0)
            if not line:
                writer.close()
                await writer.wait_closed()
                return

            line_str = line.decode("latin1", errors="replace").strip()
            parts = line_str.split()
            if not parts:
                writer.close()
                return

            method = parts[0].upper()

            if method == "CONNECT":
                target = parts[1]
                if ":" in target:
                    target_host, target_port_str = target.split(":", 1)
                    target_port = int(target_port_str)
                else:
                    target_host = target
                    target_port = 443

                # Read and consume remaining CONNECT headers
                while True:
                    hdr = await asyncio.wait_for(reader.readline(), timeout=10.0)
                    if hdr in (b"\r\n", b"\n", b""):
                        break

                if self.classifier.is_intercepted(target_host):
                    self._stats["intercepted_requests"] += 1
                    await self._handle_intercepted_tunnel(reader, writer, target_host, target_port)
                else:
                    self._stats["passthrough_tunnels"] += 1
                    await self._handle_passthrough_tunnel(reader, writer, target_host, target_port)
            else:
                # Direct plain HTTP forward request
                await self._handle_plain_http_request(reader, writer, line_str)
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            logger.debug("Proxy connection error: %s", e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # Zero-Decryption Raw TCP Tunnel (Non-AI traffic)
    # -------------------------------------------------------------------------

    async def _handle_passthrough_tunnel(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        target_host: str,
        target_port: int,
    ) -> None:
        """Transparently relays raw bytes without TLS termination."""
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(target_host, target_port),
                timeout=5.0,
            )
        except Exception as e:
            logger.debug("Failed upstream TCP connect to %s:%d (%s)", target_host, target_port, e)
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await client_writer.drain()
            return

        # Acknowledge tunnel establishment to client
        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()

        async def _forward(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except Exception:
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        await asyncio.gather(
            _forward(client_reader, upstream_writer),
            _forward(upstream_reader, client_writer),
        )

    # -------------------------------------------------------------------------
    # Dynamic SSL Termination & AI Privacy Shield
    # -------------------------------------------------------------------------

    async def _handle_intercepted_tunnel(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        target_host: str,
        target_port: int,
    ) -> None:
        """Terminates TLS with dynamically minted leaf cert and inspects prompts."""
        # 1. Acknowledge tunnel to client
        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()

        # 2. Get leaf SSL context for domain
        ssl_ctx = self.ca.get_ssl_context(target_host)
        loop = asyncio.get_running_loop()

        try:
            # Upgrade client side to TLS server
            client_transport = client_writer.transport
            client_protocol = client_writer._protocol
            new_client_transport = await loop.start_tls(
                client_transport,
                client_protocol,
                ssl_ctx,
                server_side=True,
            )
            client_writer._transport = new_client_transport
        except Exception as e:
            logger.warning("TLS handshake failed with client for %s: %s", target_host, e)
            return

        # 3. Connect to real upstream over TLS (with 2.0s connection timeout)
        upstream_reader: Optional[asyncio.StreamReader] = None
        upstream_writer: Optional[asyncio.StreamWriter] = None
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(
                    target_host,
                    target_port,
                    ssl=True,
                    server_hostname=target_host,
                ),
                timeout=2.0,
            )
        except Exception as e:
            logger.debug("Upstream TLS connect skipped/failed for %s:%d: %s", target_host, target_port, e)
            # Will handle offline shield fallback if request occurs

        # 4. Handle HTTP request loop inside the established TLS session
        try:
            while not client_reader.at_eof():
                # Read request line
                req_line = await asyncio.wait_for(client_reader.readline(), timeout=60.0)
                if not req_line:
                    break

                req_line_str = req_line.decode("latin1", errors="replace").strip()
                if not req_line_str:
                    continue

                parts = req_line_str.split()
                if len(parts) < 3:
                    break

                method, path, http_ver = parts[0], parts[1], parts[2]

                # Read headers
                headers: Dict[str, str] = {}
                raw_header_lines: List[bytes] = []
                while True:
                    hdr_line = await client_reader.readline()
                    if hdr_line in (b"\r\n", b"\n", b""):
                        break
                    raw_header_lines.append(hdr_line)
                    hdr_str = hdr_line.decode("latin1", errors="replace").strip()
                    if ":" in hdr_str:
                        h_name, h_val = hdr_str.split(":", 1)
                        headers[h_name.strip().lower()] = h_val.strip()

                # Read request body if Content-Length specified
                content_len = int(headers.get("content-length", 0))
                req_body = b""
                if content_len > 0:
                    req_body = await client_reader.readexactly(content_len)

                # Process AI chat completions & messages
                if self._is_prompt_endpoint(path):
                    await self._process_ai_prompt_request(
                        client_writer=client_writer,
                        upstream_reader=upstream_reader,
                        upstream_writer=upstream_writer,
                        method=method,
                        path=path,
                        http_ver=http_ver,
                        headers=headers,
                        req_body=req_body,
                        target_host=target_host,
                    )
                else:
                    # Non-prompt path: forward directly
                    if upstream_writer and upstream_reader:
                        await self._forward_generic_http_request(
                            client_writer=client_writer,
                            upstream_reader=upstream_reader,
                            upstream_writer=upstream_writer,
                            method=method,
                            path=path,
                            http_ver=http_ver,
                            headers=headers,
                            req_body=req_body,
                        )
                    else:
                        # Upstream unavailable
                        self._send_http_json_response(
                            client_writer,
                            status_code=502,
                            payload={"error": {"message": f"Cannot connect to upstream {target_host}"}},
                        )
                        break

                # If connection: close requested, terminate loop
                if headers.get("connection", "").lower() == "close":
                    break
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            logger.debug("Error in intercepted TLS session for %s: %s", target_host, e)
        finally:
            if upstream_writer:
                try:
                    upstream_writer.close()
                    await upstream_writer.wait_closed()
                except Exception:
                    pass

    def _is_prompt_endpoint(self, path: str) -> bool:
        """Determines if the request URL corresponds to an LLM prompt or completion."""
        p = path.lower()
        return any(
            x in p
            for x in (
                "chat/completions",
                "/completions",
                "/messages",
                "generatecontent",
                "streamgeneratecontent",
            )
        )

    async def _process_ai_prompt_request(
        self,
        client_writer: asyncio.StreamWriter,
        upstream_reader: Optional[asyncio.StreamReader],
        upstream_writer: Optional[asyncio.StreamWriter],
        method: str,
        path: str,
        http_ver: str,
        headers: Dict[str, str],
        req_body: bytes,
        target_host: str,
    ) -> None:
        """Inspects, redacts, and dispatches an AI prompt request."""
        start_time = time.perf_counter()
        session_id = headers.get("x-session-id") or f"proxy_{int(time.time())}"
        vault = vault_manager.get_session(session_id)

        try:
            payload: Dict[str, Any] = json.loads(req_body.decode("utf-8")) if req_body else {}
        except Exception:
            payload = {}

        model = payload.get("model", "unknown")
        messages = payload.get("messages", [])
        is_stream = bool(payload.get("stream", False))
        redaction_count = 0

        # Run inspection and redaction
        try:
            if messages:
                sanitized_messages, redaction_count = self.redactor.redact_chat_messages(
                    messages=messages,
                    pipeline=self.pipeline,
                    vault=vault,
                )
                payload["messages"] = sanitized_messages
            elif "prompt" in payload and isinstance(payload["prompt"], str):
                _, spans = self.pipeline.inspect(payload["prompt"])
                sanitized_p, redaction_count = self.redactor.redact_text(
                    payload["prompt"], spans, vault
                )
                payload["prompt"] = sanitized_p
        except SecretDetectedException as sde:
            self._stats["blocked_requests"] += 1
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            privacy_event_bus.publish_sync("blocked", {
                "session_id": session_id,
                "model": model,
                "reason": "Outbound prompt blocked by Veil Credential Detector",
                "violations": [v["entity_type"] for v in sde.violations],
                "latency_ms": elapsed_ms,
            })
            if settings.AUDIT_ENABLED:
                audit_ledger.record_receipt(
                    session_id=session_id,
                    provider="proxy_" + target_host,
                    model=model,
                    policy=settings.POLICY.value,
                    action_taken="BLOCKED_SECRET",
                    redaction_count=0,
                    secret_blocked_count=len(sde.violations),
                    entities_detected=[v["entity_type"] for v in sde.violations],
                    latency_ms=elapsed_ms,
                )
            self._send_http_json_response(
                client_writer,
                status_code=403,
                payload={
                    "error": {
                        "message": "🛡️ BLOCKED BY VEIL: Outbound prompt blocked by credential detector.",
                        "type": "privacy_violation_error",
                        "code": "credentials_detected",
                        "details": [v["entity_type"] for v in sde.violations],
                    }
                },
            )
            return
        except SemanticViolationException as sve:
            self._stats["blocked_requests"] += 1
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            cat = sve.violations[0].get("category", "PROPRIETARY") if sve.violations else "PROPRIETARY"
            privacy_event_bus.publish_sync("blocked", {
                "session_id": session_id,
                "model": model,
                "reason": f"Semantic vector guardrail violation ({cat})",
                "violations": [cat],
                "latency_ms": elapsed_ms,
            })
            if settings.AUDIT_ENABLED:
                audit_ledger.record_receipt(
                    session_id=session_id,
                    provider="proxy_" + target_host,
                    model=model,
                    policy=settings.POLICY.value,
                    action_taken="BLOCKED_SECRET",
                    redaction_count=0,
                    secret_blocked_count=len(sve.violations),
                    entities_detected=[cat],
                    latency_ms=elapsed_ms,
                )
            self._send_http_json_response(
                client_writer,
                status_code=403,
                payload={
                    "error": {
                        "message": f"🛡️ BLOCKED BY VEIL: Outbound prompt blocked by local vector policy ({cat}).",
                        "type": "privacy_violation_error",
                        "code": "vector_guardrail_violation",
                    }
                },
            )
            return

        if redaction_count > 0:
            self._stats["redacted_requests"] += 1
            privacy_event_bus.publish_sync("redaction", {
                "session_id": session_id,
                "model": model,
                "entity_type": "Transparent Proxy Intercept",
                "placeholder": f"<{redaction_count} tokens redacted>",
                "stream": is_stream,
            })

        # Forward modified body to upstream or return offline shield response
        new_body = json.dumps(payload).encode("utf-8")
        headers["content-length"] = str(len(new_body))

        if upstream_writer and upstream_reader:
            try:
                # Send modified request to upstream
                req_header_data = f"{method} {path} {http_ver}\r\n".encode("latin1")
                for h_k, h_v in headers.items():
                    req_header_data += f"{h_k}: {h_v}\r\n".encode("latin1")
                req_header_data += b"\r\n"

                upstream_writer.write(req_header_data + new_body)
                await upstream_writer.drain()

                # Read upstream response
                resp_line = await upstream_reader.readline()
                if not resp_line:
                    raise ConnectionError("Empty response from upstream")

                auth_val = headers.get("authorization", "") or headers.get("x-api-key", "")
                is_mock_token = "veil-dev-token" in auth_val or not auth_val
                is_err_status = any(code in resp_line for code in (b" 401 ", b" 403 ", b" 500 ", b" 502 ", b" 503 "))

                if is_err_status and is_mock_token:
                    # Drain remainder of upstream error headers
                    while True:
                        rh = await upstream_reader.readline()
                        if rh in (b"\r\n", b"\n", b""):
                            break
                    from app.main import _generate_mock_shield_response
                    mock_resp = _generate_mock_shield_response(
                        model=model,
                        redaction_count=redaction_count,
                        sanitized_messages=payload.get("messages", []),
                        vault=vault,
                    )
                    self._send_http_json_response(client_writer, status_code=200, payload=mock_resp)
                    return

                client_writer.write(resp_line)
                resp_headers: Dict[str, str] = {}
                while True:
                    resp_hdr = await upstream_reader.readline()
                    client_writer.write(resp_hdr)
                    if resp_hdr in (b"\r\n", b"\n", b""):
                        break
                    rh_str = resp_hdr.decode("latin1", errors="replace").strip()
                    if ":" in rh_str:
                        rk, rv = rh_str.split(":", 1)
                        resp_headers[rk.strip().lower()] = rv.strip()

                await client_writer.drain()

                # Stream or forward body
                resp_len = int(resp_headers.get("content-length", -1))
                if resp_len >= 0:
                    body_data = await upstream_reader.readexactly(resp_len)
                    # Restore placeholders if JSON response
                    if "application/json" in resp_headers.get("content-type", ""):
                        body_data = self.restorer.restore_openai_json_response(body_data, vault)
                    client_writer.write(body_data)
                    await client_writer.drain()
                else:
                    # Chunked or streaming response
                    while True:
                        chunk = await upstream_reader.read(8192)
                        if not chunk:
                            break
                        client_writer.write(chunk)
                        await client_writer.drain()

                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                if settings.AUDIT_ENABLED:
                    audit_ledger.record_receipt(
                        session_id=session_id,
                        provider="proxy_" + target_host,
                        model=model,
                        policy=settings.POLICY.value,
                        action_taken="ALLOWED_REDACTED" if redaction_count > 0 else "ALLOWED_CLEAN",
                        redaction_count=redaction_count,
                        secret_blocked_count=0,
                        entities_detected=[],
                        latency_ms=elapsed_ms,
                    )
                return
            except Exception as e:
                logger.warning("Upstream dispatch failed (%s). Triggering offline shield responder...", e)

        # Offline / Upstream unconfigured fallback
        from app.main import _generate_mock_shield_response
        mock_resp = _generate_mock_shield_response(
            model=model,
            redaction_count=redaction_count,
            sanitized_messages=payload.get("messages", []),
            vault=vault,
        )
        self._send_http_json_response(client_writer, status_code=200, payload=mock_resp)

    async def _forward_generic_http_request(
        self,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
        method: str,
        path: str,
        http_ver: str,
        headers: Dict[str, str],
        req_body: bytes,
    ) -> None:
        """Forwards non-prompt HTTP requests verbatim to upstream and pipes response."""
        req_head = f"{method} {path} {http_ver}\r\n".encode("latin1")
        for hk, hv in headers.items():
            req_head += f"{hk}: {hv}\r\n".encode("latin1")
        req_head += b"\r\n"

        upstream_writer.write(req_head + req_body)
        await upstream_writer.drain()

        # Pipe upstream response back to client
        while True:
            chunk = await upstream_reader.read(65536)
            if not chunk:
                break
            client_writer.write(chunk)
            await client_writer.drain()

    async def _handle_plain_http_request(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        first_line: str,
    ) -> None:
        """Handles direct forward plain HTTP requests."""
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nVeil Transparent Proxy Active\n"
        )
        await writer.drain()

    def _send_http_json_response(
        self,
        writer: asyncio.StreamWriter,
        status_code: int,
        payload: Dict[str, Any],
    ) -> None:
        """Sends a standard HTTP JSON response."""
        body = json.dumps(payload).encode("utf-8")
        status_text = {200: "OK", 403: "Forbidden", 502: "Bad Gateway"}.get(status_code, "Response")
        res = (
            f"HTTP/1.1 {status_code} {status_text}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin1") + body
        writer.write(res)


# Global singleton
transparent_proxy_server = TransparentProxyServer()
