import sys
import json
import time
import asyncio
from contextlib import asynccontextmanager
from typing import Dict, Any
from pathlib import Path
from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse, HTMLResponse
from app.core.config import settings, PolicyLevel
from app.core.exceptions import VeilSecurityException, SecretDetectedException, SemanticViolationException
from app.core.circuit_breaker import CircuitBreaker
from app.providers.openai_adapter import OpenAIAdapter
from app.providers.anthropic_adapter import AnthropicAdapter
from app.providers.ollama_adapter import OllamaAdapter
from app.engine.pipeline import InspectionPipeline
from app.engine.redactor import Redactor
from app.vault.session_vault import vault_manager
from app.restoration.restorer import ResponseRestorer
from app.audit.ledger import audit_ledger
from app.core.events import privacy_event_bus
from app.clients import client_manager

# Global component singletons
openai_adapter = OpenAIAdapter()
anthropic_adapter = AnthropicAdapter()
ollama_adapter = OllamaAdapter()
inspection_pipeline = InspectionPipeline()
redactor = Redactor()
restorer = ResponseRestorer()
gateway_breaker = CircuitBreaker("proxy_gateway", max_duration_ms=60000.0)

# Real-time gateway telemetry counters
metrics_state: Dict[str, Any] = {
    "total_requests": 0,
    "total_redactions": 0,
    "total_blocks": 0,
    "is_paused": False
}


from app.core.log_scrubber import install_log_scrubber


def _warmup_models():
    """Background model pre-warming to eliminate cold-start inference lag."""
    try:
        from app.engine.vector_encoder import vector_encoder
        vector_encoder.encode_batch(["veil privacy local vector warmup"])
    except Exception:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
    install_log_scrubber()
    # Pre-warm local quantized embedding models in a thread to ensure zero cold-start delay
    asyncio.create_task(asyncio.to_thread(_warmup_models))
    yield
    await openai_adapter.close()
    await anthropic_adapter.close()
    await ollama_adapter.close()
    vault_manager.zeroize_all()


from app.billing.routes import billing_router

app = FastAPI(
    title="Veil AI Privacy Gateway",
    description="Local, fail-closed, enterprise privacy gateway for LLM traffic.",
    version="0.1.0",
    lifespan=lifespan
)
app.include_router(billing_router)


@app.exception_handler(VeilSecurityException)
async def veil_security_exception_handler(request: Request, exc: VeilSecurityException):
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.to_dict()
    )


@app.get("/health")
@app.get("/v1/health")
async def health_check():
    return {
        "status": "HEALTHY",
        "service": "Veil Privacy Gateway",
        "version": "0.1.0",
        "policy": settings.POLICY.value,
        "fail_closed": settings.FAIL_CLOSED,
        "is_paused": metrics_state["is_paused"]
    }


# ------------------ Phase 13: Live Telemetry & Control API ------------------

@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    """Real-time WebSocket telemetry stream for Veil desktop cockpit UI."""
    await websocket.accept()
    queue = await privacy_event_bus.subscribe()
    try:
        # Initial snapshot payload on connection
        init_payload = {
            "type": "init",
            "data": {
                "policy": settings.POLICY.value,
                "is_paused": metrics_state["is_paused"],
                "metrics": dict(metrics_state),
                "clients": [c.model_dump() for c in client_manager.get_all_clients()],
                "history": privacy_event_bus.get_recent_history()
            }
        }
        await websocket.send_json(init_payload)

        async def _client_receiver():
            try:
                while True:
                    await websocket.receive_text()
            except (WebSocketDisconnect, RuntimeError):
                pass

        async def _event_sender():
            try:
                while True:
                    event = await queue.get()
                    await websocket.send_json(event)
            except (WebSocketDisconnect, RuntimeError):
                pass

        receiver_task = asyncio.create_task(_client_receiver())
        sender_task = asyncio.create_task(_event_sender())

        done, pending = await asyncio.wait(
            [receiver_task, sender_task],
            return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
    except Exception:
        pass
    finally:
        await privacy_event_bus.unsubscribe(queue)



@app.get("/api/clients")
async def get_clients():
    """Returns detected status and configuration paths of all local AI clients."""
    return [c.model_dump() for c in client_manager.get_all_clients()]


@app.post("/api/clients/{client_id}/connect")
async def connect_client_endpoint(client_id: str):
    """1-Click connect an AI client to route outbound requests through Veil."""
    result = client_manager.connect_client(client_id)
    if result.success:
        privacy_event_bus.publish_sync("client_status", {
            "client_id": client_id,
            "status": "CONNECTED",
            "url": result.new_url
        })
    return result.model_dump()


@app.post("/api/clients/{client_id}/disconnect")
async def disconnect_client_endpoint(client_id: str):
    """1-Click disconnect an AI client and restore its original configuration."""
    result = client_manager.disconnect_client(client_id)
    if result.success:
        privacy_event_bus.publish_sync("client_status", {
            "client_id": client_id,
            "status": "DETECTED"
        })
    return result.model_dump()


@app.get("/api/metrics")
async def get_metrics():
    """Returns cumulative gateway activity metrics, recent throughput buckets, and active privacy policy tier."""
    recent_receipts = audit_ledger.get_recent_receipts(limit=200)
    now = time.time()
    buckets = [{"clean": 0, "redacted": 0, "blocked": 0} for _ in range(30)]
    for r in recent_receipts:
        age_seconds = now - r.get("timestamp", 0)
        if 0 <= age_seconds < 1800:
            bucket_idx = 29 - int(age_seconds // 60)
            if 0 <= bucket_idx < 30:
                action = str(r.get("action_taken", ""))
                if "BLOCK" in action or r.get("secret_blocked_count", 0) > 0:
                    buckets[bucket_idx]["blocked"] += 1
                elif "REDACT" in action or r.get("redaction_count", 0) > 0:
                    buckets[bucket_idx]["redacted"] += 1
                else:
                    buckets[bucket_idx]["clean"] += 1

    return {
        "metrics": metrics_state,
        "policy": settings.POLICY.value,
        "audit_count": len(recent_receipts),
        "recent_buckets": buckets,
        "recent_events": [
            {
                "type": "blocked" if ("BLOCK" in str(r.get("action_taken", "")) or r.get("secret_blocked_count", 0) > 0) else ("redaction" if ("REDACT" in str(r.get("action_taken", "")) or r.get("redaction_count", 0) > 0) else "clean_pass"),
                "timestamp": r.get("timestamp", now),
                "data": {
                    "session_id": r.get("session_id", ""),
                    "model": r.get("model", "llm"),
                    "redaction_count": r.get("redaction_count", 0),
                    "reason": "Exfiltration Blocked" if "BLOCK" in str(r.get("action_taken", "")) else "Prompt Sanitized"
                }
            }
            for r in recent_receipts[:10]
        ]
    }


@app.post("/api/gateway/policy")
async def set_policy(request: Request):
    """Update active privacy policy tier (STRICT, BALANCED, PERMISSIVE)."""
    body = await request.json()
    new_policy_str = body.get("policy", "STRICT").upper()
    try:
        settings.POLICY = PolicyLevel(new_policy_str)
        privacy_event_bus.publish_sync("metric", {
            "action": "policy_change",
            "policy": settings.POLICY.value
        })
        return {"success": True, "policy": settings.POLICY.value}
    except ValueError:
        return JSONResponse(status_code=400, content={"error": f"Invalid policy tier: {new_policy_str}"})


@app.post("/api/gateway/toggle")
async def toggle_gateway():
    """Toggle gateway pause / active state."""
    metrics_state["is_paused"] = not metrics_state["is_paused"]
    privacy_event_bus.publish_sync("metric", {
        "action": "gateway_toggle",
        "is_paused": metrics_state["is_paused"]
    })
    return {"is_paused": metrics_state["is_paused"]}


@app.get("/api/system/autostart")
async def get_autostart():
    """Returns whether Veil is configured to launch on Windows startup."""
    from app.gui.autostart import is_autostart_enabled
    return {"enabled": is_autostart_enabled()}


@app.post("/api/system/autostart")
async def set_autostart(request: Request):
    """Enable or disable Veil launching on Windows startup."""
    from app.gui.autostart import is_autostart_enabled, enable_autostart, disable_autostart
    body = await request.json()
    enable = bool(body.get("enabled", False))
    if enable:
        success = enable_autostart()
    else:
        success = disable_autostart()
    return {"enabled": is_autostart_enabled(), "success": success}


# ------------------ Enterprise Custom Entity Dictionary API ------------------

@app.get("/api/custom-entities")
async def get_custom_entities():
    """Returns all configured enterprise custom entity and blacklist rules."""
    from app.engine.custom_dictionary import custom_dictionary_manager
    rules = custom_dictionary_manager.list_rules()
    return {"rules": [r.model_dump() for r in rules]}


@app.post("/api/custom-entities")
async def create_or_update_custom_entity(request: Request):
    """Creates or updates a custom enterprise entity rule."""
    from app.engine.custom_dictionary import custom_dictionary_manager, CustomEntityRule
    body = await request.json()
    rule = CustomEntityRule(**body)
    saved = custom_dictionary_manager.add_rule(rule)
    privacy_event_bus.publish_sync("metric", {
        "action": "custom_entity_updated",
        "entity_name": saved.name
    })
    return {"success": True, "rule": saved.model_dump()}


@app.delete("/api/custom-entities/{rule_id}")
async def delete_custom_entity(rule_id: str):
    """Deletes an enterprise custom entity rule."""
    from app.engine.custom_dictionary import custom_dictionary_manager
    success = custom_dictionary_manager.delete_rule(rule_id)
    return {"success": success}


@app.post("/api/custom-entities/{rule_id}/toggle")
async def toggle_custom_entity(rule_id: str):
    """Toggles active state of a custom entity rule."""
    from app.engine.custom_dictionary import custom_dictionary_manager
    updated = custom_dictionary_manager.toggle_rule(rule_id)
    if not updated:
        return JSONResponse(status_code=404, content={"error": "Rule not found"})
    return {"success": True, "enabled": updated.enabled}


# ------------------ Local Vector & Knowledge Vault API (Phase 2) ------------------

@app.get("/api/knowledge-vault")
async def get_knowledge_vault():
    """Returns all confidential vector entries and vector repository metrics."""
    from app.engine.knowledge_vault import knowledge_vault
    entries = knowledge_vault.get_all_entries()
    stats = knowledge_vault.get_vault_stats()
    return {
        "entries": [e.model_dump() for e in entries],
        "stats": stats
    }


@app.post("/api/knowledge-vault/entry")
async def add_knowledge_vault_entry(request: Request):
    """Adds a single protected knowledge vector entry to the repository."""
    from app.engine.knowledge_vault import knowledge_vault
    body = await request.json()
    title = body.get("title", "")
    text = body.get("text", "")
    category = body.get("category", "PROPRIETARY")
    action = body.get("action", "BLOCK")
    threshold_override = body.get("threshold_override")
    enabled = bool(body.get("enabled", True))

    if not text.strip():
        return JSONResponse(status_code=400, content={"error": "Text cannot be empty"})

    entry = knowledge_vault.add_entry(
        title=title,
        text=text,
        category=category,
        action=action,
        threshold_override=threshold_override,
        enabled=enabled
    )
    privacy_event_bus.publish_sync("metric", {
        "action": "knowledge_vector_added",
        "title": entry.title
    })
    return {"success": True, "entry": entry.model_dump()}


@app.post("/api/knowledge-vault/embed-document")
async def embed_document_to_vault(request: Request):
    """Splits a full document into overlapping sentence windows, embeds, and stores in the vault."""
    from app.engine.knowledge_vault import knowledge_vault
    body = await request.json()
    title = body.get("title", "")
    text = body.get("text", "")
    category = body.get("category", "PROPRIETARY")
    action = body.get("action", "BLOCK")
    threshold_override = body.get("threshold_override")
    window_size = int(body.get("window_size", 2))
    stride = int(body.get("stride", 1))

    if not text.strip():
        return JSONResponse(status_code=400, content={"error": "Document text cannot be empty"})

    entries = knowledge_vault.embed_document(
        title=title,
        document_text=text,
        category=category,
        action=action,
        threshold_override=threshold_override,
        window_size_sentences=window_size,
        stride=stride
    )
    privacy_event_bus.publish_sync("metric", {
        "action": "document_embedded",
        "title": title,
        "chunk_count": len(entries)
    })
    return {
        "success": True,
        "chunk_count": len(entries),
        "entries": [e.model_dump() for e in entries]
    }


@app.delete("/api/knowledge-vault/{entry_id}")
async def delete_knowledge_vault_entry(entry_id: str):
    """Deletes an entry from the knowledge vector repository."""
    from app.engine.knowledge_vault import knowledge_vault
    success = knowledge_vault.delete_entry(entry_id)
    if not success:
        return JSONResponse(status_code=404, content={"error": "Entry not found"})
    return {"success": True}


@app.post("/api/knowledge-vault/{entry_id}/toggle")
async def toggle_knowledge_vault_entry(entry_id: str):
    """Toggles active/inactive state of a knowledge vector entry."""
    from app.engine.knowledge_vault import knowledge_vault
    updated = knowledge_vault.toggle_entry(entry_id)
    if not updated:
        return JSONResponse(status_code=404, content={"error": "Entry not found"})
    return {"success": True, "entry": updated.model_dump(), "enabled": updated.enabled}


@app.post("/api/knowledge-vault/test-similarity")
async def test_knowledge_similarity(request: Request):
    """Tests query similarity against the knowledge vector repository in real-time."""
    from app.engine.knowledge_vault import knowledge_vault
    from app.engine.vector_encoder import vector_encoder
    body = await request.json()
    query = body.get("query") or body.get("text") or ""
    top_k = int(body.get("top_k", 5))

    if not query.strip():
        return {"matches": [], "query": query, "latency_ms": 0.0, "search_latency_ms": 0.0}

    t0 = time.perf_counter()
    query_vec = vector_encoder.encode_text(query)
    matches = knowledge_vault.search(query_vec, top_k=top_k, min_threshold=0.30)
    latency_ms = (time.perf_counter() - t0) * 1000.0

    return {
        "query": query,
        "latency_ms": round(latency_ms, 2),
        "search_latency_ms": round(latency_ms, 2),
        "matches": [m.model_dump() for m in matches]
    }


# ------------------ Phase 14: Enterprise Cockpit UI & Sandbox ------------------

if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    UI_DIR = Path(sys._MEIPASS) / "app" / "ui"
else:
    UI_DIR = Path(__file__).parent / "ui"

if UI_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(UI_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    """Serves the Veil Desktop Cockpit UI."""
    index_file = UI_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return HTMLResponse("<h1>Veil Privacy Gateway Initializing</h1>")


@app.post("/api/test/sanitize")
async def test_sanitize(request: Request):
    """Sandbox endpoint for testing prompt inspection and redaction live from the Cockpit UI."""
    body = await request.json()
    text = body.get("text", "")
    session_id = f"sandbox_{int(time.time() * 1000)}"
    vault = vault_manager.get_session(session_id)

    try:
        _, redact_spans = inspection_pipeline.inspect(text)
        sanitized_text, redaction_count = redactor.redact_text(
            text=text,
            spans=redact_spans,
            vault=vault
        )
        if redaction_count > 0:
            privacy_event_bus.publish_sync("redaction", {
                "session_id": session_id,
                "model": "sandbox",
                "entity_type": "PII / Sensitive",
                "placeholder": f"<{redaction_count} tokens sanitized>"
            })
        else:
            privacy_event_bus.publish_sync("clean_pass", {
                "session_id": session_id,
                "model": "sandbox",
                "redaction_count": 0,
                "reason": "Clean inspection test"
            })
        if settings.AUDIT_ENABLED:
            audit_ledger.record_receipt(
                session_id=session_id,
                provider="sandbox",
                model="sandbox",
                policy=settings.POLICY.value,
                action_taken="ALLOWED_REDACTED" if redaction_count > 0 else "ALLOWED_CLEAN",
                redaction_count=redaction_count,
                secret_blocked_count=0,
                entities_detected=[s.entity_type for s in redact_spans],
                latency_ms=1.0
            )
        return {
            "blocked": False,
            "original_text": text,
            "sanitized_text": sanitized_text,
            "redaction_count": redaction_count,
            "violations": []
        }
    except SecretDetectedException as sde:
        privacy_event_bus.publish_sync("blocked", {
            "session_id": session_id,
            "model": "sandbox",
            "reason": "Test prompt blocked by credential detector",
            "violations": [v["entity_type"] for v in sde.violations]
        })
        if settings.AUDIT_ENABLED:
            audit_ledger.record_receipt(
                session_id=session_id,
                provider="sandbox",
                model="sandbox",
                policy=settings.POLICY.value,
                action_taken="BLOCKED_SECRET",
                redaction_count=0,
                secret_blocked_count=len(sde.violations),
                entities_detected=[v["entity_type"] for v in sde.violations],
                latency_ms=1.0
            )
        return {
            "blocked": True,
            "original_text": text,
            "sanitized_text": None,
            "redaction_count": 0,
            "violations": sde.violations
        }
    except SemanticViolationException as sve:
        privacy_event_bus.publish_sync("blocked", {
            "session_id": session_id,
            "model": "sandbox",
            "reason": f"Semantic vector breach: {sve.violations[0].get('category') if sve.violations else 'Confidential'}",
            "violations": [v.get("category", "PROPRIETARY") for v in sve.violations]
        })
        if settings.AUDIT_ENABLED:
            audit_ledger.record_receipt(
                session_id=session_id,
                provider="sandbox",
                model="sandbox",
                policy=settings.POLICY.value,
                action_taken="BLOCKED_SECRET",
                redaction_count=0,
                secret_blocked_count=len(sve.violations),
                entities_detected=[v.get("category", "PROPRIETARY") for v in sve.violations],
                latency_ms=1.0
            )
        return {
            "blocked": True,
            "original_text": text,
            "sanitized_text": None,
            "redaction_count": 0,
            "violations": sve.violations
        }
    finally:
        vault_manager.remove_session(session_id)



def resolve_session_id(request: Request, payload: Dict[str, Any]) -> str:
    """Derive session ID from client header (e.g. X-Session-Id) or user field."""
    client_sid = request.headers.get("x-session-id") or request.headers.get("x-thread-id")
    if client_sid:
        return client_sid
    user_id = payload.get("user")
    if user_id:
        return f"user_{user_id}"
    client_ip = request.client.host if request.client else "127.0.0.1"
    return f"default_session_{client_ip}"


def _generate_mock_shield_response(model: str, redaction_count: int, sanitized_messages: list, vault=None) -> Dict[str, Any]:
    """Generates a structured, OpenAI-compatible assistant response demonstrating privacy sanitization."""
    last_user_msg = ""
    for m in reversed(sanitized_messages):
        if m.get("role") == "user":
            content_val = m.get("content", "")
            if isinstance(content_val, str):
                last_user_msg = content_val
            elif isinstance(content_val, list):
                last_user_msg = " ".join([p.get("text", "") for p in content_val if isinstance(p, dict)])
            break

    sanitized_preview = last_user_msg[:160] + ("..." if len(last_user_msg) > 160 else "")
    summary = (
        f"Protected {redaction_count} sensitive token(s)"
        if redaction_count > 0
        else "Zero confidential leaks detected"
    )

    reply_text = (
        f"🛡️ **[Veil Privacy Gateway]**\n\n"
        f"Prompt successfully intercepted and sanitized under active policy (**{settings.POLICY.value}**).\n\n"
        f"• **Inspection Outcome**: {summary}\n"
        f"• **Sanitized Inbound Context**: `{sanitized_preview}`\n\n"
        f"✅ *Your prompt was safely verified before reaching external model networks. To route prompts to a live OpenAI, Anthropic, or Ollama model, configure `UPSTREAM_API_KEY` in your `.env` or IDE settings.*"
    )

    return {
        "id": f"chatcmpl-veil-{int(time.time())}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model or "veil-privacy-shield",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": reply_text
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": max(1, len(last_user_msg) // 4),
            "completion_tokens": len(reply_text) // 4,
            "total_tokens": max(1, len(last_user_msg) // 4) + (len(reply_text) // 4)
        }
    }


async def _generate_mock_shield_stream(model: str, redaction_count: int, sanitized_messages: list, vault=None):
    """Streams the mock privacy shield response as Server-Sent Events (SSE)."""
    res_obj = _generate_mock_shield_response(model, redaction_count, sanitized_messages, vault)
    content = res_obj["choices"][0]["message"]["content"]
    cmpl_id = res_obj["id"]

    init_chunk = {
        "id": cmpl_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": None}]
    }
    yield f"data: {json.dumps(init_chunk)}\n\n".encode("utf-8")

    words = content.split(" ")
    for i, word in enumerate(words):
        chunk_text = word + (" " if i < len(words) - 1 else "")
        chunk = {
            "id": cmpl_id,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model,
            "choices": [{"index": 0, "delta": {"content": chunk_text}, "finish_reason": None}]
        }
        yield f"data: {json.dumps(chunk)}\n\n".encode("utf-8")
        await asyncio.sleep(0.01)

    finish_chunk = {
        "id": cmpl_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
    }
    yield f"data: {json.dumps(finish_chunk)}\n\n".encode("utf-8")
    yield b"data: [DONE]\n\n"


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """OpenAI-compatible chat completions proxy endpoint with fail-closed privacy inspection."""
    start_time = time.perf_counter()
    incoming_headers = dict(request.headers)
    payload: Dict[str, Any] = await request.json()
    is_stream = bool(payload.get("stream", False))
    model = payload.get("model", "unknown")

    session_id = resolve_session_id(request, payload)
    vault = vault_manager.get_session(session_id)

    # ------------------ Inbound Inspection & Redaction ------------------
    messages = payload.get("messages", [])
    redaction_count = 0
    detected_entities = []

    try:
        # If gateway is not paused, execute fail-closed inspection and token redaction
        if not metrics_state["is_paused"] and messages:
            sanitized_messages, redaction_count = redactor.redact_chat_messages(
                messages=messages,
                pipeline=inspection_pipeline,
                vault=vault
            )
            payload["messages"] = sanitized_messages
    except SecretDetectedException as sde:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        metrics_state["total_requests"] += 1
        metrics_state["total_blocks"] += 1
        privacy_event_bus.publish_sync("blocked", {
            "session_id": session_id,
            "model": model,
            "reason": "Outbound credentials blocked",
            "violations": [v["entity_type"] for v in sde.violations],
            "latency_ms": elapsed_ms
        })
        if settings.AUDIT_ENABLED:
            audit_ledger.record_receipt(
                session_id=session_id,
                provider="openai",
                model=model,
                policy=settings.POLICY.value,
                action_taken="BLOCKED",
                redaction_count=0,
                secret_blocked_count=len(sde.violations),
                entities_detected=[v["entity_type"] for v in sde.violations],
                latency_ms=elapsed_ms
            )
        raise sde
    except SemanticViolationException as sve:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        metrics_state["total_requests"] += 1
        metrics_state["total_blocks"] += 1
        privacy_event_bus.publish_sync("blocked", {
            "session_id": session_id,
            "model": model,
            "reason": f"Proprietary data blocked ({sve.violations[0]['category']})",
            "violations": [sve.violations[0]["category"]],
            "latency_ms": elapsed_ms
        })
        if settings.AUDIT_ENABLED:
            audit_ledger.record_receipt(
                session_id=session_id,
                provider="openai",
                model=model,
                policy=settings.POLICY.value,
                action_taken="BLOCKED_SEMANTIC",
                redaction_count=0,
                secret_blocked_count=1,
                entities_detected=[f"SEMANTIC:{v['category']}" for v in sve.violations],
                latency_ms=elapsed_ms
            )
        raise sve

    # Update metric counters & telemetry
    metrics_state["total_requests"] += 1
    if redaction_count > 0:
        metrics_state["total_redactions"] += redaction_count
        privacy_event_bus.publish_sync("redaction", {
            "session_id": session_id,
            "model": model,
            "redaction_count": redaction_count,
            "stream": is_stream
        })
    else:
        privacy_event_bus.publish_sync("clean_pass", {
            "session_id": session_id,
            "model": model,
            "stream": is_stream
        })



    # ------------------ Outbound Dispatch to Remote LLM ------------------
    if is_stream:
        try:
            raw_stream = openai_adapter.forward_stream(
                endpoint="chat/completions",
                headers=incoming_headers,
                payload=payload
            )
            restored_stream = (
                restorer.restore_sse_stream(raw_stream, vault)
                if not metrics_state["is_paused"]
                else raw_stream
            )
        except Exception:
            restored_stream = _generate_mock_shield_stream(model, redaction_count, payload.get("messages", []), vault)

        # Audit receipt for streaming prompt
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        if settings.AUDIT_ENABLED:
            audit_ledger.record_receipt(
                session_id=session_id,
                provider="openai",
                model=model,
                policy=settings.POLICY.value,
                action_taken="ALLOWED_REDACTED" if redaction_count > 0 else "ALLOWED_CLEAN",
                redaction_count=redaction_count,
                secret_blocked_count=0,
                entities_detected=[],
                latency_ms=elapsed_ms
            )

        return StreamingResponse(
            restored_stream,
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no"
            }
        )
    else:
        # Non-streaming standard response
        try:
            status_code, resp_headers, content = await openai_adapter.forward_request(
                endpoint="chat/completions",
                headers=incoming_headers,
                payload=payload
            )
            if status_code == 401 and not incoming_headers.get("authorization") and not openai_adapter.default_api_key:
                mock_data = _generate_mock_shield_response(model, redaction_count, payload.get("messages", []), vault)
                content = json.dumps(mock_data).encode("utf-8")
                status_code = 200
                resp_headers = {"content-type": "application/json", "content-length": str(len(content))}
        except Exception:
            mock_data = _generate_mock_shield_response(model, redaction_count, payload.get("messages", []), vault)
            content = json.dumps(mock_data).encode("utf-8")
            status_code = 200
            resp_headers = {"content-type": "application/json", "content-length": str(len(content))}

        # ------------------ Response Restoration ------------------
        if not metrics_state["is_paused"] and status_code == 200:
            content = restorer.restore_json_response(content, vault)
            resp_headers["content-length"] = str(len(content))

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        if settings.AUDIT_ENABLED:
            audit_ledger.record_receipt(
                session_id=session_id,
                provider="openai",
                model=model,
                policy=settings.POLICY.value,
                action_taken="ALLOWED_REDACTED" if redaction_count > 0 else "ALLOWED_CLEAN",
                redaction_count=redaction_count,
                secret_blocked_count=0,
                entities_detected=[],
                latency_ms=elapsed_ms
            )

        return Response(
            content=content,
            status_code=status_code,
            headers=resp_headers,
            media_type=resp_headers.get("content-type", "application/json")
        )


# ------------------ Phase 18: Anthropic Claude /v1/messages Ingress ------------------

@app.post("/v1/messages")
async def anthropic_messages(request: Request):
    """Anthropic Claude API messages proxy endpoint with fail-closed privacy inspection."""
    start_time = time.perf_counter()
    incoming_headers = dict(request.headers)
    payload: Dict[str, Any] = await request.json()
    is_stream = bool(payload.get("stream", False))
    model = payload.get("model", "claude-unknown")

    session_id = resolve_session_id(request, payload)
    vault = vault_manager.get_session(session_id)

    redaction_count = 0
    try:
        if not metrics_state["is_paused"]:
            payload, redaction_count = redactor.redact_anthropic_payload(
                payload=payload,
                pipeline=inspection_pipeline,
                vault=vault
            )
    except SecretDetectedException as sde:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        metrics_state["total_requests"] += 1
        metrics_state["total_blocks"] += 1
        privacy_event_bus.publish_sync("blocked", {
            "session_id": session_id,
            "model": model,
            "reason": "Outbound credentials blocked in Anthropic payload",
            "violations": [v["entity_type"] for v in sde.violations],
            "latency_ms": elapsed_ms
        })
        if settings.AUDIT_ENABLED:
            audit_ledger.record_receipt(
                session_id=session_id,
                provider="anthropic",
                model=model,
                policy=settings.POLICY.value,
                action_taken="BLOCKED_SECRET",
                redaction_count=0,
                secret_blocked_count=len(sde.violations),
                entities_detected=[v["entity_type"] for v in sde.violations],
                latency_ms=elapsed_ms
            )
        raise

    metrics_state["total_requests"] += 1
    metrics_state["total_redactions"] += redaction_count

    if redaction_count > 0:
        privacy_event_bus.publish_sync("redaction", {
            "session_id": session_id,
            "model": model,
            "entity_type": "Anthropic Payload",
            "placeholder": f"<{redaction_count} tokens redacted>",
            "stream": is_stream
        })

    if is_stream:
        raw_stream = anthropic_adapter.forward_stream(
            endpoint="messages",
            headers=incoming_headers,
            payload=payload
        )
        restored_stream = (
            restorer.restore_anthropic_sse_stream(raw_stream, vault)
            if not metrics_state["is_paused"]
            else raw_stream
        )
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        if settings.AUDIT_ENABLED:
            audit_ledger.record_receipt(
                session_id=session_id,
                provider="anthropic",
                model=model,
                policy=settings.POLICY.value,
                action_taken="ALLOWED_REDACTED" if redaction_count > 0 else "ALLOWED_CLEAN",
                redaction_count=redaction_count,
                secret_blocked_count=0,
                entities_detected=[],
                latency_ms=elapsed_ms
            )

        return StreamingResponse(
            restored_stream,
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "Connection": "keep-alive"}
        )
    else:
        status_code, resp_headers, content = await anthropic_adapter.forward_request(
            endpoint="messages",
            headers=incoming_headers,
            payload=payload
        )
        if not metrics_state["is_paused"] and status_code == 200:
            content = restorer.restore_anthropic_json_response(content, vault)
            resp_headers["content-length"] = str(len(content))

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        if settings.AUDIT_ENABLED:
            audit_ledger.record_receipt(
                session_id=session_id,
                provider="anthropic",
                model=model,
                policy=settings.POLICY.value,
                action_taken="ALLOWED_REDACTED" if redaction_count > 0 else "ALLOWED_CLEAN",
                redaction_count=redaction_count,
                secret_blocked_count=0,
                entities_detected=[],
                latency_ms=elapsed_ms
            )

        return Response(
            content=content,
            status_code=status_code,
            headers=resp_headers,
            media_type=resp_headers.get("content-type", "application/json")
        )


# ------------------ Phase 18: Ollama /api/chat and /api/generate Ingress ------------------

@app.post("/api/chat")
@app.post("/api/generate")
async def ollama_endpoint(request: Request):
    """Ollama local model proxy endpoint with fail-closed privacy inspection."""
    start_time = time.perf_counter()
    endpoint = request.url.path.lstrip("/")  # "api/chat" or "api/generate"
    incoming_headers = dict(request.headers)
    payload: Dict[str, Any] = await request.json()
    is_stream = bool(payload.get("stream", True))
    model = payload.get("model", "ollama-model")

    session_id = resolve_session_id(request, payload)
    vault = vault_manager.get_session(session_id)

    redaction_count = 0
    try:
        if not metrics_state["is_paused"]:
            payload, redaction_count = redactor.redact_ollama_payload(
                payload=payload,
                pipeline=inspection_pipeline,
                vault=vault
            )
    except SecretDetectedException as sde:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        metrics_state["total_requests"] += 1
        metrics_state["total_blocks"] += 1
        privacy_event_bus.publish_sync("blocked", {
            "session_id": session_id,
            "model": model,
            "reason": "Outbound credentials blocked in Ollama payload",
            "violations": [v["entity_type"] for v in sde.violations],
            "latency_ms": elapsed_ms
        })
        if settings.AUDIT_ENABLED:
            audit_ledger.record_receipt(
                session_id=session_id,
                provider="ollama",
                model=model,
                policy=settings.POLICY.value,
                action_taken="BLOCKED_SECRET",
                redaction_count=0,
                secret_blocked_count=len(sde.violations),
                entities_detected=[v["entity_type"] for v in sde.violations],
                latency_ms=elapsed_ms
            )
        raise

    metrics_state["total_requests"] += 1
    metrics_state["total_redactions"] += redaction_count

    if redaction_count > 0:
        privacy_event_bus.publish_sync("redaction", {
            "session_id": session_id,
            "model": model,
            "entity_type": "Ollama Payload",
            "placeholder": f"<{redaction_count} tokens redacted>",
            "stream": is_stream
        })

    if is_stream:
        raw_stream = ollama_adapter.forward_stream(
            endpoint=endpoint,
            headers=incoming_headers,
            payload=payload
        )
        restored_stream = (
            restorer.restore_ollama_stream(raw_stream, vault)
            if not metrics_state["is_paused"]
            else raw_stream
        )
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        if settings.AUDIT_ENABLED:
            audit_ledger.record_receipt(
                session_id=session_id,
                provider="ollama",
                model=model,
                policy=settings.POLICY.value,
                action_taken="ALLOWED_REDACTED" if redaction_count > 0 else "ALLOWED_CLEAN",
                redaction_count=redaction_count,
                secret_blocked_count=0,
                entities_detected=[],
                latency_ms=elapsed_ms
            )

        return StreamingResponse(
            restored_stream,
            media_type="application/x-ndjson",
            headers={"Cache-Control": "no-cache"}
        )
    else:
        status_code, resp_headers, content = await ollama_adapter.forward_request(
            endpoint=endpoint,
            headers=incoming_headers,
            payload=payload
        )
        if not metrics_state["is_paused"] and status_code == 200:
            content = restorer.restore_ollama_json_response(content, vault)
            resp_headers["content-length"] = str(len(content))

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        if settings.AUDIT_ENABLED:
            audit_ledger.record_receipt(
                session_id=session_id,
                provider="ollama",
                model=model,
                policy=settings.POLICY.value,
                action_taken="ALLOWED_REDACTED" if redaction_count > 0 else "ALLOWED_CLEAN",
                redaction_count=redaction_count,
                secret_blocked_count=0,
                entities_detected=[],
                latency_ms=elapsed_ms
            )

        return Response(
            content=content,
            status_code=status_code,
            headers=resp_headers,
            media_type="application/json"
        )

