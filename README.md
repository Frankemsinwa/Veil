# Veil — Enterprise-Grade Local AI Privacy Gateway

Veil is a fail-closed, high-performance, local privacy proxy engineered to intercept, inspect, redact, and audit all outbound traffic to LLM providers (OpenAI, Anthropic, Gemini, etc.) and restore redacted tokens seamlessly on the response path.

## Key Capabilities

- **OpenAI-Compatible Ingress:** Exposes `http://127.0.0.1:8080/v1/chat/completions`. Works as a drop-in local proxy for Cursor, LangChain, Cline, and any OpenAI SDK client.
- **Fail-Closed Guarantee:** Outbound prompt transmission is blocked immediately if any privacy engine component or token vault encounters an error.
- **Dual-Layer Deterministic Detection:** High-speed, ReDoS-safe Regex scanners paired with **Shannon Entropy analysis** to catch arbitrary credentials and unclassified API keys ($H(X) \ge 4.2$).
- **Reversible Tokenizer:** PII (emails, phone numbers, IPs, credit cards) is substituted with deterministic placeholders (e.g. `[EMAIL_001]`, `[PHONE_001]`) outbound, and restored automatically inbound.
- **Streaming Response Reconstruction:** A sliding-window ring buffer seamlessly reassembles placeholder tokens split across Server-Sent Events (SSE) stream chunks (`[EM` ... `AIL_001]`).
- **Cryptographic Audit Ledger:** Append-only SQLite compliance ledger with **HMAC-SHA256 hash chaining** for verifiable tamper detection. Adheres strictly to the Zero-Knowledge principle (zero plaintext prompts stored to disk).
- **Session-Scoped Ephemeral Vault:** In-memory AES-256-GCM token encryption with automatic 30-minute TTL zeroization.

## Architecture

```text
Client (Cursor/SDK) ──> [ Veil Gateway: 8080 ] ──> Remote Provider (OpenAI)
                             │
            ┌────────────────┴─────────────────────────┐
            │ 1. Regex & Shannon Entropy Scanner       │
            │ 2. Policy Decider (ALLOW/REDACT/BLOCK)   │
            │ 3. Redactor + Ephemeral AES-256-GCM Vault│
            │ 4. SSE Stream Sliding-Window Restorer    │
            │ 5. HMAC-SHA256 Cryptographic Ledger      │
            └──────────────────────────────────────────┘
```

## CLI Reference

### 1. View System & Policy Status
```bash
python -m app.cli status
```

### 2. Inspect a Prompt Locally
```bash
python -m app.cli scan "Contact Alice at alice@finance.com with key sk-proj-1234567890abcdef1234567890abcdef12"
```

### 3. View Verifiable Audit Trail
```bash
python -m app.cli audit --limit 20 --verify
```

### 4. Launch the Gateway Daemon
```bash
python -m app.cli start --port 8080 --policy STRICT
```

### 5. Run Verification Test Suite
```bash
python -m pytest -v
```
