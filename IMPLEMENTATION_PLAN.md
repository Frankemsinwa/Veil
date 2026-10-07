# Veil — Enterprise-Grade Local AI Privacy Gateway
## Production Implementation Blueprint & Roadmap

---

## 1. Executive Summary & Vision

**Veil** is a high-performance, fail-closed, local AI privacy proxy engineered to intercept, inspect, redact, and audit all outbound traffic to large language model (LLM) providers (OpenAI, Anthropic, Gemini, etc.) and seamlessly restore redacted tokens on the response path.

### Core Philosophy
1. **Defensible Privacy, Not Untestable Anonymity:** Veil acts as an auditable local Data Loss Prevention (DLP) layer. It guarantees that specific categories of sensitive data (PII, credentials, proprietary infrastructure markers) never physically leave the local machine.
2. **Deterministic-First, ML-Second:** Regex, entropy analysis, and compiled rule engines form the non-negotiable security boundary. Local SLMs (Small Language Models) serve strictly as auxiliary semantic classifiers, never as arbiters of secrets.
3. **Fail-Closed by Design:** If any inspection engine, token vault, or cryptographic routine errors or times out, the request is terminated with a structured security violation (HTTP 422/500). Outbound leakage is mathematically impossible under failure conditions.
4. **Zero Plaintext Footprint:** Mappings between sensitive tokens and synthetic placeholders are encrypted at rest with authenticated ciphers (AES-256-GCM / ChaCha20-Poly1305), stored in-memory with strict session TTLs, and zeroized upon eviction.

---

## 2. High-Level Architecture

```
                  ┌──────────────────────────────────────────────┐
                  │          Client Application / IDE            │
                  │   (Cursor, Ollama Client, LangChain, CLI)    │
                  └──────────────────────┬───────────────────────┘
                                         │ HTTP / SSE Stream
                                         ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        VEIL PRIVACY GATEWAY                            │
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │ 1. Ingress & Schema Normalization (OpenAI / Anthropic Schemas)  │   │
│   └──────────────────────────────┬─────────────────────────────────┘   │
│                                  │                                     │
│   ┌──────────────────────────────▼─────────────────────────────────┐   │
│   │ 2. Fail-Closed Pipeline Orchestrator                            │   │
│   │    - Circuit Breaker                                           │   │
│   │    - Timeouts & Memory Budget Enforcer                         │   │
│   └──────┬───────────────────────┬──────────────────────────┬──────┘   │
│          │                       │                          │          │
│   ┌──────▼──────┐         ┌──────▼──────┐            ┌──────▼──────┐   │
│   │ Regex Engine│         │ Shannon     │            │ AST & JSON  │   │
│   │ (PII/Tokens)│         │ Entropy     │            │ Structure   │   │
│   │ Hyperscan   │         │ Analyzer    │            │ Parser      │   │
│   └──────┬──────┘         └──────┬──────┘            └──────┬──────┘   │
│          │                       │                          │          │
│          └───────────────────────┼──────────────────────────┘          │
│                                  │ Matches & Spans                     │
│   ┌──────────────────────────────▼─────────────────────────────────┐   │
│   │ 3. Policy & Enforcement Engine                                 │   │
│   │    - BLOCK: API Keys, Private Keys, High-Entropy Passwords     │   │
│   │    - REDACT: Emails, Phones, Names, Custom Entities            │   │
│   │    - ALLOW: Whitelisted RFC Test Data & Safe Prompts           │   │
│   └──────────────────────────────┬─────────────────────────────────┘   │
│                                  │ Clean Text + Redaction Plan         │
│   ┌──────────────────────────────▼─────────────────────────────────┐   │
│   │ 4. Reversible Tokenizer & Ephemeral Token Vault                 │   │
│   │    - Request/Session-Scoped Isolated Namespaces                │   │
│   │    - AES-256-GCM Encrypted Key-Value Store                     │   │
│   │    - Automatic TTL Eviction & In-Memory Zeroization            │   │
│   └──────────────────────────────┬─────────────────────────────────┘   │
│                                  │ Sanitized Payload                   │
│   ┌──────────────────────────────▼─────────────────────────────────┐   │
│   │ 5. Outbound Provider Dispatcher (httpx Async)                  │   │
│   └──────────────────────────────┬─────────────────────────────────┘   │
└──────────────────────────────────┼─────────────────────────────────────┘
                                   │ HTTPS
                                   ▼
                   ┌───────────────────────────────┐
                   │    Remote AI Model Provider   │
                   │  (OpenAI / Claude / Gemini)   │
                   └───────────────┬───────────────┘
                                   │ Response / SSE Stream Chunks
                                   ▼
┌──────────────────────────────────┴─────────────────────────────────────┐
│ 6. Response Reconstruction & Restoration Engine                        │
│    - Sliding-Window Ring Buffer for Split-Token Chunk Assembly         │
│    - Deterministic Vault Lookup & Decryption                           │
│    - Streaming Re-emission to Client without Latency Spikes            │
│                                                                        │
│ 7. Audit & Compliance Ledger                                           │
│    - Append-Only SQLite with HMAC Hash-Chaining                        │
│    - Redaction Receipts (Zero Plaintext Logged by Default)             │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ De-redacted Stream
                                   ▼
                  ┌──────────────────────────────────────────────┐
                  │                 Local User                   │
                  └──────────────────────────────────────────────┘
```

---

## 3. Technology Stack & Component Selection

| Layer | Selected Tech | Justification / Industry Standard |
| :--- | :--- | :--- |
| **Language & Runtime** | Python 3.11+ / PyPy (or Rust core via PyO3 for ultra-low latency) | Fast development, extensive cryptographic bindings, native async I/O. |
| **API Framework** | FastAPI + Uvicorn (uvloop) | Native ASGI async streaming support, high throughput, robust OpenAPI schema validation. |
| **HTTP Client** | `httpx` (AsyncClient) | HTTP/2 and SSE streaming support with connection pooling and SSL verification. |
| **Pattern Matching** | Python `re` + compiled Hyperscan / re2 wrappers | Linear-time regex execution; eliminates ReDoS vulnerabilities when scanning mega-prompts. |
| **Entropy Analysis** | Custom Shannon Entropy implementation | Pinpoints arbitrary passwords, API secrets, and connection strings without predefined regexes. |
| **Cryptography** | `cryptography` (hazmat AES-256-GCM / ChaCha20-Poly1305) | FIPS/NIST compliant, constant-time operations, authenticated encryption. |
| **Local Storage / Vault** | In-Memory Cache with TTL + Encrypted SQLite for persistent audit | In-memory operations avoid disk I/O bottlenecks; encrypted SQLite ensures audit tamper-evidence. |
| **Configuration** | Pydantic V2 Settings + Argon2id key derivation | Strongly-typed configuration with secure master password derivation. |
| **Test Framework** | `pytest`, `hypothesis` (property-based), `locust` (load testing) | Rigorous edge-case coverage and benchmarking under continuous load. |

---

## 4. Phase-by-Phase Production Roadmap

### Phase 1: Threat Model, Policies & Redaction Specifications
- **Objective:** Establish the formal mathematical and security boundaries of Veil.
- **Deliverables:**
  - Define policy tiers: `STRICT` (all PII redacted, secrets blocked, fail-closed), `BALANCED` (PII redacted, dev IPs allowed), `PERMISSIVE` (audit-only).
  - Define entity taxonomy:
    - **BLOCK (Severity 1):** Private Keys (RSA/EC/Ed25519), SSH Keys, AWS/GCP/Azure credentials, JWTs, OpenAI/Anthropic/GitHub tokens, high-entropy passwords.
    - **REDACT (Severity 2):** Email addresses, Phone numbers (E.164 & national formats), IPv4/IPv6 addresses, Physical addresses, SSNs/National IDs, Person names (NER).
    - **ALLOW (Whitelisted):** RFC 5737 test IPs (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), `127.0.0.1`, RFC 2606 domain names (`example.com`, `test.com`), generic mock numbers (`555-0100..0199`).

### Phase 2: Project Architecture & Environment Initialization
- **Objective:** Stand up the production-ready directory structure with linting, typing, and packaging.
- **Directory Layout:**
  ```text
  veil/
  ├── app/
  │   ├── __init__.py
  │   ├── main.py                     # ASGI application entrypoint
  │   ├── core/
  │   │   ├── config.py               # Pydantic v2 settings
  │   │   ├── exceptions.py           # Structured security exceptions
  │   │   └── circuit_breaker.py      # Fail-closed guardrails
  │   ├── engine/
  │   │   ├── pipeline.py             # Orchestration pipeline
  │   │   ├── regex_scanner.py        # Hyperscan/re2 pattern matcher
  │   │   ├── entropy_scanner.py      # Shannon entropy detector
  │   │   ├── ast_filter.py           # Code/JSON AST awareness
  │   │   └── policy_engine.py        # Action decider (ALLOW/REDACT/BLOCK)
  │   ├── vault/
  │   │   ├── crypto.py               # AES-256-GCM envelope encryption
  │   │   ├── session_store.py        # Session-aware token mapping with TTL
  │   │   └── memory_zeroizer.py      # Secure memory sanitization
  │   ├── restoration/
  │   │   ├── buffer.py               # Sliding-window stream token restorer
  │   │   └── restorer.py             # Full-payload restorer
  │   ├── providers/
  │   │   ├── base.py                 # Abstract provider adapter
  │   │   ├── openai_adapter.py       # OpenAI completions & chat adapter
  │   │   └── anthropic_adapter.py    # Anthropic Claude adapter
  │   ├── audit/
  │   │   ├── logger.py               # Cryptographic tamper-evident logger
  │   │   └── schema.py               # Audit receipt schemas
  │   └── cli/
  │       └── cli.py                  # Typer / Click management CLI
  ├── tests/
  │   ├── corpus/                     # Real-world leaked secrets, PII, and code
  │   ├── unit/
  │   ├── integration/
  │   └── performance/
  ├── pyproject.toml
  ├── Dockerfile
  └── README.md
  ```

### Phase 3: The High-Throughput Pass-Through Proxy
- **Objective:** Deliver standard OpenAI-compatible `/v1/chat/completions` proxying with zero data alteration to establish the baseline.
- **Implementation:**
  - Support both non-streaming (`stream: false`) and Server-Sent Events (`stream: true`).
  - Pass through HTTP headers, auth tokens, status codes, and chunk framing accurately.
  - Measure baseline latency overhead ($< 5\text{ ms}$).

### Phase 4: Deterministic Detection Engine (Regex + Shannon Entropy)
- **Objective:** Detect secrets and PII with microsecond-level latency and zero external dependencies.
- **Implementation:**
  - **Pattern Matching:** Implement curated, high-accuracy regular expressions for:
    - Standard secrets: GitHub PATs, AWS Access Keys, OpenAI Keys (`sk-proj-...`), Slack Webhooks, Google API keys, JWTs, PEM-encoded private keys.
    - Standard PII: RFC 5322 Emails, E.164 phone formats, SSNs, Credit Cards (Luhn algorithm verified).
  - **Shannon Entropy Scanner:**
    $$H(X) = -\sum_{i=1}^n P(x_i) \log_2 P(x_i)$$
    Compute entropy on string literals $> 16$ characters with mixed character sets. Flag strings where $H(X) > 4.5$ as potential unclassified secrets.
  - **Span Collapser:** Merge overlapping and nested detections to prevent corrupted redaction offsets.

### Phase 5: Code & Structured Data AST Filtering
- **Objective:** Eliminate false positives inside code files, documentation, and mock data.
- **Implementation:**
  - Parse inbound messages to identify markdown code blocks (```` ```python ````, ```` ```json ````).
  - Verify if apparent emails or IPs are declared mock test constants (e.g., `user@example.com`, `localhost`, `10.0.0.0/8` private RFC 1918 space in safe contexts).
  - Ensure redaction preserves valid JSON/Python/SQL syntax so the remote model doesn't generate syntax-broken code.

### Phase 6: Fail-Closed Policy Enforcement Engine
- **Objective:** Enforce deterministic blocking and redaction actions before any request reaches the network.
- **Implementation:**
  - If any candidate matches a `BLOCK` rule: Immediately abort the request. Return HTTP 422 with a structured security receipt:
    ```json
    {
      "error": {
        "type": "security_violation",
        "code": "PROMPT_CONTAINS_SECRETS",
        "message": "Outbound prompt blocked by local Veil policy.",
        "details": [{"type": "OPENAI_API_KEY", "start": 142, "end": 193}]
      }
    }
    ```
  - If candidate matches `REDACT`: Enqueue for synthetic placeholder substitution.

### Phase 7: Reversible Tokenizer & Ephemeral Token Vault
- **Objective:** Substitute sensitive strings with type-tagged synthetic aliases and store reversible keys safely.
- **Implementation:**
  - Format placeholders deterministically: `[EMAIL_001]`, `[IP_001]`, `[PHONE_001]`.
  - **Multi-Turn Session Awareness:** Assign a `session_id` (derived from client headers or thread hash). Subsequent messages in the same conversation reuse identical placeholder mappings (`frank@example.com` is consistently `[EMAIL_001]` across turns 1 through $N$).
  - **Vault Encryption:** Encrypt in-memory mapping using AES-256-GCM with an ephemeral session key.
  - **TTL & Purge:** Implement active TTL expiration (default: 30 minutes of session inactivity) followed by explicit byte zeroization.

### Phase 8: Streaming Response Restoration Engine (Sliding-Window Buffer)
- **Objective:** Restore placeholders in real-time SSE streams without token fragmentation bugs.
- **Implementation:**
  - Problem: Provider streams chunks across arbitrary token boundaries (e.g., chunk 1: `[EM`, chunk 2: `AIL_`, chunk 3: `001]`).
  - Solution: A **Ring/Sliding-Window Character Buffer** of length $L = \max(\text{len}(\text{placeholder})) + 2$.
  - Stream chunks are pushed into the buffer. The buffer emits characters immediately until it detects the opening prefix `[`. It holds pending characters until the closing `]` is received or invalidated, resolves the placeholder against the local vault, and emits the restored text seamlessly.

### Phase 9: Tamper-Evident Audit & Compliance Logging
- **Objective:** Provide a verifiable security receipt for every prompt processed.
- **Implementation:**
  - Local SQLite database stored in protected user app data.
  - Audit record fields: `timestamp`, `session_id`, `provider`, `model`, `tokens_redacted_count`, `secrets_blocked_count`, `latency_ms`, `integrity_hmac`.
  - **Zero-Knowledge Principle:** Prompts and secret values are **NEVER** logged to disk. Only metadata, hashes, and entity counts are retained.

### Phase 10: Local ML Semantic Classifier (Completed)
- **Objective:** Detect contextual, non-regex sensitivity (e.g., "internal revenue projections", NDA-protected business memos, legal privilege).
- **Implementation Status:** [COMPLETED & VERIFIED]
  - Modular Classifier Architectures (`app/engine/semantic_classifier.py`):
    - `EmbeddedSemanticClassifier`: High-speed, zero-dependency contextual engine with linguistic density scoring, proximity clustering, and educational query false-positive suppression.
    - `OllamaSemanticClassifier`: Integration with local Ollama daemon SLMs with automatic fallback to embedded engine on failure or timeout.
    - `OnnxSemanticClassifier`: ONNX runtime interface with automatic fallback when weights or runtime are unavailable.
    - Unified `SemanticClassifier` facade with thread-safe LRU caching.
  - Data Models (`app/engine/semantic_models.py`):
    - Categories: `PROPRIETARY_BUSINESS_DATA`, `NDA_CONFIDENTIAL`, `LEGAL_PRIVILEGED`, `INTERNAL_INFRASTRUCTURE`, `SAFE_PUBLIC`.
    - Structured result: `SemanticClassificationResult` with confidence calibration, indicators, and rationale.
  - Policy Engine Integration (`app/engine/policy_engine.py`):
    - `evaluate_semantic()` method enforcing tier rules:
      - `STRICT`: Blocks high-confidence proprietary and confidential data via `SemanticViolationException` (HTTP 422).
      - `BALANCED`: Blocks NDA/Legal secrets while allowing business figures with advisory notices.
      - `PERMISSIVE`: Emits advisory receipts without blocking.
  - Invariant Verification: Deterministic-first rule strictly enforced in `InspectionPipeline.inspect_semantic()` (regex/entropy credentials block before semantic ML executes).
  - CLI & Proxy Integration: `veil scan` displays formatted semantic evaluation panels; `/v1/chat/completions` records semantic block receipts to HMAC audit ledger.
  - Test Suite: 12 comprehensive unit and integration tests in `tests/test_semantic_classifier.py` (100% passing).


### Phase 11: Production Hardening, Packaging & CLI (Completed)
- **Objective:** Deliver a turnkey single-binary or background daemon for Windows/Linux/macOS with production-grade diagnostics.
- **Implementation Status:** [COMPLETED & VERIFIED]
  - Comprehensive Diagnostic Suite (`app/core/doctor.py`):
    - Automated subsystem self-checks: AES-256-GCM authenticated cipher integrity, tamper rejection verification, memory zeroization check, SQLite audit ledger HMAC hash-chain verification, detection & semantic ML pipeline latency check, loopback binding & port collision detection, and upstream AI provider reachability test.
    - `veil doctor`: CLI command rendering formatted subsystem assessment tables and system health verdict panels.
  - Secondary Log Scrubber (`app/core/log_scrubber.py`):
    - Fulfills Security Invariant 4: `VeilLogScrubber` logging filter scrubbing API keys, tokens, emails, and credit cards from stdout and log sinks during runtime.
  - Latency & ReDoS Profiling Suite (`app/core/benchmark.py`):
    - `veil benchmark`: Profiles throughput (2,200+ prompts/sec, 180,000+ chars/sec), latency distributions (p50: 0.21ms, mean: 0.43ms), and verifies linear-time ReDoS immunity on 50,000-character adversarial inputs.
  - Production CLI Commands (`app/cli.py`):
    - `veil start --port 8080 --policy strict`: Runs daemon with fail-closed guardrails.
    - `veil doctor`: Runs deep diagnostic self-check.
    - `veil scan <prompt>`: Interactive deterministic and contextual semantic inspection.
    - `veil audit --tail 50`: Displays tamper-evident receipt trail with HMAC verification.
    - `veil policy [strict|balanced|permissive]`: View and switch active privacy policy tier.
    - `veil status`: Full configuration and invariant display.
  - Turnkey Packaging & Distribution:
    - `pyproject.toml`: Registered `[project.scripts]` entry point (`veil = "app.cli:cli"`).
    - `Dockerfile`: Multi-stage, minimal, non-root user (`veiluser`), container healthcheck.
    - `docker-compose.yml`: Turnkey local orchestration service.
    - `build_binary.py`: Standalone single-executable builder via PyInstaller.
  - Automated Tests: 10 new tests in `tests/test_production_hardening.py` (total 41 tests passing across the entire project).


---

## 5. Enterprise Desktop Product Evolution (Phases 12 — 16) [COMPLETED & VERIFIED]

Detailed production blueprint and architectural specifications are maintained in [PRODUCT_IMPLEMENTATION_PLAN.md](file:///c:/Users/frank/OneDrive/Desktop/Veil/PRODUCT_IMPLEMENTATION_PLAN.md).

- **Phase 12: Client Auto-Detection & Safe Configuration Engine** [COMPLETED]
  - Auto-discovers Cursor, VS Code (Continue/Cline), Claude Code CLI, Aider, and Windows Registry System ENV.
  - Implements 1-click proxy routing with zero-corruption `.veil.bak` backups and atomic file mutation.
- **Phase 13: Real-Time Event Bus & Live Telemetry WebSocket** [COMPLETED]
  - High-speed async pub/sub streaming redacted tokens, blocked secrets, and HMAC audit receipts to connected UI clients.
  - REST control endpoints for 1-click connect, disconnect, and gateway pause/resume.
- **Phase 14: Enterprise Desktop Cockpit UI (Frontend)** [COMPLETED]
  - Premium dark-mode cockpit dashboard (HTML5/CSS3/Vanilla JS) with real-time telemetry stream, client cards, and latency gauges.
- **Phase 15: Native Desktop Window & System Tray Integration** [COMPLETED]
  - Seamless desktop experience via `pywebview` (Edge Chromium WebView2) and `pystray` system tray resident with native desktop notifications.
- **Phase 16: Windows Single-Binary Installer & `.exe` Packaging** [COMPLETED]
  - Turnkey `Veil.exe` single-file executable build pipeline via PyInstaller with zero Python prerequisite for end users.
  - Verified with 68 passing unit and integration tests across 11 test modules.

---

## 6. Security Invariants & Fail-Closed Guardrails

Every pull request and build must strictly obey these invariants:

1. **The Network Air-Gap Rule:** No network call to any external provider may be instantiated until the Pipeline Orchestrator certifies that the payload has undergone 100% of detection and redaction phases without error.
2. **Deterministic Fallback:** If any exception occurs during redaction or encryption, the transaction drops immediately. It never degrades to an uninspected pass-through.
3. **Zero Configuration Corruption:** Client configuration adapters must create immutable `.veil.bak` backups before modifying any files, and all writes must be atomic.
4. **ReDoS Immunity:** Every regex pattern must pass linear-time static analysis. No catastrophic backtracking patterns permitted.
5. **Log Sanitization:** Log sinks (stdout, files, error handlers) must pass through a secondary scrubber preventing decrypted secrets from being printed during debug runs.

