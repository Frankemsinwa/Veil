# Veil — Enterprise-Grade Local AI Privacy Gateway

<p align="center">
  <img src="packager/veil.ico" alt="Veil Guardian Mascot" width="128" height="128" />
</p>

<p align="center">
  <strong>Zero-Retention, Fail-Closed Security Gateway for AI Developer Toolchains</strong><br />
  Intercept, Inspect, Redact, and Audit Outbound LLM Prompts with Zero Cloud Egress
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Security_Grade-A%2B-brightgreen?style=flat-square" alt="Security Grade" />
  <img src="https://img.shields.io/badge/Architecture-Fail--Closed-red?style=flat-square" alt="Fail Closed" />
  <img src="https://img.shields.io/badge/Vault-AES--256--GCM_Ephemeral-blue?style=flat-square" alt="AES-256-GCM" />
  <img src="https://img.shields.io/badge/Compliance_Ledger-HMAC--SHA256_Chained-success?style=flat-square" alt="HMAC-SHA256" />
  <img src="https://img.shields.io/badge/Semantic_Defense-Local_ONNX_INT8-purple?style=flat-square" alt="Local ONNX INT8" />
  <img src="https://img.shields.io/badge/ReDoS_Immunity-Verified_Linear-orange?style=flat-square" alt="ReDoS Immunity" />
  <img src="https://img.shields.io/badge/Cloud_Egress-0%25_Zero_Telemetry-success?style=flat-square" alt="Zero Egress" />
  <img src="https://img.shields.io/badge/Windows-Portable_EXE_%7C_MSI_%7C_Setup-blueviolet?style=flat-square" alt="Windows" />
</p>

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Threat Model & Security Invariants](#threat-model--security-invariants)
3. [Architecture & Packet Flow](#architecture--packet-flow)
4. [Multi-Tier Inspection Engine](#multi-tier-inspection-engine)
5. [Supported AI Clients & Upstream Providers](#supported-ai-clients--upstream-providers)
6. [Packaging & Windows Distribution](#packaging--windows-distribution)
7. [Quickstart & Installation](#quickstart--installation)
8. [CLI Reference](#cli-reference)
9. [Enterprise Cockpit & Web UI](#enterprise-cockpit--web-ui)
10. [Cryptographic Specifications](#cryptographic-specifications)
11. [Compliance & Audit Verification](#compliance--audit-verification)
12. [Vulnerability Disclosure Policy (VDP)](#vulnerability-disclosure-policy-vdp)

---

## Executive Summary

As engineering organizations adopt AI coding assistants (Cursor, Continue, Claude Code, Aider, Antigravity, OpenCode), outbound prompts routinely transmit high-risk intellectual property across untrusted external networks. Sensitive assets exposed in prompt contexts include:

- **Proprietary Source Code & Architecture Artifacts**
- **Hardcoded Secrets & API Keys** (AWS, GitHub, Stripe, SSH private keys)
- **Personally Identifiable Information (PII)** (GDPR/HIPAA protected user data)
- **Corporate Knowledge & NDA-Restricted Project Names**

**Veil** is an on-device, fail-closed privacy proxy running locally at `http://127.0.0.1:8080`. Veil drops directly into existing developer workflows by exposing standard OpenAI and Anthropic compatible APIs. It evaluates outbound payloads through a high-speed deterministic and local semantic defense pipeline, substitutes sensitive entities with reversible pseudonymous tokens, forwards sanitized prompts to remote LLM providers, and reconstructs the original entities in real time across streaming Server-Sent Events (SSE) responses.

**Result:** Developers retain full AI velocity while enterprise security teams enforce mathematically verifiable, zero-retention data sovereignty.

---

## Threat Model & Security Invariants

Veil operates under four non-negotiable security invariants:

| Security Invariant | Technical Implementation | Guarantee |
| :--- | :--- | :--- |
| **1. Fail-Closed Ingress** | Intercept pipeline wrapped in fail-closed exception barriers | Any scanner timeout, parsing error, or vault failure aborts outbound network dispatch immediately (`500/403`). Zero uninspected prompts leave the host. |
| **2. Zero-Retention Memory Vault** | Ephemeral `AES-256-GCM` in-memory key-value vault with OS CSPRNG keys (`os.urandom(32)`) | Token mappings exist only in process RAM and are destroyed automatically upon session TTL expiration (default: 30 minutes). Zero plaintext prompts or credentials touch disk. |
| **3. 100% Local Inference** | CPU-quantized INT8 `all-MiniLM-L6-v2` ONNX pipeline + binary vector index | Semantic proprietary data detection operates completely offline. No embeddings or prompt fragments are transmitted to external vector search APIs. |
| **4. Cryptographic Ledger Immutability** | SQLite compliance ledger with chained `HMAC-SHA256` digest records | Receipts record redaction counts, latency, and rule triggers without logging raw prompt text. Any historical modification invalidates the hash chain. |

---

## Architecture & Packet Flow

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                      DEVELOPER WORKSPACE (HOST)                        │
 │                                                                        │
 │  ┌───────────────────┐    ┌────────────────────┐    ┌───────────────┐  │
 │  │ Cursor / Continue │    │ Claude Code / Aider│    │  Antigravity  │  │
 │  └─────────┬─────────┘    └─────────┬──────────┘    └───────┬───────┘  │
 │            │                        │                       │          │
 │            └────────────────────────┼───────────────────────┘          │
 │                                     ▼                                  │
 │                      http://127.0.0.1:8080/v1/...                      │
 └─────────────────────────────────────┬──────────────────────────────────┘
                                       │
                                       ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                      VEIL PRIVACY GATEWAY (LOCAL)                      │
 │                                                                        │
 │  [1] INGRESS & AUTHENTICATION VALIDATOR                                │
 │      └── OpenAI / Anthropic format parser                              │
 │                                                                        │
 │  [2] MULTI-TIER INSPECTION PIPELINE (<0.4ms)                           │
 │      ├── Stage A: Deterministic Regex (API Keys, PII, Tokens)          │
 │      ├── Stage B: Shannon Entropy Anomaly Scanner (H(X) >= 4.2)        │
 │      ├── Stage C: Local ONNX Vector Guardrail (Semantic Similarity)    │
 │      └── Stage D: Custom Corporate Knowledge Vault                     │
 │                                                                        │
 │  [3] POLICY DECISION ENGINE                                            │
 │      ├── ALLOW: Forward unchanged                                      │
 │      ├── REDACT: Substitute with [EMAIL_001], [KEY_001]                │
 │      └── BLOCK: Reject immediately (Strict mode / Secrets detected)    │
 │                                                                        │
 │  [4] EPHEMERAL IN-MEMORY VAULT                                         │
 │      └── AES-256-GCM encrypted token-to-plaintext mapping              │
 │                                                                        │
 │  [5] CRYPTOGRAPHIC AUDIT LEDGER                                        │
 │      └── Append-only HMAC-SHA256 chained transaction receipt           │
 └───────────────────────┬────────────────────────▲───────────────────────┘
                         │                        │
       Sanitized Payload │                        │ Streaming SSE Response
       (Redacted Tokens) │                        │ (Chunks Reconstructed)
                         ▼                        │
 ┌────────────────────────────────────────────────┴───────────────────────┐
 │                       UPSTREAM REMOTE PROVIDERS                        │
 │                                                                        │
 │   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    │
 │   │  OpenAI API     │    │  Anthropic API  │    │  Ollama (Local) │    │
 │   └─────────────────┘    └─────────────────┘    └─────────────────┘    │
 └────────────────────────────────────────────────────────────────────────┘
```

---

## Multi-Tier Inspection Engine

Veil executes a multi-layered defense-in-depth pipeline on every prompt payload:

### 1. Deterministic ReDoS-Safe Pattern Scanner
- **Coverage:** High-risk credentials (AWS Access Keys, GitHub Personal Access Tokens, Stripe Live Keys, OpenAI API Keys, Google AI Studio Keys, Slack Webhooks, RSA/SSH Private Keys) and PII (RFC 5322 Emails, E.164 Phone Numbers, IPv4/IPv6 Addresses, Credit Cards).
- **Algorithmic Hardening:** Pure linear regex patterns with explicit string length bounding to guarantee strict immunity against Catastrophic Backtracking ($O(n)$ complexity).

### 2. Shannon Entropy Anomaly Detection
- Computes character distribution entropy over alphanumeric token slices:
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
- Detects arbitrary high-entropy cryptographic keys, database passwords, and base64/hex secrets ($H(X) \ge 4.2$) that evade static regex signatures.

### 3. Local ONNX INT8 Quantized Vector Guardrails
- **Model:** Quantized `all-MiniLM-L6-v2` packaged locally (`data/models/semantic/model_quantized.onnx`).
- **Inference:** Run on local CPU via `onnxruntime` with fast Rust-based tokenization.
- **Matching:** Calculates cosine similarity against a local corporate knowledge vault (`data/knowledge_vault.bin`).
- **Performance:** Sub-millisecond vector encoding with zero network telemetry.

### 4. Custom Corporate Dictionary
- Enables security teams to define proprietary project code names, unreleased product specs, internal domains, and client identifiers (`data/corporate_dictionary.json`).
- Automatically tags and applies configured policy actions (Redact or Block).

### 5. Sliding-Window Streaming Token Restorer
- LLM streaming responses deliver tokens via Server-Sent Events (SSE). When replacement tokens are fragmented across chunk boundaries (e.g. `[EM` in chunk 1, `AIL_` in chunk 2, `001]` in chunk 3), Veil's ring buffer reconstitutes the stream without dropping characters or corrupting SSE framing.

---

## Supported AI Clients & Upstream Providers

Veil includes a zero-corruption configuration manager with atomic JSON/YAML backups and automatic rollback triggers.

### Supported AI Developer Clients

| Client | Configuration Target | Mode |
| :--- | :--- | :--- |
| **Cursor** | `.cursor/settings.json` / VSCode settings | 1-Click Connect / Disconnect |
| **Continue** | `~/.continue/config.json` | 1-Click Connect / Disconnect |
| **Claude Code** | `~/.claude.json` / `ANTHROPIC_BASE_URL` | 1-Click Connect / Disconnect |
| **Aider** | `~/.aider.conf.yml` | 1-Click Connect / Disconnect |
| **Antigravity** | `.gemini/antigravity-ide/config.json` | 1-Click Connect / Disconnect |
| **OpenCode** | `~/.config/opencode/config.json` | 1-Click Connect / Disconnect |
| **System Environment** | `HTTP_PROXY`, `OPENAI_BASE_URL` | Shell Export / Registry Hook |

### Supported Upstream Providers

- **OpenAI:** `api.openai.com` (GPT-4o, GPT-4-Turbo, o1, o3)
- **Anthropic:** `api.anthropic.com` (Claude 3.5 Sonnet, Claude 3.7 Sonnet)
- **Ollama:** `127.0.0.1:11434` (Local Llama 3, DeepSeek-R1, Mistral)
- **Custom / Enterprise Gateways:** Azure OpenAI, OpenRouter, vLLM, LiteLLM

---

## Packaging & Windows Distribution

Veil provides three release formats packaged for developers and enterprise IT teams:

```text
dist/
├── Veil.exe          # (79.7 MB) Standalone portable executable (Embedded ONNX + Web UI)
├── Veil.msi          # (79.5 MB) Native Windows Installer package (Enterprise GPO / Intune)
└── VeilSetup.exe     # (81.3 MB) Windows Setup wizard with Desktop shortcut & uninstaller
```

### 1. Standalone Portable Binary (`Veil.exe`)
- Requires no Python runtime or external dependencies.
- Embeds the quantized INT8 semantic vector model, UI static assets, and client logos.
- Supports both headless CLI daemon mode and native GUI window mode.

### 2. Windows Installer Package (`Veil.msi`)
- Standard Microsoft Windows Installer (MSI) database generated via `msilib`.
- Configured with `ALLUSERS=1` and standard GUID upgrade codes for silent enterprise rollout via Microsoft Intune, SCCM, or Active Directory Group Policy (GPO):
  ```powershell
  msiexec.exe /i Veil.msi /qn /norestart
  ```

### 3. Windows Setup Wizard (`VeilSetup.exe`)
- Compiled via Inno Setup 6.
- Provides graphical installation wizard, Start Menu shortcuts, optional Windows Startup background resident hook, and clean uninstaller with automatic client disconnect rollbacks:
  ```powershell
  VeilSetup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
  ```

### Building Packages from Source

```powershell
# 1. Build standalone executable
python packager/build_exe.py

# 2. Build Inno Setup installer
python packager/build_installer.py

# 3. Build Windows MSI package
python packager/build_msi.py
```

---

## Quickstart & Installation

### Option A: Run Standalone Executable

```powershell
# Launch Veil GUI Cockpit with System Tray resident
.\dist\Veil.exe gui

# Or run headless gateway on port 8080
.\dist\Veil.exe start --port 8080 --policy BALANCED
```

### Option B: Run from Python Source

```powershell
# Clone repository
git clone https://github.com/Frankemsinwa/Veil.git
cd Veil

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run self-check diagnostic
python -m app.cli doctor

# Start gateway
python -m app.cli start
```

---

## CLI Reference

Veil includes a CLI built with `typer` and `rich`.

### `veil start`
Launches the proxy daemon.
```powershell
python -m app.cli start --host 127.0.0.1 --port 8080 --policy STRICT
```
- `--host, -h`: Bind network address (Default: `127.0.0.1`).
- `--port, -p`: Listening port (Default: `8080`).
- `--policy`: Active policy tier (`STRICT`, `BALANCED`, `PERMISSIVE`).

### `veil gui`
Launches the native desktop application and system tray icon.
```powershell
python -m app.cli gui --port 8080
```

### `veil scan`
Inspects a payload locally without sending network packets.
```powershell
python -m app.cli scan "Export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY for user alice@finance.com"
```

### `veil doctor`
Executes an automated 7-point self-diagnostic on cryptography, audit ledger, port bindings, and detection engines.
```powershell
python -m app.cli doctor
```

### `veil benchmark`
Measures scanning throughput and verifies ReDoS immunity under heavy load.
```powershell
python -m app.cli benchmark --iterations 50
```

### `veil audit`
Inspects the cryptographically verifiable audit trail.
```powershell
python -m app.cli audit --limit 20 --verify
```

### `veil clients`
Lists detected IDEs, CLI assistants, and connection statuses.
```powershell
python -m app.cli clients
```

### `veil connect` / `veil disconnect`
Connects or restores an AI developer toolchain with automatic backup.
```powershell
# Connect Cursor to route through Veil
python -m app.cli connect cursor

# Disconnect and restore original configuration
python -m app.cli disconnect cursor

# Roll back all connected clients (emergency reset)
python -m app.cli disconnect-all
```

---

## Enterprise Cockpit & Web UI

Veil provides a responsive Web UI and native Desktop Cockpit accessible via browser at `http://127.0.0.1:8080` or via native window (`veil gui`):

- **Executive Security Dashboard:** Live counters for intercepted prompts, redacted PII tokens, blocked credentials, and average proxy latency.
- **Real-Time Traffic Interceptor:** Live stream of sanitized prompt requests showing exact token substitutions and confidence scores.
- **1-Click AI Client Management:** Visual toggles to connect/disconnect Cursor, Continue, Claude Code, Aider, Antigravity, and OpenCode.
- **Provider Routing Panel:** Configure OpenAI, Anthropic, or Ollama endpoints with secure API key storage.
- **Custom Corporate Dictionary:** Add and remove proprietary project names and NDA keywords directly from the interface.
- **System Tray Resident:** Minimize to tray with quick policy switching, status indicator, and 1-click gateway pause.

---

## Cryptographic Specifications

| Component | Standard | Specification |
| :--- | :--- | :--- |
| **Ephemeral Session Vault** | NIST SP 800-38D | `AES-256-GCM` with 256-bit key generated per session via `os.urandom(32)`, 96-bit unique IVs, and 128-bit authentication tags. |
| **Ledger HMAC Signature** | FIPS PUB 198-1 | `HMAC-SHA256` computed over `record_id \| timestamp \| client_ip \| action_taken \| redaction_count \| secret_blocked_count \| latency_ms`. |
| **Audit Hash Chaining** | Merkle-Damgård Construction | $H_n = \text{HMAC-SHA256}(K, H_{n-1} \parallel \text{Payload}_n)$ with genesis block verification. |
| **Entropy Baseline** | Shannon Information Theory | Alphabet size $|A| = 62$; Secret detection threshold $H(X) \ge 4.2$ bits/symbol. |
| **Vector Embeddings** | Sentence-Transformers | 384-dimensional dense vectors via INT8 quantized `all-MiniLM-L6-v2` ONNX model. |

---

## Compliance & Audit Verification

Veil is designed to satisfy compliance controls across major security frameworks:

- **SOC 2 Type II (Trust Services Criteria):** Demonstrates automated confidentiality and privacy controls at the network boundary.
- **HIPAA (§ 164.312 Technical Safeguards):** Guarantees zero Protected Health Information (PHI) transmission to unauthorized LLM endpoints.
- **GDPR (Article 25 & Article 32):** Privacy by Design and Default; guarantees zero persistent storage of user personal data.
- **ISO/IEC 27001 (Control A.8.12 Data Leakage Prevention):** Prevents unauthorized exfiltration of corporate code and trade secrets.

To verify audit log integrity against tampering:
```powershell
python -m app.cli audit --verify
```

---

## Vulnerability Disclosure Policy (VDP)

The Veil team welcomes responsible security disclosures from researchers and users.

- **Reporting Security Issues:** Please email disclosures to `frankemesinwa@gmail.com` with encrypted details or submit a confidential advisory on GitHub.
- **Response SLA:** Security reports receive an initial response within **24 hours**, with triage and patch timelines provided within **72 hours**.
- **Scope:** Privacy engine bypasses, cryptographic implementation flaws, local privilege escalations, ReDoS vulnerabilities, and client configuration corruption bugs.

---

<p align="center">
  <strong>Veil — Sovereign Local Privacy for the AI Generation</strong><br />
  Copyright &copy; 2026 Veil Security. Released under the Apache 2.0 License.
</p>
