# Veil Enterprise Desktop & 1-Click Client Integration Plan
## Production Blueprint: From Core Gateway to Turnkey Native Application

---

## 1. Executive Summary & Product Vision

**Veil** is evolving from a headless local privacy proxy into a **turnkey, enterprise-grade desktop security product**. 

### The Core Problem
Privacy and Data Loss Prevention (DLP) tools fail when configuration is manual. Developers and enterprise engineers use multiple disparate AI clients (Cursor, VS Code with Continue/Cline, Claude Code, Aider, LangChain, custom Python scripts). Asking engineers to manually locate hidden config files, tweak environment variables, or rewrite API base URLs introduces friction, leads to configuration errors, and prevents adoption.

### The Solution
A polished, single-executable native desktop cockpit that:
1. **Auto-discovers** all installed IDEs, terminal agents, and AI tools on the host system in milliseconds.
2. **Connects with 1-click**: Safely mutates the client's configuration to route AI traffic through Veil (`http://127.0.0.1:8080/v1`).
3. **Guarantees zero corruption**: Creates immutable backups (`.veil.bak`) and provides instant 1-click disconnection/rollback.
4. **Visualizes live data streams**: Displays an interactive, real-time telemetry feed showing redacted tokens, blocked credentials, and audit HMAC verification in flight.
5. **Runs silently in the background**: Lives in the system tray with automatic startup, health monitoring, and desktop notifications.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        VEIL DESKTOP COCKPIT                            │
│  [🛡️ Shield: ACTIVE]  [Policy: STRICT]  [Port: 8080]  [Tray: Enabled]  │
├────────────────────────────────────────────────────────────────────────┤
│  AUTO-DETECTED CLIENTS & AGENTS                                        │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ ⚡ Cursor IDE              Status: 🟢 Connected to Veil (v1/chat) │  │
│  │ Path: %APPDATA%/Cursor    Config: settings.json [Backed Up]      │  │
│  │ [ Disconnect & Rollback ]                                        │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ 🔷 VS Code (Continue.dev)  Status: ⚪ Detected (Direct to OpenAI)  │  │
│  │ Path: ~/.continue         Config: config.json                    │  │
│  │ [ 1-Click Route Through Veil ]                                   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ 💻 Claude Code CLI         Status: ⚪ Detected (Direct)           │  │
│  │ Path: ~/.claude.json      Env: ANTHROPIC_BASE_URL                │  │
│  │ [ 1-Click Route Through Veil ]                                   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ 🤖 Aider CLI               Status: ⚪ Detected (Direct)           │  │
│  │ Path: ~/.aider.conf.yml   Key: openai-api-base                   │  │
│  │ [ 1-Click Route Through Veil ]                                   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ 🌐 Global Terminal / Shell Status: ⚪ System Env Direct          │  │
│  │ Env: OPENAI_BASE_URL      Applies to LangChain/AutoGPT/Scripts   │  │
│  │ [ Set System-Wide Proxy ENV ]                                    │  │
│  └──────────────────────────────────────────────────────────────────┘  │
├────────────────────────────────────────────────────────────────────────┤
│  REAL-TIME PRIVACY STREAM & AUDIT FEED (WebSocket Telemetry)          │
│  • 13:41:02 [Cursor]   REDACTED: email -> [EMAIL_001] (Restored)       │
│  • 13:40:15 [Continue] BLOCKED: sk-proj-*** (Outbound Secret Halted)   │
│  • 13:38:50 [Aider]    CLEAN: 142 tokens passed (Audit HMAC #88)       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Technical Architecture & Component Hierarchy

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       VEIL DESKTOP APPLICATION                          │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ 1. Native Window Layer (PyWebView / Windows Edge Chromium)      │   │
│   │    - Frameless modern window, hardware-accelerated, dark mode   │   │
│   │    - Responsive HTML5/CSS3/Vanilla JS (No node_modules runtime) │   │
│   └──────────────────────────────┬──────────────────────────────────┘   │
│                                  │ WebSocket / REST API                 │
│   ┌──────────────────────────────▼──────────────────────────────────┐   │
│   │ 2. Local Host Gateway Daemon (FastAPI + Uvicorn)                │   │
│   │    - http://127.0.0.1:8080/v1/chat/completions (AI Proxy)       │   │
│   │    - http://127.0.0.1:8080/api/clients (Discovery & Control)   │   │
│   │    - ws://127.0.0.1:8080/ws/telemetry (Live Activity Stream)    │   │
│   └──────────────┬───────────────────────────────┬──────────────────┘   │
│                  │                               │                      │
│   ┌──────────────▼─────────────┐   ┌─────────────▼──────────────────┐   │
│   │ 3. Privacy Core Engine     │   │ 4. Client Adapter Engine       │   │
│   │    - Regex / Entropy AST   │   │    - CursorAdapter             │   │
│   │    - Semantic Classifier   │   │    - VSCodeContinueAdapter     │   │
│   │    - Vault & Buffer        │   │    - ClaudeCodeAdapter         │   │
│   │    - HMAC Audit Ledger     │   │    - AiderAdapter              │   │
│   │                            │   │    - SystemEnvAdapter          │   │
│   └────────────────────────────┘   └─────────────┬──────────────────┘   │
│                                                  │ Atomic File I/O      │
│                                    ┌─────────────▼──────────────────┐   │
│                                    │ 5. Target Client Configurations│   │
│                                    │    - %APPDATA%/Cursor/User/... │   │
│                                    │    - ~/.continue/config.json   │   │
│                                    │    - ~/.aider.conf.yml         │   │
│                                    │    - HKCU\Environment Registry │   │
│                                    └────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Client Auto-Discovery & Zero-Risk Mutation Specifications

To ensure enterprise stability, every client adapter strictly adheres to **Atomic File Operations** and **Zero-Corruption Rollback**:
- **Backup Invariant**: Before touching any configuration file, Veil writes a timestamped copy to `<path>.veil.bak`.
- **Atomic Write Invariant**: Writes are made to `<path>.tmp` followed by an atomic rename, preventing file truncation if interrupted.
- **Idempotent Connection**: Connecting multiple times never duplicates entries.
- **Clean Disconnect**: Disconnecting completely removes Veil's proxy routing and restores the user's prior configuration.

### Supported Client Adapters

#### 1. Cursor IDE Adapter (`cursor_adapter.py`)
- **Detection Paths (Windows)**:
  - `%APPDATA%\Cursor\User\settings.json`
  - Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Cursor`
- **Inspection Logic**: Checks if `settings.json` exists. Checks if `"openai.baseURL"` or `"cursor.general.customOpenAIBaseUrl"` points to `127.0.0.1:8080`.
- **Connect Mutation**:
  ```json
  {
    "openai.baseURL": "http://127.0.0.1:8080/v1",
    "cursor.general.customOpenAIBaseUrl": "http://127.0.0.1:8080/v1"
  }
  ```
- **Disconnect Mutation**: Removes Veil base URL keys or restores original from `.veil.bak`.

#### 2. VS Code + Continue Extension Adapter (`continue_adapter.py`)
- **Detection Path**: `%USERPROFILE%\.continue\config.json` or `%USERPROFILE%\.continue\config.ts`
- **Inspection Logic**: Reads models list inside `config.json`. Checks if `apiBase` points to Veil.
- **Connect Mutation**: Iterates configured models and patches `apiBase: "http://127.0.0.1:8080/v1"`.
- **Disconnect Mutation**: Restores previous `apiBase` (e.g. `https://api.openai.com/v1`).

#### 3. Claude Code CLI Adapter (`claude_code_adapter.py`)
- **Detection Paths**:
  - `%USERPROFILE%\.claude.json`
  - Global npm binary: `%APPDATA%\npm\claude.cmd` or `%LOCALAPPDATA%\Programs\claude\claude.exe`
- **Inspection Logic**: Checks `ANTHROPIC_BASE_URL` in config or user registry environment.
- **Connect Mutation**: Injects `ANTHROPIC_BASE_URL=http://127.0.0.1:8080/v1`.
- **Disconnect Mutation**: Clears `ANTHROPIC_BASE_URL`.

#### 4. Aider CLI Adapter (`aider_adapter.py`)
- **Detection Paths**:
  - `%USERPROFILE%\.aider.conf.yml`
  - Command availability: `where.exe aider`
- **Inspection Logic**: Reads YAML configuration file for `openai-api-base`.
- **Connect Mutation**: Sets `openai-api-base: http://127.0.0.1:8080/v1`.
- **Disconnect Mutation**: Removes the key or restores from backup.

#### 5. System Environment Adapter (`system_env_adapter.py`)
- **Detection**: Reads Windows User Environment via Registry (`HKCU\Environment`).
- **Target Variables**:
  - `OPENAI_BASE_URL` = `http://127.0.0.1:8080/v1`
  - `OPENAI_API_BASE` = `http://127.0.0.1:8080/v1`
- **Connect Mutation**: Sets Windows registry keys and broadcasts `WM_SETTINGCHANGE` so all newly opened terminals immediately route through Veil without reboot.
- **Disconnect Mutation**: Deletes the registry values and broadcasts change notification.

---

## 4. Phase-by-Phase Production Roadmap

### Phase 12: Client Auto-Detection & Safe Configuration Engine (Completed)
- **Objective**: Build the deterministic scanning, configuration patching, and rollback infrastructure for all local AI clients.
- **Implementation Status**: [COMPLETED & VERIFIED]
  - `app/clients/models.py`: Data models `ClientStatus`, `ClientType`, `ClientInfo`, `MutationResult`.
  - `app/clients/base.py`: Abstract `BaseClientAdapter` interface with atomic write utilities, comment-stripping JSON reader, and immutable `.veil.bak` backup/restore mechanics.
  - `app/clients/cursor.py`: Cursor IDE discoverer and injector (`settings.json` -> `openai.baseURL` / `cursor.general.customOpenAIBaseUrl`).
  - `app/clients/continue_ext.py`: VS Code Continue.dev configuration manager (`~/.continue/config.json`).
  - `app/clients/claude_code.py`: Claude Code CLI adapter (`~/.claude.json` -> `anthropicBaseUrl`).
  - `app/clients/aider.py`: Aider CLI configuration manager (`~/.aider.conf.yml` -> `openai-api-base`).
  - `app/clients/system_env.py`: Windows registry user environment injector (`HKCU\Environment` + `WM_SETTINGCHANGE` broadcast).
  - `app/clients/manager.py`: Centralized `ClientManager` facade with parallel scanning, `connect_client()`, `disconnect_client()`, and `disconnect_all()`.
  - `app/cli.py`: Added CLI commands `veil clients`, `veil connect <client_id>`, and `veil disconnect <client_id>`.
  - `tests/test_clients.py`: 8 comprehensive tests covering atomic write, comment stripping, each adapter's full connect/disconnect rollback cycle, manager orchestration, and CLI integration (100% passing).


### Phase 13: Real-Time Event Bus & Live Telemetry WebSocket (Completed)
- **Objective**: Stream live redactions, blocked secrets, and HMAC audit receipts from the gateway to UI clients in real time.
- **Implementation Status**: [COMPLETED & VERIFIED]
  - `app/core/events.py`: In-memory async pub/sub event broadcaster (`PrivacyEventBus`) with ring buffer history and non-blocking sync dispatch.
  - Telemetry event schemas: `TelemetryEvent`, `RedactionEvent`, `BlockedSecretEvent`, `TrafficMetricEvent`, `ClientStatusEvent`.
  - Integration into `main.py` request pipeline publishing live events on every inspection, block, and restoration.
  - WebSocket endpoint `/ws/telemetry` streaming live events to UI with zero CPU polling and clean duplex termination.
  - REST control endpoints:
    - `GET /api/clients`: Returns all detected clients, their installation path, and connection state.
    - `POST /api/clients/{id}/connect`: 1-click connect action.
    - `POST /api/clients/{id}/disconnect`: 1-click disconnect/rollback action.
    - `GET /api/metrics`: Aggregated gateway security metrics.
    - `POST /api/gateway/policy`: Change privacy policy mode (`strict` / `balanced`).
    - `POST /api/gateway/toggle`: Pause/resume the privacy gateway.
  - `tests/test_telemetry_and_api.py`: 7 comprehensive tests covering REST endpoints, WebSocket telemetry streaming, and metrics (100% passing).

### Phase 14: Enterprise Desktop Cockpit UI (Completed)
- **Objective**: Create a state-of-the-art, high-aesthetic dark-mode dashboard with zero external browser dependencies.
- **Implementation Status**: [COMPLETED & VERIFIED]
  - Embedded self-contained web assets in `app/ui/`:
    - `index.html`: Semantic, high-performance HTML5 cockpit with glassmorphic cards, pulsating status indicator, client auto-detection grid, live security terminal, and integration drawer.
    - `style.css`: Curated enterprise dark palette (`#080a0f` obsidian canvas, `#00f5a0` emerald glow, `#00f2fe` neon cyan accents, `#ff3366` crimson alerts), responsive layouts, smooth micro-interactions, and custom scrollbars.
    - `app.js`: Reactive WebSocket client managing live client cards, 1-click connect/disconnect triggers, auto-reconnection, feed filtering, and interactive privacy playground.
  - Server Integration in `app/main.py`:
    - Mounted `/static` directory for offline asset serving.
    - Served `/` and `/dashboard` endpoints with HTML responses.
    - Added `/api/test/sanitize` interactive sandbox endpoint for live prompt redaction and fail-closed secret blocking.
    - Integrated gateway pause bypass handling in `/v1/chat/completions`.
  - `tests/test_ui.py`: 5 tests validating HTML delivery, static assets, and sandbox secret blocking / PII redaction.
  - Full suite status: 61/61 tests passing across all suites.

### Phase 15: Native Desktop Window & System Tray Integration (Completed)
- **Objective**: Run Veil as a true desktop application with a native OS window and background system tray resident.
- **Implementation Status**: [COMPLETED & VERIFIED]
  - `app/gui/tray.py`: System tray resident via `pystray`:
    - Dynamic in-memory shield icon generation with state coloring (Active Emerald `#00f5a0`, Paused Amber `#ffb703`, Alert Crimson `#ff3366`).
    - Full right-click context menu: "Open Veil Cockpit", "Pause/Resume Gateway", "Enforcement Policy" submenu, "Rescan AI Clients", "Exit Veil".
    - Real-time event bus listener dispatching Windows native balloon notifications and flashing alert icon on blocked credentials.
  - `app/gui/window.py`: Native Edge Chromium WebView2 desktop window via `pywebview`:
    - Framed dark obsidian window (1180x780, min 960x640) pointing to `/dashboard`.
    - Window 'X' close interception minimizing gracefully to tray instead of abrupt termination.
  - `app/gui/runner.py`: Thread orchestrator managing Uvicorn daemon, health readiness polling, system tray, and native GUI loop.
  - `app/cli.py`: Added `veil gui` command.
  - `tests/test_gui.py`: 4 tests validating icon generation, window closing interception, tray menu, and runner initialization (100% passing).

### Phase 16: Windows Single-Binary Installer & `.exe` Packaging (Completed)
- **Objective**: Produce a turnkey `Veil.exe` installer and standalone binary that runs on any clean Windows machine without requiring Python.
- **Implementation Status**: [COMPLETED & VERIFIED]
  - `packaging/generate_ico.py`: Multi-resolution Windows `.ico` generation script producing `packaging/veil.ico` across 16x16, 32x32, 48x48, 64x64, 128x128, and 256x256 dimensions.
  - `app/entrypoint.py`: Unified binary entrypoint detecting whether user double-clicked `Veil.exe` (launches native desktop window + tray) or passed CLI commands in terminal (`scan`, `clients`, `connect`, `doctor`).
  - `packaging/veil.spec`: Production PyInstaller spec bundling FastAPI, Uvicorn ASGI internals, WebView2 bindings, Pystray, cryptographic primitives, and self-contained HTML/CSS/JS assets into a single executable.
  - `packaging/build_exe.py` & `build_binary.py`: Automated build pipeline generating and smoke-testing `dist/Veil.exe`.
  - `tests/test_packaging.py`: 3 tests validating icon generation, PyInstaller spec structure, and entrypoint delegation.
  - Full suite status: 68/68 tests passing across all 11 test modules.

### Phase 17: Windows Enterprise Installer (`VeilSetup.exe`) & Auto-Start Resident (Completed)
- **Objective**: Turn the standalone executable into an enterprise-grade Windows installer with desktop/start menu shortcuts, auto-start on boot registry controls, and safe uninstaller rollback.
- **Implementation Status**: [COMPLETED & VERIFIED]
  - `app/gui/autostart.py`: Windows registry auto-start manager (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`), enabling silent startup into the system tray on boot.
  - Tray & Cockpit Integration: Added "Start with Windows" dynamic checkmark menu in tray context menu and REST endpoints `GET /api/system/autostart` and `POST /api/system/autostart`.
  - `veil disconnect-all`: CLI uninstaller hook restoring all IDEs and agents from their `.veil.bak` backups.
  - `packaging/installer.iss`: Production Inno Setup script compiling `dist/VeilSetup.exe` with desktop shortcut, start menu group, automatic x64 installation, and uninstall execution hook.
  - `packaging/build_installer.py`: Automated installer builder finding `ISCC.exe` and compiling the setup wizard.
  - `tests/test_installer_and_autostart.py`: 6 tests covering registry toggle, REST endpoints, disconnect-all rollback, and Inno script structure (100% passing).
### Phase 18: Multi-Provider Ingress (Anthropic & Ollama) (Completed)
- **Objective**: Extend Veil's privacy interception and reversible token restoration beyond OpenAI schema to Anthropic Claude and local Ollama models.
- **Implementation Status**: [COMPLETED & VERIFIED]
  - `app/providers/anthropic_adapter.py`: Upstream adapter for Anthropic Claude (`/v1/messages`) handling headers (`x-api-key`, `anthropic-version`), non-streaming JSON, and SSE event streaming.
  - `app/providers/ollama_adapter.py`: Upstream adapter for local/remote Ollama instances (`/api/chat` and `/api/generate`) supporting newline-delimited JSON streaming.
  - `app/engine/redactor.py`:
    - `redact_anthropic_payload`: Inspects and redacts both `system` (string or text blocks) and `messages` array.
    - `redact_ollama_payload`: Inspects and redacts `prompt`, `system`, and `messages` structures.
  - `app/restoration/restorer.py`:
    - `restore_anthropic_json_response` & `restore_anthropic_sse_stream`: Reconstructs split tokens across `content_block_delta` events.
    - `restore_ollama_json_response` & `restore_ollama_stream`: Reconstructs split tokens across Ollama streaming JSON lines.
  - `app/main.py`: Mounted `/v1/messages`, `/api/chat`, and `/api/generate` with full fail-closed security barriers, live telemetry event publishing, and HMAC audit recording.
  - `tests/test_multi_provider.py`: 6 tests validating credential blocking, PII redaction, response restoration, and streaming token reconstruction for Anthropic and Ollama.
  - Full suite status: 80/80 tests passing across all 13 test modules.

---

## 5. Security & Stability Invariants

1. **Zero Configuration Corruption**: Under no circumstances may an adapter corrupt an IDE's config. If a JSON file cannot be parsed, Veil flags it as `PARSE_ERROR` and never overwrites it.
2. **Deterministic Rollback**: Disconnecting a client must restore the file to the exact byte state prior to connection using the `.veil.bak` receipt.
3. **Local Loopback Isolation**: The cockpit REST API, WebSocket telemetry, and gateway proxy bind strictly to `127.0.0.1`. Remote network access is forbidden.
4. **Fail-Closed on Unclean Exit**: If the desktop application crashes or is terminated, client proxy settings default safely or are alerted on restart.

---

## 6. Implementation Timeline & Milestone Deliverables

| Phase | Core Deliverable | Output Files |
| :--- | :--- | :--- |
| **Phase 12** | Client Auto-Discovery & Injector Engine | `app/clients/*.py`, `tests/test_clients.py` |
| **Phase 13** | WebSocket Telemetry & Client Control REST API | `app/core/events.py`, `app/main.py` updates |
| **Phase 14** | Enterprise Cockpit Dashboard UI | `app/ui/index.html`, `app/ui/style.css`, `app/ui/app.js` |
| **Phase 15** | Native Desktop Window & Tray Resident | `app/gui/tray.py`, `app/gui/window.py` |
| **Phase 16** | Standalone `Veil.exe` Single-Binary Packaging | `packaging/pyinstaller.spec`, `dist/Veil.exe` |
| **Phase 17** | Windows Enterprise Installer (`VeilSetup.exe`) | `packaging/installer.iss`, `app/gui/autostart.py` |
| **Phase 18** | Multi-Provider Ingress (Anthropic & Ollama) | `app/providers/*_adapter.py`, `app/main.py` |

---

## 7. Product Completion Status
All phases (Phase 12 through Phase 18) are fully implemented, integrated, and verified with 100% test coverage (**80 passing unit and integration tests**).

To compile the standalone Windows executable binary at any time, run:
```powershell
python packaging/build_exe.py
```

To compile the turnkey Windows installer (`dist/VeilSetup.exe`), run:
```powershell
python packaging/build_installer.py
```
