"""Model Context Protocol (MCP) Server for Veil AI Privacy Gateway.

Exposes standard JSON-RPC 2.0 MCP tools over stdio to Antigravity IDE,
Claude Desktop, and any MCP-compliant agent platform.
"""
import sys
import json
import time
from typing import Dict, Any, List, Optional

from app.core.config import settings, PolicyLevel
from app.engine.pipeline import InspectionPipeline
from app.engine.redactor import Redactor
from app.vault.session_vault import vault_manager
from app.core.events import privacy_event_bus
from app.core.exceptions import SecretDetectedException, SemanticViolationException


class VeilMCPServer:
    """Stdio-based Model Context Protocol (MCP) server for real-time prompt privacy enforcement."""

    def __init__(self):
        self.pipeline = InspectionPipeline()
        self.redactor = Redactor()
        self.session_id = f"mcp_antigravity_{int(time.time())}"
        self.vault = vault_manager.get_session(self.session_id)

    def get_tools(self) -> List[Dict[str, Any]]:
        """Returns the schema of privacy tools available to the AI agent."""
        return [
            {
                "name": "veil_inspect_prompt",
                "description": (
                    "Inspect and sanitize any user prompt, file snippet, or sensitive context before sending "
                    "it to an external LLM. Detects and redacts PII (emails, phone numbers, IP addresses, SSNs, credit cards), "
                    "detects Shannon entropy credential leaks, and blocks API keys and secrets fail-closed."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "The raw text, prompt, or code snippet to inspect and sanitize."
                        },
                        "policy": {
                            "type": "string",
                            "enum": ["STRICT", "BALANCED", "PERMISSIVE"],
                            "description": "Optional privacy policy level. Defaults to active Veil gateway policy.",
                            "default": settings.POLICY.value
                        }
                    },
                    "required": ["text"]
                }
            },
            {
                "name": "veil_restore_response",
                "description": (
                    "Restore sanitized placeholders (such as [EMAIL_1], [PHONE_1]) in an AI model's response "
                    "back to their original confidential values using the secure local ephemeral session vault."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "The response text containing Veil vault placeholders to restore."
                        }
                    },
                    "required": ["text"]
                }
            },
            {
                "name": "veil_get_status",
                "description": (
                    "Check the active privacy policy tier, gateway status, and cumulative redaction statistics."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }
        ]

    def handle_inspect_prompt(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        text = arguments.get("text", "")
        policy_str = arguments.get("policy", settings.POLICY.value).upper()
        start_time = time.perf_counter()

        try:
            _, redact_spans = self.pipeline.inspect(text)
            sanitized_text, redaction_count = self.redactor.redact_text(
                text=text,
                spans=redact_spans,
                vault=self.vault
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            if redaction_count > 0:
                privacy_event_bus.publish_sync("redaction", {
                    "session_id": self.session_id,
                    "model": "antigravity_mcp",
                    "redaction_count": redaction_count,
                    "latency_ms": elapsed_ms
                })
            else:
                privacy_event_bus.publish_sync("clean_pass", {
                    "session_id": self.session_id,
                    "model": "antigravity_mcp",
                    "latency_ms": elapsed_ms
                })

            return {
                "action": "REDACTED" if redaction_count > 0 else "ALLOW",
                "blocked": False,
                "sanitized_text": sanitized_text,
                "redaction_count": redaction_count,
                "latency_ms": round(elapsed_ms, 2),
                "message": (
                    f"Successfully sanitized {redaction_count} sensitive tokens."
                    if redaction_count > 0
                    else "Prompt verified safe with zero privacy violations."
                )
            }

        except SecretDetectedException as sde:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            violations = [v["entity_type"] for v in sde.violations]
            privacy_event_bus.publish_sync("blocked", {
                "session_id": self.session_id,
                "model": "antigravity_mcp",
                "reason": "Hard credentials blocked fail-closed",
                "violations": violations,
                "latency_ms": elapsed_ms
            })

            return {
                "action": "BLOCKED",
                "blocked": True,
                "sanitized_text": None,
                "redaction_count": 0,
                "violations": violations,
                "latency_ms": round(elapsed_ms, 2),
                "message": "FAIL-CLOSED: Hard credentials detected in payload. Transmission blocked by Veil privacy policy."
            }

        except SemanticViolationException as sve:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            category = sve.violations[0]["category"]
            privacy_event_bus.publish_sync("blocked", {
                "session_id": self.session_id,
                "model": "antigravity_mcp",
                "reason": f"Proprietary business data blocked ({category})",
                "violations": [category],
                "latency_ms": elapsed_ms
            })

            return {
                "action": "BLOCKED",
                "blocked": True,
                "sanitized_text": None,
                "redaction_count": 0,
                "violations": [category],
                "latency_ms": round(elapsed_ms, 2),
                "message": f"FAIL-CLOSED: Proprietary/confidential business data ({category}) blocked by Veil policy."
            }

    def handle_restore_response(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        text = arguments.get("text", "")
        # Restore placeholders from the session vault
        restored_text = self.vault.restore_text(text)
        return {
            "restored_text": restored_text,
            "session_id": self.session_id
        }

    def handle_get_status(self) -> Dict[str, Any]:
        return {
            "service": "Veil Privacy Gateway MCP",
            "version": "0.1.0",
            "policy": settings.POLICY.value,
            "fail_closed": settings.FAIL_CLOSED,
            "session_id": self.session_id,
            "vault_active_entries": len(self.vault._entries)
        }

    def process_rpc(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Dispatches an MCP JSON-RPC 2.0 message."""
        method = request.get("method")
        msg_id = request.get("id")
        params = request.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "veil-privacy-guard",
                        "version": "0.1.0"
                    },
                    "capabilities": {
                        "tools": {}
                    }
                }
            }

        if method == "notifications/initialized":
            return None

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": self.get_tools()
                }
            }

        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})

            if name == "veil_inspect_prompt":
                res = self.handle_inspect_prompt(arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": json.dumps(res, indent=2)}
                        ]
                    }
                }
            elif name == "veil_restore_response":
                res = self.handle_restore_response(arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": json.dumps(res, indent=2)}
                        ]
                    }
                }
            elif name == "veil_get_status":
                res = self.handle_get_status()
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": json.dumps(res, indent=2)}
                        ]
                    }
                }
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32601,
                        "message": f"Tool '{name}' not found."
                    }
                }

        # Method not found
        if msg_id is not None:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32601,
                    "message": f"Method '{method}' not implemented."
                }
            }
        return None

    def run_stdio(self):
        """Main stdio loop reading JSON-RPC lines from standard input and writing to standard output."""
        # Ensure utf-8 encoding on standard I/O streams
        if sys.platform == "win32":
            import io
            sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8")
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
                response = self.process_rpc(request)
                if response is not None:
                    sys.stdout.write(json.dumps(response) + "\n")
                    sys.stdout.flush()
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32700,
                        "message": f"Parse error: {str(e)}"
                    }
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()


def main():
    server = VeilMCPServer()
    server.run_stdio()


if __name__ == "__main__":
    main()
