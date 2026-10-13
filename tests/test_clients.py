"""Tests for Phase 12: Client Auto-Detection & Safe Configuration Engine."""
import json
import pytest
from pathlib import Path
from typer.testing import CliRunner

from app.cli import cli
from app.clients.models import ClientStatus, ClientType
from app.clients.base import strip_json_comments
from app.clients.cursor import CursorAdapter
from app.clients.continue_ext import ContinueAdapter
from app.clients.claude_code import ClaudeCodeAdapter
from app.clients.aider import AiderAdapter
from app.clients.system_env import SystemEnvAdapter
from app.clients.manager import ClientManager
from app.clients.antigravity import AntigravityAdapter
from app.clients.opencode import OpenCodeAdapter


runner = CliRunner()


def test_strip_json_comments():
    raw_json = """
    {
        // Single line comment
        "theme": "dark", /* inline comment */
        "fontSize": 14,
    }
    """
    clean = strip_json_comments(raw_json)
    parsed = json.loads(clean)
    assert parsed["theme"] == "dark"
    assert parsed["fontSize"] == 14


def test_cursor_adapter_lifecycle(tmp_path):
    settings_file = tmp_path / "settings.json"
    initial_content = {"editor.tabSize": 4, "openai.baseURL": "https://api.openai.com/v1"}
    settings_file.write_text(json.dumps(initial_content), encoding="utf-8")

    adapter = CursorAdapter(config_path_override=settings_file)
    assert adapter.detect() is True

    status_before = adapter.get_status()
    assert status_before.status == ClientStatus.DETECTED
    assert status_before.has_backup is False

    # Connect
    res = adapter.connect("http://127.0.0.1:8080/v1")
    assert res.success is True
    assert res.new_url == "http://127.0.0.1:8080/v1"

    status_after = adapter.get_status()
    assert status_after.status == ClientStatus.CONNECTED
    assert status_after.has_backup is True

    updated_json = json.loads(settings_file.read_text(encoding="utf-8"))
    assert updated_json["openai.baseURL"] == "http://127.0.0.1:8080/v1"
    assert updated_json["cursor.general.customOpenAIBaseUrl"] == "http://127.0.0.1:8080/v1"

    # Disconnect (Rollback)
    disc_res = adapter.disconnect()
    assert disc_res.success is True
    assert adapter.get_status().status == ClientStatus.DETECTED

    rolled_back_json = json.loads(settings_file.read_text(encoding="utf-8"))
    assert rolled_back_json["openai.baseURL"] == "https://api.openai.com/v1"


def test_continue_adapter_lifecycle(tmp_path):
    config_file = tmp_path / "config.json"
    initial_config = {
        "models": [
            {"title": "GPT-4", "provider": "openai", "model": "gpt-4", "apiBase": "https://api.openai.com/v1"}
        ]
    }
    config_file.write_text(json.dumps(initial_config), encoding="utf-8")

    adapter = ContinueAdapter(config_path_override=config_file)
    assert adapter.detect() is True

    # Connect
    res = adapter.connect("http://127.0.0.1:8080/v1")
    assert res.success is True

    data = json.loads(config_file.read_text(encoding="utf-8"))
    assert data["models"][0]["apiBase"] == "http://127.0.0.1:8080/v1"
    assert data["models"][0]["apiKey"] == "veil-dev-token"
    assert adapter.get_status().status == ClientStatus.CONNECTED

    # Disconnect
    disc_res = adapter.disconnect()
    assert disc_res.success is True
    restored = json.loads(config_file.read_text(encoding="utf-8"))
    assert restored["models"][0]["apiBase"] == "https://api.openai.com/v1"


def test_claude_code_adapter_lifecycle(tmp_path):
    claude_file = tmp_path / ".claude.json"
    claude_file.write_text(json.dumps({"autoUpdaterStatus": "ok"}), encoding="utf-8")

    adapter = ClaudeCodeAdapter(config_path_override=claude_file)
    assert adapter.detect() is True

    # Connect
    res = adapter.connect("http://127.0.0.1:8080/v1")
    assert res.success is True

    data = json.loads(claude_file.read_text(encoding="utf-8"))
    assert data["anthropicBaseUrl"] == "http://127.0.0.1:8080/v1"

    # Disconnect
    disc_res = adapter.disconnect()
    assert disc_res.success is True
    restored = json.loads(claude_file.read_text(encoding="utf-8"))
    assert "anthropicBaseUrl" not in restored


def test_aider_adapter_lifecycle(tmp_path):
    aider_file = tmp_path / ".aider.conf.yml"
    aider_file.write_text("# Aider config\nmodel: gpt-4o\n", encoding="utf-8")

    adapter = AiderAdapter(config_path_override=aider_file)
    assert adapter.detect() is True

    # Connect
    res = adapter.connect("http://127.0.0.1:8080/v1")
    assert res.success is True

    content = aider_file.read_text(encoding="utf-8")
    assert "openai-api-base: http://127.0.0.1:8080/v1" in content

    # Disconnect
    disc_res = adapter.disconnect()
    assert disc_res.success is True
    restored = aider_file.read_text(encoding="utf-8")
    assert "openai-api-base" not in restored


def test_system_env_adapter_mock():
    mock_env = {}
    adapter = SystemEnvAdapter(mock_env=mock_env)
    assert adapter.detect() is True

    # Connect
    res = adapter.connect("http://127.0.0.1:8080/v1")
    assert res.success is True
    assert mock_env["OPENAI_BASE_URL"] == "http://127.0.0.1:8080/v1"
    assert mock_env["OPENAI_API_BASE"] == "http://127.0.0.1:8080/v1"
    assert adapter.get_status().status == ClientStatus.CONNECTED

    # Disconnect
    disc_res = adapter.disconnect()
    assert disc_res.success is True
    assert "OPENAI_BASE_URL" not in mock_env
    assert adapter.get_status().status == ClientStatus.DETECTED


def test_client_manager_orchestration(tmp_path):
    cursor_file = tmp_path / "settings.json"
    cursor_file.write_text("{}", encoding="utf-8")
    cursor_adapter = CursorAdapter(config_path_override=cursor_file)

    mock_env = {}
    env_adapter = SystemEnvAdapter(mock_env=mock_env)

    manager = ClientManager(adapters=[cursor_adapter, env_adapter])
    clients = manager.get_all_clients()
    assert len(clients) == 2

    # Connect cursor via manager
    res = manager.connect_client("cursor", "http://127.0.0.1:8080/v1")
    assert res.success is True

    status = manager.get_client("cursor").get_status()
    assert status.status == ClientStatus.CONNECTED

    # Disconnect all
    disc_all = manager.disconnect_all()
    assert "cursor" in disc_all
    assert disc_all["cursor"].success is True
    assert manager.get_client("cursor").get_status().status == ClientStatus.DETECTED


def test_cli_clients_command():
    result = runner.invoke(cli, ["clients"])
    assert result.exit_code == 0
    assert "Detected AI Clients & Proxy Status" in result.output
    assert "cursor" in result.output
    assert "system_env" in result.output


def test_antigravity_mcp_adapter_lifecycle(tmp_path):
    mcp_file = tmp_path / "mcp_config.json"
    mcp_file.write_text("{}", encoding="utf-8")
    adapter = AntigravityAdapter(config_path_override=mcp_file)

    assert adapter.detect() is True

    # Connect
    conn_res = adapter.connect("http://127.0.0.1:8080/v1")
    assert conn_res.success is True

    status = adapter.get_status()
    assert status.status == ClientStatus.CONNECTED

    # Verify mcp_config.json content
    mcp_data = json.loads(mcp_file.read_text(encoding="utf-8"))
    assert "veil-privacy-guard" in mcp_data["mcpServers"]
    assert "app.mcp_server" in mcp_data["mcpServers"]["veil-privacy-guard"]["args"]

    # Disconnect
    disc_res = adapter.disconnect()
    assert disc_res.success is True
    assert adapter.get_status().status == ClientStatus.DETECTED


def test_veil_mcp_server_protocol():
    from app.mcp_server import VeilMCPServer
    server = VeilMCPServer()

    # 1. Initialize
    init_resp = server.process_rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert init_resp["result"]["serverInfo"]["name"] == "veil-privacy-guard"

    # 2. Tools list
    tools_resp = server.process_rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tools = tools_resp["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "veil_inspect_prompt" in tool_names
    assert "veil_restore_response" in tool_names
    assert "veil_get_status" in tool_names

    # 3. Call inspect with secret -> BLOCKED
    secret_call = server.process_rpc({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "veil_inspect_prompt",
            "arguments": {"text": "My AWS key is AKIAIOSFODNN7EXAMPLE"}
        }
    })
    content = json.loads(secret_call["result"]["content"][0]["text"])
    assert content["action"] == "BLOCKED"
    assert content["blocked"] is True

    # 4. Call inspect with PII -> REDACTED
    pii_call = server.process_rpc({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "veil_inspect_prompt",
            "arguments": {"text": "Contact Sarah at sarah@corp.com"}
        }
    })
    pii_content = json.loads(pii_call["result"]["content"][0]["text"])
    assert pii_content["action"] == "REDACTED"
    assert pii_content["redaction_count"] >= 1
    assert "sarah@corp.com" not in pii_content["sanitized_text"]


def test_opencode_adapter_lifecycle(tmp_path):
    settings_file = tmp_path / "opencode_settings.json"
    initial_content = {
        "opencode.model": "gpt-4o",
        "openai.baseURL": "https://api.openai.com/v1"
    }
    settings_file.write_text(json.dumps(initial_content), encoding="utf-8")

    adapter = OpenCodeAdapter(config_path_override=settings_file)
    assert adapter.detect() is True

    status_before = adapter.get_status()
    assert status_before.status == ClientStatus.DETECTED
    assert status_before.has_backup is False

    # Connect to Veil gateway
    res = adapter.connect("http://127.0.0.1:8080/v1")
    assert res.success is True
    assert res.new_url == "http://127.0.0.1:8080/v1"

    status_after = adapter.get_status()
    assert status_after.status == ClientStatus.CONNECTED
    assert status_after.has_backup is True

    updated_json = json.loads(settings_file.read_text(encoding="utf-8"))
    assert updated_json["opencode.apiBase"] == "http://127.0.0.1:8080/v1"
    assert updated_json["openai.baseURL"] == "http://127.0.0.1:8080/v1"
    assert updated_json["api_base"] == "http://127.0.0.1:8080/v1"
    assert updated_json["opencode.apiKey"] == "veil-dev-token"
    assert updated_json["openai.apiKey"] == "veil-dev-token"

    # Disconnect / Rollback
    disc_res = adapter.disconnect()
    assert disc_res.success is True
    assert adapter.get_status().status == ClientStatus.DETECTED

    rolled_back_json = json.loads(settings_file.read_text(encoding="utf-8"))
    assert rolled_back_json["openai.baseURL"] == "https://api.openai.com/v1"
    assert "opencode.apiBase" not in rolled_back_json
    assert "opencode.apiKey" not in rolled_back_json
    assert "openai.apiKey" not in rolled_back_json


def test_client_manager_includes_opencode():
    mgr = ClientManager()
    opencode_client = mgr.get_client("opencode")
    assert opencode_client is not None
    assert opencode_client.name == "OpenCode IDE"
    assert opencode_client.client_type == ClientType.OPENCODE


def test_antigravity_rules_and_workspace_automation(tmp_path):
    """Verify Antigravity installs global rule, workspace rule, settings, and MCP server."""
    mcp_file = tmp_path / "config" / "mcp_config.json"
    settings_file = tmp_path / "settings.json"
    global_rule = tmp_path / "config" / "rules" / "veil_privacy.md"
    workspace_rule = tmp_path / "workspace" / ".agents" / "rules" / "veil_privacy.md"

    adapter = AntigravityAdapter(
        config_path_override=mcp_file,
        settings_path_override=settings_file,
        global_rule_override=global_rule,
        workspace_rule_override=workspace_rule,
    )

    # Initial connect
    res = adapter.connect("http://127.0.0.1:8080/v1")
    assert res.success is True

    # Check MCP
    mcp_data = json.loads(mcp_file.read_text(encoding="utf-8"))
    assert "veil-privacy-guard" in mcp_data["mcpServers"]

    # Check Rules
    assert global_rule.exists()
    assert "Veil AI Privacy & Security Guard" in global_rule.read_text(encoding="utf-8")
    assert workspace_rule.exists()
    assert "veil-privacy-guard" in workspace_rule.read_text(encoding="utf-8")

    # Check settings
    settings_data = json.loads(settings_file.read_text(encoding="utf-8"))
    assert settings_data["openai.baseURL"] == "http://127.0.0.1:8080/v1"
    assert settings_data["openai.apiKey"] == "veil-dev-token"

    # Status check
    status = adapter.get_status()
    assert status.status == ClientStatus.CONNECTED
    assert status.details["global_rule"] is True
    assert status.details["workspace_rule"] is True
    assert status.details["mcp_active"] is True

    # Test connection probe
    probe = adapter.test_connection("http://127.0.0.1:8080/v1")
    assert probe["client_id"] == "antigravity"
    assert probe["status"] == "VERIFIED"
    assert probe["is_routed"] is True

    # Disconnect
    disc = adapter.disconnect()
    assert disc.success is True
    assert not global_rule.exists()
    assert not workspace_rule.exists()


def test_client_manager_test_client_connection():
    """Verify ClientManager.test_client_connection handles recognized and unknown clients."""
    mgr = ClientManager()
    res = mgr.test_client_connection("opencode")
    assert "client_id" in res
    assert res["client_id"] == "opencode"
    assert "latency_ms" in res

    bad_res = mgr.test_client_connection("unknown_fake_client")
    assert bad_res["success"] is False
    assert "not recognized" in bad_res["message"]


@pytest.mark.asyncio
async def test_api_client_test_and_ping_endpoints():
    """Verify POST /api/clients/{id}/test and /ping endpoints return diagnostic probe results."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Test opencode
        resp = await client.post("/api/clients/opencode/test")
        assert resp.status_code == 200
        data = resp.json()
        assert data["client_id"] == "opencode"
        assert "message" in data
        assert "latency_ms" in data

        # Test ping alias
        ping_resp = await client.post("/api/clients/antigravity/ping")
        assert ping_resp.status_code == 200
        ping_data = ping_resp.json()
        assert ping_data["client_id"] == "antigravity"

        # Test unknown client
        bad_resp = await client.post("/api/clients/nonexistent_client/test")
        assert bad_resp.status_code == 200
        bad_data = bad_resp.json()
        assert bad_data["success"] is False
        assert "not recognized" in bad_data["message"]


def test_cli_test_and_ping_client():
    """Verify veil test-client and veil ping-client CLI commands."""
    res_test = runner.invoke(cli, ["test-client", "opencode"])
    assert res_test.exit_code == 0
    assert "Testing connection for 'opencode'" in res_test.output

    res_ping = runner.invoke(cli, ["ping-client", "antigravity"])
    assert res_ping.exit_code == 0
    assert "Testing connection for 'antigravity'" in res_ping.output

    res_unknown = runner.invoke(cli, ["test-client", "unknown_tool"])
    assert res_unknown.exit_code == 0
    assert "not recognized" in res_unknown.output



