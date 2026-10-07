import pytest
import tempfile
from pathlib import Path
from httpx import AsyncClient, ASGITransport

from app.engine.custom_dictionary import CustomDictionaryManager, CustomEntityRule
from app.engine.pipeline import InspectionPipeline
from app.engine.redactor import Redactor
from app.vault.session_vault import SessionVault
from app.restoration.restorer import ResponseRestorer
from app.main import app


def test_custom_dictionary_manager_crud():
    with tempfile.TemporaryDirectory() as tmpdir:
        storage_file = Path(tmpdir) / "custom_rules.json"
        mgr = CustomDictionaryManager(storage_path=storage_file)

        # Initially loaded default templates
        rules = mgr.list_rules()
        assert len(rules) >= 2

        # Add new rule
        new_rule = CustomEntityRule(
            id="test_titan",
            name="Project Titan",
            pattern="Project Titan",
            is_regex=False,
            case_sensitive=False,
            placeholder_prefix="PROJECT",
            action="REDACT",
            enabled=True
        )
        saved = mgr.add_rule(new_rule)
        assert saved.id == "test_titan"
        assert storage_file.exists()

        # Check retrieval
        retrieved = mgr.get_rule("test_titan")
        assert retrieved is not None
        assert retrieved.name == "Project Titan"

        # Toggle rule
        updated = mgr.toggle_rule("test_titan")
        assert updated.enabled is False
        assert mgr.get_rule("test_titan").enabled is False

        mgr.toggle_rule("test_titan")  # back to True
        assert mgr.get_rule("test_titan").enabled is True

        # Delete rule
        deleted = mgr.delete_rule("test_titan")
        assert deleted is True
        assert mgr.get_rule("test_titan") is None


def test_custom_dictionary_pattern_matching():
    with tempfile.TemporaryDirectory() as tmpdir:
        storage_file = Path(tmpdir) / "custom_rules.json"
        mgr = CustomDictionaryManager(storage_path=storage_file)

        # Clear defaults for clean test
        for r in mgr.list_rules():
            mgr.delete_rule(r.id)

        # Add literal rule
        mgr.add_rule(CustomEntityRule(
            id="titan",
            name="Project Titan",
            pattern="Project Titan",
            is_regex=False,
            case_sensitive=False,
            placeholder_prefix="PROJECT",
            action="REDACT",
            enabled=True
        ))

        # Add regex rule for client
        mgr.add_rule(CustomEntityRule(
            id="client_regex",
            name="Alpha Corp",
            pattern=r"Alpha\s+Corp|AlphaCorp",
            is_regex=True,
            case_sensitive=False,
            placeholder_prefix="CLIENT",
            action="REDACT",
            enabled=True
        ))

        # Add block rule
        mgr.add_rule(CustomEntityRule(
            id="blacklisted_tech",
            name="Forbidden Kernel Key",
            pattern="SECRET_KERNEL_BYPASS",
            is_regex=False,
            case_sensitive=True,
            placeholder_prefix="BLOCKED",
            action="BLOCK",
            enabled=True
        ))

        prompt = "We are delivering Project Titan specifications to Alpha Corp, do not leak SECRET_KERNEL_BYPASS."
        spans = mgr.scan(prompt)

        assert len(spans) == 3
        span_texts = [s.matched_text for s in spans]
        assert "Project Titan" in span_texts
        assert "Alpha Corp" in span_texts
        assert "SECRET_KERNEL_BYPASS" in span_texts

        # Verify hit count incremented
        assert mgr.get_rule("titan").hit_count == 1
        assert mgr.get_rule("client_regex").hit_count == 1
        assert mgr.get_rule("blacklisted_tech").hit_count == 1


def test_custom_dictionary_pipeline_and_vault_roundtrip():
    with tempfile.TemporaryDirectory() as tmpdir:
        storage_file = Path(tmpdir) / "custom_rules.json"
        mgr = CustomDictionaryManager(storage_path=storage_file)
        for r in mgr.list_rules():
            mgr.delete_rule(r.id)

        mgr.add_rule(CustomEntityRule(
            id="proj_rule",
            name="Apollo Moonshot",
            pattern="Apollo Moonshot",
            placeholder_prefix="PROJECT",
            action="REDACT",
            enabled=True
        ))

        pipeline = InspectionPipeline(custom_dict=mgr)
        vault = SessionVault(session_id="custom_dict_test_session")
        redactor = Redactor()
        restorer = ResponseRestorer()

        text = "Confidential report on Apollo Moonshot launch architecture."
        decisions, spans = pipeline.inspect(text)
        assert len(spans) == 1
        assert spans[0].matched_text == "Apollo Moonshot"
        assert spans[0].metadata.get("placeholder_prefix") == "PROJECT"

        sanitized, count = redactor.redact_text(text, spans, vault)
        assert count == 1
        assert "Apollo Moonshot" not in sanitized
        assert "[PROJECT_001]" in sanitized

        # Reversible restoration
        restored = restorer.restore_text(sanitized, vault)
        assert restored == text


@pytest.mark.asyncio
async def test_custom_entity_api_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # List rules
        resp = await client.get("/api/custom-entities")
        assert resp.status_code == 200
        data = resp.json()
        assert "rules" in data

        # Add new rule
        payload = {
            "name": "Project Valkyrie",
            "pattern": "Project Valkyrie",
            "is_regex": False,
            "case_sensitive": False,
            "placeholder_prefix": "PROJECT",
            "action": "REDACT",
            "enabled": True
        }
        create_resp = await client.post("/api/custom-entities", json=payload)
        assert create_resp.status_code == 200
        created = create_resp.json()
        assert created["success"] is True
        rule_id = created["rule"]["id"]
        assert created["rule"]["name"] == "Project Valkyrie"

        # Toggle rule
        toggle_resp = await client.post(f"/api/custom-entities/{rule_id}/toggle")
        assert toggle_resp.status_code == 200
        assert toggle_resp.json()["enabled"] is False

        # Delete rule
        del_resp = await client.delete(f"/api/custom-entities/{rule_id}")
        assert del_resp.status_code == 200
        assert del_resp.json()["success"] is True
