"""Comprehensive tests for Sliding-Window Vector Guardrail Pipeline Integration (Phase 3)."""
import pytest
from starlette.testclient import TestClient

from app.main import app
from app.core.config import PolicyLevel, settings
from app.core.exceptions import SemanticViolationException
from app.engine.pipeline import InspectionPipeline
from app.engine.knowledge_vault import KnowledgeVectorVault
from app.engine.redactor import Redactor
from app.restoration.restorer import ResponseRestorer
from app.vault.session_vault import SessionVault
from app.engine.models import EntityType, EntityCategory


@pytest.fixture
def isolated_vault_and_pipeline(tmp_path):
    """Creates an isolated KnowledgeVectorVault and InspectionPipeline."""
    vault = KnowledgeVectorVault(storage_dir=tmp_path)
    vault.clear()
    pipeline = InspectionPipeline(vault=vault)
    return vault, pipeline


def test_vector_pipeline_blocks_confidential_paraphrase(isolated_vault_and_pipeline):
    """Verify sliding-window vector scan raises SemanticViolationException on BLOCK action."""
    vault, pipeline = isolated_vault_and_pipeline

    # Add protected confidential entry with BLOCK action
    vault.add_entry(
        title="Unreleased Q3 Margin Compression",
        text="Internal board forecast projects Q3 operating margin compression of 400 basis points due to APAC component supply delays.",
        category="FINANCIAL",
        action="BLOCK",
        threshold_override=0.52
    )

    # Prompt with paraphrased wording
    prompt = (
        "Please help me format this executive summary for our investors: "
        "The company expects operating margins to decline by 400 basis points in Q3. "
        "Thank you for your assistance."
    )

    # Must raise SemanticViolationException fail-closed
    with pytest.raises(SemanticViolationException) as exc_info:
        pipeline.inspect(prompt)

    exc = exc_info.value
    assert exc.code == "OUTBOUND_PROPRIETARY_DATA_BLOCKED"
    assert exc.violations[0]["category"] == "FINANCIAL"
    assert "Unreleased Q3 Margin Compression" in exc.violations[0]["indicators"]
    assert exc.violations[0]["confidence"] >= 0.50


def test_vector_pipeline_redacts_confidential_paraphrase(isolated_vault_and_pipeline):
    """Verify sliding-window vector scan marks sentence for REDACT and roundtrip restores."""
    vault, pipeline = isolated_vault_and_pipeline

    # Add protected confidential entry with REDACT action
    vault.add_entry(
        title="Project Apex Acquisition Target",
        text="Confidential buyout discussions with Apex Corporation valuing the entity at $4.2 billion with 30 days exclusivity.",
        category="PROPRIETARY",
        action="REDACT",
        threshold_override=0.50
    )

    prompt = (
        "Draft a follow up note: "
        "The acquisition terms for Apex Corporation are strictly private. "
        "Make sure to keep the tone collaborative."
    )

    decisions, redact_spans = pipeline.inspect(prompt)

    assert len(redact_spans) >= 1
    target_span = redact_spans[0]
    assert target_span.entity_type == EntityType.VECTOR_GUARDRAIL
    assert target_span.category == EntityCategory.PROPRIETARY
    assert "The acquisition terms for Apex Corporation are strictly private." in target_span.matched_text

    # Test reversible redaction with SessionVault
    session_vault = SessionVault(session_id="test_vector_session")
    redactor = Redactor()
    restorer = ResponseRestorer()

    sanitized_text, count = redactor.redact_text(prompt, redact_spans, session_vault)
    assert count >= 1
    assert "The acquisition terms for Apex Corporation are strictly private." not in sanitized_text
    assert "[CONFIDENTIAL_CONTEXT_" in sanitized_text

    # Upstream model returns response repeating the placeholder
    simulated_model_response = f"I have prepared the memo: {sanitized_text}"
    restored_response = restorer.restore_text(simulated_model_response, session_vault)

    # Restores original confidential sentence
    assert "The acquisition terms for Apex Corporation are strictly private." in restored_response


def test_vector_pipeline_clean_text_passes_through(isolated_vault_and_pipeline):
    """Verify benign text without confidential concepts passes cleanly with zero redactions."""
    vault, pipeline = isolated_vault_and_pipeline

    vault.add_entry(
        title="Secret Internal Architecture",
        text="The database cluster uses port 9443 without mTLS",
        category="INFRASTRUCTURE",
        action="BLOCK",
        threshold_override=0.75
    )

    clean_prompt = "Can you write a binary search tree insertion function in Python with docstrings?"
    decisions, redact_spans = pipeline.inspect(clean_prompt)

    assert len(redact_spans) == 0


def test_sandbox_endpoint_vector_guardrail_blocking():
    """Verify POST /api/test/sanitize detects and blocks vector confidential breaches live."""
    client = TestClient(app)

    # Ensure a vector entry exists in the main vault
    res_entry = client.post("/api/knowledge-vault/entry", json={
        "title": "Confidential APAC Delay Forecast",
        "text": "Internal board forecast projects Q3 operating margin compression of 400 basis points due to APAC component supply delays.",
        "category": "FINANCIAL",
        "action": "BLOCK",
        "threshold_override": 0.52
    })
    entry_id = res_entry.json()["entry"]["id"]

    try:
        # Test through sandbox API
        res = client.post("/api/test/sanitize", json={
            "text": "The company expects operating margins to decline by 400 basis points in Q3."
        })

        # Should be blocked
        data = res.json()
        assert data["blocked"] is True
        assert len(data["violations"]) > 0
        assert data["violations"][0]["category"] == "FINANCIAL"
    finally:
        client.delete(f"/api/knowledge-vault/{entry_id}")
