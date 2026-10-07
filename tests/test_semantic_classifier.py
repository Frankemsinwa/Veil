"""Tests for Phase 10: Local ML Semantic Classifier and Contextual Policy Guardrails."""
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.config import settings, PolicyLevel
from app.core.exceptions import SecretDetectedException, SemanticViolationException
from app.engine.semantic_models import SemanticCategory, SemanticClassificationResult
from app.engine.semantic_classifier import (
    EmbeddedSemanticClassifier,
    OllamaSemanticClassifier,
    OnnxSemanticClassifier,
    SemanticClassifier
)
from app.engine.policy_engine import PolicyEngine, ActionType
from app.engine.pipeline import InspectionPipeline


def test_embedded_classifier_proprietary_financial_data():
    classifier = EmbeddedSemanticClassifier()
    text = (
        "Internal Draft: Our unreleased Q3 financial forecast indicates a 18% gross margin "
        "and preliminary EBITDA of $4.8 million. Keep strictly within executive team."
    )
    result = classifier.classify_sync(text)

    assert result.is_sensitive is True
    assert result.category == SemanticCategory.PROPRIETARY_BUSINESS_DATA
    assert result.confidence >= 0.70
    assert any(ind in ["ebitda", "gross margin", "financial forecast"] for ind in result.matched_indicators)
    assert result.backend_used == "embedded"


def test_embedded_classifier_nda_confidential():
    classifier = EmbeddedSemanticClassifier()
    text = (
        "Subject to NDA: The acquisition terms and merger agreement between Corp A and Corp B "
        "are strictly confidential and constitute material non-public information (MNPI)."
    )
    result = classifier.classify_sync(text)

    assert result.is_sensitive is True
    assert result.category == SemanticCategory.NDA_CONFIDENTIAL
    assert result.confidence >= 0.75
    assert any(ind in ["under nda", "strictly confidential", "merger agreement", "acquisition terms", "mnpi"] for ind in result.matched_indicators)


def test_embedded_classifier_legal_privileged():
    classifier = EmbeddedSemanticClassifier()
    text = (
        "CONFIDENTIAL ATTORNEY-CLIENT PRIVILEGED: Strategy memo regarding pending litigation against "
        "the plaintiff, settlement negotiations, and work-product doctrine assessment."
    )
    result = classifier.classify_sync(text)

    assert result.is_sensitive is True
    assert result.category == SemanticCategory.LEGAL_PRIVILEGED
    assert result.confidence >= 0.75
    assert any("attorney-client" in ind for ind in result.matched_indicators)


def test_embedded_classifier_internal_infrastructure():
    classifier = EmbeddedSemanticClassifier()
    text = (
        "Draft runbook: Internal network topology for the production cluster failover architecture "
        "and internal subnet map behind the bastion jump host."
    )
    result = classifier.classify_sync(text)

    assert result.is_sensitive is True
    assert result.category == SemanticCategory.INTERNAL_INFRASTRUCTURE
    assert result.confidence >= 0.70


def test_embedded_classifier_benign_content():
    classifier = EmbeddedSemanticClassifier()

    # Coding question
    code_prompt = "How do I implement binary search on an array in Python?"
    res1 = classifier.classify_sync(code_prompt)
    assert res1.is_sensitive is False
    assert res1.category == SemanticCategory.SAFE_PUBLIC

    # General inquiry
    general_prompt = "What is the distance between the Earth and the Moon?"
    res2 = classifier.classify_sync(general_prompt)
    assert res2.is_sensitive is False
    assert res2.category == SemanticCategory.SAFE_PUBLIC

    # Educational query regarding a financial term
    edu_prompt = "What is EBITDA and how does a company calculate it?"
    res3 = classifier.classify_sync(edu_prompt)
    # Educational query should not trigger high-confidence sensitivity
    assert res3.is_sensitive is False


def test_policy_engine_semantic_strict_blocks_high_confidence():
    policy_engine = PolicyEngine(policy=PolicyLevel.STRICT)
    result = SemanticClassificationResult(
        category=SemanticCategory.PROPRIETARY_BUSINESS_DATA,
        confidence=0.92,
        is_sensitive=True,
        matched_indicators=["ebitda", "revenue projection"],
        rationale="Internal earnings memo",
        backend_used="embedded"
    )

    with pytest.raises(SemanticViolationException) as exc_info:
        policy_engine.evaluate_semantic(result)

    err = exc_info.value.to_dict()
    assert err["error"]["code"] == "OUTBOUND_PROPRIETARY_DATA_BLOCKED"
    assert err["error"]["details"][0]["category"] == "PROPRIETARY_BUSINESS_DATA"


def test_policy_engine_semantic_permissive_allows_with_advisory():
    policy_engine = PolicyEngine(policy=PolicyLevel.PERMISSIVE)
    result = SemanticClassificationResult(
        category=SemanticCategory.PROPRIETARY_BUSINESS_DATA,
        confidence=0.92,
        is_sensitive=True,
        matched_indicators=["ebitda"],
        rationale="Internal earnings memo",
        backend_used="embedded"
    )

    decision = policy_engine.evaluate_semantic(result)
    assert decision.action == ActionType.ALLOW
    assert "Permissive policy advisory receipt" in decision.reason


def test_pipeline_deterministic_first_rule():
    """Security Invariant: Regex/entropy secrets ALWAYS block first before semantic classification."""
    pipeline = InspectionPipeline()
    # Prompt contains both a leaked OpenAI secret key and proprietary financial figures
    mixed_prompt = (
        "Here is our secret key: sk-proj-1234567890abcdef1234567890abcdef1234567890123456 "
        "and our unreleased Q3 EBITDA forecast is $10M."
    )

    # Must raise SecretDetectedException (Deterministic-First), NOT SemanticViolationException
    with pytest.raises(SecretDetectedException) as exc_info:
        pipeline.inspect(mixed_prompt)

    err = exc_info.value.to_dict()
    assert err["error"]["code"] == "OUTBOUND_SECRET_BLOCKED"


def test_pipeline_inspect_semantic_returns_all_components():
    pipeline = InspectionPipeline()
    clean_prompt = "Can you review my python code for sorting a list?"

    decisions, redact_spans, semantic_result = pipeline.inspect_semantic(clean_prompt)
    assert len(redact_spans) == 0
    assert semantic_result is not None
    assert semantic_result.is_sensitive is False
    assert semantic_result.category == SemanticCategory.SAFE_PUBLIC


def test_ollama_fallback_to_embedded(monkeypatch):
    """When Ollama is unreachable or errors, it seamlessly falls back to embedded classifier."""
    classifier = OllamaSemanticClassifier(base_url="http://127.0.0.1:99999")  # Non-existent port
    text = "Draft: unreleased financial revenue projections and EBITDA of $5M under NDA."

    result = classifier.classify_sync(text)
    assert result.is_sensitive is True
    assert result.backend_used == "ollama_fallback_embedded"
    assert result.category in (SemanticCategory.PROPRIETARY_BUSINESS_DATA, SemanticCategory.NDA_CONFIDENTIAL)


def test_onnx_fallback_when_model_absent():
    classifier = OnnxSemanticClassifier(model_path=None)
    text = "Draft: confidential and proprietary trade secret specifications."

    result = classifier.classify_sync(text)
    assert result.is_sensitive is True
    assert result.backend_used == "onnx_fallback_embedded"
    assert result.category == SemanticCategory.NDA_CONFIDENTIAL


@pytest.mark.asyncio
async def test_proxy_blocks_proprietary_data_under_strict_mode(monkeypatch):
    """Outbound chat completion request with proprietary data is halted with HTTP 422 under STRICT policy."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "user",
                    "content": "Our unreleased Q3 EBITDA forecast shows $12.5M with 28% gross margin. Do not distribute outside board."
                }
            ]
        }
        headers = {"x-session-id": "test_semantic_session"}
        response = await client.post("/v1/chat/completions", json=payload, headers=headers)
        assert response.status_code == 422
        body = response.json()
        assert body["error"]["code"] == "OUTBOUND_PROPRIETARY_DATA_BLOCKED"
        assert body["error"]["details"][0]["category"] == "PROPRIETARY_BUSINESS_DATA"
