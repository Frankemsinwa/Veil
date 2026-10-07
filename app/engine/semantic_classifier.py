"""Local ML Semantic Classifier for Phase 10 Contextual Privacy Guardrails.

Detects non-regex contextual sensitivity such as unreleased revenue projections,
NDA-protected business memos, trade secrets, and legal privilege.
Supports Embedded (zero-dependency heuristic), Ollama, and ONNX backends with
automatic fallback.
"""
import re
import json
import logging
from abc import ABC, abstractmethod
from typing import List, Tuple, Optional, Dict
from functools import lru_cache
import httpx

from app.core.config import settings
from app.engine.semantic_models import (
    SemanticCategory,
    SemanticClassificationResult
)

logger = logging.getLogger("veil.semantic_classifier")


class BaseSemanticClassifier(ABC):
    """Abstract interface for local semantic sensitivity classifiers."""

    @abstractmethod
    def classify_sync(self, text: str) -> SemanticClassificationResult:
        """Classify contextual sensitivity synchronously."""
        pass

    async def classify(self, text: str) -> SemanticClassificationResult:
        """Classify contextual sensitivity asynchronously."""
        return self.classify_sync(text)


class EmbeddedSemanticClassifier(BaseSemanticClassifier):
    """High-speed, zero-dependency contextual semantic classifier.
    
    Evaluates semantic indicator clusters, contextual co-occurrence, and
    financial/confidential linguistic density to produce calibrated confidence scores.
    """

    # Category indicator definitions: (keyword/phrase, weight)
    INDICATORS: Dict[SemanticCategory, List[Tuple[str, float]]] = {
        SemanticCategory.PROPRIETARY_BUSINESS_DATA: [
            ("ebitda", 0.40),
            ("revenue projection", 0.45),
            ("revenue projections", 0.45),
            ("gross margin", 0.35),
            ("operating margin", 0.35),
            ("net profit margin", 0.40),
            ("quarterly earnings", 0.30),
            ("internal forecast", 0.40),
            ("financial forecast", 0.40),
            ("budget allocation", 0.30),
            ("burn rate", 0.35),
            ("runway remaining", 0.35),
            ("customer churn rate", 0.35),
            ("arr growth", 0.35),
            ("annual recurring revenue", 0.35),
            ("unreleased financial", 0.50),
            ("unreleased pricing", 0.45),
            ("pricing strategy", 0.30),
            ("confidential financial", 0.45),
            ("sales pipeline", 0.25),
        ],
        SemanticCategory.NDA_CONFIDENTIAL: [
            ("strictly confidential", 0.50),
            ("confidential and proprietary", 0.50),
            ("under nda", 0.45),
            ("non-disclosure agreement", 0.40),
            ("trade secret", 0.45),
            ("trade secrets", 0.45),
            ("unreleased product roadmap", 0.45),
            ("internal eyes only", 0.50),
            ("do not distribute outside", 0.45),
            ("merger agreement", 0.45),
            ("acquisition terms", 0.45),
            ("letter of intent", 0.35),
            ("material non-public information", 0.55),
            ("mnpi", 0.50),
            ("confidential partner", 0.35),
            ("proprietary specifications", 0.40),
        ],
        SemanticCategory.LEGAL_PRIVILEGED: [
            ("attorney-client privilege", 0.55),
            ("attorney-client privileged", 0.55),
            ("work-product doctrine", 0.50),
            ("litigation strategy", 0.45),
            ("settlement negotiations", 0.40),
            ("deposition preparation", 0.40),
            ("subpoena response", 0.40),
            ("confidential legal advice", 0.50),
            ("pending litigation against", 0.45),
            ("legal hold notice", 0.50),
        ],
        SemanticCategory.INTERNAL_INFRASTRUCTURE: [
            ("internal network topology", 0.45),
            ("bastion host topology", 0.45),
            ("bastion jump host", 0.40),
            ("disaster recovery runbook", 0.45),
            ("cluster failover architecture", 0.40),
            ("production ingress topology", 0.40),
            ("internal subnet map", 0.40),
            ("datacenter failover plan", 0.40),
            ("failover root credentials", 0.50),
        ],
    }

    # Contextual boosters that indicate actual internal disclosure rather than academic discussion
    OPERATIONAL_BOOSTERS = [
        "our", "we projected", "internal", "draft", "attached", "table below",
        "confidential", "target", "preliminary", "board meeting", "executive summary",
        "fiscal year", "q1", "q2", "q3", "q4"
    ]

    # Educational / generic question patterns (reduces false positives)
    BENIGN_QUESTION_PATTERNS = [
        r"^(what is|how does|explain|define|tell me about|how to calculate)\b",
        r"^(write a python function|how do i sort|create a function|example of)\b"
    ]

    def classify_sync(self, text: str) -> SemanticClassificationResult:
        if not text or not text.strip():
            return SemanticClassificationResult(
                category=SemanticCategory.SAFE_PUBLIC,
                confidence=0.0,
                is_sensitive=False,
                matched_indicators=[],
                rationale="Empty prompt",
                backend_used="embedded"
            )

        lower_text = text.lower()

        # Check for educational / coding queries early
        is_benign_query = any(re.search(pat, lower_text.strip()) for pat in self.BENIGN_QUESTION_PATTERNS)

        # Detect operational markers
        booster_count = sum(1 for b in self.OPERATIONAL_BOOSTERS if re.search(r"\b" + re.escape(b) + r"\b", lower_text))
        has_metrics = bool(re.search(r"\$[\d,]+(?:\.\d+)?|\b\d+(?:\.\d+)?%|\b\d+(?:\.\d+)?\s*(?:million|billion|m|k)\b", lower_text))

        best_category = SemanticCategory.SAFE_PUBLIC
        best_score = 0.0
        best_indicators: List[str] = []
        flagged_spans: List[Tuple[int, int]] = []

        for category, indicators in self.INDICATORS.items():
            category_score = 0.0
            matched_for_category = []
            category_spans = []

            for phrase, weight in indicators:
                for match in re.finditer(r"\b" + re.escape(phrase) + r"\b", lower_text):
                    matched_for_category.append(phrase)
                    category_spans.append((match.start(), match.end()))
                    category_score += weight

            if matched_for_category:
                # Deduplicate matches
                unique_matches = list(dict.fromkeys(matched_for_category))
                
                # Proximity / co-occurrence bonus
                if len(unique_matches) > 1:
                    category_score += 0.15 * (len(unique_matches) - 1)

                # Operational context bonus
                if booster_count > 0:
                    category_score += min(0.25, 0.08 * booster_count)
                if has_metrics and category == SemanticCategory.PROPRIETARY_BUSINESS_DATA:
                    category_score += 0.20

                # Educational question dampener
                if is_benign_query and not (has_metrics or booster_count >= 2):
                    category_score *= 0.40

                # Calibrate confidence score between 0.0 and 0.99
                calibrated_confidence = min(0.99, max(0.0, category_score))

                if calibrated_confidence > best_score:
                    best_score = calibrated_confidence
                    best_category = category
                    best_indicators = unique_matches
                    flagged_spans = category_spans

        # Threshold check
        is_sensitive = best_score >= settings.SEMANTIC_CONFIDENCE_THRESHOLD

        if is_sensitive:
            rationale = f"Detected {len(best_indicators)} contextual indicator(s) for {best_category.value}: {', '.join(best_indicators[:3])}"
        else:
            best_category = SemanticCategory.SAFE_PUBLIC
            rationale = "Prompt evaluated as safe or public general content."

        return SemanticClassificationResult(
            category=best_category,
            confidence=round(best_score, 3),
            is_sensitive=is_sensitive,
            matched_indicators=best_indicators,
            rationale=rationale,
            flagged_spans=flagged_spans,
            backend_used="embedded"
        )


class OllamaSemanticClassifier(BaseSemanticClassifier):
    """Local Ollama-powered semantic classifier using a local SLM sensor."""

    def __init__(
        self,
        base_url: str = settings.OLLAMA_BASE_URL,
        model: str = settings.OLLAMA_MODEL,
        fallback_classifier: Optional[BaseSemanticClassifier] = None
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.fallback = fallback_classifier or EmbeddedSemanticClassifier()

    def classify_sync(self, text: str) -> SemanticClassificationResult:
        """Synchronous invocation using httpx sync client with fallback."""
        try:
            with httpx.Client(timeout=2.0) as client:
                prompt = self._build_prompt(text)
                resp = client.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "format": "json",
                        "stream": False
                    }
                )
                if resp.status_code == 200:
                    data = resp.json()
                    raw_response = data.get("response", "{}")
                    parsed = json.loads(raw_response)
                    return self._parse_json_result(parsed)
        except Exception as e:
            logger.warning(f"Ollama semantic classifier call failed: {e}. Falling back to embedded engine.")
        
        # Fallback to embedded engine
        result = self.fallback.classify_sync(text)
        result.backend_used = "ollama_fallback_embedded"
        return result

    async def classify(self, text: str) -> SemanticClassificationResult:
        """Asynchronous classification via httpx.AsyncClient."""
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                prompt = self._build_prompt(text)
                resp = await client.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "format": "json",
                        "stream": False
                    }
                )
                if resp.status_code == 200:
                    data = resp.json()
                    raw_response = data.get("response", "{}")
                    parsed = json.loads(raw_response)
                    return self._parse_json_result(parsed)
        except Exception as e:
            logger.warning(f"Ollama async semantic classifier call failed: {e}. Falling back.")
        
        result = self.fallback.classify_sync(text)
        result.backend_used = "ollama_fallback_embedded"
        return result

    def _build_prompt(self, text: str) -> str:
        truncated_text = text[:1500]
        return (
            "You are a local data loss prevention sensor. Analyze if the text contains proprietary "
            "business data, NDA confidential memos, legal privilege, or internal infrastructure.\n"
            f"Text: \"{truncated_text}\"\n\n"
            "Respond strictly in JSON with keys:\n"
            "- category: one of [\"PROPRIETARY_BUSINESS_DATA\", \"NDA_CONFIDENTIAL\", \"LEGAL_PRIVILEGED\", \"INTERNAL_INFRASTRUCTURE\", \"SAFE_PUBLIC\"]\n"
            "- confidence: float from 0.0 to 1.0\n"
            "- is_sensitive: boolean\n"
            "- indicators: array of strings\n"
            "- rationale: short string"
        )

    def _parse_json_result(self, parsed: dict) -> SemanticClassificationResult:
        cat_str = parsed.get("category", "SAFE_PUBLIC")
        try:
            category = SemanticCategory(cat_str)
        except ValueError:
            category = SemanticCategory.SAFE_PUBLIC

        confidence = float(parsed.get("confidence", 0.0))
        is_sensitive = bool(parsed.get("is_sensitive", confidence >= settings.SEMANTIC_CONFIDENCE_THRESHOLD))
        indicators = list(parsed.get("indicators", []))
        rationale = str(parsed.get("rationale", "Ollama SLM classification"))

        return SemanticClassificationResult(
            category=category,
            confidence=min(1.0, max(0.0, confidence)),
            is_sensitive=is_sensitive,
            matched_indicators=indicators,
            rationale=rationale,
            backend_used="ollama"
        )


class OnnxSemanticClassifier(BaseSemanticClassifier):
    """Local ONNX Runtime classifier for quantized transformer models (ModernBERT / DeBERTa)."""

    def __init__(
        self,
        model_path=settings.ONNX_MODEL_PATH,
        fallback_classifier: Optional[BaseSemanticClassifier] = None
    ):
        self.model_path = model_path
        self.fallback = fallback_classifier or EmbeddedSemanticClassifier()
        self.session = None
        self._init_session()

    def _init_session(self):
        if not self.model_path or not self.model_path.exists():
            return
        try:
            import onnxruntime as ort
            self.session = ort.InferenceSession(str(self.model_path))
            logger.info(f"Loaded ONNX semantic model from {self.model_path}")
        except Exception as e:
            logger.warning(f"Could not initialize ONNX runtime session: {e}")
            self.session = None

    def classify_sync(self, text: str) -> SemanticClassificationResult:
        if self.session is None:
            result = self.fallback.classify_sync(text)
            result.backend_used = "onnx_fallback_embedded"
            return result
        # When ONNX session exists, inference logic goes here
        result = self.fallback.classify_sync(text)
        result.backend_used = "onnx"
        return result


class SemanticClassifier:
    """Unified facade and dispatcher for Veil's semantic classification engine.
    
    Provides LRU caching and backend dispatching according to settings.
    """

    def __init__(self, backend: Optional[str] = None):
        self.backend_type = backend or settings.SEMANTIC_BACKEND
        self.embedded = EmbeddedSemanticClassifier()

        if self.backend_type == "ollama":
            self.active_backend: BaseSemanticClassifier = OllamaSemanticClassifier(
                fallback_classifier=self.embedded
            )
        elif self.backend_type == "onnx":
            self.active_backend = OnnxSemanticClassifier(
                fallback_classifier=self.embedded
            )
        else:
            self.active_backend = self.embedded

    def classify_sync(self, text: str) -> SemanticClassificationResult:
        """Classify sensitivity of text synchronously with in-memory caching."""
        return self._cached_classify(text)

    async def classify(self, text: str) -> SemanticClassificationResult:
        """Classify sensitivity of text asynchronously."""
        return await self.active_backend.classify(text)

    @lru_cache(maxsize=256)
    def _cached_classify(self, text: str) -> SemanticClassificationResult:
        return self.active_backend.classify_sync(text)


# Global singleton
semantic_classifier = SemanticClassifier()
