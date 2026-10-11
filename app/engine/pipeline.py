"""End-to-end detection pipeline combining deterministic, custom dictionary,
local vector guardrails, and contextual semantic engines with circuit breaker protection.
"""
import re
from typing import List, Tuple, Optional
from app.core.config import PolicyLevel, settings
from app.engine.models import DetectedSpan, EntityCategory, EntityType
from app.engine.regex_scanner import RegexScanner
from app.engine.entropy_scanner import EntropyScanner
from app.engine.ast_filter import AstFilter
from app.engine.policy_engine import PolicyEngine, PolicyDecision
from app.engine.semantic_models import SemanticClassificationResult
from app.engine.semantic_classifier import SemanticClassifier
from app.engine.custom_dictionary import custom_dictionary_manager, CustomDictionaryManager
from app.engine.knowledge_vault import knowledge_vault, KnowledgeVectorVault
from app.engine.vector_encoder import vector_encoder, LocalVectorEncoder
from app.core.exceptions import SemanticViolationException
from app.core.circuit_breaker import CircuitBreaker
from app.licensing.models import FeatureFlag
from app.licensing.enforcer import is_feature_allowed


class InspectionPipeline:
    """End-to-end detection pipeline with multi-tier guardrails and circuit breaker protection."""

    def __init__(
        self,
        custom_dict: Optional[CustomDictionaryManager] = None,
        vault: Optional[KnowledgeVectorVault] = None,
        encoder: Optional[LocalVectorEncoder] = None
    ):
        self.regex_scanner = RegexScanner()
        self.entropy_scanner = EntropyScanner()
        self.custom_dict = custom_dict or custom_dictionary_manager
        self.ast_filter = AstFilter()
        self.policy_engine = PolicyEngine()
        self.semantic_classifier = SemanticClassifier()
        self.knowledge_vault = vault or knowledge_vault
        self.vector_encoder = encoder or vector_encoder
        self.breaker = CircuitBreaker("inspection_pipeline", max_duration_ms=1000.0)

    def inspect(self, text: str) -> Tuple[List[PolicyDecision], List[DetectedSpan]]:
        """Run complete inspection on input text.
        
        Guaranteed to run within circuit breaker timeout and fail-closed if errors occur.
        Returns (decisions, redact_spans).
        """
        decisions, redact_spans, _ = self.inspect_semantic(text)
        return decisions, redact_spans

    def inspect_semantic(
        self,
        text: str
    ) -> Tuple[List[PolicyDecision], List[DetectedSpan], Optional[SemanticClassificationResult]]:
        """Run complete inspection on input text including contextual semantic classification.
        
        Deterministic-First: Regex, entropy, custom dictionary, and local vector guardrails
        are evaluated first. If secrets or confidential breaches are present under strict policy,
        exceptions block immediately before outbound network dispatch.
        """
        def _execute_pipeline():
            # 1. Deterministic Regex Scanning
            regex_spans = self.regex_scanner.scan(text)

            # 2. Shannon Entropy Scanning for unclassified secrets
            entropy_spans = self.entropy_scanner.scan(text)

            # 3. Enterprise Custom Entity Dictionary (Pro/Enterprise tier)
            custom_spans = []
            if is_feature_allowed(FeatureFlag.CUSTOM_DICTIONARY):
                custom_spans = self.custom_dict.scan(text)

            # 4. Local Dense Vector & Embedding Guardrails (Pro/Enterprise tier)
            vector_spans = []
            if settings.VECTOR_GUARDRAILS_ENABLED and is_feature_allowed(FeatureFlag.VECTOR_GUARDRAILS):
                vector_spans = self._scan_vector_guardrails(text)

            # 5. Combine raw candidate spans
            all_spans = regex_spans + entropy_spans + custom_spans + vector_spans

            # 6. Filter against AST & RFC Whitelists
            filtered_spans = self.ast_filter.filter_spans(text, all_spans)

            # 7. Merge overlapping or nested spans
            merged_spans = self.ast_filter.merge_overlapping_spans(filtered_spans)

            # 8. Apply Policy Decision on deterministic & vector spans (raises SecretDetectedException on BLOCK)
            decisions, redact_spans = self.policy_engine.evaluate(merged_spans)

            # 9. Semantic ML Classification (Pro/Enterprise tier)
            semantic_result: Optional[SemanticClassificationResult] = None
            if settings.SEMANTIC_CLASSIFIER_ENABLED and is_feature_allowed(FeatureFlag.VECTOR_GUARDRAILS):
                semantic_result = self.semantic_classifier.classify_sync(text)
                # Evaluates policy (raises SemanticViolationException on strict blocking violations)
                self.policy_engine.evaluate_semantic(semantic_result)

            return decisions, redact_spans, semantic_result

        return self.breaker.execute_sync(_execute_pipeline)

    def _extract_sentence_windows(self, text: str) -> List[Tuple[str, int, int]]:
        """Extracts 1-sentence and 2-sentence sliding windows with exact character offsets."""
        if not text or len(text.strip()) < 15:
            return []

        # Limit window scanning to first 8,000 chars to avoid CPU starvation on massive payloads
        scan_text = text if len(text) <= 8000 else text[:8000]

        sentence_matches = []
        pattern = re.compile(r'[^.!?:\n\r]+(?:[.!?:]|\n+|$)', re.MULTILINE)
        for m in pattern.finditer(scan_text):
            raw = m.group(0)
            s_strip = raw.strip()
            if len(s_strip) >= 15:
                if len(s_strip) > 500:
                    s_strip = s_strip[:500]
                start = m.start() + (len(raw) - len(raw.lstrip()))
                end = start + len(s_strip)
                sentence_matches.append((s_strip, start, end))
            if len(sentence_matches) >= 12:
                break

        if not sentence_matches:
            s_strip = text.strip()
            if len(s_strip) >= 15:
                if len(s_strip) > 500:
                    s_strip = s_strip[:500]
                start = len(text) - len(text.lstrip())
                return [(s_strip, start, start + len(s_strip))]
            return []

        windows = []
        # 1-Sentence Windows
        for s_text, start, end in sentence_matches:
            windows.append((s_text, start, end))

        # 2-Sentence Sliding Windows (stride = 1)
        for i in range(len(sentence_matches) - 1):
            s1_text, start1, _ = sentence_matches[i]
            s2_text, _, end2 = sentence_matches[i + 1]
            pair_text = text[start1:end2].strip()
            if len(pair_text) > 800:
                pair_text = pair_text[:800]
            windows.append((pair_text, start1, end2))

        return windows[:16]

    def _scan_vector_guardrails(self, text: str) -> List[DetectedSpan]:
        """Runs sliding-window local dense vector guardrail evaluation.
        
        Evaluates prompt against confidential knowledge vectors.
        Raises SemanticViolationException on BLOCK matches under STRICT/BALANCED policy.
        Returns DetectedSpan items for REDACT matches.
        """
        active_entries = [e for e in self.knowledge_vault.get_all_entries() if e.enabled]
        if not active_entries:
            return []

        windows = self._extract_sentence_windows(text)
        if not windows:
            return []

        window_texts = [w[0] for w in windows]
        vectors = self.vector_encoder.encode_batch(window_texts)

        vector_spans: List[DetectedSpan] = []

        for idx, (window_text, start_char, end_char) in enumerate(windows):
            query_vec = vectors[idx]
            matches = self.knowledge_vault.search(query_vec, top_k=1, min_threshold=0.50)
            if not matches or not matches[0].is_breach:
                continue

            match = matches[0]
            self.knowledge_vault.record_hit(match.entry_id)

            # Fail-closed BLOCK handling
            if match.action == "BLOCK" and self.policy_engine.policy in (PolicyLevel.STRICT, PolicyLevel.BALANCED):
                raise SemanticViolationException(
                    category=match.category,
                    confidence=match.similarity,
                    indicators=[match.title],
                    rationale=f"Local vector guardrail intercepted '{match.title}' with {match.similarity:.2f} similarity."
                )

            # REDACT handling (or PERMISSIVE policy)
            span = DetectedSpan(
                entity_type=EntityType.VECTOR_GUARDRAIL,
                category=EntityCategory.PROPRIETARY,
                start=start_char,
                end=end_char,
                matched_text=window_text,
                confidence=match.similarity,
                metadata={
                    "placeholder_prefix": "CONFIDENTIAL_CONTEXT",
                    "rule_title": match.title,
                    "similarity": match.similarity,
                    "entry_id": match.entry_id
                }
            )
            vector_spans.append(span)

        return vector_spans
