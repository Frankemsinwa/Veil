from typing import List, Tuple, Optional
from app.core.config import settings
from app.engine.models import DetectedSpan
from app.engine.regex_scanner import RegexScanner
from app.engine.entropy_scanner import EntropyScanner
from app.engine.ast_filter import AstFilter
from app.engine.policy_engine import PolicyEngine, PolicyDecision
from app.engine.semantic_models import SemanticClassificationResult
from app.engine.semantic_classifier import SemanticClassifier
from app.engine.custom_dictionary import custom_dictionary_manager, CustomDictionaryManager
from app.core.circuit_breaker import CircuitBreaker


class InspectionPipeline:
    """End-to-end detection pipeline combining deterministic, custom dictionary, and semantic engines with circuit breaker protection."""

    def __init__(self, custom_dict: Optional[CustomDictionaryManager] = None):
        self.regex_scanner = RegexScanner()
        self.entropy_scanner = EntropyScanner()
        self.custom_dict = custom_dict or custom_dictionary_manager
        self.ast_filter = AstFilter()
        self.policy_engine = PolicyEngine()
        self.semantic_classifier = SemanticClassifier()
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
        
        Deterministic-First: Regex and entropy secrets are checked first.
        If secrets are present, SecretDetectedException blocks immediately.
        Then, if enabled, the semantic classifier evaluates contextual sensitivity.
        Under STRICT policy, SemanticViolationException blocks proprietary/confidential data.
        """
        def _execute_pipeline():
            # 1. Deterministic Regex Scanning
            regex_spans = self.regex_scanner.scan(text)

            # 2. Shannon Entropy Scanning for unclassified secrets
            entropy_spans = self.entropy_scanner.scan(text)

            # 3. Enterprise Custom Entity Dictionary
            custom_spans = self.custom_dict.scan(text)

            # 4. Combine raw candidate spans
            all_spans = regex_spans + entropy_spans + custom_spans

            # 4. Filter against AST & RFC Whitelists
            filtered_spans = self.ast_filter.filter_spans(text, all_spans)

            # 5. Merge overlapping or nested spans
            merged_spans = self.ast_filter.merge_overlapping_spans(filtered_spans)

            # 6. Apply Policy Decision on deterministic spans (raises SecretDetectedException on BLOCK)
            decisions, redact_spans = self.policy_engine.evaluate(merged_spans)

            # 7. Semantic ML Classification (Phase 10)
            semantic_result: Optional[SemanticClassificationResult] = None
            if settings.SEMANTIC_CLASSIFIER_ENABLED:
                semantic_result = self.semantic_classifier.classify_sync(text)
                # Evaluates policy (raises SemanticViolationException on strict blocking violations)
                self.policy_engine.evaluate_semantic(semantic_result)

            return decisions, redact_spans, semantic_result

        return self.breaker.execute_sync(_execute_pipeline)

