"""Policy and Action Decider for Veil Detection Pipeline."""
from enum import Enum
from typing import List, Tuple
from app.core.config import PolicyLevel, settings
from app.engine.models import DetectedSpan, EntityCategory
from app.engine.semantic_models import SemanticCategory, SemanticClassificationResult
from app.core.exceptions import SecretDetectedException, SemanticViolationException


class ActionType(str, Enum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    BLOCK = "BLOCK"


class PolicyDecision:
    def __init__(self, span: DetectedSpan, action: ActionType, reason: str):
        self.span = span
        self.action = action
        self.reason = reason


class SemanticPolicyDecision:
    def __init__(self, result: SemanticClassificationResult, action: ActionType, reason: str):
        self.result = result
        self.action = action
        self.reason = reason



class PolicyEngine:
    """Evaluates detected spans against active policy level (STRICT, BALANCED, PERMISSIVE)."""

    def __init__(self, policy: PolicyLevel = settings.POLICY):
        self.policy = policy

    def evaluate(self, spans: List[DetectedSpan]) -> Tuple[List[PolicyDecision], List[DetectedSpan]]:
        """Evaluate actions for all spans.
        
        Raises SecretDetectedException immediately if any BLOCK action occurs.
        Returns list of decisions and list of spans that require redaction.
        """
        decisions: List[PolicyDecision] = []
        redact_spans: List[DetectedSpan] = []
        blocking_violations = []

        for span in spans:
            # 1. Whitelisted items always pass through cleanly
            if span.is_whitelisted:
                decisions.append(PolicyDecision(span, ActionType.ALLOW, "Whitelisted RFC mock/documentation data"))
                continue

            # 2. Evaluate according to policy
            if span.category == EntityCategory.SECRET:
                if self.policy in (PolicyLevel.STRICT, PolicyLevel.BALANCED):
                    action = ActionType.BLOCK
                    blocking_violations.append({
                        "entity_type": span.entity_type.value,
                        "category": span.category.value,
                        "span": [span.start, span.end],
                        "confidence": span.confidence,
                        "metadata": span.metadata
                    })
                else: # PERMISSIVE
                    action = ActionType.REDACT
            elif span.category == EntityCategory.PII:
                action = ActionType.REDACT
            elif span.category == EntityCategory.INFRASTRUCTURE:
                if self.policy == PolicyLevel.STRICT:
                    action = ActionType.REDACT
                else:
                    action = ActionType.ALLOW
            else:
                action = ActionType.ALLOW

            decisions.append(PolicyDecision(span, action, f"Policy {self.policy.value} action"))
            if action == ActionType.REDACT:
                redact_spans.append(span)

        # Fail-closed enforcement: Halt everything if blocking violations exist
        if blocking_violations:
            raise SecretDetectedException(violations=blocking_violations)

        return decisions, redact_spans

    def evaluate_semantic(self, result: SemanticClassificationResult) -> SemanticPolicyDecision:
        """Evaluates semantic classification result against active policy level.
        
        Under STRICT policy, high-confidence proprietary/confidential data triggers
        SemanticViolationException (HTTP 422).
        """
        if not result.is_sensitive:
            return SemanticPolicyDecision(
                result=result,
                action=ActionType.ALLOW,
                reason="Prompt evaluated as safe or public general content."
            )

        # Contextual sensitivity detected
        if self.policy == PolicyLevel.STRICT:
            if result.confidence >= settings.SEMANTIC_BLOCK_THRESHOLD:
                # Immediate fail-closed block
                raise SemanticViolationException(
                    category=result.category.value,
                    confidence=result.confidence,
                    indicators=result.matched_indicators,
                    rationale=result.rationale
                )
            elif result.confidence >= settings.SEMANTIC_CONFIDENCE_THRESHOLD:
                raise SemanticViolationException(
                    category=result.category.value,
                    confidence=result.confidence,
                    indicators=result.matched_indicators,
                    rationale=result.rationale
                )
            action = ActionType.BLOCK
            reason = f"Strict policy blocked {result.category.value} (confidence: {result.confidence:.2f})"

        elif self.policy == PolicyLevel.BALANCED:
            # Under balanced policy, block high-confidence NDA and legal privilege
            if (
                result.confidence >= settings.SEMANTIC_BLOCK_THRESHOLD
                and result.category in (SemanticCategory.NDA_CONFIDENTIAL, SemanticCategory.LEGAL_PRIVILEGED)
            ):
                raise SemanticViolationException(
                    category=result.category.value,
                    confidence=result.confidence,
                    indicators=result.matched_indicators,
                    rationale=result.rationale
                )
            action = ActionType.ALLOW
            reason = f"Balanced policy advisory flag: {result.category.value} (confidence: {result.confidence:.2f})"

        else: # PERMISSIVE
            action = ActionType.ALLOW
            reason = f"Permissive policy advisory receipt: {result.category.value} (confidence: {result.confidence:.2f})"

        return SemanticPolicyDecision(result=result, action=action, reason=reason)

