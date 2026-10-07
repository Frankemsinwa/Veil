"""Structured security and gateway exceptions."""
from typing import Any, Dict, List, Optional


class VeilSecurityException(Exception):
    """Base exception for all security violations within Veil."""
    def __init__(
        self,
        code: str,
        message: str,
        violations: Optional[List[Dict[str, Any]]] = None,
        status_code: int = 422
    ):
        super().__init__(message)
        self.code = code
        self.message = message
        self.violations = violations or []
        self.status_code = status_code

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error": {
                "type": "veil_security_violation",
                "code": self.code,
                "message": self.message,
                "details": self.violations
            }
        }


class SecretDetectedException(VeilSecurityException):
    """Raised when high-severity credentials or secrets are detected in outbound traffic."""
    def __init__(self, violations: List[Dict[str, Any]]):
        super().__init__(
            code="OUTBOUND_SECRET_BLOCKED",
            message="Outbound prompt blocked by local Veil security policy. Confidential secrets were detected.",
            violations=violations,
            status_code=422
        )


class SemanticViolationException(VeilSecurityException):
    """Raised when outbound prompt contains contextual proprietary or confidential information under strict policy."""
    def __init__(self, category: str, confidence: float, indicators: List[str], rationale: str):
        super().__init__(
            code="OUTBOUND_PROPRIETARY_DATA_BLOCKED",
            message=f"Outbound prompt blocked by local Veil policy. Contextual semantic sensitivity detected: {category} (confidence: {confidence:.2f}).",
            violations=[{
                "category": category,
                "confidence": confidence,
                "indicators": indicators,
                "rationale": rationale
            }],
            status_code=422
        )



class FailClosedEngineException(VeilSecurityException):
    """Raised when an internal privacy engine component fails under fail-closed mode."""
    def __init__(self, component: str, details: str):
        super().__init__(
            code="FAIL_CLOSED_TRIGGERED",
            message=f"Request safely blocked: Veil engine component '{component}' encountered an error under fail-closed mode.",
            violations=[{"component": component, "error": details}],
            status_code=500
        )


class UpstreamProviderException(VeilSecurityException):
    """Raised when upstream AI provider communication fails."""
    def __init__(self, provider: str, status_code: int, details: str):
        super().__init__(
            code="UPSTREAM_PROVIDER_ERROR",
            message=f"Upstream provider '{provider}' returned an error (HTTP {status_code}).",
            violations=[{"provider": provider, "status_code": status_code, "details": details}],
            status_code=status_code
        )
