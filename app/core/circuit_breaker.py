"""Fail-closed circuit breaker and timeout enforcement guardrails."""
import time
from typing import Callable, Any, TypeVar, Coroutine
from app.core.config import settings
from app.core.exceptions import FailClosedEngineException, VeilSecurityException

T = TypeVar("T")


class CircuitBreaker:
    """Enforces fail-closed execution.
    
    If any wrapped operation raises an unhandled internal error or breaches timeout,
    and FAIL_CLOSED is True, it converts the error into a structured FailClosedEngineException.
    Known VeilSecurityExceptions (like SecretDetectedException) are allowed to pass through
    intact as legitimate security outcomes.
    """
    def __init__(self, component_name: str, max_duration_ms: float = 2000.0):
        self.component_name = component_name
        self.max_duration_ms = max_duration_ms

    async def execute_async(self, coro: Coroutine[Any, Any, T]) -> T:
        start = time.perf_counter()
        try:
            result = await coro
            elapsed = (time.perf_counter() - start) * 1000.0
            if elapsed > self.max_duration_ms and settings.FAIL_CLOSED:
                raise FailClosedEngineException(
                    component=self.component_name,
                    details=f"Execution timeout exceeded: {elapsed:.2f}ms > {self.max_duration_ms}ms"
                )
            return result
        except VeilSecurityException:
            # Let deliberate security blocks pass through cleanly
            raise
        except Exception as e:
            if settings.FAIL_CLOSED:
                raise FailClosedEngineException(
                    component=self.component_name,
                    details=f"Unhandled engine fault: {str(e)}"
                ) from e
            raise

    def execute_sync(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        start = time.perf_counter()
        try:
            result = func(*args, **kwargs)
            elapsed = (time.perf_counter() - start) * 1000.0
            if elapsed > self.max_duration_ms and settings.FAIL_CLOSED:
                raise FailClosedEngineException(
                    component=self.component_name,
                    details=f"Execution timeout exceeded: {elapsed:.2f}ms > {self.max_duration_ms}ms"
                )
            return result
        except VeilSecurityException:
            # Let deliberate security blocks pass through cleanly
            raise
        except Exception as e:
            if settings.FAIL_CLOSED:
                raise FailClosedEngineException(
                    component=self.component_name,
                    details=f"Unhandled engine fault: {str(e)}"
                ) from e
            raise
