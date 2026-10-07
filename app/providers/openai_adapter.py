"""Abstract base and OpenAI upstream provider adapter."""
from abc import ABC, abstractmethod
from typing import AsyncGenerator, Dict, Any, Tuple
import httpx
from app.core.config import settings
from app.core.exceptions import UpstreamProviderException


class BaseProviderAdapter(ABC):
    """Abstract interface for all upstream model providers."""

    @abstractmethod
    async def forward_request(
        self,
        endpoint: str,
        headers: Dict[str, str],
        payload: Dict[str, Any]
    ) -> Tuple[int, Dict[str, str], bytes]:
        """Forward a non-streaming request."""
        pass

    @abstractmethod
    async def forward_stream(
        self,
        endpoint: str,
        headers: Dict[str, str],
        payload: Dict[str, Any]
    ) -> AsyncGenerator[bytes, None]:
        """Forward a streaming SSE request."""
        pass


class OpenAIAdapter(BaseProviderAdapter):
    """Adapter for OpenAI and OpenAI-compatible endpoints."""

    def __init__(self, base_url: str = settings.UPSTREAM_OPENAI_BASE_URL, default_api_key: str | None = settings.UPSTREAM_API_KEY):
        self.base_url = base_url.rstrip("/")
        self.default_api_key = default_api_key
        # We reuse an async client with HTTP/2 and standard timeouts
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0),
            follow_redirects=True
        )

    def _prepare_headers(self, incoming_headers: Dict[str, str]) -> Dict[str, str]:
        """Clean headers and inject authorization if needed."""
        cleaned = {}
        # Forward relevant headers
        for k, v in incoming_headers.items():
            k_lower = k.lower()
            if k_lower in ("authorization", "content-type", "accept", "user-agent"):
                cleaned[k_lower] = v

        if "authorization" not in cleaned and self.default_api_key:
            cleaned["authorization"] = f"Bearer {self.default_api_key}"

        return cleaned

    async def forward_request(
        self,
        endpoint: str,
        headers: Dict[str, str],
        payload: Dict[str, Any]
    ) -> Tuple[int, Dict[str, str], bytes]:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        clean_headers = self._prepare_headers(headers)
        
        try:
            response = await self.client.post(url, headers=clean_headers, json=payload)
            # Filter response headers
            resp_headers = {
                k: v for k, v in response.headers.items()
                if k.lower() in ("content-type", "openai-organization", "x-request-id")
            }
            return response.status_code, resp_headers, response.content
        except httpx.RequestError as e:
            raise UpstreamProviderException(
                provider="openai",
                status_code=502,
                details=f"Network error connecting to {url}: {str(e)}"
            ) from e

    async def forward_stream(
        self,
        endpoint: str,
        headers: Dict[str, str],
        payload: Dict[str, Any]
    ) -> AsyncGenerator[bytes, None]:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        clean_headers = self._prepare_headers(headers)
        
        try:
            async with self.client.stream("POST", url, headers=clean_headers, json=payload) as response:
                if response.status_code >= 400:
                    error_body = await response.aread()
                    raise UpstreamProviderException(
                        provider="openai",
                        status_code=response.status_code,
                        details=error_body.decode("utf-8", errors="replace")
                    )

                async for chunk in response.aiter_bytes():
                    yield chunk
        except httpx.RequestError as e:
            raise UpstreamProviderException(
                provider="openai",
                status_code=502,
                details=f"Stream connection interrupted to {url}: {str(e)}"
            ) from e

    async def close(self):
        await self.client.aclose()
