"""Ollama Local Model Provider Adapter for /api/chat and /api/generate."""
from typing import AsyncGenerator, Dict, Any, Tuple
import httpx
from app.core.config import settings
from app.core.exceptions import UpstreamProviderException
from app.providers.openai_adapter import BaseProviderAdapter


class OllamaAdapter(BaseProviderAdapter):
    """Adapter for local Ollama API endpoints (/api/chat and /api/generate)."""

    def __init__(self, base_url: str = settings.UPSTREAM_OLLAMA_BASE_URL):
        self.base_url = base_url.rstrip("/")
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=120.0, write=10.0, pool=10.0),
            follow_redirects=True
        )

    def _prepare_headers(self, incoming_headers: Dict[str, str]) -> Dict[str, str]:
        """Normalize headers for Ollama."""
        cleaned = {"content-type": "application/json"}
        for k, v in incoming_headers.items():
            if k.lower() in ("accept", "user-agent"):
                cleaned[k.lower()] = v
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
            resp_headers = {"content-type": "application/json"}
            return response.status_code, resp_headers, response.content
        except httpx.RequestError as e:
            raise UpstreamProviderException(
                provider="ollama",
                status_code=502,
                details=f"Error connecting to local Ollama instance at {url}: {str(e)}"
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
                        provider="ollama",
                        status_code=response.status_code,
                        details=error_body.decode("utf-8", errors="replace")
                    )
                async for chunk in response.aiter_bytes():
                    yield chunk
        except httpx.RequestError as e:
            raise UpstreamProviderException(
                provider="ollama",
                status_code=502,
                details=f"Stream error connecting to Ollama at {url}: {str(e)}"
            ) from e

    async def close(self):
        await self.client.aclose()
