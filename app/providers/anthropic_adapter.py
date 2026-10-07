"""Anthropic Upstream Provider Adapter for /v1/messages."""
from typing import AsyncGenerator, Dict, Any, Tuple, Optional
import httpx
from app.core.config import settings
from app.core.exceptions import UpstreamProviderException
from app.providers.openai_adapter import BaseProviderAdapter


class AnthropicAdapter(BaseProviderAdapter):
    """Adapter for Anthropic Claude API endpoints (/v1/messages)."""

    def __init__(
        self,
        base_url: str = settings.UPSTREAM_ANTHROPIC_BASE_URL,
        default_api_key: Optional[str] = settings.UPSTREAM_ANTHROPIC_API_KEY
    ):
        self.base_url = base_url.rstrip("/")
        self.default_api_key = default_api_key
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0),
            follow_redirects=True
        )

    def _prepare_headers(self, incoming_headers: Dict[str, str]) -> Dict[str, str]:
        """Normalize headers for Anthropic's API requirements."""
        cleaned = {}
        for k, v in incoming_headers.items():
            k_lower = k.lower()
            if k_lower in ("x-api-key", "anthropic-version", "anthropic-beta", "content-type", "accept", "user-agent"):
                cleaned[k_lower] = v

        # If authorization header has a Bearer token and no x-api-key, map it
        auth_hdr = incoming_headers.get("authorization") or incoming_headers.get("Authorization")
        if "x-api-key" not in cleaned:
            if auth_hdr and auth_hdr.startswith("Bearer "):
                cleaned["x-api-key"] = auth_hdr[7:].strip()
            elif self.default_api_key:
                cleaned["x-api-key"] = self.default_api_key

        # Standard Anthropic API version if omitted
        if "anthropic-version" not in cleaned:
            cleaned["anthropic-version"] = "2023-06-01"

        cleaned["content-type"] = "application/json"
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
            resp_headers = {
                k: v for k, v in response.headers.items()
                if k.lower() in ("content-type", "request-id", "x-ratelimit-requests-remaining")
            }
            return response.status_code, resp_headers, response.content
        except httpx.RequestError as e:
            raise UpstreamProviderException(
                provider="anthropic",
                status_code=502,
                details=f"Network error connecting to Anthropic at {url}: {str(e)}"
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
                        provider="anthropic",
                        status_code=response.status_code,
                        details=error_body.decode("utf-8", errors="replace")
                    )
                async for chunk in response.aiter_bytes():
                    yield chunk
        except httpx.RequestError as e:
            raise UpstreamProviderException(
                provider="anthropic",
                status_code=502,
                details=f"Network error during Anthropic stream to {url}: {str(e)}"
            ) from e

    async def close(self):
        await self.client.aclose()
