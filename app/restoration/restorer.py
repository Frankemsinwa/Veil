"""Restoration engine for SSE streams and non-streaming responses."""
import json
import re
from typing import AsyncGenerator, Callable, Dict, Any
from app.vault.session_vault import SessionVault
from app.restoration.buffer import StreamBuffer

PLACEHOLDER_REGEX = re.compile(r"\[([A-Z_]+_\d{3})\]")


class ResponseRestorer:
    """Restores placeholders in model responses back to original confidential values."""

    def restore_text(self, text: str, vault: SessionVault) -> str:
        """Replace all [TYPE_001] placeholders in text with decrypted values."""
        if not text:
            return text

        def _replace_match(match: re.Match) -> str:
            token = match.group(0)
            original = vault.restore_placeholder(token)
            return original if original is not None else token

        return PLACEHOLDER_REGEX.sub(_replace_match, text)

    def restore_json_response(self, response_bytes: bytes, vault: SessionVault) -> bytes:
        """Restores placeholders in a standard non-streaming OpenAI JSON response."""
        try:
            data = json.loads(response_bytes.decode("utf-8"))
            if "choices" in data and isinstance(data["choices"], list):
                for choice in data["choices"]:
                    if "message" in choice and "content" in choice["message"]:
                        content = choice["message"]["content"]
                        if isinstance(content, str):
                            choice["message"]["content"] = self.restore_text(content, vault)
            return json.dumps(data).encode("utf-8")
        except Exception:
            text = response_bytes.decode("utf-8", errors="replace")
            restored = self.restore_text(text, vault)
            return restored.encode("utf-8")

    restore_openai_json_response = restore_json_response

    async def restore_sse_stream(
        self,
        upstream_stream: AsyncGenerator[bytes, None],
        vault: SessionVault
    ) -> AsyncGenerator[bytes, None]:
        """Intercepts SSE chunks, reconstructs split tokens across chunk deltas, and yields restored SSE chunks."""
        buffer = StreamBuffer(restore_func=vault.restore_placeholder)

        async for raw_chunk in upstream_stream:
            try:
                chunk_str = raw_chunk.decode("utf-8")
            except UnicodeDecodeError:
                yield raw_chunk
                continue

            # Check if this is an SSE data line (data: {...})
            lines = chunk_str.split("\n")
            restored_lines = []

            for line in lines:
                if line.startswith("data: ") and not line.startswith("data: [DONE]"):
                    json_str = line[6:].strip()
                    try:
                        data = json.loads(json_str)
                        choices = data.get("choices", [])
                        if choices and "delta" in choices[0] and "content" in choices[0]["delta"]:
                            delta_content = choices[0]["delta"]["content"]
                            if isinstance(delta_content, str):
                                # Pass through stream character buffer
                                restored_content = buffer.process_chunk(delta_content)
                                choices[0]["delta"]["content"] = restored_content
                                restored_lines.append(f"data: {json.dumps(data)}")
                                continue
                    except Exception:
                        pass
                elif line.startswith("data: [DONE]"):
                    # Stream complete: flush any leftover buffered chars before [DONE]
                    flushed = buffer.flush()
                    if flushed:
                        flush_event = {
                            "choices": [{"index": 0, "delta": {"content": flushed}, "finish_reason": None}]
                        }
                        restored_lines.append(f"data: {json.dumps(flush_event)}")
                    restored_lines.append(line)
                    continue

                restored_lines.append(line)

            yield "\n".join(restored_lines).encode("utf-8")

    def restore_anthropic_json_response(self, response_bytes: bytes, vault: SessionVault) -> bytes:
        """Restores placeholders in a standard non-streaming Anthropic JSON response."""
        try:
            data = json.loads(response_bytes.decode("utf-8"))
            if "content" in data and isinstance(data["content"], list):
                for block in data["content"]:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text_val = block.get("text", "")
                        block["text"] = self.restore_text(text_val, vault)
            return json.dumps(data).encode("utf-8")
        except Exception:
            text = response_bytes.decode("utf-8", errors="replace")
            restored = self.restore_text(text, vault)
            return restored.encode("utf-8")

    def restore_ollama_json_response(self, response_bytes: bytes, vault: SessionVault) -> bytes:
        """Restores placeholders in a non-streaming Ollama JSON response."""
        try:
            data = json.loads(response_bytes.decode("utf-8"))
            if "message" in data and isinstance(data["message"], dict):
                content = data["message"].get("content", "")
                data["message"]["content"] = self.restore_text(content, vault)
            elif "response" in data and isinstance(data["response"], str):
                data["response"] = self.restore_text(data["response"], vault)
            return json.dumps(data).encode("utf-8")
        except Exception:
            text = response_bytes.decode("utf-8", errors="replace")
            restored = self.restore_text(text, vault)
            return restored.encode("utf-8")

    async def restore_anthropic_sse_stream(
        self,
        upstream_stream: AsyncGenerator[bytes, None],
        vault: SessionVault
    ) -> AsyncGenerator[bytes, None]:
        """Intercepts Anthropic SSE events and restores content_block_delta deltas."""
        buffer = StreamBuffer(restore_func=vault.restore_placeholder)

        async for raw_chunk in upstream_stream:
            try:
                chunk_str = raw_chunk.decode("utf-8")
            except UnicodeDecodeError:
                yield raw_chunk
                continue

            lines = chunk_str.split("\n")
            restored_lines = []

            for line in lines:
                if line.startswith("data: "):
                    json_str = line[6:].strip()
                    try:
                        data = json.loads(json_str)
                        if data.get("type") == "content_block_delta":
                            delta = data.get("delta", {})
                            if delta.get("type") == "text_delta" and "text" in delta:
                                text_val = delta["text"]
                                restored_text = buffer.process_chunk(text_val)
                                delta["text"] = restored_text
                                restored_lines.append(f"data: {json.dumps(data)}")
                                continue
                        elif data.get("type") == "message_stop":
                            flushed = buffer.flush()
                            if flushed:
                                flush_event = {
                                    "type": "content_block_delta",
                                    "index": 0,
                                    "delta": {"type": "text_delta", "text": flushed}
                                }
                                restored_lines.append(f"data: {json.dumps(flush_event)}")
                    except Exception:
                        pass

                restored_lines.append(line)

            yield "\n".join(restored_lines).encode("utf-8")

    async def restore_ollama_stream(
        self,
        upstream_stream: AsyncGenerator[bytes, None],
        vault: SessionVault
    ) -> AsyncGenerator[bytes, None]:
        """Intercepts Ollama newline-delimited JSON stream chunks and restores tokens."""
        buffer = StreamBuffer(restore_func=vault.restore_placeholder)

        async for raw_chunk in upstream_stream:
            try:
                chunk_str = raw_chunk.decode("utf-8")
            except UnicodeDecodeError:
                yield raw_chunk
                continue

            lines = chunk_str.split("\n")
            restored_lines = []

            for line in lines:
                trimmed = line.strip()
                if not trimmed:
                    restored_lines.append(line)
                    continue

                try:
                    data = json.loads(trimmed)
                    is_done = data.get("done", False)

                    if "message" in data and isinstance(data["message"], dict):
                        content = data["message"].get("content", "")
                        data["message"]["content"] = buffer.process_chunk(content)
                    elif "response" in data and isinstance(data["response"], str):
                        data["response"] = buffer.process_chunk(data["response"])

                    if is_done:
                        flushed = buffer.flush()
                        if flushed:
                            if "message" in data and isinstance(data["message"], dict):
                                data["message"]["content"] = (data["message"].get("content", "") + flushed)
                            elif "response" in data:
                                data["response"] = (data.get("response", "") + flushed)

                    restored_lines.append(json.dumps(data))
                except Exception:
                    restored_lines.append(line)

            yield "\n".join(restored_lines).encode("utf-8")

