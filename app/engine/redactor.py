"""Reversible Redactor replacing sensitive spans with vault placeholders."""
from typing import List, Tuple
from app.engine.models import DetectedSpan
from app.vault.session_vault import SessionVault


class Redactor:
    """Applies synthetic placeholder substitutions to text using the session vault."""

    def redact_text(
        self,
        text: str,
        spans: List[DetectedSpan],
        vault: SessionVault
    ) -> Tuple[str, int]:
        """Replaces matched spans in text with vault placeholders.
        
        Processes spans in reverse character order so earlier offsets remain valid.
        Returns (redacted_text, count_of_redactions).
        """
        if not spans:
            return text, 0

        # Sort spans in descending order of their start position
        sorted_spans = sorted(spans, key=lambda s: s.start, reverse=True)
        redacted = text
        count = 0

        for span in sorted_spans:
            entity_key = span.metadata.get("placeholder_prefix") if (span.metadata and span.metadata.get("placeholder_prefix")) else span.entity_type.value
            placeholder = vault.get_or_create_placeholder(
                entity_type=entity_key,
                original_val=span.matched_text
            )
            # Slice replace
            redacted = redacted[:span.start] + placeholder + redacted[span.end:]
            count += 1

        return redacted, count

    def redact_chat_messages(
        self,
        messages: List[dict],
        pipeline,
        vault: SessionVault
    ) -> Tuple[List[dict], int]:
        """Iterates through OpenAI chat messages list, inspects and redacts each message."""
        sanitized_messages = []
        total_redactions = 0

        for msg in messages:
            content = msg.get("content")
            if isinstance(content, str):
                # Run inspection pipeline (raises SecretDetectedException on secrets)
                _, redact_spans = pipeline.inspect(content)
                sanitized_content, count = self.redact_text(content, redact_spans, vault)
                total_redactions += count
                new_msg = dict(msg)
                new_msg["content"] = sanitized_content
                sanitized_messages.append(new_msg)
            elif isinstance(content, list):
                # Multi-modal / structured content parts
                new_parts = []
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        text_val = part.get("text", "")
                        _, redact_spans = pipeline.inspect(text_val)
                        sanitized_val, count = self.redact_text(text_val, redact_spans, vault)
                        total_redactions += count
                        new_part = dict(part)
                        new_part["text"] = sanitized_val
                        new_parts.append(new_part)
                    else:
                        new_parts.append(part)
                new_msg = dict(msg)
                new_msg["content"] = new_parts
                sanitized_messages.append(new_msg)
            else:
                sanitized_messages.append(msg)

        return sanitized_messages, total_redactions

    def redact_anthropic_payload(
        self,
        payload: dict,
        pipeline,
        vault: SessionVault
    ) -> Tuple[dict, int]:
        """Inspects and redacts an Anthropic /v1/messages request payload (system + messages)."""
        new_payload = dict(payload)
        total_redactions = 0

        # 1. Redact system prompt if present
        system_val = new_payload.get("system")
        if isinstance(system_val, str):
            _, spans = pipeline.inspect(system_val)
            sanitized_sys, count = self.redact_text(system_val, spans, vault)
            new_payload["system"] = sanitized_sys
            total_redactions += count
        elif isinstance(system_val, list):
            new_sys_parts = []
            for part in system_val:
                if isinstance(part, dict) and part.get("type") == "text":
                    text_val = part.get("text", "")
                    _, spans = pipeline.inspect(text_val)
                    sanitized_val, count = self.redact_text(text_val, spans, vault)
                    total_redactions += count
                    new_part = dict(part)
                    new_part["text"] = sanitized_val
                    new_sys_parts.append(new_part)
                else:
                    new_sys_parts.append(part)
            new_payload["system"] = new_sys_parts

        # 2. Redact messages array
        messages = new_payload.get("messages", [])
        if messages:
            sanitized_msgs, count = self.redact_chat_messages(messages, pipeline, vault)
            new_payload["messages"] = sanitized_msgs
            total_redactions += count

        return new_payload, total_redactions

    def redact_ollama_payload(
        self,
        payload: dict,
        pipeline,
        vault: SessionVault
    ) -> Tuple[dict, int]:
        """Inspects and redacts an Ollama /api/chat or /api/generate payload."""
        new_payload = dict(payload)
        total_redactions = 0

        # Check prompt (for /api/generate)
        if "prompt" in new_payload and isinstance(new_payload["prompt"], str):
            prompt_val = new_payload["prompt"]
            _, spans = pipeline.inspect(prompt_val)
            sanitized_p, count = self.redact_text(prompt_val, spans, vault)
            new_payload["prompt"] = sanitized_p
            total_redactions += count

        # Check system (optional system instructions)
        if "system" in new_payload and isinstance(new_payload["system"], str):
            sys_val = new_payload["system"]
            _, spans = pipeline.inspect(sys_val)
            sanitized_s, count = self.redact_text(sys_val, spans, vault)
            new_payload["system"] = sanitized_s
            total_redactions += count

        # Check messages (for /api/chat)
        if "messages" in new_payload and isinstance(new_payload["messages"], list):
            sanitized_msgs, count = self.redact_chat_messages(new_payload["messages"], pipeline, vault)
            new_payload["messages"] = sanitized_msgs
            total_redactions += count

        return new_payload, total_redactions
