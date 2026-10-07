"""AST & Syntax Filter for Markdown, Code Blocks, and RFC Test Data."""
import re
import ipaddress
from typing import List, Set
from app.engine.models import DetectedSpan, EntityType

# RFC 2606 reserved domains
RFC_RESERVED_DOMAINS = {
    "example.com", "example.net", "example.org",
    "test.com", "localhost", "invalid", "test"
}

# Markdown code block regex (```...```)
CODE_BLOCK_REGEX = re.compile(r"```[a-zA-Z0-9_-]*\n([\s\S]*?)```")
# Inline code (`...`)
INLINE_CODE_REGEX = re.compile(r"`([^`]+)`")


def is_rfc_mock_email(email_str: str) -> bool:
    """Check if email uses standard RFC reserved documentation domains."""
    try:
        parts = email_str.split("@")
        if len(parts) == 2:
            domain = parts[1].lower()
            return domain in RFC_RESERVED_DOMAINS or domain.endswith(".example")
    except Exception:
        pass
    return False


def is_safe_test_ip(ip_str: str) -> bool:
    """Check if IPv4 address is loopback (127.0.0.1) or RFC 5737 documentation space."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback:
            return True
        # RFC 5737 Test nets:
        # TEST-NET-1: 192.0.2.0/24
        # TEST-NET-2: 198.51.100.0/24
        # TEST-NET-3: 203.0.113.0/24
        if (
            ip in ipaddress.ip_network("192.0.2.0/24") or
            ip in ipaddress.ip_network("198.51.100.0/24") or
            ip in ipaddress.ip_network("203.0.113.0/24")
        ):
            return True
    except Exception:
        pass
    return False


class AstFilter:
    """Analyzes text structure to identify whitelisted mock data and code contexts."""

    def filter_spans(self, text: str, spans: List[DetectedSpan]) -> List[DetectedSpan]:
        """Mark whitelisted test data or eliminate non-sensitive mock spans."""
        refined_spans: List[DetectedSpan] = []

        for span in spans:
            # 1. Check RFC Email Whitelist
            if span.entity_type == EntityType.EMAIL_ADDRESS:
                if is_rfc_mock_email(span.matched_text):
                    span.is_whitelisted = True

            # 2. Check RFC IP Whitelist
            elif span.entity_type == EntityType.IPV4_ADDRESS:
                if is_safe_test_ip(span.matched_text):
                    span.is_whitelisted = True

            refined_spans.append(span)

        return refined_spans

    def merge_overlapping_spans(self, spans: List[DetectedSpan]) -> List[DetectedSpan]:
        """Merge overlapping spans favoring higher severity (SECRET over PII) and wider ranges."""
        if not spans:
            return []

        # Sort by start asc, end desc
        sorted_spans = sorted(spans, key=lambda s: (s.start, -s.end))
        merged: List[DetectedSpan] = []

        current = sorted_spans[0]
        for next_span in sorted_spans[1:]:
            # Check for overlap
            if next_span.start < current.end:
                # Overlap detected. Keep the higher severity or longer span
                if next_span.category.value == "SECRET" and current.category.value != "SECRET":
                    current = next_span
                elif next_span.end > current.end:
                    # Extend end if same category or current is dominant
                    current.end = next_span.end
                    current.matched_text = current.matched_text + next_span.matched_text[current.end - next_span.start:]
            else:
                merged.append(current)
                current = next_span

        merged.append(current)
        return merged
