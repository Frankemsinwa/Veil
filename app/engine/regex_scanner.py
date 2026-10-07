"""Deterministic Pattern Matcher for PII and Secrets."""
import re
from typing import List, Tuple, Dict
from app.engine.models import DetectedSpan, EntityType, EntityCategory

# Verified, ReDoS-safe patterns with clear word boundaries
REGEX_RULES: Dict[EntityType, Tuple[EntityCategory, re.Pattern, float]] = {
    # ------------------ High Severity Secrets ------------------
    # OpenAI project and personal keys (e.g. sk-proj-..., sk-...)
    EntityType.OPENAI_API_KEY: (
        EntityCategory.SECRET,
        re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{32,120})\b"),
        1.0
    ),
    # Anthropic API Keys (e.g. sk-ant-api03-...)
    EntityType.ANTHROPIC_API_KEY: (
        EntityCategory.SECRET,
        re.compile(r"\b(sk-ant-[a-zA-Z0-9_\-]{40,120})\b"),
        1.0
    ),
    # GitHub Personal Access Tokens (classic and fine-grained)
    EntityType.GITHUB_PAT: (
        EntityCategory.SECRET,
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b"),
        1.0
    ),
    # AWS Access Key IDs (AKIA..., ASIA...)
    EntityType.AWS_ACCESS_KEY: (
        EntityCategory.SECRET,
        re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        1.0
    ),
    # Google Cloud / Firebase API Keys
    EntityType.GOOGLE_API_KEY: (
        EntityCategory.SECRET,
        re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
        1.0
    ),
    # Slack Bot / User Tokens
    EntityType.SLACK_TOKEN: (
        EntityCategory.SECRET,
        re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
        1.0
    ),
    # JWT Tokens (eyJ...)
    EntityType.JWT_TOKEN: (
        EntityCategory.SECRET,
        re.compile(r"\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b"),
        0.98
    ),
    # PEM Private Keys (RSA, EC, OPENSSH, etc.)
    EntityType.PRIVATE_KEY_PEM: (
        EntityCategory.SECRET,
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        1.0
    ),

    # ------------------ PII (Personally Identifiable Info) ------------------
    # Standard RFC-compliant Email Addresses
    EntityType.EMAIL_ADDRESS: (
        EntityCategory.PII,
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b"),
        0.99
    ),
    # International & US Phone Numbers
    EntityType.PHONE_NUMBER: (
        EntityCategory.PII,
        re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"),
        0.85
    ),
    # IPv4 Addresses
    EntityType.IPV4_ADDRESS: (
        EntityCategory.INFRASTRUCTURE,
        re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
        0.95
    ),
    # US Social Security Number (SSN)
    EntityType.SSN: (
        EntityCategory.PII,
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        0.95
    ),
}

# Standard credit card pattern (Visa, MC, Amex, Discover)
CC_REGEX = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def luhn_checksum_valid(card_number_str: str) -> bool:
    """Validate credit card candidate using the Luhn Algorithm."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


class RegexScanner:
    """Scans text for deterministic secret and PII patterns."""

    def scan(self, text: str) -> List[DetectedSpan]:
        detected: List[DetectedSpan] = []

        for entity_type, (category, pattern, confidence) in REGEX_RULES.items():
            for match in pattern.finditer(text):
                matched_str = match.group(0)
                # Filter false-positive phone numbers (e.g. single dates or short numbers)
                if entity_type == EntityType.PHONE_NUMBER:
                    digit_count = sum(1 for c in matched_str if c.isdigit())
                    if digit_count < 7 or digit_count > 15:
                        continue

                detected.append(
                    DetectedSpan(
                        entity_type=entity_type,
                        category=category,
                        start=match.start(),
                        end=match.end(),
                        matched_text=matched_str,
                        confidence=confidence
                    )
                )

        # Credit Card scanning with Luhn algorithm validation
        for match in CC_REGEX.finditer(text):
            matched_str = match.group(0)
            if luhn_checksum_valid(matched_str):
                detected.append(
                    DetectedSpan(
                        entity_type=EntityType.CREDIT_CARD,
                        category=EntityCategory.PII,
                        start=match.start(),
                        end=match.end(),
                        matched_text=matched_str,
                        confidence=0.99
                    )
                )

        return detected
