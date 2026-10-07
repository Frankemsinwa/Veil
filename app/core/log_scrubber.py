"""Log Scrubber ensuring sensitive secrets and PII never leak into logging sinks.

Fulfills Security Invariant 4:
Log Sanitization: Log sinks (stdout, files, error handlers) must pass through
a secondary scrubber preventing decrypted secrets from being printed during debug runs.
"""
import re
import logging
from typing import List, Tuple

# Compiled scrubber patterns for credential patterns and sensitive identifiers
SCRUB_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # OpenAI and generic API keys
    (re.compile(r"sk-[a-zA-Z0-9_\-]{20,}", re.IGNORECASE), "[REDACTED_API_KEY]"),
    # GitHub Tokens
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}", re.IGNORECASE), "[REDACTED_GITHUB_TOKEN]"),
    # AWS Access Keys
    (re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b"), "[REDACTED_AWS_KEY]"),
    # Slack Webhooks and Tokens
    (re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,}", re.IGNORECASE), "[REDACTED_SLACK_TOKEN]"),
    # JWT Tokens
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b"), "[REDACTED_JWT]"),
    # PEM Private Keys
    (re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    # Credit card numbers
    (re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"), "[REDACTED_CREDIT_CARD]"),
    # Standard email addresses
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
]


def scrub_string(text: str) -> str:
    """Scrub sensitive patterns from text string."""
    if not isinstance(text, str):
        return text
    scrubbed = text
    for pattern, replacement in SCRUB_PATTERNS:
        scrubbed = pattern.sub(replacement, scrubbed)
    return scrubbed


class VeilLogScrubber(logging.Filter):
    """Logging filter that scrubs sensitive strings from all log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = scrub_string(record.msg)
        if record.args:
            if isinstance(record.args, tuple):
                record.args = tuple(scrub_string(str(a)) if isinstance(a, str) else a for a in record.args)
            elif isinstance(record.args, dict):
                record.args = {k: scrub_string(str(v)) if isinstance(v, str) else v for k, v in record.args.items()}
        return True


def install_log_scrubber():
    """Install VeilLogScrubber across root and common application loggers."""
    scrubber = VeilLogScrubber()
    loggers_to_patch = [
        logging.getLogger(),
        logging.getLogger("uvicorn"),
        logging.getLogger("uvicorn.access"),
        logging.getLogger("uvicorn.error"),
        logging.getLogger("fastapi"),
        logging.getLogger("httpx"),
        logging.getLogger("veil"),
    ]
    for logger in loggers_to_patch:
        # Avoid duplicate filters
        if not any(isinstance(f, VeilLogScrubber) for f in logger.filters):
            logger.addFilter(scrubber)
