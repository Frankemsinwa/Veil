"""Shannon Entropy Analyzer for finding unclassified high-entropy secrets and keys."""
import math
import re
from typing import List, Dict
from app.engine.models import DetectedSpan, EntityType, EntityCategory

# Potential token words: strings of alphanumeric/special characters
TOKEN_CANDIDATE_REGEX = re.compile(r"""(?:["']|(?<=\s)|(?<==)|(?<=:))([A-Za-z0-9+/=_\-!@#$%^&*]{16,128})(?:["']|(?=\s)|(?=[,;}]))""")


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon Entropy of a string: H(X) = -sum(P(x) * log2(P(x)))."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    char_counts: Dict[str, int] = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1

    for count in char_counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy


class EntropyScanner:
    """Scans text for strings with high information density (API secrets, passwords, hash tokens)."""

    def __init__(self, min_length: int = 20, entropy_threshold: float = 4.2):
        self.min_length = min_length
        self.entropy_threshold = entropy_threshold

    def scan(self, text: str) -> List[DetectedSpan]:
        detected: List[DetectedSpan] = []

        for match in TOKEN_CANDIDATE_REGEX.finditer(text):
            candidate = match.group(1)
            if len(candidate) < self.min_length:
                continue

            # Skip common false positive patterns: pure hex numbers or UUIDs without hyphens
            # Calculate character variety: uppercase, lowercase, digits, symbols
            has_upper = any(c.isupper() for c in candidate)
            has_lower = any(c.islower() for c in candidate)
            has_digit = any(c.isdigit() for c in candidate)
            has_symbol = any(not c.isalnum() for c in candidate)

            charset_diversity = sum([has_upper, has_lower, has_digit, has_symbol])
            if charset_diversity < 2:
                # E.g. long string of all lowercase letters or numbers
                continue

            entropy = calculate_shannon_entropy(candidate)
            if entropy >= self.entropy_threshold:
                # Calculate span coordinates within original text
                start = match.start(1)
                end = match.end(1)
                detected.append(
                    DetectedSpan(
                        entity_type=EntityType.GENERIC_SECRET_ENTROPY,
                        category=EntityCategory.SECRET,
                        start=start,
                        end=end,
                        matched_text=candidate,
                        confidence=min(1.0, 0.70 + (entropy - self.entropy_threshold) * 0.2),
                        metadata={"entropy": round(entropy, 2)}
                    )
                )

        return detected
