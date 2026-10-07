"""Sliding-window buffer for assembling and restoring split placeholders across SSE stream chunks."""
import re
from typing import AsyncGenerator, Callable, Optional

# Placeholder regex matching [TYPE_001]
PLACEHOLDER_REGEX = re.compile(r"\[([A-Z_]+_\d{3})\]")
MAX_PLACEHOLDER_LEN = 32  # e.g., '[GENERIC_SECRET_ENTROPY_001]'


class StreamBuffer:
    """Buffers streaming characters across chunk boundaries to detect and restore split placeholders.
    
    When an opening bracket '[' is observed without a matching ']' in the current chunk,
    the buffer holds the potential candidate until it is either completed or invalidated.
    """

    def __init__(self, restore_func: Callable[[str], Optional[str]]):
        self.restore_func = restore_func
        self._accumulator = ""

    def process_chunk(self, chunk: str) -> str:
        """Feed a new chunk of characters and return safe, de-redacted text ready to be emitted."""
        self._accumulator += chunk
        output = []

        while self._accumulator:
            # Look for an opening bracket
            open_bracket_idx = self._accumulator.find("[")

            if open_bracket_idx == -1:
                # No bracket in accumulator; entire accumulator is safe to emit
                output.append(self._accumulator)
                self._accumulator = ""
                break

            # If there's text before the '[', emit it immediately
            if open_bracket_idx > 0:
                output.append(self._accumulator[:open_bracket_idx])
                self._accumulator = self._accumulator[open_bracket_idx:]

            # Now self._accumulator begins with '['
            close_bracket_idx = self._accumulator.find("]")

            if close_bracket_idx != -1:
                # Found a potential full placeholder: [TOKEN]
                candidate = self._accumulator[:close_bracket_idx + 1]
                match = PLACEHOLDER_REGEX.fullmatch(candidate)
                if match:
                    # Resolve from vault
                    original = self.restore_func(candidate)
                    output.append(original if original is not None else candidate)
                else:
                    # Not a valid placeholder (e.g., markdown link or array index like '[0]')
                    output.append(candidate)
                
                # Advance accumulator
                self._accumulator = self._accumulator[close_bracket_idx + 1:]
            else:
                # We have a '[' with no closing ']' yet
                # Check if accumulator length exceeded maximum plausible placeholder length
                if len(self._accumulator) > MAX_PLACEHOLDER_LEN:
                    # It cannot be a valid placeholder, emit the '[' and continue
                    output.append(self._accumulator[0])
                    self._accumulator = self._accumulator[1:]
                else:
                    # Hold in buffer waiting for next chunk!
                    break

        return "".join(output)

    def flush(self) -> str:
        """Flush remaining buffered text at end of stream."""
        remaining = self._accumulator
        self._accumulator = ""
        # Check if remaining happens to be a valid placeholder
        match = PLACEHOLDER_REGEX.fullmatch(remaining)
        if match:
            original = self.restore_func(remaining)
            return original if original is not None else remaining
        return remaining
