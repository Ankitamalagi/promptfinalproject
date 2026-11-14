"""
Input Normalizer

Creates a predictable analysis representation from untrusted input.
The original input is preserved separately - normalization must not
silently change what gets forwarded to the provider.

This is a security control: we analyze normalized text but forward original text.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class NormalizedInput:
    """
    Container for both original and normalized text.

    Attributes:
        original_user_message: The exact user message as received
        original_retrieved_content: The exact retrieved content as received (or None)
        analysis_user_message: Normalized version for detection analysis
        analysis_retrieved_content: Normalized version for detection analysis
        sources: Source labels for each content piece
    """

    original_user_message: str
    original_retrieved_content: Optional[str]
    analysis_user_message: str
    analysis_retrieved_content: Optional[str]
    sources: list[str]

    def get_analysis_text(self) -> str:
        """Get combined text for analysis (detector runs on this)."""
        parts = [self.analysis_user_message]
        if self.analysis_retrieved_content:
            parts.append(self.analysis_retrieved_content)
        return "\n\n---\n\n".join(parts)

    def get_original_text(self) -> str:
        """Get combined original text for forwarding (if allowed)."""
        parts = [self.original_user_message]
        if self.original_retrieved_content:
            parts.append(self.original_retrieved_content)
        return "\n\n---\n\n".join(parts)


def normalize_text(text: str) -> str:
    """
    Normalize text for consistent detection analysis.

    Normalization rules:
    - Convert to lowercase for case-insensitive matching
    - Normalize unicode (NFKC) to handle lookalike characters
    - Collapse multiple whitespace to single space
    - Strip leading/trailing whitespace

    Args:
        text: Raw input text

    Returns:
        Normalized text for analysis
    """
    if not text:
        return ""

    # Normalize unicode (handles lookalike characters, fullwidth, etc.)
    import unicodedata
    text = unicodedata.normalize("NFKC", text)

    # Convert to lowercase for case-insensitive matching
    text = text.lower()

    # Collapse whitespace (newlines, tabs, multiple spaces -> single space)
    import re
    text = re.sub(r"\s+", " ", text)

    # Strip leading/trailing whitespace
    text = text.strip()

    return text


def create_normalized_input(
    user_message: str,
    retrieved_content: Optional[str],
    sources: list[str],
) -> NormalizedInput:
    """
    Create a NormalizedInput container from raw request data.

    This is the main entry point - it preserves originals and creates
    normalized versions for the detector.

    Args:
        user_message: Raw user message
        retrieved_content: Raw retrieved content (may be None)
        sources: Source labels

    Returns:
        NormalizedInput with both original and analysis-ready text
    """
    return NormalizedInput(
        original_user_message=user_message,
        original_retrieved_content=retrieved_content,
        analysis_user_message=normalize_text(user_message),
        analysis_retrieved_content=normalize_text(retrieved_content) if retrieved_content else None,
        sources=sources,
    )