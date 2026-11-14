"""
Provider Interface

Defines the common interface for LLM providers.
This allows swapping providers (OpenAI, demo, etc.) without changing the gateway logic.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class ProviderResponse:
    """Response from an LLM provider."""
    content: str
    model: str
    usage: Optional[dict] = None
    error: Optional[str] = None


class Provider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    async def complete(
        self,
        messages: list[dict],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
    ) -> ProviderResponse:
        """
        Send a chat completion request to the LLM provider.

        Args:
            messages: List of message dicts with 'role' and 'content'
            model: Model name (optional, uses provider default)
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response

        Returns:
            ProviderResponse with content or error
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider is configured and available."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name for logging/identification."""
        pass