"""
Demo Provider (Fake Provider for Testing/Demonstration)

Returns simulated AI responses without calling any real API.
Used for testing and demos without requiring an OpenAI API key.
"""

import asyncio
import random
from typing import Optional
from app.providers.base import Provider, ProviderResponse


class DemoProvider(Provider):
    """
    Fake provider that returns clearly-labelled simulated responses.

    This provider:
    - Never makes real API calls
    - Returns responses marked as [DEMO RESPONSE]
    - Simulates realistic delays
    - Can be configured to simulate errors for testing
    """

    def __init__(
        self,
        delay_seconds: float = 0.5,
        error_rate: float = 0.0,
        fixed_response: Optional[str] = None,
    ):
        """
        Initialize demo provider.

        Args:
            delay_seconds: Simulated network delay
            error_rate: Probability of returning an error (0.0 to 1.0)
            fixed_response: If set, always return this response
        """
        self.delay_seconds = delay_seconds
        self.error_rate = error_rate
        self.fixed_response = fixed_response
        self.call_count = 0
        self.last_request = None

    @property
    def name(self) -> str:
        return "demo"

    def is_available(self) -> bool:
        """Demo provider is always available (no API key needed)."""
        return True

    async def complete(
        self,
        messages: list[dict],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
    ) -> ProviderResponse:
        """
        Return a simulated AI response.

        The response is clearly marked as a demo response.
        """
        self.call_count += 1
        self.last_request = {
            "messages": messages,
            "model": model,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        # Simulate network delay
        await asyncio.sleep(self.delay_seconds)

        # Simulate random errors if configured
        if self.error_rate > 0 and random.random() < self.error_rate:
            return ProviderResponse(
                content="",
                model=model or "demo-model",
                error="[DEMO] Simulated provider error",
            )

        # Use fixed response if provided
        if self.fixed_response:
            return ProviderResponse(
                content=f"[DEMO RESPONSE] {self.fixed_response}",
                model=model or "demo-model",
            )

        # Generate contextual demo response based on last user message
        last_user_msg = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                last_user_msg = msg.get("content", "")
                break

        # Simple demo responses based on message content
        demo_responses = [
            f"[DEMO RESPONSE] I understand you're asking about: '{last_user_msg[:50]}...'. As a demo provider, I'm simulating an AI response without calling a real API.",
            f"[DEMO RESPONSE] This is a simulated response to: '{last_user_msg[:50]}...'. In a real deployment, this would come from an LLM like GPT-4.",
            f"[DEMO RESPONSE] Demo mode active. Your message was received and processed by the security gateway. Real AI integration would go here.",
        ]

        return ProviderResponse(
            content=random.choice(demo_responses),
            model=model or "demo-model",
            usage={"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
        )


class AlwaysErrorDemoProvider(DemoProvider):
    """Demo provider that always returns an error (for testing error handling)."""

    async def complete(self, *args, **kwargs) -> ProviderResponse:
        await asyncio.sleep(self.delay_seconds)
        return ProviderResponse(
            content="",
            model="demo-model",
            error="[DEMO] Simulated provider error - always fails",
        )