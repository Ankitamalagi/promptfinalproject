"""
OpenAI Provider

Real OpenAI API integration using the official OpenAI Python SDK.
Reads API key from environment variable OPENAI_API_KEY.
"""

import os
import asyncio
from typing import Optional
from openai import AsyncOpenAI, APIError, APITimeoutError, APIConnectionError
from app.providers.base import Provider, ProviderResponse


class OpenAIProvider(Provider):
    """
    OpenAI API provider using the official AsyncOpenAI client.

    Configuration via environment variables:
    - OPENAI_API_KEY: Required API key
    - OPENAI_MODEL: Model name (default: gpt-4o-mini)
    - OPENAI_TIMEOUT: Request timeout in seconds (default: 30)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 30.0,
    ):
        """
        Initialize OpenAI provider.

        Args:
            api_key: OpenAI API key (defaults to OPENAI_API_KEY env var)
            model: Model name (defaults to OPENAI_MODEL env var or gpt-4o-mini)
            timeout: Request timeout in seconds
        """
        self._api_key = api_key or os.getenv("OPENAI_API_KEY")
        self._model = model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self._timeout = timeout
        self._client: Optional[AsyncOpenAI] = None

    @property
    def name(self) -> str:
        return "openai"

    def is_available(self) -> bool:
        """Check if provider is configured with a valid API key."""
        return bool(self._api_key and self._api_key.strip())

    def _get_client(self) -> AsyncOpenAI:
        """Get or create the OpenAI async client."""
        if self._client is None:
            if not self.is_available():
                raise ValueError("OpenAI API key not configured. Set OPENAI_API_KEY environment variable.")
            self._client = AsyncOpenAI(
                api_key=self._api_key,
                timeout=self._timeout,
            )
        return self._client

    async def complete(
        self,
        messages: list[dict],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
    ) -> ProviderResponse:
        """
        Send a chat completion request to OpenAI API.

        Args:
            messages: List of message dicts with 'role' and 'content'
            model: Model name (optional, uses configured default)
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response

        Returns:
            ProviderResponse with content or error
        """
        if not self.is_available():
            return ProviderResponse(
                content="",
                model=model or self._model,
                error="OpenAI API key not configured. Set OPENAI_API_KEY environment variable.",
            )

        client = self._get_client()
        use_model = model or self._model

        try:
            response = await client.chat.completions.create(
                model=use_model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )

            content = response.choices[0].message.content if response.choices else ""

            return ProviderResponse(
                content=content,
                model=use_model,
                usage={
                    "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                    "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                    "total_tokens": response.usage.total_tokens if response.usage else 0,
                } if response.usage else None,
            )

        except APITimeoutError:
            return ProviderResponse(
                content="",
                model=use_model,
                error="OpenAI request timed out",
            )
        except APIConnectionError:
            return ProviderResponse(
                content="",
                model=use_model,
                error="Failed to connect to OpenAI API",
            )
        except APIError as e:
            return ProviderResponse(
                content="",
                model=use_model,
                error=f"OpenAI API error: {str(e)}",
            )
        except Exception as e:
            # Catch-all for unexpected errors
            return ProviderResponse(
                content="",
                model=use_model,
                error=f"Unexpected error calling OpenAI: {str(e)}",
            )