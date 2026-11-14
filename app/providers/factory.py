"""
Provider Factory

Creates the appropriate provider instance based on configuration.
"""

from app.core.config import get_settings
from app.providers.base import Provider
from app.providers.demo_provider import DemoProvider, AlwaysErrorDemoProvider
from app.providers.openai_provider import OpenAIProvider


def get_provider() -> Provider:
    """
    Get the configured provider instance.

    Priority:
    1. If OPENAI_API_KEY is set and provider is 'openai', use OpenAI
    2. If provider is 'demo' or no API key, use Demo provider
    3. Default to Demo provider for safety

    Returns:
        Provider instance
    """
    settings = get_settings()

    # Check if OpenAI provider is explicitly requested and configured
    if settings.openai_api_key and settings.openai_api_key.strip():
        return OpenAIProvider(
            api_key=settings.openai_api_key,
            model=settings.openai_model,
            timeout=settings.openai_timeout,
        )

    # Default to demo provider
    return DemoProvider()


def get_provider_by_name(name: str) -> Provider:
    """
    Get a specific provider by name.

    Args:
        name: 'openai', 'demo', or 'demo-error'

    Returns:
        Provider instance
    """
    settings = get_settings()

    if name == "openai":
        return OpenAIProvider(
            api_key=settings.openai_api_key,
            model=settings.openai_model,
            timeout=settings.openai_timeout,
        )
    elif name == "demo":
        return DemoProvider()
    elif name == "demo-error":
        return AlwaysErrorDemoProvider()
    else:
        raise ValueError(f"Unknown provider: {name}")