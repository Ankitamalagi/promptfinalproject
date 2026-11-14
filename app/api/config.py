"""
Config endpoint - exposes safe, non-secret configuration.

Provides operational metadata to clients and dashboard without exposing
API keys, credentials, or internal tokens.
"""

from fastapi import APIRouter, Depends

from app.core.config import Settings, get_settings
from app.core.models import ConfigResponse
from app.security.risk import get_risk_thresholds
from app.providers.factory import get_provider

router = APIRouter()


@router.get("/config", response_model=ConfigResponse)
async def config_endpoint(
    settings: Settings = Depends(get_settings),
) -> ConfigResponse:
    """
    Return safe server configuration.

    Guarantees:
    - Never returns API keys or credentials
    - Returns active server policy and risk thresholds
    - Returns input size limits and active provider status
    """
    provider = get_provider()

    return ConfigResponse(
        default_policy=settings.default_policy,
        risk_thresholds=get_risk_thresholds(),
        provider_enabled=provider.is_available(),
        provider_name=provider.name,
        max_user_message_length=settings.max_user_message_length,
        max_retrieved_content_length=settings.max_retrieved_content_length,
    )
