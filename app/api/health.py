"""
Health check endpoint.

Provides a simple endpoint to verify the service is running.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional

from app.core.config import Settings, get_settings


router = APIRouter()


class HealthResponse(BaseModel):
    """Health check response model."""

    status: str
    version: str
    environment: str
    provider_configured: bool


@router.get("/health", response_model=HealthResponse)
async def health_check(settings: Settings = Depends(get_settings)) -> HealthResponse:
    """
    Health check endpoint.

    Returns basic service status without exposing secrets.
    """
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        environment=settings.app_env,
        provider_configured=settings.openai_api_key is not None,
    )