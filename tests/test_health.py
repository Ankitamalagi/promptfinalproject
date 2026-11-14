"""
Tests for the health endpoint.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_endpoint():
    """Test that health endpoint returns expected structure."""
    response = client.get("/api/health")
    assert response.status_code == 200

    data = response.json()
    assert "status" in data
    assert data["status"] == "healthy"
    assert "version" in data
    assert "environment" in data
    assert "provider_configured" in data


def test_root_endpoint():
    """Test that root endpoint returns basic info."""
    response = client.get("/")
    assert response.status_code == 200

    data = response.json()
    assert "name" in data
    assert "docs" in data
    assert "health" in data