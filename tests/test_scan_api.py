"""
Tests for the /api/scan endpoint.

Tests cover valid requests, missing fields, malformed requests,
and oversized requests.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


class TestScanEndpoint:
    """Tests for POST /api/scan endpoint."""

    def test_valid_minimal_request(self):
        """Test scan with only required user_message."""
        response = client.post("/api/scan", json={"user_message": "Hello world"})
        assert response.status_code == 200

        data = response.json()
        assert data["risk_score"] == 0
        assert data["risk_level"] == "low"
        assert data["provider_called"] is False
        assert "request_id" in data
        assert len(data["request_id"]) == 8

    def test_valid_with_retrieved_content(self):
        """Test scan with user_message and retrieved_content."""
        response = client.post(
            "/api/scan",
            json={
                "user_message": "Summarize this document",
                "retrieved_content": "This is the document content from a PDF",
                "sources": ["user", "pdf"],
            },
        )
        assert response.status_code == 200

        data = response.json()
        assert data["risk_score"] == 0
        assert data["risk_level"] == "low"

    def test_valid_with_custom_request_id(self):
        """Test scan with client-provided request_id."""
        response = client.post(
            "/api/scan",
            json={"user_message": "Hello", "request_id": "my-custom-id-123"},
        )
        assert response.status_code == 200
        assert response.json()["request_id"] == "my-custom-id-123"

    def test_missing_user_message_returns_422(self):
        """Test that missing user_message returns 422 validation error."""
        response = client.post("/api/scan", json={})
        assert response.status_code == 422

        data = response.json()
        assert "detail" in data
        # Check that error mentions user_message
        assert any("user_message" in str(err) for err in data["detail"])

    def test_empty_user_message_returns_422(self):
        """Test that empty user_message returns 422 validation error."""
        response = client.post("/api/scan", json={"user_message": ""})
        assert response.status_code == 422

    def test_whitespace_only_user_message_returns_422(self):
        """Test that whitespace-only user_message returns 422 validation error."""
        response = client.post("/api/scan", json={"user_message": "   \n\t  "})
        assert response.status_code == 422

    def test_empty_retrieved_content_treated_as_none(self):
        """Test that empty retrieved_content is treated as not provided."""
        response = client.post(
            "/api/scan", json={"user_message": "Hi", "retrieved_content": ""}
        )
        assert response.status_code == 200

    def test_whitespace_retrieved_content_treated_as_none(self):
        """Test that whitespace-only retrieved_content is treated as not provided."""
        response = client.post(
            "/api/scan", json={"user_message": "Hi", "retrieved_content": "   \n\t  "}
        )
        assert response.status_code == 200

    def test_empty_sources_defaults_to_user(self):
        """Test that empty sources list defaults to ['user']."""
        response = client.post(
            "/api/scan", json={"user_message": "Hi", "sources": []}
        )
        assert response.status_code == 200

    def test_sources_strips_whitespace(self):
        """Test that source labels are stripped."""
        response = client.post(
            "/api/scan", json={"user_message": "Hi", "sources": [" user ", " pdf "]}
        )
        assert response.status_code == 200

    def test_empty_source_label_returns_422(self):
        """Test that empty source label returns 422 validation error."""
        response = client.post(
            "/api/scan", json={"user_message": "Hi", "sources": ["user", ""]}
        )
        assert response.status_code == 422

    def test_malformed_json_returns_422(self):
        """Test that malformed JSON returns 422."""
        response = client.post(
            "/api/scan",
            content='{"user_message": "Hi",}',  # Trailing comma - invalid JSON
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 422

    def test_wrong_content_type_returns_422(self):
        """Test that wrong content type returns 422."""
        response = client.post(
            "/api/scan",
            content="user_message=Hi",  # Form data, not JSON
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert response.status_code == 422

    def test_oversized_user_message_returns_422(self):
        """Test that oversized user_message returns 422."""
        # Create a message longer than max_user_message_length (default 10000)
        oversized_message = "x" * 10001
        response = client.post("/api/scan", json={"user_message": oversized_message})
        assert response.status_code == 422

    def test_oversized_retrieved_content_returns_422(self):
        """Test that oversized retrieved_content returns 422."""
        # Create content longer than max_retrieved_content_length (default 50000)
        oversized_content = "x" * 50001
        response = client.post(
            "/api/scan",
            json={"user_message": "Hi", "retrieved_content": oversized_content},
        )
        assert response.status_code == 422


class TestChatEndpoint:
    """Tests for POST /api/chat endpoint (validation only, not full implementation)."""

    def test_valid_chat_request(self):
        """Test chat with valid request returns proper response structure.

        For ALLOW policy (default), benign requests should call the provider.
        """
        response = client.post(
            "/api/chat", json={"user_message": "Hi", "task": "Say hello"}
        )
        assert response.status_code == 200

        data = response.json()
        assert "request_id" in data
        assert "risk_score" in data
        assert "risk_level" in data
        assert "findings" in data
        assert "score_breakdown" in data
        assert "policy" in data
        assert "decision" in data
        assert "provider_called" in data
        # ALLOW policy with benign request -> provider should be called
        assert data["provider_called"] is True
        # Provider response should be present (demo provider returns simulated response)
        assert data["provider_response"] is not None
        assert "[DEMO RESPONSE]" in data["provider_response"]

    def test_missing_task_returns_422(self):
        """Test that missing task returns 422."""
        response = client.post("/api/chat", json={"user_message": "Hi"})
        assert response.status_code == 422

    def test_empty_task_returns_422(self):
        """Test that empty task returns 422."""
        response = client.post("/api/chat", json={"user_message": "Hi", "task": ""})
        assert response.status_code == 422