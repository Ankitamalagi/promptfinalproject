"""
Tests for Phase 8: Dashboard static assets and security verification.

Verifies:
- GET /dashboard returns index.html successfully.
- Static assets (styles.css, app.js) are accessible.
- Dashboard files and responses never contain secret keys or tokens.
"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


class TestDashboard:
    """Tests for dashboard UI and static endpoints."""

    def test_dashboard_endpoint_loads(self):
        """Test GET /dashboard returns HTTP 200 with HTML content."""
        response = client.get("/dashboard")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
        assert "Prompt Injection Security Gateway" in response.text
        assert "Live Security Scan Console" in response.text

    def test_static_files_accessible(self):
        """Test static CSS and JS are served properly."""
        css_resp = client.get("/static/styles.css")
        assert css_resp.status_code == 200
        assert "css" in css_resp.headers.get("content-type", "")

        js_resp = client.get("/static/app.js")
        assert js_resp.status_code == 200
        assert "javascript" in js_resp.headers.get("content-type", "")

    def test_dashboard_does_not_expose_secrets(self):
        """Security: Assert HTML and JS do not contain hardcoded API keys or secrets."""
        import re
        html_resp = client.get("/dashboard")
        js_resp = client.get("/static/app.js")

        combined_text = html_resp.text + js_resp.text
        # Assert no real OpenAI key format is exposed
        assert not re.search(r"\bsk-[a-zA-Z0-9_-]{20,}\b", combined_text), "API key exposed in dashboard"
        forbidden_strings = ["api_key_secret", "bearer secret_", "password123"]
        for forbidden in forbidden_strings:
            assert forbidden not in combined_text.lower(), f"Potential secret leak in dashboard: {forbidden}"

    def test_root_includes_dashboard_link(self):
        """Test root JSON includes dashboard URL."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data.get("dashboard") == "/dashboard"
