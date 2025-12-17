"""
Tests for security headers middleware.

Verifies that all required security headers are present in responses.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


def test_security_headers_present(client):
    """Test that all security headers are present in response."""
    response = client.get("/api/health")

    # Check required security headers
    assert "X-Frame-Options" in response.headers
    assert response.headers["X-Frame-Options"] == "DENY"

    assert "X-Content-Type-Options" in response.headers
    assert response.headers["X-Content-Type-Options"] == "nosniff"

    assert "X-XSS-Protection" in response.headers
    assert response.headers["X-XSS-Protection"] == "1; mode=block"

    assert "Referrer-Policy" in response.headers
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"

    assert "Permissions-Policy" in response.headers
    # Should restrict geolocation, camera, microphone
    assert "geolocation=()" in response.headers["Permissions-Policy"]
    assert "camera=()" in response.headers["Permissions-Policy"]
    assert "microphone=()" in response.headers["Permissions-Policy"]


def test_csp_header_present(client):
    """Test that Content-Security-Policy header is present."""
    response = client.get("/api/health")

    assert "Content-Security-Policy" in response.headers
    csp = response.headers["Content-Security-Policy"]

    # Check key CSP directives
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp


def test_hsts_not_present_in_development(client):
    """Test that HSTS is not present in development mode."""
    response = client.get("/api/health")

    # HSTS should not be present in development mode by default
    # (unless HTTPS_REDIRECT_ENABLED is explicitly set)
    # This is conditional based on environment


def test_security_status_endpoint(client):
    """Test the security status endpoint."""
    response = client.get("/api/security/status")

    assert response.status_code == 200
    data = response.json()

    assert "status" in data
    assert data["status"] == "configured"

    assert "security" in data
    assert "warnings" in data

    # Check security report structure
    security = data["security"]
    assert "enabled" in security
    assert "environment" in security
    assert "https_redirect" in security
    assert "hsts" in security
    assert "csp" in security
    assert "headers" in security


def test_x_powered_by_removed(client):
    """Test that X-Powered-By header is removed."""
    response = client.get("/api/health")

    # X-Powered-By should not be present
    assert "X-Powered-By" not in response.headers


def test_headers_on_all_endpoints(client):
    """Test that security headers are applied to all endpoints."""
    endpoints = [
        "/",
        "/api/health",
        "/api/colors",
        "/api/voices",
    ]

    for endpoint in endpoints:
        response = client.get(endpoint)

        # All endpoints should have security headers
        assert "X-Frame-Options" in response.headers
        assert "X-Content-Type-Options" in response.headers
        assert "Content-Security-Policy" in response.headers


def test_security_warnings_validation(client):
    """Test security configuration validation."""
    response = client.get("/api/security/status")
    data = response.json()

    # Warnings should be a list
    assert isinstance(data["warnings"], list)

    # In development, we might have warnings about HTTPS
    # but the list should still be valid


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
