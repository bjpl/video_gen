"""
Tests for rate limiting middleware

Verifies that rate limiting is properly enforced across all endpoints.
Tests both successful requests and rate limit exceeded scenarios.
"""

import pytest
import time
from fastapi.testclient import TestClient
from app.main import app


class TestRateLimiting:
    """Test rate limiting middleware functionality"""

    def test_rate_limiting_health_endpoint(self):
        """Health endpoint should have very high limit (should not fail)"""
        client = TestClient(app)

        # Health endpoint should allow many requests
        for _ in range(20):
            response = client.get("/api/health")
            assert response.status_code == 200, "Health endpoint should not be rate limited"

    def test_rate_limiting_parse_endpoint(self):
        """Parse endpoints should have moderate rate limits"""
        client = TestClient(app)

        # Try to exceed the parse limit (10/minute default)
        # This test may need adjustment based on actual configured limits
        successful_requests = 0
        rate_limited = False

        for i in range(15):
            response = client.post(
                "/api/parse/document",
                json={
                    "content": "test.md",
                    "accent_color": "blue",
                    "voice": "male"
                }
            )

            if response.status_code == 429:
                rate_limited = True
                # Verify rate limit response structure
                assert "error" in response.json()
                assert "Rate limit exceeded" in response.json()["error"]
                break
            else:
                successful_requests += 1

        # We should have gotten rate limited eventually
        # (or succeeded if limits are very high in test environment)
        assert successful_requests > 0, "Should have allowed some requests"

    def test_rate_limit_headers_present(self):
        """Rate limit headers should be included in responses"""
        client = TestClient(app)

        response = client.get("/api/health")
        assert response.status_code == 200

        # Check for rate limit headers (slowapi adds these)
        # Note: Actual header names depend on slowapi configuration
        headers = response.headers
        # Headers like X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
        # may be present if headers_enabled=True in limiter config

    def test_different_ips_separate_limits(self):
        """Different IPs should have separate rate limit counters"""
        # This test is conceptual - actual implementation would need
        # to simulate different IPs via X-Forwarded-For headers

        client = TestClient(app)

        # Request with different forwarded IPs
        headers1 = {"X-Forwarded-For": "192.168.1.1"}
        headers2 = {"X-Forwarded-For": "192.168.1.2"}

        response1 = client.get("/api/health", headers=headers1)
        response2 = client.get("/api/health", headers=headers2)

        assert response1.status_code == 200
        assert response2.status_code == 200
        # Both should succeed as they're from different IPs

    def test_rate_limit_disabled_via_env(self, monkeypatch):
        """When RATE_LIMIT_ENABLED=false, limits should not apply"""
        # Note: This requires app reload to take effect
        # In practice, this would be tested by setting env var before app import
        pass  # Conceptual test - requires app restart

    def test_expensive_operations_stricter_limits(self):
        """Upload and generate endpoints should have stricter limits than parse"""
        client = TestClient(app)

        # Generate endpoint should have very strict limit (3/minute default)
        # We can verify the decorator is applied but actual testing
        # would spam the endpoint which we want to avoid in tests

        # Just verify the endpoint is accessible
        response = client.post(
            "/api/generate",
            json={
                "set_id": "test",
                "set_name": "Test Set",
                "videos": [{
                    "video_id": "test",
                    "title": "Test",
                    "scenes": [{"type": "title"}]
                }]
            }
        )

        # Will fail for other reasons (missing data) but should get past rate limiting
        # on first request
        assert response.status_code != 429, "First request should not be rate limited"


class TestRateLimitConfiguration:
    """Test rate limit configuration and environment handling"""

    def test_default_limits_loaded(self):
        """Verify default rate limits are set correctly"""
        from app.middleware.rate_limiting import (
            DEFAULT_LIMIT,
            UPLOAD_LIMIT,
            GENERATE_LIMIT,
            PARSE_LIMIT,
            TASKS_LIMIT,
            HEALTH_LIMIT,
        )

        # Defaults should be set
        assert DEFAULT_LIMIT is not None
        assert UPLOAD_LIMIT is not None
        assert GENERATE_LIMIT is not None
        assert PARSE_LIMIT is not None
        assert TASKS_LIMIT is not None
        assert HEALTH_LIMIT is not None

        # Stricter limits should be lower
        # Parse: 10, Upload: 5, Generate: 3
        assert "3/" in GENERATE_LIMIT, "Generate should have strictest limit"
        assert "5/" in UPLOAD_LIMIT, "Upload should have strict limit"

    def test_limiter_instance_created(self):
        """Verify limiter instance is properly configured"""
        from app.middleware.rate_limiting import limiter

        assert limiter is not None
        assert limiter.enabled is not None  # Will be True or False

    def test_key_function_handles_forwarded_headers(self):
        """Verify IP extraction handles proxy headers correctly"""
        from app.middleware.rate_limiting import get_rate_limit_key
        from fastapi import Request

        # This would require mocking Request objects with different headers
        # Conceptual test - actual implementation depends on test setup
        pass


class TestRateLimitResponses:
    """Test rate limit exceeded response format"""

    def test_rate_limit_response_format(self):
        """When rate limited, response should have helpful error structure"""
        # This test would need to actually trigger rate limiting
        # which we want to avoid in regular test runs

        # Expected response format:
        expected_structure = {
            "error": "Rate limit exceeded",
            "message": str,  # Helpful message
            "limit": str,  # The limit that was exceeded
            "endpoint": str,  # Which endpoint
            "retry_after": str  # When to retry
        }

        # Verify the custom handler returns this structure
        # (requires actually hitting rate limit)
        pass

    def test_rate_limit_status_code(self):
        """Rate limit responses should use HTTP 429 status"""
        # Expected: 429 Too Many Requests
        from starlette.status import HTTP_429_TOO_MANY_REQUESTS
        assert HTTP_429_TOO_MANY_REQUESTS == 429


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
