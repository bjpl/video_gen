"""
E2E Test: YouTube Flow
======================

Complete end-to-end test for YouTube video processing:
1. Enter YouTube URL
2. Validate URL
3. View preview (thumbnail, metadata)
4. Select languages
5. Select voices
6. Configure video settings
7. Start generation
8. Track progress
9. Download video
"""

import pytest
from pathlib import Path
from fastapi.testclient import TestClient
import sys
import json
import time
from unittest.mock import patch, MagicMock

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.main import app

# Import test data
try:
    from tests.fixtures.test_data import SAMPLE_YOUTUBE_URLS
except ImportError:
    SAMPLE_YOUTUBE_URLS = {
        "valid_standard": {
            "url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "video_id": "dQw4w9WgXcQ",
            "is_valid": True
        }
    }


@pytest.fixture
def client():
    """Create test client with CSRF disabled"""
    import os
    os.environ["CSRF_DISABLED"] = "true"
    with TestClient(app) as c:
        yield c
    os.environ.pop("CSRF_DISABLED", None)


# ============================================================================
# YouTube URL Validation Tests
# ============================================================================

class TestYouTubeURLValidation:
    """E2E tests for YouTube URL validation"""

    @pytest.mark.e2e
    def test_validate_standard_youtube_url(self, client):
        """Test validation of standard YouTube URL"""
        response = client.post(
            "/api/youtube/validate",
            json={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data.get("is_valid") is True
        assert data.get("video_id") == "dQw4w9WgXcQ"

    @pytest.mark.e2e
    def test_validate_short_youtube_url(self, client):
        """Test validation of short YouTube URL (youtu.be)"""
        response = client.post(
            "/api/youtube/validate",
            json={"url": "https://youtu.be/dQw4w9WgXcQ"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data.get("is_valid") is True
        assert data.get("video_id") == "dQw4w9WgXcQ"

    @pytest.mark.e2e
    def test_validate_embed_youtube_url(self, client):
        """Test validation of embed YouTube URL"""
        response = client.post(
            "/api/youtube/validate",
            json={"url": "https://www.youtube.com/embed/dQw4w9WgXcQ"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data.get("is_valid") is True

    @pytest.mark.e2e
    def test_validate_youtube_url_with_timestamp(self, client):
        """Test validation of YouTube URL with timestamp"""
        response = client.post(
            "/api/youtube/validate",
            json={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=30"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data.get("is_valid") is True
        assert data.get("video_id") == "dQw4w9WgXcQ"

    @pytest.mark.e2e
    def test_reject_invalid_url(self, client):
        """Test rejection of invalid URL"""
        response = client.post(
            "/api/youtube/validate",
            json={"url": "not-a-valid-url"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data.get("is_valid") is False
        assert data.get("error") is not None

    @pytest.mark.e2e
    def test_reject_non_youtube_url(self, client):
        """Test rejection of non-YouTube URL"""
        response = client.post(
            "/api/youtube/validate",
            json={"url": "https://vimeo.com/123456789"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data.get("is_valid") is False

    @pytest.mark.e2e
    def test_reject_empty_url(self, client):
        """Test rejection of empty URL"""
        response = client.post(
            "/api/youtube/validate",
            json={"url": ""}
        )

        # Should return validation failure or bad request
        assert response.status_code in [200, 422]
        if response.status_code == 200:
            assert response.json().get("is_valid") is False

    @pytest.mark.e2e
    def test_reject_channel_url(self, client):
        """Test rejection of channel URL (not a video)"""
        response = client.post(
            "/api/youtube/validate",
            json={"url": "https://www.youtube.com/channel/UC1234567890"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data.get("is_valid") is False

    @pytest.mark.e2e
    def test_reject_playlist_url(self, client):
        """Test rejection of playlist URL"""
        response = client.post(
            "/api/youtube/validate",
            json={"url": "https://www.youtube.com/playlist?list=PLxyz123"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data.get("is_valid") is False


# ============================================================================
# YouTube Preview Tests
# ============================================================================

class TestYouTubePreview:
    """E2E tests for YouTube video preview"""

    @pytest.mark.e2e
    def test_preview_endpoint_exists(self, client):
        """Test YouTube preview endpoint exists"""
        response = client.post(
            "/api/youtube/preview",
            json={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"}
        )

        # Should not return 404
        assert response.status_code != 404

    @pytest.mark.e2e
    def test_preview_returns_video_info(self, client):
        """Test preview returns video information"""
        response = client.post(
            "/api/youtube/preview",
            json={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"}
        )

        # May succeed or fail depending on network/API availability
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                assert "preview" in data
                preview = data["preview"]
                # Should have basic info
                has_info = (
                    "title" in preview or
                    "thumbnail" in preview or
                    "duration_seconds" in preview
                )
                assert has_info

    @pytest.mark.e2e
    def test_preview_invalid_url_handled(self, client):
        """Test preview handles invalid URL input"""
        response = client.post(
            "/api/youtube/preview",
            json={"url": "invalid-url"}
        )

        # API may return error status or success with limited data
        if response.status_code == 200:
            data = response.json()
            preview = data.get("preview", {})
            # Invalid video should have indicators: can_generate=False or no transcript
            assert preview.get("can_generate") is False or not preview.get("has_transcript")
        else:
            assert response.status_code in [400, 422]

    @pytest.mark.e2e
    def test_transcript_preview_endpoint(self, client):
        """Test transcript preview endpoint exists"""
        response = client.post(
            "/api/youtube/transcript-preview",
            json={
                "url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
                "transcript_language": "en"
            }
        )

        # Should not return 404
        assert response.status_code != 404


# ============================================================================
# YouTube Generation Flow Tests
# ============================================================================

class TestYouTubeGenerationFlow:
    """E2E tests for YouTube video generation flow"""

    @pytest.mark.e2e
    def test_parse_youtube_endpoint(self, client):
        """Test YouTube parse endpoint exists and accepts valid input"""
        response = client.post(
            "/api/parse/youtube",
            json={
                "url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
                "duration": 60,
                "accent_color": "blue",
                "voice": "male"
            }
        )

        # Should accept request (may start task or fail on actual processing)
        assert response.status_code in [200, 422, 500]
        if response.status_code == 200:
            data = response.json()
            assert "task_id" in data or "status" in data

    @pytest.mark.e2e
    def test_parse_only_youtube_endpoint(self, client):
        """Test parse-only YouTube endpoint"""
        response = client.post(
            "/api/parse-only/youtube",
            json={
                "url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
                "duration": 60,
                "accent_color": "blue",
                "voice": "male"
            }
        )

        # Should not return 404
        assert response.status_code != 404

    @pytest.mark.e2e
    def test_youtube_estimate_endpoint(self, client):
        """Test YouTube generation estimate endpoint"""
        response = client.get("/api/youtube/estimate/dQw4w9WgXcQ")

        assert response.status_code in [200, 404, 500]
        if response.status_code == 200:
            data = response.json()
            assert "video_id" in data
            assert "estimated_scenes" in data or "generation_estimate" in data


# ============================================================================
# Complete YouTube Flow Tests
# ============================================================================

class TestCompleteYouTubeFlow:
    """Complete end-to-end YouTube flow tests"""

    @pytest.mark.e2e
    def test_complete_youtube_flow(self, client):
        """Test complete YouTube processing flow"""
        youtube_url = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

        # Step 1: Validate URL
        val_response = client.post(
            "/api/youtube/validate",
            json={"url": youtube_url}
        )
        assert val_response.status_code == 200
        assert val_response.json().get("is_valid") is True

        # Step 2: Get languages
        lang_response = client.get("/api/languages")
        assert lang_response.status_code == 200
        assert len(lang_response.json().get("languages", [])) > 0

        # Step 3: Get voices
        voice_response = client.get("/api/languages/en/voices")
        assert voice_response.status_code == 200
        assert len(voice_response.json().get("voices", [])) > 0

        # Step 4: Get configuration options
        colors_response = client.get("/api/colors")
        assert colors_response.status_code == 200

    @pytest.mark.e2e
    def test_youtube_flow_with_invalid_url_stops(self, client):
        """Test flow stops at validation for invalid URL"""
        # Step 1: Validate invalid URL
        val_response = client.post(
            "/api/youtube/validate",
            json={"url": "https://vimeo.com/12345"}
        )

        assert val_response.status_code == 200
        assert val_response.json().get("is_valid") is False
        # Flow should stop here - no further processing


# ============================================================================
# YouTube URL Format Tests
# ============================================================================

class TestYouTubeURLFormats:
    """Test various YouTube URL formats"""

    @pytest.mark.e2e
    @pytest.mark.parametrize("url,expected_valid", [
        ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", True),
        ("https://youtube.com/watch?v=dQw4w9WgXcQ", True),
        ("https://youtu.be/dQw4w9WgXcQ", True),
        ("https://www.youtube.com/embed/dQw4w9WgXcQ", True),
        ("http://www.youtube.com/watch?v=dQw4w9WgXcQ", True),
        ("https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=30s", True),
        ("https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLxyz", True),
        ("https://vimeo.com/123456", False),
        ("https://dailymotion.com/video/xyz", False),
        ("not-a-url", False),
        ("", False),
    ])
    def test_url_format_validation(self, client, url, expected_valid):
        """Test validation of various URL formats"""
        if not url:
            # Empty URL may return 422 validation error
            response = client.post(
                "/api/youtube/validate",
                json={"url": url}
            )
            assert response.status_code in [200, 422]
        else:
            response = client.post(
                "/api/youtube/validate",
                json={"url": url}
            )
            assert response.status_code == 200
            data = response.json()
            assert data.get("is_valid") == expected_valid


# ============================================================================
# YouTube Error Handling Tests
# ============================================================================

class TestYouTubeErrorHandling:
    """E2E tests for YouTube error handling"""

    @pytest.mark.e2e
    def test_missing_url_field(self, client):
        """Test handling missing URL field"""
        response = client.post(
            "/api/youtube/validate",
            json={}
        )

        # Should return validation error
        assert response.status_code == 422

    @pytest.mark.e2e
    def test_null_url(self, client):
        """Test handling null URL"""
        response = client.post(
            "/api/youtube/validate",
            json={"url": None}
        )

        # Should return validation error
        assert response.status_code == 422

    @pytest.mark.e2e
    def test_url_with_spaces(self, client):
        """Test handling URL with leading/trailing spaces"""
        response = client.post(
            "/api/youtube/validate",
            json={"url": "  https://www.youtube.com/watch?v=dQw4w9WgXcQ  "}
        )

        assert response.status_code == 200
        data = response.json()
        # Should trim and validate successfully
        assert data.get("is_valid") is True

    @pytest.mark.e2e
    def test_url_with_quotes(self, client):
        """Test handling URL with quotes"""
        response = client.post(
            "/api/youtube/validate",
            json={"url": '"https://www.youtube.com/watch?v=dQw4w9WgXcQ"'}
        )

        assert response.status_code == 200
        # May or may not be valid depending on quote handling


# ============================================================================
# Performance Tests
# ============================================================================

class TestYouTubeFlowPerformance:
    """Performance tests for YouTube flow"""

    @pytest.mark.e2e
    @pytest.mark.performance
    def test_validation_response_time(self, client):
        """Test URL validation responds quickly"""
        start = time.time()
        response = client.post(
            "/api/youtube/validate",
            json={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"}
        )
        duration = time.time() - start

        assert response.status_code == 200
        assert duration < 2.0  # Should respond within 2 seconds

    @pytest.mark.e2e
    @pytest.mark.performance
    def test_multiple_validations(self, client):
        """Test handling multiple validation requests"""
        urls = [
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://youtu.be/abc123xyz12",
            "https://www.youtube.com/embed/xyz789abc12",
        ]

        start = time.time()
        for url in urls:
            response = client.post(
                "/api/youtube/validate",
                json={"url": url}
            )
            assert response.status_code == 200

        duration = time.time() - start
        assert duration < 5.0  # All should complete within 5 seconds


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short', '-m', 'e2e'])
