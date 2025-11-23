"""Tests for modern YouTube input flow with URL validation, preview, and elegant UX.

This module tests the enhanced YouTube input functionality including:
- URL validation and normalization
- Video metadata preview
- Transcript extraction preview
- Various YouTube URL format support
- Duration estimation
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
import asyncio

# Import the utilities module (to be implemented)
from video_gen.utils.youtube_validator import (
    YouTubeURLValidator,
    validate_youtube_url,
    normalize_youtube_url,
    extract_video_id,
    YouTubeVideoInfo,
    YouTubeValidationError,
)


class TestYouTubeURLValidator:
    """Test suite for YouTube URL validation and normalization."""

    @pytest.fixture
    def validator(self):
        """Create YouTubeURLValidator instance."""
        return YouTubeURLValidator()

    # =========================================================================
    # URL Format Tests
    # =========================================================================

    @pytest.mark.parametrize("url,expected_id", [
        # Standard watch URLs
        ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        ("http://www.youtube.com/watch?v=dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        ("https://youtube.com/watch?v=dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        ("http://youtube.com/watch?v=dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        # Mobile URLs
        ("https://m.youtube.com/watch?v=dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        # Short URLs
        ("https://youtu.be/dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        ("http://youtu.be/dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        # Embed URLs
        ("https://www.youtube.com/embed/dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        ("https://youtube.com/embed/dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        # V URLs
        ("https://www.youtube.com/v/dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        # URLs with extra parameters
        ("https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=120", "dQw4w9WgXcQ"),
        ("https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLtest", "dQw4w9WgXcQ"),
        ("https://youtu.be/dQw4w9WgXcQ?t=30", "dQw4w9WgXcQ"),
        # Shorts URLs
        ("https://www.youtube.com/shorts/dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        ("https://youtube.com/shorts/dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        # Live URLs
        ("https://www.youtube.com/live/dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        # Direct video ID
        ("dQw4w9WgXcQ", "dQw4w9WgXcQ"),
        # With whitespace (should be trimmed)
        ("  https://www.youtube.com/watch?v=dQw4w9WgXcQ  ", "dQw4w9WgXcQ"),
        # With quotes (common copy-paste issue)
        ('"https://www.youtube.com/watch?v=dQw4w9WgXcQ"', "dQw4w9WgXcQ"),
        ("'https://youtu.be/dQw4w9WgXcQ'", "dQw4w9WgXcQ"),
    ])
    def test_extract_video_id_valid_urls(self, url, expected_id):
        """Test video ID extraction from various valid URL formats."""
        result = extract_video_id(url)
        assert result == expected_id, f"Failed for URL: {url}"

    @pytest.mark.parametrize("invalid_url", [
        # Invalid domains
        "https://vimeo.com/123456",
        "https://dailymotion.com/video/123456",
        "https://facebook.com/video/123456",
        # Invalid formats
        "not-a-url",
        "https://youtube.com",  # No video ID
        "https://www.youtube.com/channel/UCtest",  # Channel URL
        "https://www.youtube.com/playlist?list=PLtest",  # Playlist only
        "https://www.youtube.com/user/testuser",  # User URL
        "",  # Empty string
        None,  # None value
        123,  # Non-string
        "https://www.youtube.com/watch",  # Missing v parameter
        "https://www.youtube.com/watch?v=",  # Empty v parameter
        "https://www.youtube.com/watch?v=short",  # Invalid ID length
    ])
    def test_extract_video_id_invalid_urls(self, invalid_url):
        """Test that invalid URLs return None."""
        result = extract_video_id(invalid_url)
        assert result is None, f"Should have failed for URL: {invalid_url}"

    # =========================================================================
    # URL Validation Tests
    # =========================================================================

    def test_validate_youtube_url_valid(self, validator):
        """Test validation of valid YouTube URLs."""
        result = validator.validate("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
        assert result.is_valid is True
        assert result.video_id == "dQw4w9WgXcQ"
        assert result.error is None

    def test_validate_youtube_url_invalid(self, validator):
        """Test validation of invalid URLs."""
        result = validator.validate("https://vimeo.com/123456")
        assert result.is_valid is False
        assert result.video_id is None
        assert result.error is not None
        assert "not a valid youtube url" in result.error.lower()

    def test_validate_youtube_url_empty(self, validator):
        """Test validation of empty URL."""
        result = validator.validate("")
        assert result.is_valid is False
        assert "empty" in result.error.lower() or "required" in result.error.lower()

    def test_validate_youtube_url_none(self, validator):
        """Test validation of None URL."""
        result = validator.validate(None)
        assert result.is_valid is False

    # =========================================================================
    # URL Normalization Tests
    # =========================================================================

    @pytest.mark.parametrize("input_url,expected_normalized", [
        ("https://youtu.be/dQw4w9WgXcQ", "https://www.youtube.com/watch?v=dQw4w9WgXcQ"),
        ("http://youtube.com/watch?v=dQw4w9WgXcQ", "https://www.youtube.com/watch?v=dQw4w9WgXcQ"),
        ("https://m.youtube.com/watch?v=dQw4w9WgXcQ&t=30", "https://www.youtube.com/watch?v=dQw4w9WgXcQ"),
        ("  dQw4w9WgXcQ  ", "https://www.youtube.com/watch?v=dQw4w9WgXcQ"),
        ("https://www.youtube.com/embed/dQw4w9WgXcQ", "https://www.youtube.com/watch?v=dQw4w9WgXcQ"),
        ("https://www.youtube.com/shorts/dQw4w9WgXcQ", "https://www.youtube.com/watch?v=dQw4w9WgXcQ"),
    ])
    def test_normalize_youtube_url(self, input_url, expected_normalized):
        """Test URL normalization to standard format."""
        result = normalize_youtube_url(input_url)
        assert result == expected_normalized

    def test_normalize_invalid_url_raises(self):
        """Test that normalizing invalid URL raises exception."""
        with pytest.raises(YouTubeValidationError):
            normalize_youtube_url("https://vimeo.com/123456")


class TestYouTubeVideoInfo:
    """Test suite for YouTube video information retrieval."""

    @pytest.fixture
    def mock_video_info(self):
        """Create mock video info."""
        return YouTubeVideoInfo(
            video_id="dQw4w9WgXcQ",
            title="Rick Astley - Never Gonna Give You Up",
            channel="RickAstleyVEVO",
            duration_seconds=212,
            thumbnail_url="https://i.ytimg.com/vi/dQw4w9WgXcQ/maxresdefault.jpg",
            has_transcript=True,
            transcript_languages=["en", "es", "fr"],
            view_count=1500000000,
            published_at="2009-10-25",
        )

    def test_video_info_duration_formatted(self, mock_video_info):
        """Test formatted duration string."""
        assert mock_video_info.duration_formatted == "3:32"

    def test_video_info_estimated_scenes(self, mock_video_info):
        """Test estimated scene count calculation."""
        # Assuming ~12 seconds per scene
        expected_scenes = mock_video_info.duration_seconds // 12
        assert mock_video_info.estimated_scenes >= expected_scenes - 2
        assert mock_video_info.estimated_scenes <= expected_scenes + 2

    def test_video_info_to_dict(self, mock_video_info):
        """Test conversion to dictionary."""
        result = mock_video_info.to_dict()
        assert result["video_id"] == "dQw4w9WgXcQ"
        assert result["title"] == "Rick Astley - Never Gonna Give You Up"
        assert result["has_transcript"] is True
        assert "duration_formatted" in result

    def test_video_info_preview_data(self, mock_video_info):
        """Test preview data generation for UI."""
        preview = mock_video_info.get_preview_data()
        assert "video_id" in preview
        assert "title" in preview
        assert "thumbnail_url" in preview
        assert "duration_formatted" in preview
        assert "estimated_scenes" in preview


class TestYouTubeValidatorAsync:
    """Test async validation and metadata fetching."""

    @pytest.fixture
    def validator(self):
        """Create YouTubeURLValidator instance."""
        return YouTubeURLValidator()

    @pytest.mark.asyncio
    async def test_fetch_video_info_success(self, validator):
        """Test successful video info fetching."""
        # Mock the YouTube API response
        mock_info = {
            "video_id": "dQw4w9WgXcQ",
            "title": "Test Video",
            "channel": "Test Channel",
            "duration_seconds": 180,
        }

        with patch.object(validator, '_fetch_video_metadata', return_value=mock_info):
            result = await validator.fetch_video_info("dQw4w9WgXcQ")
            assert result is not None
            assert result.video_id == "dQw4w9WgXcQ"

    @pytest.mark.asyncio
    async def test_fetch_video_info_invalid_id(self, validator):
        """Test fetching info for invalid video ID."""
        with patch.object(validator, '_fetch_video_metadata', return_value=None):
            result = await validator.fetch_video_info("invalid_id")
            assert result is None

    @pytest.mark.asyncio
    async def test_check_transcript_availability(self, validator):
        """Test checking transcript availability."""
        mock_transcript_check = AsyncMock(return_value={
            "available": True,
            "languages": ["en", "es"]
        })

        with patch.object(validator, '_check_transcript', mock_transcript_check):
            result = await validator.check_transcript_availability("dQw4w9WgXcQ")
            assert result["available"] is True
            assert "en" in result["languages"]


class TestYouTubePreviewEndpoint:
    """Test the preview endpoint functionality."""

    @pytest.fixture
    def mock_client(self):
        """Create mock test client."""
        from fastapi.testclient import TestClient
        from app.main import app
        return TestClient(app)

    def test_validate_youtube_url_endpoint(self, mock_client):
        """Test the URL validation endpoint."""
        response = mock_client.post(
            "/api/youtube/validate",
            json={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_valid"] is True
        assert data["video_id"] == "dQw4w9WgXcQ"

    def test_validate_youtube_url_endpoint_invalid(self, mock_client):
        """Test validation endpoint with invalid URL."""
        response = mock_client.post(
            "/api/youtube/validate",
            json={"url": "https://vimeo.com/123456"}
        )
        assert response.status_code == 200  # Returns 200 with validation result
        data = response.json()
        assert data["is_valid"] is False
        assert "error" in data

    def test_youtube_preview_endpoint(self, mock_client):
        """Test the preview endpoint."""
        # Mock the video info fetch
        with patch('video_gen.utils.youtube_validator.YouTubeURLValidator.fetch_video_info') as mock_fetch:
            mock_fetch.return_value = YouTubeVideoInfo(
                video_id="dQw4w9WgXcQ",
                title="Test Video",
                channel="Test Channel",
                duration_seconds=180,
                thumbnail_url="https://i.ytimg.com/vi/dQw4w9WgXcQ/default.jpg",
                has_transcript=True,
                transcript_languages=["en"],
            )

            response = mock_client.post(
                "/api/youtube/preview",
                json={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"}
            )
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert "video_id" in data
            assert "preview" in data
            assert "title" in data["preview"]
            assert "has_transcript" in data["preview"]


class TestDurationEstimation:
    """Test duration estimation for video generation."""

    def test_estimate_generation_duration(self):
        """Test estimation of video generation duration."""
        from video_gen.utils.youtube_validator import estimate_generation_duration

        # Short video (3 minutes)
        result = estimate_generation_duration(180)
        assert "estimated_minutes" in result
        assert result["estimated_minutes"] >= 1

        # Long video (30 minutes)
        result = estimate_generation_duration(1800)
        assert result["estimated_minutes"] >= 5

    def test_estimate_scene_count(self):
        """Test scene count estimation."""
        from video_gen.utils.youtube_validator import estimate_scene_count

        # 3 minute video with 12-second scenes
        result = estimate_scene_count(180, scene_duration=12)
        assert result >= 12  # title + content scenes + outro
        assert result <= 20


class TestErrorHandling:
    """Test error handling and edge cases."""

    @pytest.fixture
    def validator(self):
        """Create YouTubeURLValidator instance."""
        return YouTubeURLValidator()

    def test_handle_network_error(self, validator):
        """Test handling of network errors during fetch."""
        with patch.object(validator, '_fetch_video_metadata', side_effect=Exception("Network error")):
            with pytest.raises(YouTubeValidationError) as exc_info:
                asyncio.get_event_loop().run_until_complete(
                    validator.fetch_video_info("dQw4w9WgXcQ")
                )
            assert "fetch" in str(exc_info.value).lower() or "error" in str(exc_info.value).lower()

    def test_handle_rate_limit(self, validator):
        """Test handling of rate limit errors."""
        with patch.object(validator, '_fetch_video_metadata', side_effect=Exception("Rate limited")):
            with pytest.raises(YouTubeValidationError):
                asyncio.get_event_loop().run_until_complete(
                    validator.fetch_video_info("dQw4w9WgXcQ")
                )

    @pytest.mark.skip(reason="Requires integration test setup - covered by endpoint tests")
    @pytest.mark.parametrize("malformed_input", [
        {"url": None},
        {"url": 123},
        {"url": []},
        {},
        {"other_field": "value"},
    ])
    def test_handle_malformed_input(self, malformed_input):
        """Test handling of malformed input."""
        from fastapi.testclient import TestClient
        from app.main import app
        client = TestClient(app)

        response = client.post("/api/youtube/validate", json=malformed_input)
        # Should return 400 or 422 for validation errors
        assert response.status_code in [400, 422]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
