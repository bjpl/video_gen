"""Tests for YouTube adapter implementation."""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from video_gen.input_adapters.youtube import YouTubeAdapter


class TestYouTubeAdapter:
    """Test suite for YouTube adapter."""

    @pytest.fixture
    def adapter(self):
        """Create YouTubeAdapter instance."""
        return YouTubeAdapter()

    @pytest.mark.asyncio
    async def test_validate_youtube_url(self, adapter):
        """Test YouTube URL validation."""
        # Valid URLs
        assert await adapter.validate_source("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
        assert await adapter.validate_source("https://youtu.be/dQw4w9WgXcQ")
        assert await adapter.validate_source("https://m.youtube.com/watch?v=dQw4w9WgXcQ")
        assert await adapter.validate_source("dQw4w9WgXcQ")  # Video ID

        # Invalid URLs
        assert not await adapter.validate_source("https://vimeo.com/123456")
        assert not await adapter.validate_source("not-a-url")
        assert not await adapter.validate_source(123)  # Not a string

    def test_extract_video_ids(self, adapter):
        """Test video ID extraction from URLs."""
        # Standard watch URL
        ids = adapter._extract_video_ids("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
        assert ids == ["dQw4w9WgXcQ"]

        # Short URL
        ids = adapter._extract_video_ids("https://youtu.be/dQw4w9WgXcQ")
        assert ids == ["dQw4w9WgXcQ"]

        # Embed URL
        ids = adapter._extract_video_ids("https://www.youtube.com/embed/dQw4w9WgXcQ")
        assert ids == ["dQw4w9WgXcQ"]

        # Direct video ID
        ids = adapter._extract_video_ids("dQw4w9WgXcQ")
        assert ids == ["dQw4w9WgXcQ"]

    def test_create_title(self, adapter):
        """Test title creation from text."""
        # Normal text
        title = adapter._create_title("this is a test video about python")
        assert title == "This is a test video about python"

        # Long text (should truncate)
        long_text = "this is a very long text that should be truncated because it exceeds the maximum allowed length"
        title = adapter._create_title(long_text, max_length=50)
        assert len(title) <= 53  # 50 + "..."
        assert title.endswith("...")

    def test_create_bullet_points(self, adapter):
        """Test bullet point creation from text."""
        text = "First point. Second point. Third point. Fourth point. Fifth point."
        bullets = adapter._create_bullet_points(text, max_points=3)

        assert len(bullets) == 3
        # Should have 3 evenly spaced items from the 5 sentences
        assert "First point" in bullets[0]
        assert len(bullets) <= 3

    @pytest.mark.asyncio
    async def test_adapt_missing_library(self, adapter):
        """Test adapter behavior when youtube-transcript-api is not installed."""
        # Mock the import to fail
        import sys
        with patch.dict('sys.modules', {'youtube_transcript_api': None}):
            result = await adapter.adapt("dQw4w9WgXcQ")

            # Should handle missing library gracefully
            assert not result.success
            assert "youtube-transcript-api" in result.error

    @pytest.mark.asyncio
    async def test_adapt_invalid_url(self, adapter):
        """Test adapter with invalid URL."""
        result = await adapter.adapt("https://invalid-url.com/video")

        assert not result.success
        assert "Invalid YouTube URL" in result.error

    @pytest.mark.asyncio
    async def test_adapt_success(self, adapter):
        """Test successful video adaptation."""
        # Mock transcript data
        mock_transcript_data = [
            {"text": "Welcome to this tutorial", "start": 0.0, "duration": 3.0},
            {"text": "Today we will learn about Python", "start": 3.0, "duration": 4.0},
            {"text": "Python is a great language", "start": 7.0, "duration": 3.0},
            {"text": "Let's get started", "start": 10.0, "duration": 2.0},
            {"text": "First we need to install Python", "start": 12.0, "duration": 4.0},
            {"text": "Then we can write our first program", "start": 16.0, "duration": 4.0},
            {"text": "Thank you for watching", "start": 20.0, "duration": 2.0},
        ]

        # Mock the transcript API
        mock_transcript = Mock()
        mock_transcript.fetch.return_value = mock_transcript_data

        mock_transcript_list = Mock()
        mock_transcript_list.find_transcript.return_value = mock_transcript

        mock_api = Mock()
        mock_api.list_transcripts.return_value = mock_transcript_list

        # Patch inside the method where it's imported
        with patch('youtube_transcript_api.YouTubeTranscriptApi', mock_api):
            # Run adapter
            result = await adapter.adapt("dQw4w9WgXcQ", scene_duration=10)

            # Verify success
            assert result.success
            assert result.video_set is not None
            assert result.video_set.set_id == "youtube_dQw4w9WgXcQ"
            assert len(result.video_set.videos) == 1

            # Verify video structure
            video = result.video_set.videos[0]
            assert video.video_id == "youtube_dQw4w9WgXcQ"
            assert len(video.scenes) > 2  # Should have title + content + outro

            # Check scene types
            assert video.scenes[0].scene_type == "title"
            assert video.scenes[-1].scene_type == "outro"

            # Check content scenes are 'list' type
            for scene in video.scenes[1:-1]:
                assert scene.scene_type == "list"
                assert "items" in scene.visual_content

    @pytest.mark.asyncio
    async def test_adapt_transcript_disabled(self, adapter):
        """Test adapter when transcripts are disabled."""
        from youtube_transcript_api._errors import TranscriptsDisabled

        mock_api = Mock()
        mock_api.list_transcripts.side_effect = TranscriptsDisabled("video_id")

        with patch('youtube_transcript_api.YouTubeTranscriptApi', mock_api):
            result = await adapter.adapt("dQw4w9WgXcQ")

            assert not result.success
            assert "Transcripts are disabled" in result.error

    @pytest.mark.asyncio
    async def test_adapt_no_transcript_found(self, adapter):
        """Test adapter when no transcript is found."""
        from youtube_transcript_api._errors import NoTranscriptFound

        mock_transcript_list = Mock()
        mock_transcript_list.find_transcript.side_effect = NoTranscriptFound(
            "video_id", ["en"], None
        )
        mock_transcript_list.find_generated_transcript.side_effect = NoTranscriptFound(
            "video_id", ["en"], None
        )

        mock_api = Mock()
        mock_api.list_transcripts.return_value = mock_transcript_list

        with patch('youtube_transcript_api.YouTubeTranscriptApi', mock_api):
            result = await adapter.adapt("dQw4w9WgXcQ")

            assert not result.success
            assert "No transcript found" in result.error

    def test_supports_format(self, adapter):
        """Test format support check."""
        assert adapter.supports_format("youtube")
        assert adapter.supports_format("YOUTUBE")
        assert not adapter.supports_format("vimeo")
        assert not adapter.supports_format("pdf")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
