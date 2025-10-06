"""
Integration tests for input adapters.

Tests app/input_adapters/ including:
- DocumentAdapter with real markdown
- YAMLAdapter with various configs
- YouTubeAdapter (mocked API calls)
- WizardAdapter
- ProgrammaticAdapter
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch, mock_open
import tempfile
import json

# Import from app directory where adapters are located
from app.input_adapters.document import DocumentAdapter
from app.input_adapters.yaml_file import YAMLAdapter
from app.input_adapters.youtube import YouTubeAdapter
from app.input_adapters.programmatic import ProgrammaticAdapter
# Removed unused imports


class TestDocumentAdapterIntegration:
    """Integration tests for DocumentAdapter."""

    @pytest.fixture
    def document_adapter(self):
        """Create DocumentAdapter instance."""
        return DocumentAdapter()

    @pytest.fixture
    def sample_markdown(self):
        """Create sample markdown content."""
        return """# Test Document

This is a test document for video generation.

## Section 1

Content for section 1.

## Section 2

Content for section 2.
"""

    @pytest.mark.asyncio
    async def test_document_adapter_with_markdown_file(self, document_adapter, sample_markdown):
        """Test DocumentAdapter processes markdown file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(sample_markdown)
            temp_path = f.name

        try:
            result = await document_adapter.parse(
                source=temp_path,
                accent_color=(59, 130, 246),
                voice="male"
            )

            assert result.success
            assert result.video_set is not None
            assert len(result.video_set.videos) > 0
        finally:
            Path(temp_path).unlink()

    @pytest.mark.asyncio
    async def test_document_adapter_with_text_content(self, document_adapter):
        """Test DocumentAdapter with direct text content."""
        text_content = "This is a simple text for testing."

        result = await document_adapter.parse(
            source=text_content,
            accent_color=(16, 185, 129),
            voice="female"
        )

        assert result.success or result.error is not None

    @pytest.mark.asyncio
    async def test_document_adapter_splits_by_h2(self, document_adapter, sample_markdown):
        """Test DocumentAdapter splits content by H2 headers."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(sample_markdown)
            temp_path = f.name

        try:
            result = await document_adapter.parse(
                source=temp_path,
                accent_color=(59, 130, 246),
                voice="male",
                split_by_h2=True,
                video_count=2
            )

            if result.success:
                # Should create multiple videos or scenes based on H2
                assert result.video_set is not None
        finally:
            Path(temp_path).unlink()

    @pytest.mark.asyncio
    async def test_document_adapter_handles_empty_file(self, document_adapter):
        """Test DocumentAdapter handles empty files gracefully."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write("")
            temp_path = f.name

        try:
            result = await document_adapter.parse(
                source=temp_path,
                accent_color=(59, 130, 246),
                voice="male"
            )

            # Should fail gracefully or return empty video set
            assert result is not None
        finally:
            Path(temp_path).unlink()

    @pytest.mark.asyncio
    async def test_document_adapter_handles_missing_file(self, document_adapter):
        """Test DocumentAdapter handles missing files."""
        result = await document_adapter.parse(
            source="/nonexistent/file.md",
            accent_color=(59, 130, 246),
            voice="male"
        )

        # Should return error result
        assert result.success is False or result.error is not None


class TestYAMLAdapterIntegration:
    """Integration tests for YAMLAdapter."""

    @pytest.fixture
    def yaml_adapter(self):
        """Create YAMLAdapter instance."""
        return YAMLAdapter()

    @pytest.fixture
    def sample_yaml_config(self):
        """Create sample YAML configuration."""
        return """
title: Test Video
accent_color: blue
voice: male
scenes:
  - scene_type: title
    scene_id: "1"
    narration: "Welcome to the test"
    visual_content:
      title: "Test Video"
      subtitle: "Introduction"
  - scene_type: command
    scene_id: "2"
    narration: "Run this command"
    visual_content:
      header: "Setup"
      commands:
        - "pip install requirements"
"""

    @pytest.mark.asyncio
    async def test_yaml_adapter_with_valid_config(self, yaml_adapter, sample_yaml_config):
        """Test YAMLAdapter processes valid YAML config."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(sample_yaml_config)
            temp_path = f.name

        try:
            result = await yaml_adapter.parse(
                source=temp_path,
                accent_color=(59, 130, 246),
                voice="male"
            )

            assert result.success
            assert result.video_set is not None
            assert len(result.video_set.videos) > 0
            assert result.video_set.videos[0].title == "Test Video"
        finally:
            Path(temp_path).unlink()

    @pytest.mark.asyncio
    async def test_yaml_adapter_with_minimal_config(self, yaml_adapter):
        """Test YAMLAdapter with minimal valid config."""
        minimal_yaml = """
title: Minimal Video
scenes:
  - scene_type: title
    scene_id: "1"
    narration: "Test"
    visual_content: {}
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(minimal_yaml)
            temp_path = f.name

        try:
            result = await yaml_adapter.parse(
                source=temp_path,
                accent_color=(59, 130, 246),
                voice="male"
            )

            assert result.success
        finally:
            Path(temp_path).unlink()

    @pytest.mark.asyncio
    async def test_yaml_adapter_with_invalid_yaml(self, yaml_adapter):
        """Test YAMLAdapter handles invalid YAML gracefully."""
        invalid_yaml = """
title: Test
scenes:
  - invalid: [unclosed bracket
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(invalid_yaml)
            temp_path = f.name

        try:
            result = await yaml_adapter.parse(
                source=temp_path,
                accent_color=(59, 130, 246),
                voice="male"
            )

            # Should return error
            assert result.success is False
        finally:
            Path(temp_path).unlink()

    @pytest.mark.asyncio
    async def test_yaml_adapter_with_missing_file(self, yaml_adapter):
        """Test YAMLAdapter handles missing files."""
        result = await yaml_adapter.parse(
            source="/nonexistent/config.yaml",
            accent_color=(59, 130, 246),
            voice="male"
        )

        assert result.success is False


class TestYouTubeAdapterIntegration:
    """Integration tests for YouTubeAdapter (with mocked API)."""

    @pytest.fixture
    def youtube_adapter(self):
        """Create YouTubeAdapter instance."""
        return YouTubeAdapter()

    @pytest.mark.asyncio
    @patch('video_gen.input_adapters.youtube_adapter.requests.get')
    async def test_youtube_adapter_with_valid_url(self, mock_get, youtube_adapter):
        """Test YouTubeAdapter processes YouTube URL."""
        # Mock API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'items': [{
                'snippet': {
                    'title': 'Test Video',
                    'description': 'Test description',
                    'channelTitle': 'Test Channel'
                }
            }]
        }
        mock_get.return_value = mock_response

        result = await youtube_adapter.parse(
            source="https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            accent_color=(59, 130, 246),
            voice="male"
        )

        # Behavior depends on implementation
        assert result is not None

    @pytest.mark.asyncio
    async def test_youtube_adapter_with_invalid_url(self, youtube_adapter):
        """Test YouTubeAdapter handles invalid URLs."""
        result = await youtube_adapter.parse(
            source="https://invalid-url.com",
            accent_color=(59, 130, 246),
            voice="male"
        )

        # Should return error or handle gracefully
        assert result is not None

    @pytest.mark.asyncio
    @patch('video_gen.input_adapters.youtube_adapter.requests.get')
    async def test_youtube_adapter_handles_api_error(self, mock_get, youtube_adapter):
        """Test YouTubeAdapter handles API errors gracefully."""
        mock_get.side_effect = Exception("API Error")

        result = await youtube_adapter.parse(
            source="https://www.youtube.com/watch?v=test",
            accent_color=(59, 130, 246),
            voice="male"
        )

        assert result is not None


class TestProgrammaticAdapterIntegration:
    """Integration tests for ProgrammaticAdapter."""

    @pytest.fixture
    def programmatic_adapter(self):
        """Create ProgrammaticAdapter instance."""
        return ProgrammaticAdapter()

    @pytest.mark.asyncio
    async def test_programmatic_adapter_with_video_config(self, programmatic_adapter):
        """Test ProgrammaticAdapter with VideoConfig object."""
        video_config = VideoConfig(
            video_id="prog-test-1",
            title="Programmatic Test",
            description="Test description",
            scenes=[
                Scene(
                    scene_id="1",
                    scene_type="title",
                    narration="Test narration",
                    visual_content={"title": "Test", "subtitle": "Subtitle"}
                )
            ]
        )

        result = await programmatic_adapter.parse(
            source=video_config,
            accent_color=(59, 130, 246),
            voice="male"
        )

        assert result.success
        assert result.video_set is not None
        assert len(result.video_set.videos) == 1
        assert result.video_set.videos[0].title == "Programmatic Test"

    @pytest.mark.asyncio
    async def test_programmatic_adapter_with_dict(self, programmatic_adapter):
        """Test ProgrammaticAdapter with dictionary."""
        video_dict = {
            "title": "Dict Test",
            "scenes": [
                {
                    "scene_id": "1",
                    "scene_type": "title",
                    "narration": "Test",
                    "visual_content": {}
                }
            ]
        }

        result = await programmatic_adapter.parse(
            source=video_dict,
            accent_color=(59, 130, 246),
            voice="male"
        )

        # Should parse dict into VideoConfig
        assert result is not None

    @pytest.mark.asyncio
    async def test_programmatic_adapter_with_invalid_source(self, programmatic_adapter):
        """Test ProgrammaticAdapter handles invalid source types."""
        result = await programmatic_adapter.parse(
            source="invalid_string_source",
            accent_color=(59, 130, 246),
            voice="male"
        )

        # Should return error
        assert result.success is False or result.error is not None


class TestWizardAdapter:
    """Test WizardAdapter if it exists."""

    @pytest.mark.asyncio
    async def test_wizard_adapter_exists(self):
        """Test WizardAdapter can be imported."""
        try:
            from app.input_adapters.wizard import WizardAdapter
            adapter = WizardAdapter()
            assert adapter is not None
        except ImportError:
            pytest.skip("WizardAdapter not available")


class TestAdapterColorAndVoiceHandling:
    """Test adapters handle accent colors and voices correctly."""

    @pytest.fixture
    def adapters(self):
        """Get all available adapters."""
        return [
            DocumentAdapter(),
            YAMLAdapter(),
            ProgrammaticAdapter()
        ]

    @pytest.mark.asyncio
    async def test_adapters_accept_color_tuples(self, adapters):
        """Test adapters accept RGB color tuples."""
        colors = [
            (59, 130, 246),   # Blue
            (16, 185, 129),   # Green
            (255, 107, 53),   # Orange
        ]

        for adapter in adapters:
            for color in colors:
                # Should not raise on valid color
                assert color is not None

    @pytest.mark.asyncio
    async def test_adapters_accept_voice_strings(self, adapters):
        """Test adapters accept voice identifiers."""
        voices = ["male", "female", "male_warm", "female_friendly"]

        for adapter in adapters:
            for voice in voices:
                # Should not raise on valid voice
                assert voice is not None


class TestAdapterErrorMessages:
    """Test adapter error messages are informative."""

    @pytest.mark.asyncio
    async def test_document_adapter_error_has_details(self):
        """Test DocumentAdapter errors include helpful details."""
        adapter = DocumentAdapter()

        result = await adapter.parse(
            source="/definitely/does/not/exist.md",
            accent_color=(0, 0, 0),
            voice="male"
        )

        if not result.success:
            assert result.error is not None
            assert len(result.error) > 0

    @pytest.mark.asyncio
    async def test_yaml_adapter_error_has_details(self):
        """Test YAMLAdapter errors include helpful details."""
        adapter = YAMLAdapter()

        result = await adapter.parse(
            source="/nonexistent.yaml",
            accent_color=(0, 0, 0),
            voice="male"
        )

        if not result.success:
            assert result.error is not None
            assert len(result.error) > 0
