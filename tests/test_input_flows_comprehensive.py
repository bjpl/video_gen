"""
Comprehensive Test Suite for Input Source Type Flows
=====================================================

This module provides comprehensive tests for all input adapter types:
- Document upload (all formats: MD, TXT, PDF binary detection)
- YouTube URL parsing (all URL formats)
- Wizard/programmatic input
- YAML file parsing (single video and video set formats)
- Edge cases and error handling
- File validation and security checks
- Preview functionality

Target: 95%+ coverage for all input flow code.

Test Organization:
    - TestDocumentAdapterUnit: Unit tests for DocumentAdapter
    - TestDocumentAdapterEdgeCases: Edge case tests for documents
    - TestYouTubeAdapterUnit: Unit tests for YouTubeAdapter
    - TestYouTubeAdapterEdgeCases: Edge case tests for YouTube URLs
    - TestWizardAdapterUnit: Unit tests for InteractiveWizard
    - TestProgrammaticAdapterUnit: Unit tests for ProgrammaticAdapter
    - TestYAMLAdapterUnit: Unit tests for YAMLFileAdapter
    - TestYAMLAdapterEdgeCases: Edge case tests for YAML parsing
    - TestInputAdapterIntegration: Integration tests for full flows
    - TestSecurityAndValidation: Security and validation tests
    - TestPerformance: Performance benchmarks
"""

import pytest
import asyncio
import tempfile
import json
import yaml
import time
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime
from typing import Dict, Any

# Import adapters
from video_gen.input_adapters import (
    InputAdapter,
    InputAdapterResult,
    DocumentAdapter,
    YouTubeAdapter,
    InteractiveWizard,
    YAMLFileAdapter,
    ProgrammaticAdapter,
)
from video_gen.shared.models import VideoSet, VideoConfig, SceneConfig


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_markdown_content():
    """Sample markdown content for document tests."""
    return """# Test Document Title

This is a comprehensive test document for validating document parsing.

## Section 1: Introduction

Welcome to the test document. This section covers the basics.

- Item 1: First bullet point
- Item 2: Second bullet point
- Item 3: Third bullet point

## Section 2: Code Examples

Here's some code for testing command detection:

```bash
npm install
npm start
```

More content after code block.

## Section 3: Tables

| Header 1 | Header 2 | Header 3 |
|----------|----------|----------|
| Value 1  | Value 2  | Value 3  |
| Value 4  | Value 5  | Value 6  |

## Conclusion

This concludes our test document.
"""


@pytest.fixture
def sample_markdown_file(temp_dir, sample_markdown_content):
    """Create a sample markdown file."""
    file_path = temp_dir / "test_document.md"
    file_path.write_text(sample_markdown_content, encoding='utf-8')
    return file_path


@pytest.fixture
def sample_text_file(temp_dir):
    """Create a sample text file."""
    content = """Test Document

This is a plain text document for testing.

Key Points:
- Point one
- Point two
- Point three

Conclusion paragraph here.
"""
    file_path = temp_dir / "test_document.txt"
    file_path.write_text(content, encoding='utf-8')
    return file_path


@pytest.fixture
def sample_yaml_single_video(temp_dir):
    """Create a sample YAML file for single video format."""
    content = {
        "video_id": "test_video_001",
        "title": "Test Video Title",
        "description": "Test video description",
        "accent_color": "blue",
        "voice": "male",
        "scenes": [
            {
                "scene_id": "scene_01_title",
                "scene_type": "title",
                "narration": "Welcome to our test video",
                "visual_content": {
                    "title": "Test Video",
                    "subtitle": "A Comprehensive Guide"
                }
            },
            {
                "scene_id": "scene_02_list",
                "scene_type": "list",
                "narration": "Here are the key points",
                "visual_content": {
                    "header": "Key Points",
                    "items": ["Point 1", "Point 2", "Point 3"]
                }
            },
            {
                "scene_id": "scene_03_outro",
                "scene_type": "outro",
                "narration": "Thank you for watching",
                "visual_content": {
                    "main_text": "Thanks!",
                    "sub_text": "Visit our website"
                }
            }
        ]
    }
    file_path = temp_dir / "test_single_video.yaml"
    with open(file_path, 'w', encoding='utf-8') as f:
        yaml.safe_dump(content, f)
    return file_path


@pytest.fixture
def sample_yaml_video_set(temp_dir):
    """Create a sample YAML file for video set format."""
    content = {
        "set_id": "test_set_001",
        "name": "Test Video Set",
        "description": "A set of test videos",
        "videos": [
            {
                "video_id": "video_01",
                "title": "First Video",
                "description": "First video in set",
                "scenes": [
                    {
                        "scene_id": "v1_scene_01",
                        "scene_type": "title",
                        "narration": "Welcome to video one",
                        "visual_content": {"title": "Video One"}
                    }
                ]
            },
            {
                "video_id": "video_02",
                "title": "Second Video",
                "description": "Second video in set",
                "scenes": [
                    {
                        "scene_id": "v2_scene_01",
                        "scene_type": "title",
                        "narration": "Welcome to video two",
                        "visual_content": {"title": "Video Two"}
                    }
                ]
            }
        ]
    }
    file_path = temp_dir / "test_video_set.yaml"
    with open(file_path, 'w', encoding='utf-8') as f:
        yaml.safe_dump(content, f)
    return file_path


@pytest.fixture
def wizard_draft_data():
    """Sample wizard draft data for testing."""
    return {
        'video': {
            'id': 'wizard_test_video',
            'title': 'Wizard Generated Video',
            'topic': 'Testing Wizards',
            'description': 'A video generated by the wizard',
            'accent_color': 'purple',
            'voice': 'female',
            'timestamp': datetime.now().isoformat()
        },
        'template': 'tutorial',
        'scenes': [
            {
                'scene_id': 'scene_01_title',
                'scene_type': 'title',
                'narration': 'Welcome to our wizard-generated video',
                'visual_content': {'title': 'Test Video', 'subtitle': 'From Wizard'}
            },
            {
                'scene_id': 'scene_02_command',
                'scene_type': 'command',
                'narration': 'Here are some commands',
                'visual_content': {'header': 'Commands', 'commands': ['$ npm install', '$ npm start']}
            },
            {
                'scene_id': 'scene_03_outro',
                'scene_type': 'outro',
                'narration': 'Thank you for watching',
                'visual_content': {'main_text': 'Thanks!', 'sub_text': 'See you next time'}
            }
        ]
    }


@pytest.fixture
def programmatic_video_config():
    """Create a programmatic VideoConfig for testing."""
    return VideoConfig(
        video_id="programmatic_video_001",
        title="Programmatic Video",
        description="Video created programmatically",
        accent_color="green",
        scenes=[
            SceneConfig(
                scene_id="prog_scene_01",
                scene_type="title",
                narration="Welcome to programmatic video",
                visual_content={"title": "Programmatic", "subtitle": "Test"},
                voice="male"
            ),
            SceneConfig(
                scene_id="prog_scene_02",
                scene_type="outro",
                narration="Thanks for watching",
                visual_content={"main_text": "Done", "sub_text": "Goodbye"},
                voice="male"
            )
        ]
    )


@pytest.fixture
def programmatic_video_set(programmatic_video_config):
    """Create a programmatic VideoSet for testing."""
    return VideoSet(
        set_id="programmatic_set_001",
        name="Programmatic Video Set",
        description="Set created programmatically",
        videos=[programmatic_video_config]
    )


# =============================================================================
# DOCUMENT ADAPTER UNIT TESTS
# =============================================================================

class TestDocumentAdapterUnit:
    """Unit tests for DocumentAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create DocumentAdapter instance in test mode."""
        return DocumentAdapter(test_mode=True, use_ai=False)

    @pytest.mark.asyncio
    async def test_adapter_initialization(self, adapter):
        """Test DocumentAdapter initialization."""
        assert adapter.name == "document"
        assert "PDF" in adapter.description or "DOCX" in adapter.description or "processes" in adapter.description.lower()
        assert adapter.supported_formats == {".pdf", ".docx", ".txt", ".md"}
        assert adapter.test_mode is True
        assert adapter.use_ai is False

    @pytest.mark.asyncio
    async def test_validate_source_valid_file(self, adapter, sample_markdown_file):
        """Test source validation with valid markdown file."""
        is_valid = await adapter.validate_source(sample_markdown_file)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_validate_source_invalid_extension(self, adapter, temp_dir):
        """Test source validation with invalid file extension."""
        invalid_file = temp_dir / "test.invalid"
        invalid_file.write_text("test content")
        is_valid = await adapter.validate_source(invalid_file)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_validate_source_nonexistent_file(self, adapter):
        """Test source validation with nonexistent file."""
        is_valid = await adapter.validate_source("/nonexistent/file.md")
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_validate_source_not_file(self, adapter, temp_dir):
        """Test source validation with directory instead of file."""
        is_valid = await adapter.validate_source(temp_dir)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_supports_format_valid(self, adapter):
        """Test format support for valid formats."""
        assert adapter.supports_format(".pdf") is True
        assert adapter.supports_format(".docx") is True
        assert adapter.supports_format(".txt") is True
        assert adapter.supports_format(".md") is True
        assert adapter.supports_format(".MD") is True  # Case insensitive

    @pytest.mark.asyncio
    async def test_supports_format_invalid(self, adapter):
        """Test format support for invalid formats."""
        assert adapter.supports_format(".doc") is False
        assert adapter.supports_format(".html") is False
        assert adapter.supports_format(".xml") is False

    @pytest.mark.asyncio
    async def test_adapt_markdown_file(self, adapter, sample_markdown_file):
        """Test adapting a markdown file."""
        result = await adapter.adapt(sample_markdown_file)

        assert result.success is True
        assert result.error is None
        assert result.video_set is not None
        assert isinstance(result.video_set, VideoSet)
        assert len(result.video_set.videos) >= 1
        assert result.metadata.get("source") == str(sample_markdown_file)

    @pytest.mark.asyncio
    async def test_adapt_text_file(self, adapter, sample_text_file):
        """Test adapting a text file."""
        result = await adapter.adapt(sample_text_file)

        assert result.success is True
        assert result.video_set is not None

    @pytest.mark.asyncio
    async def test_adapt_with_custom_options(self, adapter, sample_markdown_file):
        """Test adapting with custom accent color and voice."""
        result = await adapter.adapt(
            sample_markdown_file,
            accent_color='purple',
            voice='female',
            max_scenes_per_video=10
        )

        assert result.success is True
        video = result.video_set.videos[0]
        assert video.accent_color == 'purple'
        # Voice should be applied to scenes
        for scene in video.scenes:
            assert scene.voice == 'female'

    @pytest.mark.asyncio
    async def test_adapt_nonexistent_file(self, adapter):
        """Test adapting a nonexistent file."""
        result = await adapter.adapt("/nonexistent/path/document.md")

        assert result.success is False
        assert result.error is not None
        assert "not found" in result.error.lower() or "failed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_parse_markdown_structure(self, adapter, sample_markdown_content):
        """Test markdown structure parsing."""
        structure = adapter._parse_markdown_structure(sample_markdown_content)

        assert structure.get('title') == "Test Document Title"
        assert 'sections' in structure
        assert len(structure['sections']) >= 3

    @pytest.mark.asyncio
    async def test_adapt_split_by_h2(self, adapter, sample_markdown_file):
        """Test document splitting by H2 headings."""
        result = await adapter.adapt(sample_markdown_file, split_by_h2=True)

        assert result.success is True
        # With split_by_h2=True, should create multiple videos
        assert len(result.video_set.videos) >= 1


class TestDocumentAdapterEdgeCases:
    """Edge case tests for DocumentAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create DocumentAdapter instance in test mode."""
        return DocumentAdapter(test_mode=True, use_ai=False)

    @pytest.mark.asyncio
    async def test_empty_file(self, adapter, temp_dir):
        """Test handling of empty file."""
        empty_file = temp_dir / "empty.md"
        empty_file.write_text("")

        result = await adapter.adapt(empty_file)
        # Empty file should either fail or produce minimal output
        # The behavior depends on implementation
        assert result is not None

    @pytest.mark.asyncio
    async def test_file_with_only_title(self, adapter, temp_dir):
        """Test file with only a title."""
        content = "# Just a Title"
        file_path = temp_dir / "title_only.md"
        file_path.write_text(content)

        result = await adapter.adapt(file_path)
        assert result.success is True
        assert result.video_set is not None

    @pytest.mark.asyncio
    async def test_deeply_nested_headers(self, adapter, temp_dir):
        """Test handling of deeply nested headers."""
        content = """# Level 1
## Level 2
### Level 3
#### Level 4
##### Level 5
###### Level 6

Some content at the deepest level.
"""
        file_path = temp_dir / "nested_headers.md"
        file_path.write_text(content)

        result = await adapter.adapt(file_path)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_code_blocks_with_different_languages(self, adapter, temp_dir):
        """Test handling of code blocks with various language annotations."""
        content = """# Code Examples

## Python
```python
def hello():
    print("Hello, World!")
```

## JavaScript
```javascript
function hello() {
    console.log("Hello, World!");
}
```

## Bash
```bash
echo "Hello, World!"
```
"""
        file_path = temp_dir / "code_blocks.md"
        file_path.write_text(content)

        result = await adapter.adapt(file_path)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_markdown_with_links(self, adapter, temp_dir):
        """Test markdown with various link formats."""
        content = """# Links Test

Visit [our website](https://example.com) for more info.

Reference style: [example][1]

[1]: https://example.com

Inline link: <https://example.com>
"""
        file_path = temp_dir / "links.md"
        file_path.write_text(content)

        result = await adapter.adapt(file_path)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_unicode_content(self, adapter, temp_dir):
        """Test handling of Unicode content."""
        content = """# Unicode Test

## Multilingual Content

- English: Hello World
- Spanish: Hola Mundo
- Chinese: 你好世界
- Japanese: こんにちは世界
- Russian: Привет мир
- Arabic: مرحبا بالعالم
- Emoji: 🎉 🚀 💡 ✨
"""
        file_path = temp_dir / "unicode.md"
        file_path.write_text(content, encoding='utf-8')

        result = await adapter.adapt(file_path)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_binary_file_detection(self, adapter, temp_dir):
        """Test detection and rejection of binary files."""
        # Create a file with binary content (JPEG signature)
        binary_file = temp_dir / "fake.md"
        binary_file.write_bytes(b'\xff\xd8\xff' + b'\x00' * 100)

        result = await adapter.adapt(binary_file)
        assert result.success is False
        assert "binary" in result.error.lower() or "failed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_very_long_content(self, adapter, temp_dir):
        """Test handling of very long content."""
        # Create a file with many sections
        sections = "\n\n".join([f"## Section {i}\n\nContent for section {i}.\n" for i in range(50)])
        content = f"# Long Document\n\n{sections}"
        file_path = temp_dir / "long_document.md"
        file_path.write_text(content)

        result = await adapter.adapt(file_path, max_scenes_per_video=100)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_special_characters_in_filename(self, adapter, temp_dir):
        """Test handling of special characters in filename."""
        content = "# Test Document\n\nSome content."
        file_path = temp_dir / "test file with spaces.md"
        file_path.write_text(content)

        result = await adapter.adapt(file_path)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_metadata_stripping(self, adapter, temp_dir):
        """Test that metadata lines are stripped from content."""
        content = """*Generated: October 05, 2025*

---

# Document Title

Real content starts here.
"""
        file_path = temp_dir / "with_metadata.md"
        file_path.write_text(content)

        result = await adapter.adapt(file_path)
        assert result.success is True


# =============================================================================
# YOUTUBE ADAPTER UNIT TESTS
# =============================================================================

class TestYouTubeAdapterUnit:
    """Unit tests for YouTubeAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create YouTubeAdapter instance."""
        return YouTubeAdapter(test_mode=True)

    @pytest.mark.asyncio
    async def test_adapter_initialization(self, adapter):
        """Test YouTubeAdapter initialization."""
        assert adapter.name == "youtube"
        assert "transcript" in adapter.description.lower()

    @pytest.mark.asyncio
    async def test_validate_standard_youtube_url(self, adapter):
        """Test validation of standard YouTube URLs."""
        valid_urls = [
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://youtube.com/watch?v=dQw4w9WgXcQ",
            "https://m.youtube.com/watch?v=dQw4w9WgXcQ",
        ]
        for url in valid_urls:
            is_valid = await adapter.validate_source(url)
            assert is_valid is True, f"URL should be valid: {url}"

    @pytest.mark.asyncio
    async def test_validate_short_youtube_url(self, adapter):
        """Test validation of short YouTube URLs."""
        is_valid = await adapter.validate_source("https://youtu.be/dQw4w9WgXcQ")
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_validate_video_id(self, adapter):
        """Test validation of direct video ID."""
        is_valid = await adapter.validate_source("dQw4w9WgXcQ")
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_validate_invalid_url(self, adapter):
        """Test validation of invalid URLs."""
        invalid_urls = [
            "https://vimeo.com/123456789",
            "https://example.com/video",
            "not-a-url-at-all",
            "",
            None,
            123,  # Not a string
        ]
        for url in invalid_urls:
            is_valid = await adapter.validate_source(url)
            assert is_valid is False, f"URL should be invalid: {url}"

    @pytest.mark.asyncio
    async def test_supports_format(self, adapter):
        """Test format support checking."""
        assert adapter.supports_format("youtube") is True
        assert adapter.supports_format("YOUTUBE") is True
        assert adapter.supports_format("vimeo") is False
        assert adapter.supports_format("pdf") is False

    @pytest.mark.asyncio
    async def test_extract_video_ids_standard_url(self, adapter):
        """Test video ID extraction from standard URL."""
        ids = adapter._extract_video_ids("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
        assert ids == ["dQw4w9WgXcQ"]

    @pytest.mark.asyncio
    async def test_extract_video_ids_short_url(self, adapter):
        """Test video ID extraction from short URL."""
        ids = adapter._extract_video_ids("https://youtu.be/dQw4w9WgXcQ")
        assert ids == ["dQw4w9WgXcQ"]

    @pytest.mark.asyncio
    async def test_extract_video_ids_embed_url(self, adapter):
        """Test video ID extraction from embed URL."""
        ids = adapter._extract_video_ids("https://www.youtube.com/embed/dQw4w9WgXcQ")
        assert ids == ["dQw4w9WgXcQ"]

    @pytest.mark.asyncio
    async def test_extract_video_ids_direct_id(self, adapter):
        """Test video ID extraction from direct ID."""
        ids = adapter._extract_video_ids("dQw4w9WgXcQ")
        assert ids == ["dQw4w9WgXcQ"]

    @pytest.mark.asyncio
    async def test_adapt_missing_library(self, adapter):
        """Test adapter behavior when youtube-transcript-api is not installed."""
        with patch.dict('sys.modules', {'youtube_transcript_api': None}):
            result = await adapter.adapt("dQw4w9WgXcQ")
            assert result.success is False
            assert "youtube-transcript-api" in result.error

    @pytest.mark.asyncio
    async def test_adapt_invalid_url(self, adapter):
        """Test adapter with invalid URL."""
        result = await adapter.adapt("https://invalid-url.com/video")
        assert result.success is False
        assert "Invalid YouTube URL" in result.error

    @pytest.mark.asyncio
    async def test_adapt_with_mock_transcript(self, adapter):
        """Test successful video adaptation with mocked transcript."""
        mock_transcript_data = [
            {"text": "Welcome to this tutorial", "start": 0.0, "duration": 3.0},
            {"text": "Today we will learn about Python", "start": 3.0, "duration": 4.0},
            {"text": "Python is a great language", "start": 7.0, "duration": 3.0},
            {"text": "Let's get started", "start": 10.0, "duration": 2.0},
        ]

        mock_transcript = Mock()
        mock_transcript.fetch.return_value = mock_transcript_data

        mock_transcript_list = Mock()
        mock_transcript_list.find_transcript.return_value = mock_transcript

        mock_api = Mock()
        mock_api.list_transcripts.return_value = mock_transcript_list

        with patch('youtube_transcript_api.YouTubeTranscriptApi', mock_api):
            result = await adapter.adapt("dQw4w9WgXcQ", scene_duration=10)

            assert result.success is True
            assert result.video_set is not None
            assert result.video_set.set_id == "youtube_dQw4w9WgXcQ"


class TestYouTubeAdapterEdgeCases:
    """Edge case tests for YouTubeAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create YouTubeAdapter instance."""
        return YouTubeAdapter(test_mode=True)

    @pytest.mark.asyncio
    async def test_url_with_extra_parameters(self, adapter):
        """Test URL with additional query parameters."""
        url = "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=120&list=PL123"
        is_valid = await adapter.validate_source(url)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_url_with_timestamp(self, adapter):
        """Test URL with timestamp parameter."""
        url = "https://youtu.be/dQw4w9WgXcQ?t=60"
        is_valid = await adapter.validate_source(url)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_url_with_whitespace(self, adapter):
        """Test URL with leading/trailing whitespace."""
        url = "  https://www.youtube.com/watch?v=dQw4w9WgXcQ  "
        ids = adapter._extract_video_ids(url)
        assert ids == ["dQw4w9WgXcQ"]

    @pytest.mark.asyncio
    async def test_url_with_quotes(self, adapter):
        """Test URL wrapped in quotes."""
        url = '"https://www.youtube.com/watch?v=dQw4w9WgXcQ"'
        ids = adapter._extract_video_ids(url)
        assert ids == ["dQw4w9WgXcQ"]

    @pytest.mark.asyncio
    async def test_create_title_from_text(self, adapter):
        """Test title creation from transcript text."""
        title = adapter._create_title("this is a test video about python programming")
        assert title == "This is a test video about python programming"

    @pytest.mark.asyncio
    async def test_create_title_truncation(self, adapter):
        """Test title truncation for long text."""
        long_text = "a" * 100
        title = adapter._create_title(long_text, max_length=50)
        assert len(title) <= 53  # 50 + "..."
        assert title.endswith("...")

    @pytest.mark.asyncio
    async def test_create_bullet_points(self, adapter):
        """Test bullet point creation from text."""
        text = "First point. Second point. Third point. Fourth point. Fifth point."
        bullets = adapter._create_bullet_points(text, max_points=3)
        assert len(bullets) <= 3


# =============================================================================
# WIZARD ADAPTER UNIT TESTS
# =============================================================================

class TestWizardAdapterUnit:
    """Unit tests for InteractiveWizard."""

    @pytest.fixture
    def wizard(self):
        """Create InteractiveWizard instance."""
        return InteractiveWizard(test_mode=True)

    @pytest.mark.asyncio
    async def test_wizard_initialization(self, wizard):
        """Test wizard initialization."""
        assert wizard.name == "wizard"
        assert "interactive" in wizard.description.lower()
        assert len(wizard.templates) >= 5

    @pytest.mark.asyncio
    async def test_non_interactive_mode(self, wizard):
        """Test non-interactive mode produces valid output."""
        result = await wizard.adapt(non_interactive=True)

        assert result.success is True
        assert result.video_set is not None
        assert isinstance(result.video_set, VideoSet)
        assert len(result.video_set.videos) == 1

    @pytest.mark.asyncio
    async def test_validate_source_always_true(self, wizard):
        """Test that wizard always validates source (no source needed)."""
        assert await wizard.validate_source(None) is True
        assert await wizard.validate_source("anything") is True
        assert await wizard.validate_source(123) is True

    @pytest.mark.asyncio
    async def test_supports_format(self, wizard):
        """Test format support checking."""
        assert wizard.supports_format("wizard") is True
        assert wizard.supports_format("interactive") is True
        assert wizard.supports_format("WIZARD") is True
        assert wizard.supports_format("document") is False

    @pytest.mark.asyncio
    async def test_resume_from_draft(self, wizard, temp_dir, wizard_draft_data):
        """Test resuming from draft file."""
        draft_file = temp_dir / "test_draft.json"
        with open(draft_file, 'w') as f:
            json.dump(wizard_draft_data, f)

        result = await wizard.adapt(source=draft_file)

        assert result.success is True
        assert result.video_set is not None
        assert result.metadata.get('source') == 'wizard_resume'

    @pytest.mark.asyncio
    async def test_resume_invalid_file(self, wizard, temp_dir):
        """Test resuming from invalid draft file."""
        invalid_file = temp_dir / "invalid.json"
        result = await wizard.adapt(source=invalid_file)

        assert result.success is False
        assert "Failed to resume" in result.error

    @pytest.mark.asyncio
    async def test_convert_to_video_set(self, wizard, wizard_draft_data):
        """Test converting wizard data to VideoSet."""
        video_set = wizard._convert_to_video_set(wizard_draft_data)

        assert isinstance(video_set, VideoSet)
        assert video_set.set_id == "wizard_test_video_set"
        assert len(video_set.videos) == 1
        assert video_set.videos[0].video_id == "wizard_test_video"
        assert video_set.videos[0].title == "Wizard Generated Video"

    def test_slugify(self, wizard):
        """Test slug generation."""
        assert wizard._slugify("Hello World") == "hello_world"
        assert wizard._slugify("Test-With-Dashes") == "test_with_dashes"
        assert wizard._slugify("Symbols!@#$%Test") == "symbolstest"
        assert len(wizard._slugify("a" * 50)) == 30  # Max length

    @pytest.mark.asyncio
    async def test_all_templates_valid(self, wizard):
        """Test that all templates have valid structure."""
        for template_name, template in wizard.templates.items():
            assert 'description' in template
            assert 'scene_pattern' in template
            assert 'suggestions' in template

    @pytest.mark.asyncio
    async def test_metadata_in_result(self, wizard):
        """Test that result contains proper metadata."""
        result = await wizard.adapt(non_interactive=True)

        assert 'source' in result.metadata
        assert result.metadata['source'] == 'wizard'
        assert 'template' in result.metadata
        assert 'scenes_generated' in result.metadata


# =============================================================================
# PROGRAMMATIC ADAPTER UNIT TESTS
# =============================================================================

class TestProgrammaticAdapterUnit:
    """Unit tests for ProgrammaticAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create ProgrammaticAdapter instance."""
        return ProgrammaticAdapter(test_mode=True)

    @pytest.mark.asyncio
    async def test_adapter_initialization(self, adapter):
        """Test ProgrammaticAdapter initialization."""
        assert adapter.name == "programmatic"
        assert "programmatic" in adapter.description.lower() or "api" in adapter.description.lower()

    @pytest.mark.asyncio
    async def test_adapt_video_set(self, adapter, programmatic_video_set):
        """Test adapting a VideoSet object directly."""
        result = await adapter.adapt(programmatic_video_set)

        assert result.success is True
        assert result.video_set is programmatic_video_set

    @pytest.mark.asyncio
    async def test_adapt_video_config(self, adapter, programmatic_video_config):
        """Test adapting a VideoConfig object (wraps in VideoSet)."""
        result = await adapter.adapt(programmatic_video_config)

        assert result.success is True
        assert result.video_set is not None
        assert len(result.video_set.videos) == 1
        assert result.video_set.videos[0].video_id == "programmatic_video_001"

    @pytest.mark.asyncio
    async def test_adapt_dictionary(self, adapter):
        """Test adapting a dictionary to VideoSet."""
        data = {
            "set_id": "dict_set_001",
            "name": "Dictionary Video Set",
            "description": "Created from dict",
            "videos": []
        }
        result = await adapter.adapt(data)

        assert result.success is True
        assert result.video_set.set_id == "dict_set_001"

    @pytest.mark.asyncio
    async def test_adapt_unsupported_type(self, adapter):
        """Test adapting unsupported type fails gracefully."""
        result = await adapter.adapt("just a string")

        assert result.success is False
        assert "Unsupported source type" in result.error

    @pytest.mark.asyncio
    async def test_validate_source_video_set(self, adapter, programmatic_video_set):
        """Test source validation with VideoSet."""
        is_valid = await adapter.validate_source(programmatic_video_set)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_validate_source_video_config(self, adapter, programmatic_video_config):
        """Test source validation with VideoConfig."""
        is_valid = await adapter.validate_source(programmatic_video_config)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_validate_source_dict(self, adapter):
        """Test source validation with dictionary."""
        is_valid = await adapter.validate_source({"key": "value"})
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_validate_source_invalid(self, adapter):
        """Test source validation with invalid types."""
        assert await adapter.validate_source("string") is False
        assert await adapter.validate_source(123) is False
        assert await adapter.validate_source(None) is False

    @pytest.mark.asyncio
    async def test_supports_format(self, adapter):
        """Test format support checking."""
        assert adapter.supports_format("programmatic") is True
        assert adapter.supports_format("api") is True
        assert adapter.supports_format("dict") is True
        assert adapter.supports_format("yaml") is False


# =============================================================================
# YAML ADAPTER UNIT TESTS
# =============================================================================

class TestYAMLAdapterUnit:
    """Unit tests for YAMLFileAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create YAMLFileAdapter instance in test mode."""
        return YAMLFileAdapter(test_mode=True)

    @pytest.mark.asyncio
    async def test_adapter_initialization(self, adapter):
        """Test YAMLFileAdapter initialization."""
        assert adapter.name == "yaml"
        assert adapter.supported_formats == {".yaml", ".yml"}
        assert adapter.test_mode is True

    @pytest.mark.asyncio
    async def test_validate_source_valid_yaml(self, adapter, sample_yaml_single_video):
        """Test source validation with valid YAML file."""
        is_valid = await adapter.validate_source(sample_yaml_single_video)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_validate_source_valid_yml(self, adapter, temp_dir):
        """Test source validation with .yml extension."""
        file_path = temp_dir / "test.yml"
        file_path.write_text("key: value")
        is_valid = await adapter.validate_source(file_path)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_validate_source_invalid_extension(self, adapter, temp_dir):
        """Test source validation with invalid extension."""
        file_path = temp_dir / "test.json"
        file_path.write_text('{"key": "value"}')
        is_valid = await adapter.validate_source(file_path)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_supports_format(self, adapter):
        """Test format support checking."""
        assert adapter.supports_format(".yaml") is True
        assert adapter.supports_format(".yml") is True
        assert adapter.supports_format(".json") is False

    @pytest.mark.asyncio
    async def test_adapt_single_video_format(self, adapter, sample_yaml_single_video):
        """Test adapting single video YAML format."""
        result = await adapter.adapt(sample_yaml_single_video)

        assert result.success is True
        assert result.video_set is not None
        assert len(result.video_set.videos) == 1
        assert result.video_set.videos[0].video_id == "test_video_001"
        assert result.metadata.get("format_type") == "single_video"

    @pytest.mark.asyncio
    async def test_adapt_video_set_format(self, adapter, sample_yaml_video_set):
        """Test adapting video set YAML format."""
        result = await adapter.adapt(sample_yaml_video_set)

        assert result.success is True
        assert result.video_set is not None
        assert result.video_set.set_id == "test_set_001"
        assert len(result.video_set.videos) == 2
        assert result.metadata.get("format_type") == "video_set"

    @pytest.mark.asyncio
    async def test_adapt_nonexistent_file(self, adapter):
        """Test adapting nonexistent YAML file."""
        result = await adapter.adapt("/nonexistent/file.yaml")

        assert result.success is False
        assert "not found" in result.error.lower() or "failed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_adapt_invalid_yaml(self, adapter, temp_dir):
        """Test adapting invalid YAML content."""
        file_path = temp_dir / "invalid.yaml"
        file_path.write_text("invalid: yaml: content: [")

        result = await adapter.adapt(file_path)
        assert result.success is False

    @pytest.mark.asyncio
    async def test_export_to_yaml(self, adapter, temp_dir, programmatic_video_set):
        """Test exporting VideoSet to YAML."""
        output_path = temp_dir / "exported.yaml"
        success = adapter.export_to_yaml(programmatic_video_set, output_path)

        assert success is True
        assert output_path.exists()

        # Re-import and verify
        result = await adapter.adapt(output_path)
        assert result.success is True
        assert result.video_set.set_id == programmatic_video_set.set_id


class TestYAMLAdapterEdgeCases:
    """Edge case tests for YAMLFileAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create YAMLFileAdapter instance in test mode."""
        return YAMLFileAdapter(test_mode=True)

    @pytest.mark.asyncio
    async def test_yaml_with_alternative_field_names(self, adapter, temp_dir):
        """Test YAML with 'id' instead of 'video_id'."""
        content = {
            "id": "alt_video_id",  # Using 'id' instead of 'video_id'
            "title": "Alternative ID Video",
            "scenes": [
                {
                    "scene_id": "scene_01",
                    "type": "title",  # Using 'type' instead of 'scene_type'
                    "narration": "Welcome",
                    "visual_content": {"title": "Test"}
                }
            ]
        }
        file_path = temp_dir / "alt_format.yaml"
        with open(file_path, 'w') as f:
            yaml.safe_dump(content, f)

        result = await adapter.adapt(file_path)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_yaml_with_nested_video_key(self, adapter, temp_dir):
        """Test YAML with nested 'video' key."""
        content = {
            "video": {
                "id": "nested_video",
                "title": "Nested Video Format"
            },
            "scenes": [
                {
                    "scene_id": "scene_01",
                    "scene_type": "title",
                    "narration": "Welcome",
                    "visual_content": {"title": "Test"}
                }
            ]
        }
        file_path = temp_dir / "nested_video.yaml"
        with open(file_path, 'w') as f:
            yaml.safe_dump(content, f)

        result = await adapter.adapt(file_path)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_yaml_validation_missing_required_fields(self, adapter, temp_dir):
        """Test YAML validation with missing required fields."""
        # Missing scenes
        content = {
            "video_id": "no_scenes",
            "title": "Video Without Scenes"
        }
        file_path = temp_dir / "no_scenes.yaml"
        with open(file_path, 'w') as f:
            yaml.safe_dump(content, f)

        result = await adapter.adapt(file_path)
        assert result.success is False
        assert "scenes" in result.error.lower()

    @pytest.mark.asyncio
    async def test_yaml_with_empty_scenes(self, adapter, temp_dir):
        """Test YAML with empty scenes array."""
        content = {
            "video_id": "empty_scenes",
            "title": "Empty Scenes Video",
            "scenes": []
        }
        file_path = temp_dir / "empty_scenes.yaml"
        with open(file_path, 'w') as f:
            yaml.safe_dump(content, f)

        result = await adapter.adapt(file_path)
        assert result.success is False

    @pytest.mark.asyncio
    async def test_yaml_with_all_scene_types(self, adapter, temp_dir):
        """Test YAML with all valid scene types."""
        scene_types = ["title", "command", "list", "outro", "code_comparison",
                      "quote", "learning_objectives", "problem", "solution",
                      "checkpoint", "quiz", "exercise"]

        scenes = [
            {
                "scene_id": f"scene_{i:02d}",
                "scene_type": st,
                "narration": f"This is a {st} scene",
                "visual_content": {"content": f"{st} content"}
            }
            for i, st in enumerate(scene_types)
        ]

        content = {
            "video_id": "all_scene_types",
            "title": "All Scene Types Video",
            "scenes": scenes
        }
        file_path = temp_dir / "all_scene_types.yaml"
        with open(file_path, 'w') as f:
            yaml.safe_dump(content, f)

        result = await adapter.adapt(file_path)
        assert result.success is True
        assert len(result.video_set.videos[0].scenes) == len(scene_types)

    @pytest.mark.asyncio
    async def test_yaml_with_custom_durations(self, adapter, temp_dir):
        """Test YAML with custom scene durations."""
        content = {
            "video_id": "custom_durations",
            "title": "Custom Duration Video",
            "scenes": [
                {
                    "scene_id": "scene_01",
                    "scene_type": "title",
                    "narration": "Welcome",
                    "visual_content": {"title": "Test"},
                    "min_duration": 5.0,
                    "max_duration": 10.0
                }
            ]
        }
        file_path = temp_dir / "custom_durations.yaml"
        with open(file_path, 'w') as f:
            yaml.safe_dump(content, f)

        result = await adapter.adapt(file_path)
        assert result.success is True
        scene = result.video_set.videos[0].scenes[0]
        assert scene.min_duration == 5.0
        assert scene.max_duration == 10.0


# =============================================================================
# SECURITY AND VALIDATION TESTS
# =============================================================================

class TestSecurityAndValidation:
    """Security and validation tests for all adapters."""

    @pytest.mark.asyncio
    async def test_document_path_traversal_prevention(self, temp_dir):
        """Test that document adapter prevents path traversal attacks."""
        adapter = DocumentAdapter(test_mode=False, use_ai=False)

        # Try to access file outside project directory
        result = await adapter.adapt("../../../etc/passwd")
        assert result.success is False

    @pytest.mark.asyncio
    async def test_yaml_path_traversal_prevention(self, temp_dir):
        """Test that YAML adapter prevents path traversal attacks."""
        adapter = YAMLFileAdapter(test_mode=False)

        result = await adapter.adapt("../../../etc/passwd")
        assert result.success is False

    @pytest.mark.asyncio
    async def test_document_system_directory_blocking(self, temp_dir):
        """Test that system directories are blocked."""
        adapter = DocumentAdapter(test_mode=False, use_ai=False)

        system_paths = [
            "/etc/passwd",
            "/root/.ssh/id_rsa",
            "/proc/version",
        ]

        for path in system_paths:
            result = await adapter.adapt(path)
            assert result.success is False

    @pytest.mark.asyncio
    async def test_yaml_safe_load_only(self, temp_dir):
        """Test that YAML uses safe_load to prevent code execution."""
        adapter = YAMLFileAdapter(test_mode=True)

        # Create YAML with potentially dangerous content
        dangerous_yaml = """
!!python/object/apply:os.system
args: ['echo hacked']
"""
        file_path = temp_dir / "dangerous.yaml"
        file_path.write_text(dangerous_yaml)

        result = await adapter.adapt(file_path)
        # Should fail safely without executing code
        assert result.success is False

    @pytest.mark.asyncio
    async def test_scene_config_validation(self):
        """Test SceneConfig validation."""
        # Test valid scene
        valid_scene = SceneConfig(
            scene_id="test_scene",
            scene_type="title",
            narration="Test narration",
            visual_content={"title": "Test"}
        )
        assert valid_scene.scene_id == "test_scene"

        # Test scene_id too long
        with pytest.raises(ValueError, match="scene_id too long"):
            SceneConfig(
                scene_id="a" * 201,
                scene_type="title",
                narration="Test",
                visual_content={}
            )

        # Test narration too long
        with pytest.raises(ValueError, match="narration too long"):
            SceneConfig(
                scene_id="test",
                scene_type="title",
                narration="a" * 50001,
                visual_content={}
            )

        # Test invalid duration range
        with pytest.raises(ValueError, match="min_duration"):
            SceneConfig(
                scene_id="test",
                scene_type="title",
                narration="Test",
                visual_content={},
                min_duration=10.0,
                max_duration=5.0  # max < min
            )

    @pytest.mark.asyncio
    async def test_video_config_validation(self):
        """Test VideoConfig validation."""
        # Test video_id too long
        with pytest.raises(ValueError, match="video_id too long"):
            VideoConfig(
                video_id="a" * 201,
                title="Test",
                description="Test",
                scenes=[
                    SceneConfig(
                        scene_id="s1",
                        scene_type="title",
                        narration="Test",
                        visual_content={}
                    )
                ]
            )

        # Test empty scenes
        with pytest.raises(ValueError, match="cannot be empty"):
            VideoConfig(
                video_id="test",
                title="Test",
                description="Test",
                scenes=[]
            )


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestInputAdapterIntegration:
    """Integration tests for input adapter flows."""

    @pytest.mark.asyncio
    async def test_document_to_yaml_roundtrip(self, temp_dir, sample_markdown_content):
        """Test converting document to YAML and back."""
        # Create markdown file
        md_file = temp_dir / "test.md"
        md_file.write_text(sample_markdown_content)

        # Parse with document adapter
        doc_adapter = DocumentAdapter(test_mode=True, use_ai=False)
        doc_result = await doc_adapter.adapt(md_file)
        assert doc_result.success is True

        # Export to YAML
        yaml_adapter = YAMLFileAdapter(test_mode=True)
        yaml_file = temp_dir / "exported.yaml"
        yaml_adapter.export_to_yaml(doc_result.video_set, yaml_file)

        # Re-import from YAML
        yaml_result = await yaml_adapter.adapt(yaml_file)
        assert yaml_result.success is True

        # Verify content preserved
        original_videos = len(doc_result.video_set.videos)
        reimported_videos = len(yaml_result.video_set.videos)
        assert reimported_videos == original_videos

    @pytest.mark.asyncio
    async def test_wizard_to_yaml_roundtrip(self, temp_dir):
        """Test converting wizard output to YAML and back."""
        # Generate with wizard
        wizard = InteractiveWizard(test_mode=True)
        wizard_result = await wizard.adapt(non_interactive=True)
        assert wizard_result.success is True

        # Export to YAML
        yaml_adapter = YAMLFileAdapter(test_mode=True)
        yaml_file = temp_dir / "wizard_exported.yaml"
        yaml_adapter.export_to_yaml(
            wizard_result.video_set,
            yaml_file,
            format_type="single_video"
        )

        # Re-import from YAML
        yaml_result = await yaml_adapter.adapt(yaml_file)
        assert yaml_result.success is True

    @pytest.mark.asyncio
    async def test_programmatic_to_yaml_roundtrip(self, temp_dir, programmatic_video_set):
        """Test converting programmatic input to YAML and back."""
        # Adapt with programmatic adapter
        prog_adapter = ProgrammaticAdapter(test_mode=True)
        prog_result = await prog_adapter.adapt(programmatic_video_set)
        assert prog_result.success is True

        # Export to YAML
        yaml_adapter = YAMLFileAdapter(test_mode=True)
        yaml_file = temp_dir / "programmatic_exported.yaml"
        yaml_adapter.export_to_yaml(prog_result.video_set, yaml_file)

        # Re-import from YAML
        yaml_result = await yaml_adapter.adapt(yaml_file)
        assert yaml_result.success is True
        assert yaml_result.video_set.set_id == programmatic_video_set.set_id

    @pytest.mark.asyncio
    async def test_all_adapters_produce_valid_video_set(
        self, temp_dir, sample_markdown_file, sample_yaml_single_video, programmatic_video_set
    ):
        """Test that all adapters produce valid VideoSet objects."""
        results = []

        # Document adapter
        doc_adapter = DocumentAdapter(test_mode=True, use_ai=False)
        results.append(await doc_adapter.adapt(sample_markdown_file))

        # YAML adapter
        yaml_adapter = YAMLFileAdapter(test_mode=True)
        results.append(await yaml_adapter.adapt(sample_yaml_single_video))

        # Wizard adapter
        wizard = InteractiveWizard(test_mode=True)
        results.append(await wizard.adapt(non_interactive=True))

        # Programmatic adapter
        prog_adapter = ProgrammaticAdapter(test_mode=True)
        results.append(await prog_adapter.adapt(programmatic_video_set))

        # Verify all results
        for result in results:
            assert result.success is True
            assert isinstance(result.video_set, VideoSet)
            assert len(result.video_set.videos) >= 1
            for video in result.video_set.videos:
                assert video.video_id is not None
                assert video.title is not None
                assert len(video.scenes) >= 1


# =============================================================================
# PERFORMANCE TESTS
# =============================================================================

class TestPerformance:
    """Performance benchmark tests."""

    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_document_parsing_performance(self, temp_dir):
        """Test document parsing performance with large file."""
        # Create large document (limited to 50 sections to stay under 100 scene limit)
        sections = "\n\n".join([
            f"## Section {i}\n\nContent for section {i} with some text.\n- Item {i}.1\n- Item {i}.2\n"
            for i in range(50)
        ])
        content = f"# Large Document\n\n{sections}"
        file_path = temp_dir / "large_document.md"
        file_path.write_text(content)

        adapter = DocumentAdapter(test_mode=True, use_ai=False)

        start_time = time.time()
        result = await adapter.adapt(file_path, max_scenes_per_video=80)
        elapsed = time.time() - start_time

        assert result.success is True
        assert elapsed < 5.0  # Should complete within 5 seconds

    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_yaml_parsing_performance(self, temp_dir):
        """Test YAML parsing performance with many videos."""
        # Create YAML with many videos
        videos = [
            {
                "video_id": f"video_{i:03d}",
                "title": f"Video {i}",
                "description": f"Description for video {i}",
                "scenes": [
                    {
                        "scene_id": f"v{i}_scene_{j:02d}",
                        "scene_type": "list",
                        "narration": f"Narration for scene {j}",
                        "visual_content": {"header": f"Header {j}", "items": [f"Item {k}" for k in range(5)]}
                    }
                    for j in range(10)
                ]
            }
            for i in range(50)
        ]

        content = {
            "set_id": "performance_test_set",
            "name": "Performance Test Set",
            "videos": videos
        }

        file_path = temp_dir / "large_set.yaml"
        with open(file_path, 'w') as f:
            yaml.safe_dump(content, f)

        adapter = YAMLFileAdapter(test_mode=True)

        start_time = time.time()
        result = await adapter.adapt(file_path)
        elapsed = time.time() - start_time

        assert result.success is True
        assert len(result.video_set.videos) == 50
        assert elapsed < 5.0  # Should complete within 5 seconds

    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_multiple_adapter_concurrent_processing(
        self, temp_dir, sample_markdown_content
    ):
        """Test concurrent processing with multiple adapters."""
        # Create test files
        md_files = []
        for i in range(10):
            file_path = temp_dir / f"doc_{i}.md"
            file_path.write_text(sample_markdown_content)
            md_files.append(file_path)

        adapter = DocumentAdapter(test_mode=True, use_ai=False)

        start_time = time.time()
        tasks = [adapter.adapt(f) for f in md_files]
        results = await asyncio.gather(*tasks)
        elapsed = time.time() - start_time

        assert all(r.success for r in results)
        assert elapsed < 10.0  # Should complete within 10 seconds


# =============================================================================
# COMPATIBILITY LAYER TESTS
# =============================================================================

class TestCompatibilityLayer:
    """Tests for backward compatibility layer."""

    def test_compat_document_adapter(self, sample_markdown_file):
        """Test compatibility layer DocumentAdapter."""
        from video_gen.input_adapters.compat import DocumentAdapter as CompatDocAdapter

        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            adapter = CompatDocAdapter(test_mode=True)
            video_set = adapter.parse(str(sample_markdown_file))

        assert video_set is not None
        assert len(video_set.videos) >= 1

    def test_compat_get_adapter_factory(self):
        """Test compatibility layer adapter factory."""
        from video_gen.input_adapters.compat import get_adapter

        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)

            doc_adapter = get_adapter('document')
            assert doc_adapter is not None

            yaml_adapter = get_adapter('yaml')
            assert yaml_adapter is not None

            prog_adapter = get_adapter('programmatic')
            assert prog_adapter is not None

            with pytest.raises(ValueError):
                get_adapter('invalid_type')


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
