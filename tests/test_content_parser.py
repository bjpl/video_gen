"""Tests for content_parser module.

This module tests the ContentParser class for extracting structured content
from text, including topic extraction, keyword extraction, and section splitting.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from video_gen.content_parser.parser import ContentParser, ParseResult


class TestParseResult:
    """Tests for ParseResult dataclass."""

    def test_parse_result_success(self):
        """Test successful ParseResult creation."""
        result = ParseResult(success=True)
        assert result.success is True
        assert result.scenes == []
        assert result.metadata == {}
        assert result.error is None

    def test_parse_result_with_error(self):
        """Test ParseResult with error."""
        result = ParseResult(success=False, error="Test error")
        assert result.success is False
        assert result.error == "Test error"

    def test_parse_result_with_metadata(self):
        """Test ParseResult with metadata."""
        metadata = {"method": "ai", "topics": ["python", "testing"]}
        result = ParseResult(success=True, metadata=metadata)
        assert result.metadata == metadata

    def test_parse_result_defaults(self):
        """Test ParseResult default values are set correctly."""
        result = ParseResult(success=True, scenes=None, metadata=None)
        assert result.scenes == []
        assert result.metadata == {}


class TestContentParser:
    """Tests for ContentParser class."""

    def test_content_parser_initialization(self):
        """Test ContentParser initializes correctly."""
        parser = ContentParser()
        assert hasattr(parser, 'anthropic_available')

    def test_content_parser_without_api_key(self):
        """Test ContentParser works without API key."""
        with patch('video_gen.content_parser.parser.config') as mock_config:
            mock_config.get_api_key.return_value = None
            parser = ContentParser()
            assert parser.anthropic_available is False

    @pytest.mark.asyncio
    async def test_parse_without_ai(self):
        """Test parse returns basic result when AI not available."""
        parser = ContentParser()
        parser.anthropic_available = False

        result = await parser.parse("Test content here")

        assert result.success is True
        assert result.metadata["method"] == "basic"
        assert result.metadata["ai_enabled"] is False

    @pytest.mark.asyncio
    async def test_parse_with_ai_mock(self):
        """Test parse with mocked AI client."""
        parser = ContentParser()
        parser.anthropic_available = True

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text='{"topics": ["python"], "keywords": ["test"], "complexity": "simple"}')]

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        parser.client = mock_client

        result = await parser.parse("Python testing content")

        assert result.success is True
        assert result.metadata["method"] == "ai"
        assert result.metadata["ai_enabled"] is True
        assert "python" in result.metadata.get("topics", [])

    @pytest.mark.asyncio
    async def test_parse_handles_exception(self):
        """Test parse handles exceptions gracefully."""
        parser = ContentParser()
        parser.anthropic_available = True

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(side_effect=Exception("API Error"))
        parser.client = mock_client

        result = await parser.parse("Test content")

        assert result.success is False
        assert "API Error" in result.error


class TestContentParserPrompts:
    """Tests for prompt creation."""

    def test_create_analysis_prompt(self):
        """Test analysis prompt creation."""
        parser = ContentParser()
        prompt = parser._create_analysis_prompt("Sample content", "educational")

        assert "Sample content" in prompt
        assert "educational" in prompt
        assert "JSON" in prompt

    def test_create_analysis_prompt_truncates_long_content(self):
        """Test that long content is truncated in prompt."""
        parser = ContentParser()
        long_content = "x" * 2000
        prompt = parser._create_analysis_prompt(long_content, "general")

        # Content should be truncated to first 1000 chars
        assert len(prompt) < 2500


class TestAnalysisParsing:
    """Tests for AI response parsing."""

    def test_parse_analysis_valid_json(self):
        """Test parsing valid JSON response."""
        parser = ContentParser()
        response = '{"topics": ["python"], "keywords": ["test"], "complexity": "simple"}'

        result = parser._parse_analysis(response)

        assert result["topics"] == ["python"]
        assert result["keywords"] == ["test"]
        assert result["complexity"] == "simple"

    def test_parse_analysis_with_extra_text(self):
        """Test parsing JSON embedded in text."""
        parser = ContentParser()
        response = 'Here is the analysis: {"topics": ["ai"], "complexity": "medium"} End.'

        result = parser._parse_analysis(response)

        assert result["topics"] == ["ai"]
        assert result["complexity"] == "medium"

    def test_parse_analysis_invalid_json(self):
        """Test parsing handles invalid JSON."""
        parser = ContentParser()
        response = "This is not JSON"

        result = parser._parse_analysis(response)

        assert result == {"topics": [], "keywords": [], "complexity": "medium"}


class TestTopicExtraction:
    """Tests for topic extraction."""

    @pytest.mark.asyncio
    async def test_extract_topics_without_ai(self):
        """Test extract_topics returns empty list when AI not available."""
        parser = ContentParser()
        parser.anthropic_available = False

        topics = await parser.extract_topics("Test content")

        assert topics == []

    @pytest.mark.asyncio
    async def test_extract_topics_with_ai_mock(self):
        """Test extract_topics with mocked AI."""
        parser = ContentParser()
        parser.anthropic_available = True

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text='{"topics": ["python", "testing"], "keywords": [], "complexity": "simple"}')]

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        parser.client = mock_client

        topics = await parser.extract_topics("Python testing tutorial")

        assert "python" in topics
        assert "testing" in topics


class TestKeywordExtraction:
    """Tests for keyword extraction."""

    @pytest.mark.asyncio
    async def test_extract_keywords_without_ai(self):
        """Test extract_keywords returns empty list when AI not available."""
        parser = ContentParser()
        parser.anthropic_available = False

        keywords = await parser.extract_keywords("Test content")

        assert keywords == []


class TestSectionSplitting:
    """Tests for content section splitting."""

    @pytest.mark.asyncio
    async def test_split_into_sections_basic(self):
        """Test basic section splitting."""
        parser = ContentParser()
        content = "First paragraph.\n\nSecond paragraph.\n\nThird paragraph."

        sections = await parser.split_into_sections(content)

        assert len(sections) >= 1
        assert all("text" in s for s in sections)
        assert all("length" in s for s in sections)

    @pytest.mark.asyncio
    async def test_split_into_sections_respects_max_length(self):
        """Test section splitting respects max length."""
        parser = ContentParser()
        content = "Short.\n\n" + "x" * 600 + "\n\nAnother paragraph."

        sections = await parser.split_into_sections(content, max_section_length=100)

        # Verify sections don't exceed max by too much
        for section in sections:
            # Allow some overflow since we don't split mid-paragraph
            assert section["length"] < 700

    @pytest.mark.asyncio
    async def test_split_into_sections_empty_content(self):
        """Test section splitting with empty content."""
        parser = ContentParser()

        sections = await parser.split_into_sections("")

        assert sections == []

    @pytest.mark.asyncio
    async def test_split_into_sections_single_paragraph(self):
        """Test section splitting with single paragraph."""
        parser = ContentParser()
        content = "Single paragraph without any breaks."

        sections = await parser.split_into_sections(content)

        assert len(sections) == 1
        assert sections[0]["text"] == content
