"""Tests for intelligent content splitting and AI narration generation."""

import pytest
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock
from video_gen.input_adapters.content_splitter import (
    ContentSplitter,
    SplitStrategy,
    ContentSection,
    SplitResult
)


class TestContentSplitter:
    """Test the intelligent content splitter."""

    @pytest.fixture
    def sample_markdown(self):
        """Sample markdown content with headers."""
        return """# Machine Learning Guide

## Introduction
Machine learning is a subset of artificial intelligence...

## Neural Networks
Neural networks are computational models inspired by...

## Training Process
Training involves adjusting weights and biases...

## Applications
ML is used in various fields including..."""

    @pytest.fixture
    def sample_plain_text(self):
        """Sample plain text without structure."""
        return """Machine learning has transformed the way we process data.
It enables computers to learn from experience without explicit programming.
The field encompasses various algorithms and techniques that allow systems to improve over time.
From recommendation systems to autonomous vehicles, ML powers modern technology.
Understanding these concepts is crucial for developers and data scientists."""

    def test_strategy_auto_selection_markdown(self, sample_markdown):
        """Test auto strategy selects headers for markdown."""
        splitter = ContentSplitter(use_ai=False)
        strategy = splitter._select_best_strategy(sample_markdown, num_sections=3)
        assert strategy == SplitStrategy.MARKDOWN_HEADERS

    def test_strategy_auto_selection_plain_text(self, sample_plain_text):
        """Test auto strategy selects sentence for plain text."""
        splitter = ContentSplitter(use_ai=False)
        strategy = splitter._select_best_strategy(sample_plain_text, num_sections=3)
        # Should select SENTENCE for short plain text
        assert strategy in [SplitStrategy.SENTENCE, SplitStrategy.PARAGRAPH]

    @pytest.mark.asyncio
    async def test_split_by_headers(self, sample_markdown):
        """Test splitting by markdown headers."""
        splitter = ContentSplitter(use_ai=False)

        result = await splitter.split(
            content=sample_markdown,
            num_sections=4,
            strategy=SplitStrategy.MARKDOWN_HEADERS
        )

        assert isinstance(result, SplitResult)
        assert result.strategy_used == SplitStrategy.MARKDOWN_HEADERS
        assert len(result.sections) == 4
        assert all(isinstance(s, ContentSection) for s in result.sections)
        # First section is the H1 title
        assert "Machine Learning" in result.sections[0].title
        # Verify we have the H2 sections
        section_titles = [s.title for s in result.sections]
        assert any("Introduction" in t for t in section_titles)
        assert any("Neural" in t for t in section_titles)

    @pytest.mark.asyncio
    async def test_split_by_sentences(self, sample_plain_text):
        """Test splitting by sentences."""
        splitter = ContentSplitter(use_ai=False)

        result = await splitter.split(
            content=sample_plain_text,
            num_sections=3,
            strategy=SplitStrategy.SENTENCE
        )

        assert isinstance(result, SplitResult)
        assert result.strategy_used == SplitStrategy.SENTENCE
        assert len(result.sections) == 3
        assert all(s.word_count > 0 for s in result.sections)

    @pytest.mark.asyncio
    async def test_split_by_length(self, sample_plain_text):
        """Test splitting by length."""
        splitter = ContentSplitter(use_ai=False)

        result = await splitter.split(
            content=sample_plain_text,
            num_sections=2,
            strategy=SplitStrategy.LENGTH
        )

        assert len(result.sections) == 2
        # Check sections are relatively balanced
        total_words = sum(s.word_count for s in result.sections)
        avg_words = total_words / 2
        for section in result.sections:
            # Within 30% of average
            assert abs(section.word_count - avg_words) < avg_words * 0.3

    @pytest.mark.asyncio
    async def test_split_by_paragraphs(self):
        """Test splitting by paragraphs."""
        content = """First paragraph here.

Second paragraph here with more content.

Third paragraph continues.

Fourth paragraph with details.

Fifth paragraph concludes."""

        splitter = ContentSplitter(use_ai=False)

        result = await splitter.split(
            content=content,
            num_sections=2,
            strategy=SplitStrategy.PARAGRAPH
        )

        assert len(result.sections) == 2
        assert result.strategy_used == SplitStrategy.PARAGRAPH

    @pytest.mark.asyncio
    async def test_manual_split_points(self, sample_plain_text):
        """Test manual splitting with user-defined points."""
        splitter = ContentSplitter(use_ai=False)

        result = await splitter.split(
            content=sample_plain_text,
            num_sections=2,  # Ignored for manual
            strategy=SplitStrategy.MANUAL,
            split_points=[100, 200]  # Split at char 100 and 200
        )

        assert len(result.sections) == 3  # 3 sections from 2 split points
        assert result.strategy_used == SplitStrategy.MANUAL
        assert result.confidence == 1.0

    @pytest.mark.asyncio
    async def test_section_adjustment_split(self):
        """Test adjusting section count by splitting."""
        content = "Test content " * 100

        splitter = ContentSplitter(use_ai=False)

        # Request more sections than natural splits
        result = await splitter.split(
            content=content,
            num_sections=5,
            strategy=SplitStrategy.SENTENCE
        )

        assert len(result.sections) == 5

    @pytest.mark.asyncio
    async def test_section_adjustment_merge(self, sample_markdown):
        """Test adjusting section count by merging."""
        splitter = ContentSplitter(use_ai=False)

        # Request fewer sections than headers available
        result = await splitter.split(
            content=sample_markdown,
            num_sections=2,
            strategy=SplitStrategy.MARKDOWN_HEADERS
        )

        assert len(result.sections) == 2

    def test_content_section_dataclass(self):
        """Test ContentSection dataclass."""
        section = ContentSection(
            title="Test Section",
            content="Test content here",
            start_index=0,
            end_index=17,
            word_count=3,
            metadata={"test": True},
            narration="This is test narration",
            narration_hook="Hook line",
            key_takeaway="Main point"
        )

        assert section.title == "Test Section"
        assert section.narration == "This is test narration"
        assert section.narration_hook == "Hook line"
        assert section.key_takeaway == "Main point"

    def test_split_result_dataclass(self):
        """Test SplitResult dataclass."""
        section = ContentSection(
            title="Test",
            content="Content",
            start_index=0,
            end_index=7,
            word_count=1,
            metadata={}
        )

        result = SplitResult(
            sections=[section],
            strategy_used=SplitStrategy.AUTO,
            confidence=0.8,
            metadata={"test": True}
        )

        assert len(result.sections) == 1
        assert result.strategy_used == SplitStrategy.AUTO
        assert result.confidence == 0.8


class TestAISplitting:
    """Test AI-powered splitting with mocked API."""

    @pytest.mark.asyncio
    async def test_ai_splitting_with_narration(self):
        """Test AI splitting generates narration for sections (with mocked API)."""
        content = """Machine learning is transforming technology.
It enables computers to learn from data without explicit programming.
Neural networks are the foundation of modern AI systems.
They process information in layers, similar to the human brain.
Training these models requires large datasets and computational power.
Applications range from image recognition to natural language processing."""

        # Mock the AI API response
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="""
{
  "sections": [
    {
      "title": "Introduction to Machine Learning",
      "content": "Machine learning is transforming technology. It enables computers to learn from data without explicit programming. Neural networks are the foundation of modern AI systems.",
      "narration": "Welcome to our exploration of machine learning! This revolutionary technology is transforming how computers understand and process information, enabling them to learn from data without explicit programming.",
      "narration_hook": "Imagine computers that can learn just like humans do...",
      "key_takeaway": "Machine learning enables computers to learn from data automatically"
    },
    {
      "title": "Neural Networks and Training",
      "content": "They process information in layers, similar to the human brain. Training these models requires large datasets and computational power. Applications range from image recognition to natural language processing.",
      "narration": "Neural networks process information in layers, mimicking the human brain. Training requires massive datasets and computational power, but the results are transformative across numerous applications.",
      "narration_hook": "From recognizing faces to understanding language...",
      "key_takeaway": "Neural networks power modern AI with brain-inspired processing"
    }
  ],
  "metadata": {
    "strategy": "ai_intelligent",
    "ai_model": "claude-sonnet-4.5",
    "narration_generated": true,
    "input_tokens": 150,
    "output_tokens": 250
  }
}
""")]
        mock_response.usage = MagicMock(input_tokens=150, output_tokens=250)

        # Create splitter with mocked AI client
        splitter = ContentSplitter(ai_api_key="test-key", use_ai=True)

        # Mock the Anthropic client
        with patch('anthropic.AsyncAnthropic') as mock_anthropic:
            mock_client = AsyncMock()
            mock_client.messages.create = AsyncMock(return_value=mock_response)
            mock_anthropic.return_value = mock_client

            result = await splitter.split(
                content=content,
                num_sections=2,
                strategy=SplitStrategy.AI_INTELLIGENT
            )

            # Verify AI splitting worked
            assert result.strategy_used == SplitStrategy.AI_INTELLIGENT
            assert len(result.sections) == 2
            assert result.metadata.get('narration_generated') is True

            # Verify narration was generated for each section
            for section in result.sections:
                assert section.narration is not None
                assert len(section.narration) > 0
                assert isinstance(section.narration, str)

            # Verify AI metadata
            assert 'ai_model' in result.metadata
            assert 'input_tokens' in result.metadata
            assert 'output_tokens' in result.metadata
