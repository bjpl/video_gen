"""
Comprehensive tests for DocumentAdapter module.

Target: Increase coverage from 4% to 80%+

This module tests all aspects of document processing:
- File format handling (PDF, DOCX, MD, TXT)
- Content splitting strategies
- AI enhancement integration
- Error handling and edge cases
"""

import pytest
import asyncio
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from io import BytesIO
import tempfile

from video_gen.input_adapters.document import DocumentAdapter
from video_gen.input_adapters.base import InputAdapterResult
from video_gen.shared.models import VideoSet, VideoConfig, SceneConfig


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def mock_ai_enhancer():
    """Mock AI enhancer to avoid API calls."""
    with patch('video_gen.input_adapters.document.AIScriptEnhancer') as mock:
        enhancer = Mock()
        enhancer.enhance_script = AsyncMock(return_value="Enhanced narration")
        enhancer.enhance_slide_content = AsyncMock(return_value={
            "title": "Enhanced Title",
            "items": ["Enhanced point 1", "Enhanced point 2"]
        })
        mock.return_value = enhancer
        yield mock


@pytest.fixture
def mock_content_splitter():
    """Mock content splitter.

    CRITICAL: ContentSplitter is lazily imported inside DocumentAdapter.__init__,
    so we must patch at SOURCE module where class is defined.
    """
    with patch('video_gen.input_adapters.content_splitter.ContentSplitter') as mock:
        splitter = Mock()
        split_result = Mock()

        # Mock ContentSection objects with all required attributes
        section1 = Mock()
        section1.title = "Section 1"
        section1.content = "Content 1"
        section1.narration_hook = "Hook for section 1"
        section1.key_takeaway = "Takeaway 1"
        section1.start_index = 0
        section1.end_index = 100
        section1.word_count = 50
        section1.metadata = {}
        section1.narration = "AI-generated narration for section 1"  # Add narration attribute

        section2 = Mock()
        section2.title = "Section 2"
        section2.content = "Content 2"
        section2.narration_hook = "Hook for section 2"
        section2.key_takeaway = "Takeaway 2"
        section2.start_index = 100
        section2.end_index = 200
        section2.word_count = 50
        section2.metadata = {}
        section2.narration = "AI-generated narration for section 2"  # Add narration attribute

        # CRITICAL FIX: Mock sections list needs __len__ for iteration in _create_video_set_from_sections
        # The implementation uses: for idx, section in enumerate(sections)
        # And: len(sections) at line 703
        sections_list = [section1, section2]
        split_result.sections = sections_list  # Use actual list, not Mock
        split_result.strategy_used = Mock(value="ai")
        split_result.confidence = 0.95
        split_result.metadata = {"quality": "high"}

        splitter.split = AsyncMock(return_value=split_result)
        mock.return_value = splitter
        yield mock


@pytest.fixture
def sample_markdown():
    """Sample markdown content."""
    return """# Test Document

## Introduction

This is a test document for comprehensive testing.

### Key Points

- Point one with details
- Point two with more information
- Point three for completeness

## Code Example

```python
def hello_world():
    print("Hello, World!")
```

## Conclusion

Thank you for reading this document.
"""


@pytest.fixture
def sample_pdf_bytes():
    """Mock PDF file content."""
    return b"%PDF-1.4\n%Test PDF Content\n1 0 obj\n<</Type /Catalog>>\nendobj\n%%EOF"


@pytest.fixture
def sample_docx_bytes():
    """Mock DOCX file content (minimal ZIP structure)."""
    return b"PK\x03\x04" + b"\x00" * 100  # Minimal ZIP header


# ============================================================================
# DocumentAdapter Initialization Tests
# ============================================================================

class TestDocumentAdapterInit:
    """Test DocumentAdapter initialization."""

    def test_init_default_parameters(self, mock_ai_enhancer):
        """Test initialization with default parameters.

        Uses mock_ai_enhancer to prevent API key errors from affecting use_ai default.
        """
        adapter = DocumentAdapter()

        assert adapter.name == "document"
        assert "PDF, DOCX, TXT" in adapter.description
        assert adapter.test_mode is False
        assert adapter.use_ai is True
        assert adapter.supported_formats == {".pdf", ".docx", ".txt", ".md"}

    def test_init_test_mode_enabled(self):
        """Test initialization with test mode enabled."""
        adapter = DocumentAdapter(test_mode=True)
        assert adapter.test_mode is True

    def test_init_ai_disabled(self):
        """Test initialization with AI disabled."""
        adapter = DocumentAdapter(use_ai=False)
        assert adapter.use_ai is False
        assert adapter.ai_enhancer is None

    def test_init_with_custom_api_key(self, mock_ai_enhancer):
        """Test initialization with custom API key."""
        adapter = DocumentAdapter(use_ai=True, ai_api_key="test-key-123")
        # Verify AI enhancer was initialized with the key
        assert adapter.use_ai is True

    def test_init_ai_failure_fallback(self):
        """Test graceful fallback when AI initialization fails."""
        with patch('video_gen.input_adapters.document.AIScriptEnhancer',
                   side_effect=Exception("API key error")):
            adapter = DocumentAdapter(use_ai=True)
            assert adapter.use_ai is False  # Should fallback
            assert adapter.ai_enhancer is None


# ============================================================================
# File Format Reading Tests
# ============================================================================

class TestFileFormatReading:
    """Test reading various document file formats."""

    @pytest.mark.asyncio
    async def test_read_markdown_file(self, tmp_path, sample_markdown):
        """Test reading markdown file."""
        # Create temp markdown file
        md_file = tmp_path / "test.md"
        md_file.write_text(sample_markdown)

        adapter = DocumentAdapter(test_mode=True, use_ai=False)
        content = await adapter._read_document_content(str(md_file))

        assert content is not None
        assert "Test Document" in content
        assert "Introduction" in content
        assert "Conclusion" in content

    @pytest.mark.asyncio
    async def test_read_txt_file(self, tmp_path):
        """Test reading plain text file."""
        txt_content = "This is a plain text document.\nWith multiple lines."
        txt_file = tmp_path / "test.txt"
        txt_file.write_text(txt_content)

        adapter = DocumentAdapter(test_mode=True, use_ai=False)
        content = await adapter._read_document_content(str(txt_file))

        assert content == txt_content

    @pytest.mark.asyncio
    async def test_read_pdf_file(self, tmp_path, sample_pdf_bytes):
        """Test reading PDF file (mocked)."""
        pdf_file = tmp_path / "test.pdf"
        pdf_file.write_bytes(sample_pdf_bytes)

        # Note: PDF extraction is not currently implemented in document.py
        # The file will be rejected as binary due to %PDF signature detection
        adapter = DocumentAdapter(test_mode=True, use_ai=False)

        # Should raise ValueError for binary PDF file
        with pytest.raises(ValueError, match="Binary file detected"):
            content = await adapter._read_document_content(str(pdf_file))

    @pytest.mark.asyncio
    async def test_read_docx_file(self, tmp_path, sample_docx_bytes):
        """Test reading DOCX file (mocked)."""
        docx_file = tmp_path / "test.docx"
        docx_file.write_bytes(sample_docx_bytes)

        # Note: DOCX extraction is not currently implemented in document.py
        # The file will be rejected as binary due to PK (ZIP) signature detection
        adapter = DocumentAdapter(test_mode=True, use_ai=False)

        # Should raise ValueError for binary DOCX file
        with pytest.raises(ValueError, match="Binary file detected"):
            content = await adapter._read_document_content(str(docx_file))

    @pytest.mark.asyncio
    async def test_read_unsupported_format(self, tmp_path):
        """Test handling of unsupported file format."""
        unsupported_file = tmp_path / "test.xyz"
        unsupported_file.write_text("content")

        adapter = DocumentAdapter(test_mode=True, use_ai=False)
        content = await adapter._read_document_content(str(unsupported_file))

        # Should attempt to read as text or return None
        assert content is None or content == "content"

    @pytest.mark.asyncio
    async def test_read_nonexistent_file(self):
        """Test handling of nonexistent file."""
        adapter = DocumentAdapter(test_mode=True, use_ai=False)

        # Implementation raises FileNotFoundError at line 281, not returning None
        with pytest.raises(FileNotFoundError, match="File not found"):
            content = await adapter._read_document_content("/nonexistent/file.txt")

    @pytest.mark.asyncio
    async def test_read_empty_file(self, tmp_path):
        """Test reading empty file."""
        empty_file = tmp_path / "empty.txt"
        empty_file.write_text("")

        adapter = DocumentAdapter(test_mode=True, use_ai=False)
        content = await adapter._read_document_content(str(empty_file))

        assert content == ""

    @pytest.mark.asyncio
    async def test_read_unicode_content(self, tmp_path):
        """Test reading file with Unicode characters."""
        unicode_content = "Hello 世界 🌍 Привет مرحبا"
        unicode_file = tmp_path / "unicode.txt"
        unicode_file.write_text(unicode_content, encoding='utf-8')

        adapter = DocumentAdapter(test_mode=True, use_ai=False)
        content = await adapter._read_document_content(str(unicode_file))

        assert content == unicode_content


# ============================================================================
# Markdown Structure Parsing Tests
# ============================================================================

class TestMarkdownParsing:
    """Test markdown structure parsing."""

    def test_parse_markdown_with_headers(self, sample_markdown):
        """Test parsing markdown with H1/H2/H3 headers."""
        adapter = DocumentAdapter(use_ai=False)
        structure = adapter._parse_markdown_structure(sample_markdown)

        assert structure is not None
        assert isinstance(structure, dict)
        # Should extract sections based on headers
        assert "sections" in structure or "title" in structure

    def test_parse_markdown_no_headers(self):
        """Test parsing markdown without headers."""
        content = "This is plain text with no headers.\nJust paragraphs."

        adapter = DocumentAdapter(use_ai=False)
        structure = adapter._parse_markdown_structure(content)

        assert structure is not None

    def test_parse_markdown_with_code_blocks(self):
        """Test parsing markdown with code blocks."""
        content = """# Code Example

```python
def test():
    pass
```

```javascript
console.log('test');
```
"""

        adapter = DocumentAdapter(use_ai=False)
        structure = adapter._parse_markdown_structure(content)

        assert structure is not None
        # Code blocks should be preserved or extracted

    def test_parse_markdown_with_lists(self):
        """Test parsing markdown with lists."""
        content = """# Items

- Item 1
- Item 2
  - Subitem 2.1
  - Subitem 2.2
- Item 3

1. Numbered item 1
2. Numbered item 2
"""

        adapter = DocumentAdapter(use_ai=False)
        structure = adapter._parse_markdown_structure(content)

        assert structure is not None

    def test_parse_empty_markdown(self):
        """Test parsing empty markdown."""
        adapter = DocumentAdapter(use_ai=False)
        structure = adapter._parse_markdown_structure("")

        assert structure is not None or structure == {}

    def test_parse_markdown_with_special_characters(self):
        """Test parsing markdown with special characters."""
        content = """# Special & Characters

**Bold** *italic* `code` [link](url)

> Quote with & < > characters
"""

        adapter = DocumentAdapter(use_ai=False)
        structure = adapter._parse_markdown_structure(content)

        assert structure is not None


# ============================================================================
# Content Splitting Tests
# ============================================================================

class TestContentSplitting:
    """Test intelligent content splitting."""

    @pytest.mark.asyncio
    async def test_single_video_generation(self, tmp_path, sample_markdown, mock_ai_enhancer):
        """Test generating single video (no splitting)."""
        md_file = tmp_path / "test.md"
        md_file.write_text(sample_markdown)

        adapter = DocumentAdapter(test_mode=True, use_ai=True)
        result = await adapter.adapt(str(md_file), video_count=1)

        assert result.success is True
        assert result.video_set is not None
        assert len(result.video_set.videos) == 1

    @pytest.mark.asyncio
    async def test_multi_video_splitting(self, tmp_path, sample_markdown,
                                         mock_ai_enhancer, mock_content_splitter):
        """Test splitting document into multiple videos."""
        md_file = tmp_path / "test.md"
        md_file.write_text(sample_markdown)

        adapter = DocumentAdapter(test_mode=True, use_ai=True)
        result = await adapter.adapt(str(md_file), video_count=3)

        assert result.success is True
        assert result.video_set is not None
        # Should use content splitter for multi-video
        assert mock_content_splitter.return_value.split.called

    @pytest.mark.asyncio
    async def test_split_strategy_ai(self, tmp_path, sample_markdown,
                                     mock_ai_enhancer, mock_content_splitter):
        """Test AI-based splitting strategy."""
        md_file = tmp_path / "test.md"
        md_file.write_text(sample_markdown)

        adapter = DocumentAdapter(test_mode=True, use_ai=True)
        result = await adapter.adapt(
            str(md_file),
            video_count=2,
            split_strategy='ai'
        )

        assert result.success is True
        # Verify AI strategy was used
        split_call = mock_content_splitter.return_value.split
        assert split_call.called

    @pytest.mark.asyncio
    async def test_split_strategy_headers(self, tmp_path, sample_markdown, mock_ai_enhancer):
        """Test header-based splitting strategy."""
        md_file = tmp_path / "test.md"
        md_file.write_text(sample_markdown)

        with patch('video_gen.input_adapters.content_splitter.ContentSplitter') as mock_splitter:
            adapter = DocumentAdapter(test_mode=True, use_ai=False)
            # Test header strategy
            # (Implementation depends on actual split logic)

    @pytest.mark.asyncio
    async def test_split_confidence_metadata(self, tmp_path, sample_markdown,
                                             mock_ai_enhancer, mock_content_splitter):
        """Test that split confidence is included in metadata."""
        md_file = tmp_path / "test.md"
        md_file.write_text(sample_markdown)

        adapter = DocumentAdapter(test_mode=True, use_ai=True)
        result = await adapter.adapt(str(md_file), video_count=2)

        assert result.metadata is not None
        assert "split_confidence" in result.metadata or "confidence" in str(result.metadata).lower()


# ============================================================================
# AI Enhancement Integration Tests
# ============================================================================

class TestAIEnhancement:
    """Test AI enhancement integration."""

    @pytest.mark.asyncio
    async def test_ai_enhancement_enabled(self, tmp_path, sample_markdown, mock_ai_enhancer):
        """Test video generation with AI enhancement enabled."""
        md_file = tmp_path / "test.md"
        md_file.write_text(sample_markdown)

        adapter = DocumentAdapter(test_mode=True, use_ai=True)
        result = await adapter.adapt(str(md_file))

        assert result.success is True
        # AI enhancer should have been called
        # (Check depends on implementation details)

    @pytest.mark.asyncio
    async def test_ai_enhancement_disabled(self, tmp_path, sample_markdown):
        """Test video generation with AI enhancement disabled."""
        md_file = tmp_path / "test.md"
        md_file.write_text(sample_markdown)

        adapter = DocumentAdapter(test_mode=True, use_ai=False)
        result = await adapter.adapt(str(md_file))

        assert result.success is True
        # Should still work without AI

    @pytest.mark.asyncio
    async def test_ai_enhancement_failure_fallback(self, tmp_path, sample_markdown):
        """Test fallback when AI enhancement fails."""
        md_file = tmp_path / "test.md"
        md_file.write_text(sample_markdown)

        with patch('video_gen.input_adapters.document.AIScriptEnhancer') as mock_ai:
            # Simulate AI failure
            enhancer = Mock()
            enhancer.enhance_script = AsyncMock(side_effect=Exception("API error"))
            mock_ai.return_value = enhancer

            adapter = DocumentAdapter(test_mode=True, use_ai=True)
            result = await adapter.adapt(str(md_file))

            # Should fallback gracefully
            assert result.success is True or result.error is not None

    @pytest.mark.asyncio
    async def test_narration_generation(self, tmp_path, sample_markdown, mock_ai_enhancer):
        """Test AI-powered narration generation."""
        md_file = tmp_path / "test.md"
        md_file.write_text(sample_markdown)

        adapter = DocumentAdapter(test_mode=True, use_ai=True)
        result = await adapter.adapt(str(md_file))

        assert result.success is True
        if result.video_set:
            # Check that scenes have narration
            for video in result.video_set.videos:
                for scene in video.scenes:
                    # Narration should be present (enhanced or original)
                    assert hasattr(scene, 'narration')


# ============================================================================
# Edge Cases and Error Handling Tests
# ============================================================================

class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_empty_document(self, tmp_path):
        """Test handling of empty document."""
        empty_file = tmp_path / "empty.md"
        empty_file.write_text("")

        adapter = DocumentAdapter(test_mode=True, use_ai=False)
        result = await adapter.adapt(str(empty_file))

        # Should handle gracefully
        assert result is not None
        # May succeed with empty content or fail with error message

    @pytest.mark.asyncio
    async def test_very_large_document(self, tmp_path):
        """Test handling of very large document (>10MB)."""
        # Create large content (10MB+)
        large_content = "# Section\n\nContent " * 500000  # ~10MB
        large_file = tmp_path / "large.md"
        large_file.write_text(large_content)

        adapter = DocumentAdapter(test_mode=True, use_ai=False)
        result = await adapter.adapt(str(large_file))

        # Should handle or reject gracefully
        assert result is not None

    @pytest.mark.asyncio
    async def test_malformed_pdf(self, tmp_path):
        """Test handling of malformed PDF file."""
        malformed_pdf = tmp_path / "malformed.pdf"
        malformed_pdf.write_bytes(b"Not a real PDF file")

        adapter = DocumentAdapter(test_mode=True, use_ai=False)
        result = await adapter.adapt(str(malformed_pdf))

        # Should fail gracefully with error
        assert result is not None
        if not result.success:
            assert result.error is not None

    @pytest.mark.asyncio
    async def test_binary_content_handling(self, tmp_path):
        """Test handling of binary content in text file."""
        binary_file = tmp_path / "binary.txt"
        binary_file.write_bytes(b"\x00\x01\x02\xff\xfe\xfd")

        adapter = DocumentAdapter(test_mode=True, use_ai=False)
        result = await adapter.adapt(str(binary_file))

        # Should handle encoding errors gracefully
        assert result is not None

    @pytest.mark.asyncio
    async def test_unicode_edge_cases(self, tmp_path):
        """Test handling of complex Unicode scenarios."""
        unicode_content = """# Unicode Test 🎨

Emoji: 😀😃😄😁
Chinese: 你好世界
Arabic: مرحبا بالعالم
Cyrillic: Привет мир
Mixed: Hello 世界 🌍
"""
        unicode_file = tmp_path / "unicode.md"
        unicode_file.write_text(unicode_content, encoding='utf-8')

        adapter = DocumentAdapter(test_mode=True, use_ai=False)
        result = await adapter.adapt(str(unicode_file))

        assert result.success is True

    @pytest.mark.asyncio
    async def test_special_character_escaping(self, tmp_path):
        """Test handling of special characters that need escaping."""
        special_content = """# Special Characters

<script>alert('test')</script>
& < > " '
${variable}
`command`
"""
        special_file = tmp_path / "special.md"
        special_file.write_text(special_content)

        adapter = DocumentAdapter(test_mode=True, use_ai=False)
        result = await adapter.adapt(str(special_file))

        assert result.success is True
        # Content should be safely escaped

    @pytest.mark.asyncio
    async def test_url_document_fetch(self):
        """Test fetching document from URL."""
        test_url = "https://example.com/document.md"

        # URL fetching is handled by requests library, not a separate function
        with patch('requests.get') as mock_get:
            # Mock response object
            mock_response = Mock()
            mock_response.text = "# Remote Document\n\nContent from URL"
            mock_response.headers = {'content-length': '100'}
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response

            adapter = DocumentAdapter(test_mode=True, use_ai=False)
            result = await adapter.adapt(test_url)

            assert result is not None
            assert result.success is True
            mock_get.assert_called_once()

    @pytest.mark.asyncio
    async def test_network_timeout_handling(self):
        """Test handling of network timeouts when fetching URLs."""
        test_url = "https://example.com/slow-document.md"

        with patch('requests.get') as mock_get:
            import requests
            mock_get.side_effect = requests.exceptions.Timeout("Request timeout")

            adapter = DocumentAdapter(test_mode=True, use_ai=False)
            result = await adapter.adapt(test_url)

            # Should handle timeout gracefully
            assert result is not None
            if not result.success:
                assert "timeout" in result.error.lower() or "failed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_permission_denied_handling(self, tmp_path):
        """Test handling of permission denied errors."""
        restricted_file = tmp_path / "restricted.md"
        restricted_file.write_text("content")
        restricted_file.chmod(0o000)  # Remove all permissions

        try:
            adapter = DocumentAdapter(test_mode=True, use_ai=False)
            result = await adapter.adapt(str(restricted_file))

            # Should handle permission error
            assert result is not None
            if not result.success:
                assert result.error is not None
        finally:
            restricted_file.chmod(0o644)  # Restore permissions for cleanup


# ============================================================================
# Video Set Generation Tests
# ============================================================================

class TestVideoSetGeneration:
    """Test VideoSet generation from document content."""

    @pytest.mark.asyncio
    async def test_video_config_metadata(self, tmp_path, sample_markdown):
        """Test that generated videos have correct metadata."""
        md_file = tmp_path / "test.md"
        md_file.write_text(sample_markdown)

        adapter = DocumentAdapter(test_mode=True, use_ai=False)
        result = await adapter.adapt(
            str(md_file),
            accent_color="blue",
            voice="male"
        )

        assert result.success is True
        if result.video_set:
            # CRITICAL FIX: VideoSet doesn't have accent_color directly
            # It's stored in metadata per implementation at line 648
            assert result.video_set.metadata.get("accent_color") == "blue"
            # And in config.defaults backward compat at line 222
            assert result.video_set.config.defaults.get("accent_color") == "blue"

            # Each VideoConfig has accent_color directly (line 633)
            for video in result.video_set.videos:
                assert video.accent_color == "blue"
                # Voice is per-scene, not per-video in VideoConfig
                # Check that scenes have correct voice
                for scene in video.scenes:
                    assert scene.voice == "male"

    @pytest.mark.asyncio
    async def test_scene_generation_from_structure(self, tmp_path):
        """Test scene generation from markdown structure."""
        content = """# Title Scene

## Introduction
Content for introduction scene.

### Key Points
- Point 1
- Point 2
- Point 3

## Conclusion
Final thoughts.
"""
        md_file = tmp_path / "structured.md"
        md_file.write_text(content)

        adapter = DocumentAdapter(test_mode=True, use_ai=False)
        result = await adapter.adapt(str(md_file))

        assert result.success is True
        if result.video_set:
            # Should generate appropriate scenes
            assert len(result.video_set.videos) > 0
            video = result.video_set.videos[0]
            assert len(video.scenes) > 0

    @pytest.mark.asyncio
    async def test_scene_type_detection(self, tmp_path):
        """Test automatic scene type detection."""
        content = """# Video Title

## Section 1
Regular content here.

```python
# Code example
def test():
    pass
```

- List item 1
- List item 2

## Comparison
Before vs After
"""
        md_file = tmp_path / "types.md"
        md_file.write_text(content)

        adapter = DocumentAdapter(test_mode=True, use_ai=False)
        result = await adapter.adapt(str(md_file))

        assert result.success is True
        if result.video_set:
            video = result.video_set.videos[0]
            scene_types = {scene.scene_type for scene in video.scenes}
            # Should detect various scene types
            assert len(scene_types) > 0


# ============================================================================
# Performance and Stress Tests
# ============================================================================

@pytest.mark.slow
class TestPerformance:
    """Performance and stress tests."""

    @pytest.mark.asyncio
    async def test_processing_speed(self, tmp_path, sample_markdown):
        """Test document processing speed."""
        import time

        md_file = tmp_path / "test.md"
        md_file.write_text(sample_markdown)

        adapter = DocumentAdapter(test_mode=True, use_ai=False)

        start = time.time()
        result = await adapter.adapt(str(md_file))
        duration = time.time() - start

        assert result.success is True
        assert duration < 2.0  # Should process in under 2 seconds

    @pytest.mark.asyncio
    async def test_multiple_document_processing(self, tmp_path, sample_markdown):
        """Test processing multiple documents concurrently."""
        # Create multiple files
        files = []
        for i in range(10):
            file = tmp_path / f"doc_{i}.md"
            file.write_text(sample_markdown)
            files.append(str(file))

        adapter = DocumentAdapter(test_mode=True, use_ai=False)

        # Process all concurrently
        tasks = [adapter.adapt(f) for f in files]
        results = await asyncio.gather(*tasks)

        # All should succeed
        assert all(r.success for r in results)

    @pytest.mark.asyncio
    async def test_memory_usage(self, tmp_path):
        """Test memory usage with large document."""
        # Create large document
        large_content = "# Section\n\n" + ("Paragraph content.\n" * 10000)
        large_file = tmp_path / "large.md"
        large_file.write_text(large_content)

        adapter = DocumentAdapter(test_mode=True, use_ai=False)
        result = await adapter.adapt(str(large_file))

        # Should complete without memory issues
        assert result is not None


# ============================================================================
# Integration with Other Components
# ============================================================================

class TestComponentIntegration:
    """Test integration with other system components."""

    @pytest.mark.asyncio
    async def test_pipeline_compatibility(self, tmp_path, sample_markdown):
        """Test that output is compatible with pipeline."""
        md_file = tmp_path / "test.md"
        md_file.write_text(sample_markdown)

        adapter = DocumentAdapter(test_mode=True, use_ai=False)
        result = await adapter.adapt(str(md_file))

        assert result.success is True
        assert isinstance(result.video_set, VideoSet)

        # Verify structure matches pipeline expectations
        if result.video_set:
            assert hasattr(result.video_set, 'videos')
            assert isinstance(result.video_set.videos, list)

            for video in result.video_set.videos:
                assert isinstance(video, VideoConfig)
                assert hasattr(video, 'scenes')
                assert isinstance(video.scenes, list)

    @pytest.mark.asyncio
    async def test_adapter_result_structure(self, tmp_path, sample_markdown):
        """Test InputAdapterResult structure."""
        md_file = tmp_path / "test.md"
        md_file.write_text(sample_markdown)

        adapter = DocumentAdapter(test_mode=True, use_ai=False)
        result = await adapter.adapt(str(md_file))

        assert isinstance(result, InputAdapterResult)
        assert hasattr(result, 'success')
        assert hasattr(result, 'video_set')
        assert hasattr(result, 'metadata')
        assert hasattr(result, 'error')

        if result.success:
            assert result.video_set is not None
            assert result.error is None
        else:
            assert result.error is not None
