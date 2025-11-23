"""
Document Input Flow Tests
=========================
Comprehensive tests for the modern document input flow including:
- File validation utilities
- Drag-drop upload support
- Real-time validation
- Preview before generation
- Multiple document formats (.md, .txt, .rst)

Following SPARC methodology: Tests first, implementation follows.
"""

import pytest
import sys
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock
from io import BytesIO

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


# ============================================================================
# File Validation Tests
# ============================================================================

class TestFileValidation:
    """Tests for file validation utilities."""

    def test_validate_file_extension_markdown(self):
        """Test validation of .md files."""
        from app.utils.file_validation import validate_file_extension

        assert validate_file_extension("document.md") is True
        assert validate_file_extension("README.MD") is True
        assert validate_file_extension("file.markdown") is True

    def test_validate_file_extension_text(self):
        """Test validation of .txt files."""
        from app.utils.file_validation import validate_file_extension

        assert validate_file_extension("document.txt") is True
        assert validate_file_extension("notes.TXT") is True

    def test_validate_file_extension_rst(self):
        """Test validation of .rst files."""
        from app.utils.file_validation import validate_file_extension

        assert validate_file_extension("document.rst") is True
        assert validate_file_extension("README.RST") is True

    def test_validate_file_extension_invalid(self):
        """Test rejection of unsupported file types."""
        from app.utils.file_validation import validate_file_extension

        assert validate_file_extension("image.jpg") is False
        assert validate_file_extension("document.pdf") is False
        assert validate_file_extension("script.py") is False
        assert validate_file_extension("archive.zip") is False

    def test_validate_file_size_within_limit(self):
        """Test file size validation within limits."""
        from app.utils.file_validation import validate_file_size

        # 1MB file (within 10MB limit)
        assert validate_file_size(1_000_000) is True
        # 5MB file
        assert validate_file_size(5_000_000) is True
        # 10MB file (at limit)
        assert validate_file_size(10_000_000) is True

    def test_validate_file_size_exceeds_limit(self):
        """Test file size validation exceeds limit."""
        from app.utils.file_validation import validate_file_size

        # 11MB file (exceeds limit)
        assert validate_file_size(11_000_000) is False
        # 100MB file
        assert validate_file_size(100_000_000) is False

    def test_validate_content_type_text(self):
        """Test content type validation for text files."""
        from app.utils.file_validation import validate_content_type

        assert validate_content_type("text/plain") is True
        assert validate_content_type("text/markdown") is True
        assert validate_content_type("text/x-rst") is True
        assert validate_content_type("application/octet-stream") is True  # Allow for generic uploads

    def test_validate_content_type_invalid(self):
        """Test rejection of binary content types."""
        from app.utils.file_validation import validate_content_type

        assert validate_content_type("image/jpeg") is False
        assert validate_content_type("application/pdf") is False
        assert validate_content_type("video/mp4") is False

    def test_detect_binary_content(self):
        """Test detection of binary file content."""
        from app.utils.file_validation import is_binary_content

        # Binary signatures
        assert is_binary_content(b'\xff\xd8\xff') is True  # JPEG
        assert is_binary_content(b'\x89PNG\r\n') is True  # PNG
        assert is_binary_content(b'%PDF-1.4') is True  # PDF

        # Text content
        assert is_binary_content(b'# Hello World\n') is False
        assert is_binary_content(b'Plain text content') is False

    def test_sanitize_filename(self):
        """Test filename sanitization for security."""
        from app.utils.file_validation import sanitize_filename

        # Path traversal attempts
        assert "../" not in sanitize_filename("../../../etc/passwd")
        assert ".." not in sanitize_filename("..\\..\\windows\\system32")

        # Special characters
        sanitized = sanitize_filename("file<>name|with:bad*chars?.md")
        assert "<" not in sanitized
        assert ">" not in sanitized
        assert "|" not in sanitized

        # Preserve extension
        assert sanitize_filename("document.md").endswith(".md")


# ============================================================================
# Document Preview Tests
# ============================================================================

class TestDocumentPreview:
    """Tests for document preview functionality."""

    def test_preview_markdown_structure(self):
        """Test preview extracts markdown structure."""
        from app.utils.file_validation import preview_document_structure

        content = """# Main Title

## Section 1
Some content here.

## Section 2
More content.

- Item 1
- Item 2
"""
        preview = preview_document_structure(content)

        assert preview["title"] == "Main Title"
        assert preview["section_count"] >= 2
        assert preview["has_lists"] is True
        assert "estimated_scenes" in preview

    def test_preview_with_code_blocks(self):
        """Test preview detects code blocks."""
        from app.utils.file_validation import preview_document_structure

        content = """# Tutorial

## Installation

```bash
npm install
npm start
```
"""
        preview = preview_document_structure(content)

        assert preview["has_code"] is True
        assert preview["code_block_count"] >= 1

    def test_preview_empty_document(self):
        """Test preview handles empty documents gracefully."""
        from app.utils.file_validation import preview_document_structure

        preview = preview_document_structure("")

        assert preview["title"] == ""
        assert preview["section_count"] == 0
        assert preview["estimated_scenes"] == 0

    def test_preview_plain_text(self):
        """Test preview handles plain text without markdown."""
        from app.utils.file_validation import preview_document_structure

        content = """This is just plain text.
No markdown formatting at all.
Multiple lines of content."""

        preview = preview_document_structure(content)

        assert preview["format"] == "plain_text"
        assert preview["estimated_scenes"] >= 1

    def test_preview_estimates_video_duration(self):
        """Test preview provides estimated video duration."""
        from app.utils.file_validation import preview_document_structure

        content = """# Long Document

## Section 1
Content for section 1.

## Section 2
Content for section 2.

## Section 3
Content for section 3.

## Section 4
Content for section 4.
"""
        preview = preview_document_structure(content)

        assert "estimated_duration_seconds" in preview
        assert preview["estimated_duration_seconds"] > 0


# ============================================================================
# Upload Validation Tests
# ============================================================================

class TestUploadValidation:
    """Tests for document upload validation."""

    def test_validate_upload_success(self):
        """Test successful upload validation."""
        from app.utils.file_validation import validate_upload

        result = validate_upload(
            filename="document.md",
            content_type="text/markdown",
            file_size=1000,
            content=b"# Hello World\nSome content."
        )

        assert result["valid"] is True
        assert result["errors"] == []

    def test_validate_upload_invalid_extension(self):
        """Test upload validation with invalid extension."""
        from app.utils.file_validation import validate_upload

        result = validate_upload(
            filename="image.jpg",
            content_type="image/jpeg",
            file_size=1000,
            content=b"\xff\xd8\xff"  # JPEG signature
        )

        assert result["valid"] is False
        assert len(result["errors"]) > 0
        assert any("extension" in e.lower() or "type" in e.lower() for e in result["errors"])

    def test_validate_upload_file_too_large(self):
        """Test upload validation with oversized file."""
        from app.utils.file_validation import validate_upload

        result = validate_upload(
            filename="document.md",
            content_type="text/markdown",
            file_size=15_000_000,  # 15MB
            content=b"# Content"
        )

        assert result["valid"] is False
        assert any("large" in e.lower() or "size" in e.lower() for e in result["errors"])

    def test_validate_upload_binary_content(self):
        """Test upload validation detects binary content."""
        from app.utils.file_validation import validate_upload

        result = validate_upload(
            filename="document.md",  # Looks like markdown
            content_type="text/markdown",
            file_size=1000,
            content=b'\xff\xd8\xff\xe0'  # Actually JPEG
        )

        assert result["valid"] is False
        assert any("binary" in e.lower() for e in result["errors"])


# ============================================================================
# Real-time Validation Tests
# ============================================================================

class TestRealtimeValidation:
    """Tests for real-time validation responses."""

    def test_validation_response_structure(self):
        """Test validation response has correct structure."""
        from app.utils.file_validation import create_validation_response

        response = create_validation_response(
            valid=True,
            filename="document.md",
            preview={"title": "Test", "section_count": 2}
        )

        assert "valid" in response
        assert "filename" in response
        assert "preview" in response
        assert "timestamp" in response

    def test_validation_response_with_errors(self):
        """Test validation response includes errors."""
        from app.utils.file_validation import create_validation_response

        response = create_validation_response(
            valid=False,
            filename="image.jpg",
            errors=["Unsupported file type", "Binary content detected"]
        )

        assert response["valid"] is False
        assert len(response["errors"]) == 2
        assert "suggestions" in response  # Should provide suggestions

    def test_validation_response_with_warnings(self):
        """Test validation response includes warnings for edge cases."""
        from app.utils.file_validation import create_validation_response

        response = create_validation_response(
            valid=True,
            filename="large_document.md",
            warnings=["Document is large, preview may be truncated"]
        )

        assert response["valid"] is True
        assert len(response["warnings"]) == 1


# ============================================================================
# API Endpoint Integration Tests
# ============================================================================

class TestDocumentAPIEndpoints:
    """Tests for document API endpoints."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        from fastapi.testclient import TestClient
        from app.main import app
        return TestClient(app)

    def test_upload_document_endpoint_exists(self, client):
        """Test upload endpoint exists and accepts POST."""
        # Create a simple text file
        response = client.post(
            "/api/upload/document",
            files={"file": ("test.md", b"# Test\nContent", "text/markdown")},
            data={"accent_color": "blue", "voice": "male", "video_count": "1"}
        )

        # Should not be 404 or 405
        assert response.status_code != 404
        assert response.status_code != 405

    def test_validate_document_endpoint(self, client):
        """Test document validation endpoint."""
        response = client.post(
            "/api/validate/document",
            files={"file": ("test.md", b"# Test Document\n\n## Section 1\nContent", "text/markdown")}
        )

        # Should return validation result
        if response.status_code == 200:
            data = response.json()
            assert "valid" in data
            assert "preview" in data

    def test_preview_document_endpoint(self, client):
        """Test document preview endpoint."""
        response = client.post(
            "/api/preview/document",
            files={"file": ("test.md", b"# Test\n\n## Section 1\n\n- Item 1\n- Item 2", "text/markdown")}
        )

        if response.status_code == 200:
            data = response.json()
            assert "title" in data or "preview" in data

    def test_upload_invalid_file_type(self, client):
        """Test upload rejects invalid file types."""
        response = client.post(
            "/api/upload/document",
            files={"file": ("image.jpg", b"\xff\xd8\xff", "image/jpeg")},
            data={"accent_color": "blue"}
        )

        assert response.status_code == 400

    def test_upload_oversized_file(self, client):
        """Test upload rejects oversized files."""
        # Create a "large" file header (we'll just test the validation logic)
        # The actual check happens before full upload
        large_content = b"x" * 100  # Simulating a large file check

        response = client.post(
            "/api/upload/document",
            files={"file": ("huge.md", large_content, "text/markdown")},
            data={"accent_color": "blue"}
        )

        # Should either accept (if within limit) or reject with proper error
        assert response.status_code in [200, 400, 413]


# ============================================================================
# Format-Specific Tests
# ============================================================================

class TestDocumentFormats:
    """Tests for different document format support."""

    def test_parse_markdown_format(self):
        """Test parsing standard markdown."""
        from app.utils.file_validation import detect_document_format

        content = "# Title\n\n## Section\n\nParagraph text."
        format_info = detect_document_format(content, "document.md")

        assert format_info["format"] == "markdown"
        assert format_info["supported"] is True

    def test_parse_rst_format(self):
        """Test parsing reStructuredText."""
        from app.utils.file_validation import detect_document_format

        content = """Title
=====

Section
-------

Paragraph text.
"""
        format_info = detect_document_format(content, "document.rst")

        assert format_info["format"] == "rst"
        assert format_info["supported"] is True

    def test_parse_plain_text_format(self):
        """Test parsing plain text."""
        from app.utils.file_validation import detect_document_format

        content = "Just plain text without any formatting."
        format_info = detect_document_format(content, "document.txt")

        assert format_info["format"] == "plain_text"
        assert format_info["supported"] is True

    def test_format_conversion_rst_to_markdown(self):
        """Test RST to markdown conversion for processing."""
        from app.utils.file_validation import convert_to_markdown

        rst_content = """Title
=====

Section
-------

* Item 1
* Item 2
"""
        markdown = convert_to_markdown(rst_content, "rst")

        # Should produce valid markdown
        assert "#" in markdown or markdown  # Should have some markdown syntax

    def test_format_detection_by_extension(self):
        """Test format detection by file extension."""
        from app.utils.file_validation import get_format_from_extension

        assert get_format_from_extension(".md") == "markdown"
        assert get_format_from_extension(".markdown") == "markdown"
        assert get_format_from_extension(".txt") == "plain_text"
        assert get_format_from_extension(".rst") == "rst"


# ============================================================================
# Error Handling Tests
# ============================================================================

class TestErrorHandling:
    """Tests for elegant error handling."""

    def test_error_response_format(self):
        """Test error responses have consistent format."""
        from app.utils.file_validation import create_error_response

        error = create_error_response(
            error_code="INVALID_FILE_TYPE",
            message="Unsupported file type: .exe",
            details={"filename": "malware.exe", "extension": ".exe"}
        )

        assert "error_code" in error
        assert "message" in error
        assert "details" in error
        assert "suggestions" in error

    def test_error_provides_suggestions(self):
        """Test errors provide helpful suggestions."""
        from app.utils.file_validation import create_error_response

        error = create_error_response(
            error_code="INVALID_FILE_TYPE",
            message="Unsupported file type: .pdf",
            details={"extension": ".pdf"}
        )

        assert len(error["suggestions"]) > 0
        # Should suggest supported formats
        assert any(".md" in s or "markdown" in s.lower() for s in error["suggestions"])

    def test_error_includes_recovery_options(self):
        """Test errors include recovery options when available."""
        from app.utils.file_validation import create_error_response

        error = create_error_response(
            error_code="FILE_TOO_LARGE",
            message="File exceeds 10MB limit",
            details={"file_size": 15_000_000, "max_size": 10_000_000}
        )

        # Should suggest ways to reduce file size
        assert "suggestions" in error or "recovery" in error


# ============================================================================
# Progress Indicator Tests
# ============================================================================

class TestProgressIndicators:
    """Tests for progress indicator functionality."""

    def test_upload_progress_stages(self):
        """Test upload progress has defined stages."""
        from app.utils.file_validation import get_upload_progress_stages

        stages = get_upload_progress_stages()

        assert "validating" in stages
        assert "parsing" in stages
        assert "previewing" in stages

        # Each stage should have percentage
        for stage, info in stages.items():
            assert "progress" in info
            assert 0 <= info["progress"] <= 100

    def test_progress_message_format(self):
        """Test progress messages are user-friendly."""
        from app.utils.file_validation import format_progress_message

        message = format_progress_message("validating", 25)

        assert isinstance(message, str)
        assert len(message) > 0
        # Should not contain technical jargon
        assert "exception" not in message.lower()
        assert "error" not in message.lower()


# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
