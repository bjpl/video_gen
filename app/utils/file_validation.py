"""
File Validation Utilities
=========================
Modern, elegant file validation utilities for document input flow.

Features:
- File extension validation
- File size validation
- Content type validation
- Binary content detection
- Filename sanitization
- Document preview/structure extraction
- Format detection and conversion
- Progress indicators
- Elegant error handling with suggestions
"""

import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

# ============================================================================
# Constants
# ============================================================================

# Supported file extensions
SUPPORTED_EXTENSIONS = {'.md', '.markdown', '.txt', '.rst'}

# Maximum file size (10MB)
MAX_FILE_SIZE = 10_000_000

# Allowed content types
ALLOWED_CONTENT_TYPES = {
    'text/plain',
    'text/markdown',
    'text/x-markdown',
    'text/x-rst',
    'text/restructuredtext',
    'application/octet-stream',  # Generic - we check content separately
}

# Binary file signatures
BINARY_SIGNATURES = [
    (b'\xff\xd8\xff', 'JPEG image'),
    (b'\x89PNG', 'PNG image'),
    (b'GIF8', 'GIF image'),
    (b'%PDF', 'PDF document'),
    (b'PK\x03\x04', 'ZIP archive'),
    (b'\x00\x00\x00', 'Binary file'),
    (b'RIFF', 'RIFF container'),
    (b'ID3', 'MP3 audio'),
    (b'\xff\xfb', 'MP3 audio'),
    (b'OggS', 'OGG audio'),
]

# Characters not allowed in filenames
UNSAFE_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
PATH_TRAVERSAL_PATTERN = re.compile(r'\.\.[\\/]|[\\/]\.\.')


# ============================================================================
# File Extension Validation
# ============================================================================

def validate_file_extension(filename: str) -> bool:
    """
    Validate that a file has a supported extension.

    Args:
        filename: Name of the file to validate

    Returns:
        True if extension is supported, False otherwise
    """
    if not filename:
        return False

    ext = Path(filename).suffix.lower()
    return ext in SUPPORTED_EXTENSIONS


def get_format_from_extension(extension: str) -> str:
    """
    Get document format from file extension.

    Args:
        extension: File extension (with or without dot)

    Returns:
        Format string: 'markdown', 'plain_text', 'rst', or 'unknown'
    """
    ext = extension.lower()
    if not ext.startswith('.'):
        ext = '.' + ext

    format_map = {
        '.md': 'markdown',
        '.markdown': 'markdown',
        '.txt': 'plain_text',
        '.rst': 'rst',
    }

    return format_map.get(ext, 'unknown')


# ============================================================================
# File Size Validation
# ============================================================================

def validate_file_size(size: int, max_size: int = MAX_FILE_SIZE) -> bool:
    """
    Validate that a file is within size limits.

    Args:
        size: File size in bytes
        max_size: Maximum allowed size (default 10MB)

    Returns:
        True if size is within limit, False otherwise
    """
    return 0 <= size <= max_size


# ============================================================================
# Content Type Validation
# ============================================================================

def validate_content_type(content_type: str) -> bool:
    """
    Validate content type is allowed.

    Args:
        content_type: MIME type string

    Returns:
        True if content type is allowed, False otherwise
    """
    if not content_type:
        return False

    # Normalize content type (remove charset, etc.)
    ct = content_type.lower().split(';')[0].strip()

    return ct in ALLOWED_CONTENT_TYPES


# ============================================================================
# Binary Content Detection
# ============================================================================

def is_binary_content(content: bytes) -> bool:
    """
    Detect if content is binary (not text).

    Args:
        content: File content as bytes

    Returns:
        True if binary content detected, False otherwise
    """
    if not content:
        return False

    # Check first 16 bytes for binary signatures
    header = content[:16]

    for signature, _ in BINARY_SIGNATURES:
        if header.startswith(signature):
            return True

    # Check for null bytes (common in binary files)
    if b'\x00' in content[:1024]:
        return True

    return False


# ============================================================================
# Filename Sanitization
# ============================================================================

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for security.

    Removes:
    - Path traversal attempts (../)
    - Unsafe characters
    - Leading/trailing whitespace

    Args:
        filename: Original filename

    Returns:
        Sanitized filename safe for file system use
    """
    if not filename:
        return "unnamed_document"

    # Remove path traversal attempts
    clean = PATH_TRAVERSAL_PATTERN.sub('', filename)

    # Remove unsafe characters
    clean = UNSAFE_FILENAME_CHARS.sub('_', clean)

    # Remove leading/trailing whitespace and dots
    clean = clean.strip().strip('.')

    # Ensure we have a valid filename
    if not clean:
        return "unnamed_document"

    # Preserve extension
    original_ext = Path(filename).suffix.lower()
    if original_ext in SUPPORTED_EXTENSIONS:
        if not clean.lower().endswith(original_ext):
            clean = Path(clean).stem + original_ext

    return clean


# ============================================================================
# Document Preview / Structure Extraction
# ============================================================================

def preview_document_structure(content: str) -> Dict[str, Any]:
    """
    Extract document structure for preview.

    Analyzes markdown content and returns:
    - Title
    - Section count
    - List detection
    - Code block detection
    - Estimated scenes
    - Estimated duration

    Args:
        content: Document content as string

    Returns:
        Dictionary with preview information
    """
    if not content or not content.strip():
        return {
            "title": "",
            "section_count": 0,
            "has_lists": False,
            "has_code": False,
            "code_block_count": 0,
            "estimated_scenes": 0,
            "estimated_duration_seconds": 0,
            "format": "empty",
            "word_count": 0,
        }

    lines = content.split('\n')

    # Extract title (first H1)
    title = ""
    for line in lines:
        if line.startswith('# '):
            title = line[2:].strip()
            break

    # Count sections (H2 headings)
    section_count = sum(1 for line in lines if line.startswith('## '))

    # Detect lists
    has_lists = any(
        re.match(r'^\s*[-*+]\s+', line) or re.match(r'^\s*\d+\.\s+', line)
        for line in lines
    )

    # Count code blocks
    code_block_count = content.count('```') // 2
    has_code = code_block_count > 0

    # Word count
    word_count = len(content.split())

    # Determine format
    if '# ' in content or '## ' in content or has_lists or has_code:
        doc_format = "markdown"
    elif re.search(r'^[=\-]{3,}$', content, re.MULTILINE):
        doc_format = "rst"
    else:
        doc_format = "plain_text"

    # Estimate scenes (title + sections + outro, or at least 2)
    estimated_scenes = max(2, 1 + section_count + 1)  # title + sections + outro

    # Estimate duration (roughly 5-8 seconds per scene)
    estimated_duration_seconds = estimated_scenes * 6

    return {
        "title": title,
        "section_count": section_count,
        "has_lists": has_lists,
        "has_code": has_code,
        "code_block_count": code_block_count,
        "estimated_scenes": estimated_scenes,
        "estimated_duration_seconds": estimated_duration_seconds,
        "format": doc_format,
        "word_count": word_count,
    }


# ============================================================================
# Document Format Detection
# ============================================================================

def detect_document_format(content: str, filename: str) -> Dict[str, Any]:
    """
    Detect document format from content and filename.

    Args:
        content: Document content
        filename: File name

    Returns:
        Dictionary with format information
    """
    ext = Path(filename).suffix.lower()

    # Get format from extension
    format_from_ext = get_format_from_extension(ext)

    # Detect format from content
    content_indicators = {
        "markdown": content.count('# ') + content.count('```') + content.count('- '),
        "rst": len(re.findall(r'^[=\-~]{3,}$', content, re.MULTILINE)),
        "plain_text": 0,  # Default
    }

    # Determine most likely format
    if format_from_ext != 'unknown':
        detected_format = format_from_ext
    elif content_indicators["rst"] > 2:
        detected_format = "rst"
    elif content_indicators["markdown"] > 3:
        detected_format = "markdown"
    else:
        detected_format = "plain_text"

    return {
        "format": detected_format,
        "supported": True,
        "extension": ext,
        "confidence": "high" if format_from_ext != 'unknown' else "medium",
    }


def convert_to_markdown(content: str, source_format: str) -> str:
    """
    Convert document content to markdown for processing.

    Args:
        content: Source content
        source_format: Source format ('rst', 'plain_text', 'markdown')

    Returns:
        Content converted to markdown
    """
    if source_format == "markdown":
        return content

    if source_format == "rst":
        # Basic RST to Markdown conversion
        lines = content.split('\n')
        result = []
        i = 0

        while i < len(lines):
            line = lines[i]

            # Convert RST headings (underlined with =, -, ~)
            if i + 1 < len(lines) and re.match(r'^[=]+$', lines[i + 1]):
                result.append(f"# {line}")
                i += 2
                continue
            elif i + 1 < len(lines) and re.match(r'^[-]+$', lines[i + 1]):
                result.append(f"## {line}")
                i += 2
                continue
            elif i + 1 < len(lines) and re.match(r'^[~]+$', lines[i + 1]):
                result.append(f"### {line}")
                i += 2
                continue

            # Convert RST bullet lists
            if re.match(r'^\* ', line):
                line = re.sub(r'^\* ', '- ', line)

            result.append(line)
            i += 1

        return '\n'.join(result)

    if source_format == "plain_text":
        # Convert plain text to basic markdown
        paragraphs = content.split('\n\n')
        if paragraphs:
            # First paragraph becomes title
            result = [f"# Document\n"]
            for i, para in enumerate(paragraphs):
                if para.strip():
                    result.append(para.strip())
                    result.append("")
            return '\n'.join(result)
        return f"# Document\n\n{content}"

    return content


# ============================================================================
# Upload Validation
# ============================================================================

def validate_upload(
    filename: str,
    content_type: str,
    file_size: int,
    content: bytes
) -> Dict[str, Any]:
    """
    Comprehensive upload validation.

    Args:
        filename: Uploaded file name
        content_type: MIME content type
        file_size: Size in bytes
        content: File content as bytes

    Returns:
        Dictionary with validation result and any errors
    """
    errors = []
    warnings = []

    # Validate extension
    if not validate_file_extension(filename):
        ext = Path(filename).suffix.lower()
        errors.append(f"Unsupported file extension: {ext}. Supported: .md, .txt, .rst")

    # Validate size
    if not validate_file_size(file_size):
        size_mb = file_size / 1_000_000
        errors.append(f"File too large: {size_mb:.1f}MB. Maximum: 10MB")

    # Validate content type
    if not validate_content_type(content_type) and content_type not in ['', None]:
        warnings.append(f"Unusual content type: {content_type}")

    # Check for binary content
    if is_binary_content(content):
        errors.append("Binary content detected. Please upload a text file.")

    # Sanitize filename
    sanitized_name = sanitize_filename(filename)

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "sanitized_filename": sanitized_name,
    }


# ============================================================================
# Response Builders
# ============================================================================

def create_validation_response(
    valid: bool,
    filename: str,
    preview: Optional[Dict] = None,
    errors: Optional[List[str]] = None,
    warnings: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Create standardized validation response.

    Args:
        valid: Whether validation passed
        filename: File name
        preview: Document preview data
        errors: List of error messages
        warnings: List of warning messages

    Returns:
        Standardized response dictionary
    """
    response = {
        "valid": valid,
        "filename": filename,
        "timestamp": datetime.utcnow().isoformat(),
    }

    if preview:
        response["preview"] = preview

    if errors:
        response["errors"] = errors
        # Add suggestions based on errors
        response["suggestions"] = _generate_suggestions(errors)
    else:
        response["errors"] = []

    if warnings:
        response["warnings"] = warnings
    else:
        response["warnings"] = []

    return response


def create_error_response(
    error_code: str,
    message: str,
    details: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Create standardized error response with helpful suggestions.

    Args:
        error_code: Error code identifier
        message: Human-readable error message
        details: Additional error details

    Returns:
        Standardized error response
    """
    suggestions = _get_suggestions_for_error(error_code, details)

    return {
        "error_code": error_code,
        "message": message,
        "details": details or {},
        "suggestions": suggestions,
        "timestamp": datetime.utcnow().isoformat(),
    }


def _generate_suggestions(errors: List[str]) -> List[str]:
    """Generate helpful suggestions based on errors."""
    suggestions = []

    for error in errors:
        error_lower = error.lower()

        if "extension" in error_lower or "file type" in error_lower:
            suggestions.append("Use a .md, .txt, or .rst file format")
            suggestions.append("Convert your document to Markdown for best results")

        if "size" in error_lower or "large" in error_lower:
            suggestions.append("Try splitting your document into smaller parts")
            suggestions.append("Remove unnecessary images or embedded content")

        if "binary" in error_lower:
            suggestions.append("Ensure your file is saved as plain text")
            suggestions.append("If exporting from Word, use 'Save As' with .txt format")

    return list(set(suggestions))  # Remove duplicates


def _get_suggestions_for_error(error_code: str, details: Optional[Dict]) -> List[str]:
    """Get specific suggestions for an error code."""
    suggestions_map = {
        "INVALID_FILE_TYPE": [
            "Supported formats: .md (Markdown), .txt (Plain Text), .rst (reStructuredText)",
            "For best results, use Markdown (.md) format",
        ],
        "FILE_TOO_LARGE": [
            "Maximum file size is 10MB",
            "Try splitting your document into multiple files",
            "Remove embedded images or large code blocks",
        ],
        "BINARY_CONTENT": [
            "Please upload a plain text file",
            "If copying from another application, paste into a text editor first",
        ],
        "PARSE_ERROR": [
            "Check your document for formatting issues",
            "Ensure headings use proper Markdown syntax (# for titles)",
        ],
    }

    return suggestions_map.get(error_code, ["Please try again with a different file"])


# ============================================================================
# Progress Indicators
# ============================================================================

def get_upload_progress_stages() -> Dict[str, Dict[str, Any]]:
    """
    Get defined stages for upload progress tracking.

    Returns:
        Dictionary of stage names to progress information
    """
    return {
        "uploading": {
            "progress": 0,
            "message": "Uploading file...",
        },
        "validating": {
            "progress": 25,
            "message": "Validating file format...",
        },
        "parsing": {
            "progress": 50,
            "message": "Analyzing document structure...",
        },
        "previewing": {
            "progress": 75,
            "message": "Generating preview...",
        },
        "complete": {
            "progress": 100,
            "message": "Ready for video generation",
        },
    }


def format_progress_message(stage: str, progress: int) -> str:
    """
    Format a user-friendly progress message.

    Args:
        stage: Current processing stage
        progress: Progress percentage (0-100)

    Returns:
        User-friendly progress message
    """
    stages = get_upload_progress_stages()

    if stage in stages:
        return stages[stage]["message"]

    if progress < 25:
        return "Starting upload..."
    elif progress < 50:
        return "Validating your document..."
    elif progress < 75:
        return "Analyzing content..."
    elif progress < 100:
        return "Almost ready..."
    else:
        return "Complete!"


# ============================================================================
# Utility Functions
# ============================================================================

def get_supported_extensions() -> List[str]:
    """Get list of supported file extensions."""
    return list(SUPPORTED_EXTENSIONS)


def get_max_file_size() -> int:
    """Get maximum file size in bytes."""
    return MAX_FILE_SIZE


def format_file_size(size: int) -> str:
    """Format file size for display."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    else:
        return f"{size / (1024 * 1024):.1f} MB"
