"""Utility functions for document processing.

This module contains helper functions for:
- File reading and validation
- Security checks (path traversal, SSRF protection)
- URL handling
- Encoding detection
"""

import socket
from pathlib import Path
from typing import Any, Optional
import logging

logger = logging.getLogger(__name__)


async def read_document_content(
    source: Any,
    test_mode: bool = False,
    project_root: Optional[Path] = None
) -> str:
    """Read document from file or URL with security validation.

    Args:
        source: Path to file or URL
        test_mode: If True, bypass security checks for testing
        project_root: Root directory of the project (for path validation)

    Returns:
        Document content as string

    Raises:
        ValueError: For invalid paths or security violations
        FileNotFoundError: If file doesn't exist
        Exception: For other read errors
    """
    # Clean the source path - strip quotes and whitespace
    source_str = str(source).strip().strip('"').strip("'")

    # Check if URL
    if source_str.startswith('http://') or source_str.startswith('https://'):
        return await _read_from_url(source_str)
    else:
        return await _read_from_file(source_str, test_mode, project_root)


async def _read_from_url(url: str) -> str:
    """Read document from URL with security checks.

    Args:
        url: URL to fetch

    Returns:
        Document content

    Raises:
        ValueError: For security violations
        Exception: For fetch errors
    """
    try:
        import requests
        from urllib.parse import urlparse

        # URL validation - only http/https allowed
        parsed = urlparse(url)
        if parsed.scheme not in ['http', 'https']:
            raise ValueError(f"Invalid URL scheme: {parsed.scheme} (only http/https allowed)")

        # SSRF Protection: Block internal/private IP addresses
        try:
            ip = socket.gethostbyname(parsed.hostname)
            # Block private IP ranges
            if (ip.startswith('127.') or ip.startswith('192.168.') or
                ip.startswith('10.') or ip.startswith('172.16.') or
                ip.startswith('169.254.') or ip == 'localhost'):
                raise ValueError(f"Internal/private URLs not allowed for security: {ip}")
        except socket.gaierror:
            pass  # DNS lookup failed, let requests handle it

        # Convert GitHub URLs to raw
        fetch_url = url
        if 'github.com' in url and '/blob/' in url:
            fetch_url = url.replace('github.com', 'raw.githubusercontent.com')
            fetch_url = fetch_url.replace('/blob/', '/')

        # Fetch with size limit check
        response = requests.get(fetch_url, timeout=10, stream=True)
        response.raise_for_status()

        # Check content length before reading
        content_length = int(response.headers.get('content-length', 0))
        MAX_FILE_SIZE = 10_000_000  # 10MB limit
        if content_length > MAX_FILE_SIZE:
            raise ValueError(f"Document too large: {content_length} bytes (max {MAX_FILE_SIZE})")

        # Read content with size limit
        content = response.text
        if len(content) > MAX_FILE_SIZE:
            raise ValueError(f"Document too large: {len(content)} bytes (max {MAX_FILE_SIZE})")

        return content

    except ImportError:
        raise Exception("requests library required for URL fetching. Install: pip install requests")
    except Exception as e:
        raise Exception(f"Failed to fetch URL: {e}")


async def _read_from_file(
    source_str: str,
    test_mode: bool,
    project_root: Optional[Path]
) -> str:
    """Read document from file with security validation.

    Args:
        source_str: File path string
        test_mode: If True, bypass security checks
        project_root: Root directory of the project

    Returns:
        File content

    Raises:
        ValueError: For security violations or invalid paths
        FileNotFoundError: If file doesn't exist
    """
    file_path = Path(source_str)

    # Security: Resolve to absolute path to detect traversal attempts
    try:
        file_path = file_path.resolve()
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid file path: {e}")

    # Determine workspace and project roots if not provided
    if project_root is None:
        # This file is in: video_gen/video_gen/input_adapters/document_utils.py
        # Project root: video_gen/ (3 levels up)
        project_root = Path(__file__).parent.parent.parent.resolve()

    workspace_root = project_root.parent.resolve()  # active-development/

    # CRITICAL SECURITY: Block absolute paths to system directories
    # This prevents access to sensitive files like /etc/passwd, /root/.ssh/id_rsa, etc.
    system_dirs = ['/etc', '/sys', '/proc', '/root', '/boot', '/var', '/usr', '/bin', '/sbin']
    file_path_str = str(file_path)
    if any(file_path_str.startswith(d) for d in system_dirs):
        raise ValueError(f"Access to system directories denied: {file_path}")

    # Path traversal protection with whitelist approach
    # Allow: workspace files, /tmp directory, project uploads/ directory
    # Block: parent directory traversal, unauthorized paths
    if not test_mode:
        # Define allowed base paths
        allowed_paths = [
            workspace_root,  # Workspace and sibling projects
            Path("/tmp"),    # System temp directory (for uploads)
            project_root / "uploads"  # Project uploads directory
        ]

        # Check if file is under any allowed path
        is_allowed = False
        for allowed_path in allowed_paths:
            try:
                file_path.relative_to(allowed_path)
                is_allowed = True
                break
            except ValueError:
                continue

        if not is_allowed:
            # Build helpful error message
            allowed_paths_str = ", ".join(str(p) for p in allowed_paths)
            raise ValueError(
                f"Path traversal detected: {file_path} is not under any allowed directory. "
                f"Allowed directories: {allowed_paths_str}"
            )

        # Additional security: Detect parent directory traversal in original source
        if ".." in source_str:
            raise ValueError(f"Path traversal pattern detected in source: {source_str}")

    # Validate file exists and is actually a file
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if not file_path.is_file():
        raise ValueError(f"Not a file: {file_path}")

    # File size limit (10MB)
    MAX_FILE_SIZE = 10_000_000
    file_size = file_path.stat().st_size
    if file_size > MAX_FILE_SIZE:
        raise ValueError(f"File too large: {file_size} bytes (max {MAX_FILE_SIZE})")

    # Detect binary files by checking for common binary signatures
    with open(file_path, 'rb') as f:
        header = f.read(16)
        # Check for common binary file signatures
        binary_signatures = [
            (b'\xff\xd8\xff', 'JPEG image'),
            (b'\x89PNG', 'PNG image'),
            (b'GIF8', 'GIF image'),
            (b'%PDF', 'PDF document'),
            (b'PK\x03\x04', 'ZIP archive (DOCX/XLSX)'),
            (b'\x00\x00\x00', 'MP4/MP3/other binary'),
        ]

        for sig, file_type in binary_signatures:
            if header.startswith(sig):
                raise ValueError(
                    f"Binary file detected: {file_type}. "
                    f"Please upload a text file (.md, .txt) instead of '{file_path.name}'"
                )

    # Try to read as UTF-8 with better error handling
    try:
        return file_path.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        # Try other common encodings
        for encoding in ['utf-16', 'latin-1', 'cp1252']:
            try:
                content = file_path.read_text(encoding=encoding)
                logger.warning(f"File decoded using {encoding} instead of UTF-8")
                return content
            except (UnicodeDecodeError, UnicodeError, LookupError):
                continue

        # If all encodings fail, provide helpful error
        raise ValueError(
            f"Unable to read file '{file_path.name}'. "
            f"The file appears to be binary or uses an unsupported text encoding. "
            f"Please ensure you're uploading a plain text or markdown file."
        )


def validate_file_path(source: Any, supported_formats: set) -> bool:
    """Validate document file path.

    Args:
        source: Path to document file
        supported_formats: Set of supported file extensions

    Returns:
        True if valid, False otherwise
    """
    if not isinstance(source, (str, Path)):
        return False

    file_path = Path(source)
    return (
        file_path.exists()
        and file_path.is_file()
        and file_path.suffix.lower() in supported_formats
    )


__all__ = [
    'read_document_content',
    'validate_file_path'
]
