"""Utility functions for the video_gen package.

This module provides common utility functions used throughout the video
generation system for tasks like formatting, validation, and file operations.
"""

from typing import Optional
from pathlib import Path
import re
from datetime import timedelta

from .constants import SUPPORTED_LANGUAGES


def format_timestamp(seconds: float, include_hours: bool = True) -> str:
    """Format seconds as timestamp string.

    Args:
        seconds: Number of seconds
        include_hours: Whether to include hours in format

    Returns:
        Formatted timestamp (HH:MM:SS or MM:SS)

    Examples:
        >>> format_timestamp(90)
        '00:01:30'
        >>> format_timestamp(90, include_hours=False)
        '01:30'
    """
    td = timedelta(seconds=seconds)
    total_seconds = int(td.total_seconds())
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    secs = total_seconds % 60

    if include_hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """Sanitize a filename by removing invalid characters.

    Args:
        filename: Original filename
        max_length: Maximum filename length

    Returns:
        Sanitized filename safe for all operating systems

    Examples:
        >>> sanitize_filename("My Video: Part 1")
        'My_Video_Part_1'
    """
    # Remove invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)

    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip('. ')

    # Replace multiple underscores with single
    sanitized = re.sub(r'_+', '_', sanitized)

    # Truncate if too long
    if len(sanitized) > max_length:
        name, ext = Path(sanitized).stem, Path(sanitized).suffix
        sanitized = name[:max_length - len(ext)] + ext

    return sanitized


def validate_language_code(code: str) -> bool:
    """Validate a language code.

    Args:
        code: Language code to validate (e.g., "en", "es")

    Returns:
        True if valid, False otherwise

    Examples:
        >>> validate_language_code("en")
        True
        >>> validate_language_code("invalid")
        False
    """
    return code.lower() in SUPPORTED_LANGUAGES


def get_language_name(code: str) -> Optional[str]:
    """Get full language name from code.

    Args:
        code: Language code (e.g., "en")

    Returns:
        Full language name if valid, None otherwise

    Examples:
        >>> get_language_name("en")
        'English'
    """
    return SUPPORTED_LANGUAGES.get(code.lower())


def ensure_dir(path: Path) -> Path:
    """Ensure a directory exists, creating it if necessary.

    Args:
        path: Directory path

    Returns:
        Path object for the directory
    """
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_file_extension(filename: str) -> str:
    """Get file extension in lowercase.

    Args:
        filename: Filename or path

    Returns:
        File extension including dot (e.g., ".txt")

    Examples:
        >>> get_file_extension("video.MP4")
        '.mp4'
    """
    return Path(filename).suffix.lower()


def calculate_progress(current: int, total: int) -> float:
    """Calculate progress percentage.

    Args:
        current: Current item number
        total: Total number of items

    Returns:
        Progress as percentage (0-100)

    Examples:
        >>> calculate_progress(25, 100)
        25.0
    """
    if total == 0:
        return 0.0
    return (current / total) * 100


def truncate_text(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate text to maximum length.

    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add when truncated

    Returns:
        Truncated text

    Examples:
        >>> truncate_text("This is a long text", 10)
        'This is...'
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix
