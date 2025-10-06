"""Custom exceptions for the video_gen package.

This module defines all custom exceptions used throughout the video generation
pipeline to provide clear error handling and debugging information.
"""

from typing import Optional, Any


class VideoGenError(Exception):
    """Base exception for all video_gen errors."""

    def __init__(self, message: str, details: Optional[dict[str, Any]] = None):
        super().__init__(message)
        self.details = details or {}


class PipelineError(VideoGenError):
    """Raised when pipeline execution fails."""


class InputAdapterError(VideoGenError):
    """Raised when input adaptation fails."""


class ContentParserError(VideoGenError):
    """Raised when content parsing fails."""


class ScriptGenerationError(VideoGenError):
    """Raised when script generation fails."""


class AudioGenerationError(VideoGenError):
    """Raised when audio generation fails."""


class VideoGenerationError(VideoGenError):
    """Raised when video generation fails."""


class OutputHandlerError(VideoGenError):
    """Raised when output handling fails."""


class ConfigurationError(VideoGenError):
    """Raised when configuration is invalid."""


class ValidationError(VideoGenError):
    """Raised when data validation fails."""
