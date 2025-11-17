"""
Custom exceptions for the video generation system.
"""


class VideoGenError(Exception):
    """Base exception for all video generation errors."""

    def __init__(self, message: str, stage: str = None, details: dict = None):
        self.message = message
        self.stage = stage
        self.details = details or {}
        super().__init__(self.message)


class StageError(VideoGenError):
    """Raised when a pipeline stage fails."""


class ValidationError(VideoGenError):
    """Raised when validation fails."""


class StateError(VideoGenError):
    """Raised when state management operations fail."""


class ConfigError(VideoGenError):
    """Raised when configuration is invalid."""


class InputError(VideoGenError):
    """Raised when input data is invalid."""


class AudioGenerationError(StageError):
    """Raised when audio generation fails."""


class VideoGenerationError(StageError):
    """Raised when video generation fails."""


class ScriptGenerationError(StageError):
    """Raised when script generation fails."""


class ContentParserError(VideoGenError):
    """Raised when content parsing fails."""


class PipelineError(VideoGenError):
    """Raised when pipeline execution fails."""


class OutputHandlerError(VideoGenError):
    """Raised when output handling fails."""


class TranslationError(StageError):
    """Raised when translation fails."""
