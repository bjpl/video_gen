"""Programmatic input adapter for direct API usage.

This adapter allows direct programmatic creation of VideoSet objects through
Python code, providing the most flexible input method.
"""

from typing import Any

from .base import InputAdapter, InputAdapterResult
from ..shared.models import VideoSet, VideoConfig


class ProgrammaticAdapter(InputAdapter):
    """Adapter for programmatic video creation.

    This adapter accepts dictionaries or VideoSet objects directly,
    allowing full programmatic control over video generation.
    """

    def __init__(self, test_mode: bool = False):
        """Initialize the programmatic adapter.

        Args:
            test_mode: If True, runs in test mode (no external dependencies)
        """
        super().__init__(
            name="programmatic",
            description="Direct programmatic API for video creation"
        )
        self.test_mode = test_mode

    async def adapt(self, source: Any, **kwargs) -> InputAdapterResult:
        """Adapt programmatic input to VideoSet structure.

        Args:
            source: VideoSet, VideoConfig, or dictionary
            **kwargs: Additional parameters

        Returns:
            InputAdapterResult with VideoSet
        """
        try:
            # Handle VideoSet objects directly
            if isinstance(source, VideoSet):
                return InputAdapterResult(
                    success=True,
                    video_set=source
                )

            # Handle VideoConfig objects - wrap in VideoSet
            if isinstance(source, VideoConfig):
                video_set = VideoSet(
                    set_id=source.video_id,
                    name=source.title,
                    description=source.description,
                    videos=[source]
                )
                return InputAdapterResult(
                    success=True,
                    video_set=video_set
                )

            # Handle dictionaries
            if isinstance(source, dict):
                video_set = VideoSet(**source)
                return InputAdapterResult(
                    success=True,
                    video_set=video_set
                )

            return InputAdapterResult(
                success=False,
                error=f"Unsupported source type: {type(source)}"
            )

        except Exception as e:
            return InputAdapterResult(
                success=False,
                error=f"Programmatic adaptation failed: {e}"
            )

    async def validate_source(self, source: Any) -> bool:
        """Validate programmatic source.

        Args:
            source: VideoSet, VideoConfig, or dict

        Returns:
            True if valid VideoSet, VideoConfig, or dict
        """
        return isinstance(source, (VideoSet, VideoConfig, dict))

    def supports_format(self, format_type: str) -> bool:
        """Check if format is supported.

        Args:
            format_type: Format type

        Returns:
            True if "programmatic" or "api"
        """
        return format_type.lower() in {"programmatic", "api", "dict"}
