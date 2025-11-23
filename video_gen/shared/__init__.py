"""
Shared Module
=============
Common utilities, models, and configuration shared across the system.
"""

from .models import VideoConfig, SceneConfig, InputConfig, PipelineResult
from .config import Config
from .exceptions import (
    VideoGenError,
    StageError,
    ValidationError,
    StateError,
    ConfigError,
)

__all__ = [
    "VideoConfig",
    "SceneConfig",
    "InputConfig",
    "PipelineResult",
    "Config",
    "VideoGenError",
    "StageError",
    "ValidationError",
    "StateError",
    "ConfigError",
]
