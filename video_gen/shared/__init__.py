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
from .logging_config import (
    setup_logging,
    get_logger,
    JSONFormatter,
    StructuredLogger,
    PerfTimer,
)
from .retry import (
    retry,
    RetryConfig,
    RetryStrategy,
    CircuitBreaker,
    CircuitBreakerError,
    CircuitState,
    anthropic_breaker,
    ffmpeg_breaker,
    edge_tts_breaker,
)

__all__ = [
    # Models
    "VideoConfig",
    "SceneConfig",
    "InputConfig",
    "PipelineResult",
    "Config",
    # Exceptions
    "VideoGenError",
    "StageError",
    "ValidationError",
    "StateError",
    "ConfigError",
    # Logging
    "setup_logging",
    "get_logger",
    "JSONFormatter",
    "StructuredLogger",
    "PerfTimer",
    # Retry & Circuit Breaker
    "retry",
    "RetryConfig",
    "RetryStrategy",
    "CircuitBreaker",
    "CircuitBreakerError",
    "CircuitState",
    "anthropic_breaker",
    "ffmpeg_breaker",
    "edge_tts_breaker",
]
