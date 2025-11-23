"""
Video Generation Module
========================
Unified video generator consolidating all optimizations from v2 and v3.

Main classes:
- UnifiedVideoGenerator: Complete video generation with multiple modes
- TimingReport: Audio timing report data structure
- VideoConfig: Video configuration data structure

Functions:
- generate_videos_from_timings: Legacy compatibility function
"""

from .unified import (
    UnifiedVideoGenerator,
    TimingReport,
    VideoConfig,
    generate_videos_from_timings,
)

__all__ = [
    "UnifiedVideoGenerator",
    "TimingReport",
    "VideoConfig",
    "generate_videos_from_timings",
]
