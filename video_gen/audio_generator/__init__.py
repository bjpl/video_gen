"""
Audio Generator Module
=====================
Unified audio generation for all video types.

This module consolidates:
- generate_all_videos_unified_v2.py
- generate_video_set.py

Provides:
- Neural TTS (Edge-TTS) with multiple voices
- Precise duration measurement
- Timing report generation
- Support for single and batch processing
- Progress tracking
"""

from .unified import UnifiedAudioGenerator, AudioGenerationConfig, AudioGenerationResult

__all__ = ['UnifiedAudioGenerator', 'AudioGenerationConfig', 'AudioGenerationResult']
