"""
Multilingual video generation models.

This module contains models for generating videos in multiple languages
with translation and voice mapping support.
"""
from pydantic import BaseModel, field_validator
from typing import List, Dict, Optional, Literal
from .video import VideoSet


class MultilingualRequest(BaseModel):
    """
    Request model for multilingual video generation.

    Attributes:
        video_set: The base video set to translate
        target_languages: List of target language codes (e.g., ["en", "es", "fr"])
        source_language: Original language code
        translation_method: Translation service to use
        language_voices: Optional per-language voice mapping
    """
    video_set: VideoSet
    target_languages: List[str]  # e.g., ["en", "es", "fr"]
    source_language: str = "en"
    translation_method: Optional[Literal["claude", "google"]] = "claude"
    language_voices: Optional[Dict[str, str]] = None  # NEW: Per-language voice mapping
