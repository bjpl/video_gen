"""
Video model definitions for the video generation system.

This module contains Pydantic models for video content including:
- SceneBase: Base scene structure with type and voice configuration
- Video: Individual video with scenes, voices, and metadata
- VideoSet: Collection of videos with shared styling and language settings
"""
from pydantic import BaseModel, Field, field_validator
from typing import List, Dict, Optional, Literal


class SceneBase(BaseModel):
    """
    Base scene model with common fields across all scene types.

    Attributes:
        type: Scene type identifier (title, command, list, etc.)
        voice: Voice selection for this scene
        narration: Optional narration text
    """
    type: Literal[
        "title", "command", "list", "outro", "code_comparison", "quote",
        "learning_objectives", "problem", "solution", "checkpoint", "quiz", "exercise"
    ]
    voice: Optional[Literal["male", "male_warm", "female", "female_friendly"]] = "male"
    narration: Optional[str] = None

    class Config:
        extra = "allow"  # Allow additional fields for scene-specific content


class Video(BaseModel):
    """
    Individual video configuration.

    Attributes:
        video_id: Unique identifier for the video
        title: Video title (1-200 characters)
        scenes: List of scene dictionaries
        voice: Legacy single voice setting
        voices: Modern multi-voice support
        duration: Optional duration in seconds
    """
    video_id: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1, max_length=200)
    scenes: List[Dict] = Field(..., min_length=1)  # Accept any scene type
    voice: Optional[str] = "male"  # Deprecated: use voices instead
    voices: Optional[List[str]] = None  # NEW: Support multiple voices
    duration: Optional[int] = None

    @field_validator('scenes')
    @classmethod
    def validate_scenes(cls, v):
        """Validate scenes list is not empty and has required fields."""
        if not v or len(v) == 0:
            raise ValueError('scenes list cannot be empty - must have at least one scene')

        # Validate each scene has required 'type' field
        for i, scene in enumerate(v):
            if not isinstance(scene, dict):
                raise ValueError(f'Scene {i} must be a dictionary')
            if 'type' not in scene:
                raise ValueError(f'Scene {i} missing required field: type')

        return v

    def get_voices(self) -> List[str]:
        """
        Get voice list, handling backward compatibility.

        Returns:
            List of voice IDs to use for this video
        """
        if self.voices:
            return self.voices
        return [self.voice] if self.voice else ["male"]


class VideoSet(BaseModel):
    """
    Collection of videos with shared configuration.

    Attributes:
        set_id: Unique identifier (alphanumeric, dash, underscore)
        set_name: Display name for the set
        videos: List of Video objects
        accent_color: Theme color for all videos
        languages: Target languages for generation
        source_language: Original content language
        translation_method: Translation service to use
    """
    set_id: str = Field(..., min_length=1, pattern="^[a-zA-Z0-9_-]+$")
    set_name: str = Field(..., min_length=1, max_length=200)
    videos: List[Video] = Field(..., min_length=1)
    accent_color: Optional[str] = "blue"
    languages: Optional[List[str]] = ["en"]  # Default to English only
    source_language: Optional[str] = "en"
    translation_method: Optional[Literal["claude", "google", "manual"]] = "claude"

    @field_validator('accent_color')
    @classmethod
    def validate_accent_color(cls, v):
        """Validate accent color is in allowed list."""
        if v is None:
            return "blue"
        valid_colors = ['orange', 'blue', 'purple', 'green', 'pink', 'cyan']
        if v not in valid_colors:
            raise ValueError(f'accent_color must be one of: {valid_colors}')
        return v

    @field_validator('videos')
    @classmethod
    def validate_videos_not_empty(cls, v):
        """Validate videos list is not empty."""
        if not v or len(v) == 0:
            raise ValueError('videos list cannot be empty - must have at least one video')
        return v
