"""
YouTube input models for video preview and generation.

This module contains Pydantic models for YouTube video processing including:
- YouTubeInput: Main input configuration
- YouTubeURLValidation: URL validation request
- YouTubePreviewRequest: Preview data request
"""
from pydantic import BaseModel, Field, field_validator
from typing import Optional


class YouTubeInput(BaseModel):
    """
    YouTube video input configuration.

    Attributes:
        url: YouTube video URL
        duration: Target duration for generated video (30-600 seconds)
        accent_color: Theme color for the video
        voice: Voice selection for narration
        scene_duration: Duration per scene (5-30 seconds)
    """
    url: str = Field(..., min_length=1)
    duration: Optional[int] = Field(default=60, ge=30, le=600)
    accent_color: Optional[str] = "blue"
    voice: Optional[str] = "male"
    scene_duration: Optional[int] = Field(default=12, ge=5, le=30)

    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        """Validate YouTube URL format and extract video ID."""
        if not v or not v.strip():
            raise ValueError('url cannot be empty')
        v = v.strip().strip('"').strip("'")
        # Import and use the validator for comprehensive URL checking
        from video_gen.utils.youtube_validator import extract_video_id
        video_id = extract_video_id(v)
        if not video_id:
            raise ValueError('Invalid YouTube URL. Please provide a valid YouTube video link.')
        return v

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


class YouTubeURLValidation(BaseModel):
    """
    Request model for YouTube URL validation.

    Attributes:
        url: YouTube URL to validate
    """
    url: str = Field(..., min_length=1)


class YouTubePreviewRequest(BaseModel):
    """
    Request model for YouTube video preview.

    Attributes:
        url: YouTube video URL
        include_transcript_preview: Whether to include transcript preview
        transcript_language: Language code for transcript (default: en)
    """
    url: str = Field(..., min_length=1)
    include_transcript_preview: Optional[bool] = False
    transcript_language: Optional[str] = "en"
