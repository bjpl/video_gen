"""
Document input model for parsing and generating videos from documents.

This module contains the DocumentInput model for accepting document content
and configuration for video generation.
"""
from pydantic import BaseModel, Field, field_validator
from typing import Optional


class DocumentInput(BaseModel):
    """
    Document input configuration for video generation.

    Attributes:
        content: Document content or file path
        accent_color: Theme color for generated videos
        voice: Voice selection for narration
        video_count: Number of videos to split document into (1-10)
        split_strategy: Strategy for splitting document content
        split_by_h2: Legacy H2 header splitting (auto-calculated)
        enable_ai_splitting: Enable AI-powered intelligent splitting
    """
    content: str = Field(..., min_length=1)
    accent_color: Optional[str] = "blue"
    voice: Optional[str] = "male"
    video_count: Optional[int] = Field(default=1, ge=1, le=10)  # Number of videos to split document into
    split_strategy: Optional[str] = "auto"  # Splitting strategy (auto, ai, headers, paragraph, sentence, length)
    split_by_h2: Optional[bool] = None  # Legacy: auto-calculated from video_count if not provided
    enable_ai_splitting: Optional[bool] = True  # Enable AI-powered splitting

    @field_validator('content')
    @classmethod
    def validate_content(cls, v):
        """Validate content is not empty."""
        if not v or not v.strip():
            raise ValueError('content cannot be empty')
        return v.strip()

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
