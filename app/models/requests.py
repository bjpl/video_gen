"""
Pydantic Request Models

All request validation models for the Video Generation API.
"""
from pydantic import BaseModel, Field, field_validator
from typing import List, Dict, Optional, Literal, Any


class SceneBase(BaseModel):
    type: Literal[
        "title", "command", "list", "outro", "code_comparison", "quote",
        "learning_objectives", "problem", "solution", "checkpoint", "quiz", "exercise"
    ]
    voice: Optional[Literal["male", "male_warm", "female", "female_friendly"]] = "male"
    narration: Optional[str] = None

    class Config:
        extra = "allow"  # Allow additional fields for scene-specific content


class Video(BaseModel):
    video_id: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1, max_length=200)
    scenes: List[Dict] = Field(..., min_length=1)  # Accept any scene type
    voice: Optional[str] = "male"  # Deprecated: use voices instead
    voices: Optional[List[str]] = None  # NEW: Support multiple voices
    duration: Optional[int] = None

    @field_validator('scenes')
    @classmethod
    def validate_scenes(cls, v):
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
        """Get voice list, handling backward compatibility."""
        if self.voices:
            return self.voices
        return [self.voice] if self.voice else ["male"]


class VideoSet(BaseModel):
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
        if v is None:
            return "blue"
        valid_colors = ['orange', 'blue', 'purple', 'green', 'pink', 'cyan']
        if v not in valid_colors:
            raise ValueError(f'accent_color must be one of: {valid_colors}')
        return v

    @field_validator('videos')
    @classmethod
    def validate_videos_not_empty(cls, v):
        if not v or len(v) == 0:
            raise ValueError('videos list cannot be empty - must have at least one video')
        return v


class DocumentInput(BaseModel):
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
        if not v or not v.strip():
            raise ValueError('content cannot be empty')
        return v.strip()

    @field_validator('accent_color')
    @classmethod
    def validate_accent_color(cls, v):
        if v is None:
            return "blue"
        valid_colors = ['orange', 'blue', 'purple', 'green', 'pink', 'cyan']
        if v not in valid_colors:
            raise ValueError(f'accent_color must be one of: {valid_colors}')
        return v


class YouTubeInput(BaseModel):
    url: str = Field(..., min_length=1)
    duration: Optional[int] = Field(default=60, ge=30, le=600)
    accent_color: Optional[str] = "blue"
    voice: Optional[str] = "male"
    scene_duration: Optional[int] = Field(default=12, ge=5, le=30)

    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
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
        if v is None:
            return "blue"
        valid_colors = ['orange', 'blue', 'purple', 'green', 'pink', 'cyan']
        if v not in valid_colors:
            raise ValueError(f'accent_color must be one of: {valid_colors}')
        return v


class YouTubeURLValidation(BaseModel):
    """Request model for YouTube URL validation."""
    url: str = Field(..., min_length=1)


class YouTubePreviewRequest(BaseModel):
    """Request model for YouTube video preview."""
    url: str = Field(..., min_length=1)
    include_transcript_preview: Optional[bool] = False
    transcript_language: Optional[str] = "en"


class MultilingualRequest(BaseModel):
    video_set: VideoSet
    target_languages: List[str]  # e.g., ["en", "es", "fr"]
    source_language: str = "en"
    translation_method: Optional[Literal["claude", "google"]] = "claude"
    language_voices: Optional[Dict[str, str]] = None  # NEW: Per-language voice mapping


class TemplateModel(BaseModel):
    name: str
    description: Optional[str] = ""
    mode: Literal["single", "set"]
    config: Dict[str, Any]
