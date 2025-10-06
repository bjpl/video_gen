"""
Data models for the video generation system.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Literal, Any
from pathlib import Path
from datetime import datetime

@dataclass
class SceneConfig:
    """Configuration for a single scene."""

    scene_id: str
    scene_type: Literal[
        "title", "command", "list", "outro", "code_comparison", "quote",
        "learning_objectives", "problem", "solution", "checkpoint", "quiz", "exercise"
    ]
    narration: str
    visual_content: Dict[str, Any]
    voice: str = "male"
    min_duration: float = 3.0
    max_duration: float = 15.0

    # Runtime fields (populated during generation)
    actual_audio_duration: Optional[float] = None
    final_duration: Optional[float] = None
    audio_file: Optional[Path] = None
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "scene_id": self.scene_id,
            "scene_type": self.scene_type,
            "narration": self.narration,
            "visual_content": self.visual_content,
            "voice": self.voice,
            "min_duration": self.min_duration,
            "max_duration": self.max_duration,
            "actual_audio_duration": self.actual_audio_duration,
            "final_duration": self.final_duration,
            "audio_file": str(self.audio_file) if self.audio_file else None,
            "warnings": self.warnings,
        }


@dataclass
class VideoConfig:
    """Configuration for a complete video."""

    video_id: str
    title: str
    description: str
    scenes: List[SceneConfig]
    accent_color: str = "blue"
    version: str = "v2.0"
    voices: List[str] = field(default_factory=lambda: ["male"])  # Support multiple voices for rotation

    # Runtime fields
    total_duration: float = 0.0
    audio_dir: Optional[Path] = None
    video_file: Optional[Path] = None
    final_file: Optional[Path] = None
    generation_timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "video_id": self.video_id,
            "title": self.title,
            "description": self.description,
            "accent_color": self.accent_color,
            "version": self.version,
            "voices": self.voices,  # Include voices in serialization
            "scenes": [scene.to_dict() for scene in self.scenes],
            "total_duration": self.total_duration,
            "audio_dir": str(self.audio_dir) if self.audio_dir else None,
            "video_file": str(self.video_file) if self.video_file else None,
            "final_file": str(self.final_file) if self.final_file else None,
            "generation_timestamp": self.generation_timestamp,
        }


@dataclass
class InputConfig:
    """Input configuration for the pipeline."""

    input_type: Literal["document", "youtube", "wizard", "yaml", "programmatic"]
    source: str  # File path, URL, or programmatic data

    # Optional parameters
    accent_color: str = "blue"
    voice: str = "male"
    languages: List[str] = field(default_factory=lambda: ["en"])
    output_dir: Optional[Path] = None

    # Advanced options
    auto_generate: bool = True
    skip_review: bool = False
    resume_from: Optional[str] = None

    # Document splitting options
    video_count: Optional[int] = 1  # Number of videos to split document into
    split_by_h2: bool = False  # Split document by level 2 headings

    # Backward compatibility fields (deprecated, for old tests)
    config: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "input_type": self.input_type,
            "source": self.source,
            "accent_color": self.accent_color,
            "voice": self.voice,
            "languages": self.languages,
            "output_dir": str(self.output_dir) if self.output_dir else None,
            "auto_generate": self.auto_generate,
            "skip_review": self.skip_review,
            "resume_from": self.resume_from,
        }


@dataclass
class VideoSet:
    """Collection of related videos (for batch processing)."""

    set_id: str
    name: str
    description: str = ""
    videos: List[VideoConfig] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def languages(self) -> List[str]:
        """Get languages from metadata."""
        return self.metadata.get("languages", ["en"])

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "set_id": self.set_id,
            "name": self.name,
            "description": self.description,
            "videos": [v.to_dict() for v in self.videos],
            "metadata": self.metadata,
        }


@dataclass
class PipelineResult:
    """Result from a complete pipeline execution."""

    success: bool
    task_id: str
    video_config: VideoConfig

    # Output artifacts
    video_path: Optional[Path] = None
    audio_dir: Optional[Path] = None
    timing_report: Optional[Path] = None

    # Metadata
    total_duration: float = 0.0
    scene_count: int = 0
    generation_time: float = 0.0
    timestamp: Optional[datetime] = None

    # Errors and warnings
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "success": self.success,
            "task_id": self.task_id,
            "video_config": self.video_config.to_dict() if self.video_config else None,
            "video_path": str(self.video_path) if self.video_path else None,
            "audio_dir": str(self.audio_dir) if self.audio_dir else None,
            "timing_report": str(self.timing_report) if self.timing_report else None,
            "total_duration": self.total_duration,
            "scene_count": self.scene_count,
            "generation_time": self.generation_time,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "errors": self.errors,
            "warnings": self.warnings,
        }


# Backward compatibility exports
Scene = SceneConfig  # Alias for old code using 'Scene' instead of 'SceneConfig'

__all__ = [
    'SceneConfig',
    'Scene',  # Backward compat
    'VideoConfig',
    'InputConfig',
    'VideoSet',
    'PipelineResult',
]
