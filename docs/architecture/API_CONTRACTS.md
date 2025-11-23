# API Contracts - Internal Pipeline Interfaces

**Version:** 1.0
**Status:** Design Phase
**Last Updated:** 2025-10-04

---

## Table of Contents

1. [Overview](#overview)
2. [Data Transfer Objects (DTOs)](#data-transfer-objects-dtos)
3. [Stage Contracts](#stage-contracts)
4. [Adapter Contracts](#adapter-contracts)
5. [Event Contracts](#event-contracts)
6. [Error Contracts](#error-contracts)
7. [Configuration Contracts](#configuration-contracts)
8. [Validation Rules](#validation-rules)

---

## Overview

### Purpose

This document defines the **internal API contracts** for the pipeline system:
- Data structures passed between stages
- Interface contracts for all components
- Event types and payloads
- Error types and handling

### Contract Principles

1. **Type Safety**: All contracts use strong typing (Pydantic models)
2. **Immutability**: DTOs are immutable where possible
3. **Validation**: All inputs validated at boundaries
4. **Versioning**: Support for contract evolution
5. **Documentation**: Self-documenting through type hints

---

## Data Transfer Objects (DTOs)

### Input Layer DTOs

#### InputConfig

**Purpose:** Unified input configuration for all entry points

```python
from typing import Literal, Optional, Dict, Any, List
from pydantic import BaseModel, Field, HttpUrl

class InputConfig(BaseModel):
    """
    Normalized input configuration.
    All entry points (CLI, Web, Python API) convert to this format.
    """

    # Source specification
    source_type: Literal[
        "document",
        "youtube",
        "wizard",
        "yaml",
        "programmatic"
    ] = Field(
        description="Type of input source"
    )

    source_data: Dict[str, Any] = Field(
        description="Source-specific data"
    )

    # Common options
    accent_color: str = Field(
        default="blue",
        pattern="^(orange|blue|purple|green|pink|cyan)$"
    )

    voice: str = Field(
        default="male",
        pattern="^(male|female|male_warm|female_friendly)$"
    )

    target_duration: Optional[int] = Field(
        default=60,
        ge=10,
        le=600,
        description="Target video duration in seconds"
    )

    use_ai: bool = Field(
        default=False,
        description="Use AI for narration enhancement"
    )

    # Multilingual options
    languages: List[str] = Field(
        default=["en"],
        description="Target languages (ISO 639-1 codes)"
    )

    translation_service: Optional[Literal["claude", "google"]] = Field(
        default=None,
        description="Translation service to use"
    )

    # Output options
    output_dir: Optional[str] = Field(
        default=None,
        description="Output directory for videos"
    )

    output_format: str = Field(
        default="mp4",
        pattern="^(mp4|webm|avi)$"
    )

    # Processing options
    batch_mode: bool = Field(
        default=False,
        description="Generate multiple videos in parallel"
    )

    max_parallel: int = Field(
        default=4,
        ge=1,
        le=16,
        description="Max parallel video generation"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "source_type": "document",
                "source_data": {
                    "path": "README.md"
                },
                "accent_color": "blue",
                "voice": "male",
                "target_duration": 60,
                "use_ai": True,
                "languages": ["en", "es"],
                "output_dir": "./videos"
            }
        }
```

#### DocumentInput

**Purpose:** Document-specific input data

```python
class DocumentInput(BaseModel):
    """Document input data"""

    path: Optional[str] = Field(
        default=None,
        description="Local file path"
    )

    url: Optional[HttpUrl] = Field(
        default=None,
        description="Remote document URL"
    )

    content: Optional[str] = Field(
        default=None,
        description="Raw document content"
    )

    format: Optional[Literal["md", "txt", "pdf", "docx"]] = Field(
        default=None,
        description="Document format (auto-detected if not provided)"
    )

    # At least one of path, url, or content required
    @model_validator(mode='after')
    def validate_source(self):
        if not any([self.path, self.url, self.content]):
            raise ValueError(
                "At least one of path, url, or content required"
            )
        return self
```

#### YouTubeInput

```python
class YouTubeInput(BaseModel):
    """YouTube input data"""

    url: Optional[HttpUrl] = Field(
        default=None,
        description="YouTube video URL"
    )

    video_id: Optional[str] = Field(
        default=None,
        description="YouTube video ID"
    )

    extract_sections: bool = Field(
        default=True,
        description="Extract sections from chapters/timestamps"
    )

    max_sections: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum sections to extract"
    )

    @model_validator(mode='after')
    def validate_source(self):
        if not any([self.url, self.video_id]):
            raise ValueError("url or video_id required")
        return self
```

### Processing Layer DTOs

#### VideoSetConfig

**Purpose:** Normalized video set structure

```python
class VideoSetConfig(BaseModel):
    """
    Normalized video set configuration.
    Output from InputAdapter stage.
    """

    set_id: str = Field(
        description="Unique identifier for this set"
    )

    set_name: str = Field(
        description="Human-readable name"
    )

    description: str = Field(
        default="",
        description="Set description"
    )

    videos: List['VideoConfig'] = Field(
        description="Videos in this set"
    )

    defaults: Dict[str, Any] = Field(
        default_factory=dict,
        description="Default settings for all videos"
    )

    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata"
    )

class VideoConfig(BaseModel):
    """Individual video configuration"""

    video_id: str = Field(
        description="Unique video identifier"
    )

    title: str = Field(
        description="Video title"
    )

    description: str = Field(
        default="",
        description="Video description"
    )

    scenes: List['SceneConfig'] = Field(
        description="Scenes in this video"
    )

    # Video-specific overrides
    accent_color: Optional[str] = None
    voice: Optional[str] = None
    target_duration: Optional[int] = None

class SceneConfig(BaseModel):
    """Scene configuration"""

    scene_id: str = Field(
        description="Unique scene identifier"
    )

    scene_type: Literal[
        "title",
        "subtitle",
        "command",
        "list",
        "code",
        "image",
        "outro",
        "lesson_intro",
        "course_overview"
    ] = Field(
        description="Type of scene"
    )

    visual_content: Dict[str, Any] = Field(
        description="Scene-specific visual content"
    )

    narration: Optional[str] = Field(
        default=None,
        description="Narration text (may be auto-generated)"
    )

    voice: Optional[str] = None

    min_duration: float = Field(
        default=3.0,
        ge=1.0,
        description="Minimum scene duration"
    )

    max_duration: float = Field(
        default=15.0,
        ge=1.0,
        description="Maximum scene duration"
    )
```

#### ParsedContent

**Purpose:** Structured content from parsing stage

```python
class ParsedSection(BaseModel):
    """Parsed content section"""

    section_id: str
    section_type: Literal[
        "introduction",
        "installation",
        "usage",
        "configuration",
        "examples",
        "conclusion"
    ]
    title: str
    content: str
    code_blocks: List[str] = Field(default_factory=list)
    key_points: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ParsedContent(BaseModel):
    """
    Output from ParsingStage.
    Structured content ready for script generation.
    """

    sections: List[ParsedSection] = Field(
        description="Parsed content sections"
    )

    document_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Document-level metadata"
    )

    suggested_duration: int = Field(
        description="Suggested total duration in seconds"
    )

    complexity: Literal["simple", "moderate", "complex"] = Field(
        default="moderate",
        description="Content complexity level"
    )
```

#### VideoScript

**Purpose:** Complete script with narration

```python
class ScriptedScene(BaseModel):
    """Scene with generated narration"""

    scene_id: str
    scene_type: str
    visual_content: Dict[str, Any]

    narration: str = Field(
        description="Generated narration text"
    )

    narration_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Narration generation metadata (AI model, tokens, etc.)"
    )

    word_count: int
    estimated_duration: float  # Based on speaking rate

    voice: str
    min_duration: float
    max_duration: float

class VideoScript(BaseModel):
    """
    Output from ScriptGenerationStage.
    Complete script ready for audio generation.
    """

    video_id: str
    title: str
    scenes: List[ScriptedScene]

    total_words: int
    estimated_duration: float  # Total estimated duration

    validation_warnings: List[str] = Field(
        default_factory=list,
        description="Validation warnings (timing, content, etc.)"
    )

    metadata: Dict[str, Any] = Field(default_factory=dict)
```

#### AudioAssets

**Purpose:** Generated audio with timing

```python
class SceneAudio(BaseModel):
    """Audio for a single scene"""

    scene_id: str
    audio_file: str = Field(
        description="Path to audio file"
    )

    actual_duration: float = Field(
        description="Actual audio duration in seconds"
    )

    word_count: int
    speaking_rate: float = Field(
        description="Words per second"
    )

    voice_used: str

class AudioAssets(BaseModel):
    """
    Output from AudioGenerationStage.
    Audio files and timing data.
    """

    video_id: str
    scene_audios: List[SceneAudio]

    total_duration: float
    average_speaking_rate: float

    timing_report: Dict[str, Any] = Field(
        description="Detailed timing information"
    )

    warnings: List[str] = Field(
        default_factory=list,
        description="Duration mismatches, etc."
    )
```

#### VideoAssets

**Purpose:** Rendered video files

```python
class RenderedVideo(BaseModel):
    """Single rendered video"""

    video_id: str
    video_file: str = Field(
        description="Path to video file"
    )

    silent_video_file: Optional[str] = Field(
        default=None,
        description="Path to silent video (before audio mux)"
    )

    duration: float
    resolution: str  # e.g., "1920x1080"
    fps: int
    file_size_mb: float

    encoding_settings: Dict[str, Any] = Field(
        default_factory=dict
    )

class VideoAssets(BaseModel):
    """
    Output from VideoGenerationStage.
    Final video files.
    """

    videos: List[RenderedVideo]

    total_file_size_mb: float
    total_duration: float

    rendering_stats: Dict[str, Any] = Field(
        default_factory=dict,
        description="Rendering statistics"
    )
```

### Output Layer DTOs

#### PipelineResult

**Purpose:** Complete pipeline output

```python
class PipelineResult(BaseModel):
    """
    Final output from pipeline execution.
    Returned to user.
    """

    task_id: str

    status: Literal["success", "partial", "failed"]

    videos: List[str] = Field(
        description="Paths to generated video files"
    )

    artifacts: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Artifacts by stage (scripts, audio, intermediate files)"
    )

    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Execution metadata"
    )

    metrics: Dict[str, Any] = Field(
        default_factory=dict,
        description="Performance metrics"
    )

    errors: List[str] = Field(
        default_factory=list,
        description="Any errors encountered"
    )

    warnings: List[str] = Field(
        default_factory=list,
        description="Validation warnings"
    )

    execution_time_seconds: float
```

---

## Stage Contracts

### Base Stage Interface

```python
from abc import ABC, abstractmethod

class StageInput(BaseModel):
    """Base input for all stages"""
    data: Dict[str, Any]
    task_id: str
    config: Dict[str, Any] = Field(default_factory=dict)

class StageOutput(BaseModel):
    """Base output for all stages"""
    data: Dict[str, Any]
    artifacts: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ValidationResult(BaseModel):
    """Validation result"""
    is_valid: bool
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)

class Stage(ABC):
    """Abstract base class for all stages"""

    @abstractmethod
    async def execute(
        self,
        input: StageInput
    ) -> StageOutput:
        """Execute this stage"""
        pass

    @abstractmethod
    def validate(
        self,
        input: StageInput
    ) -> ValidationResult:
        """Validate input before execution"""
        pass

    def get_estimated_duration(
        self,
        input: StageInput
    ) -> float:
        """Estimate execution time in seconds"""
        return 30.0  # Default
```

### Input Stage Contract

```python
class InputStageInput(StageInput):
    """Input for InputStage"""
    data: InputConfig  # type: ignore

class InputStageOutput(StageOutput):
    """Output from InputStage"""
    data: VideoSetConfig  # type: ignore

class InputStage(Stage):
    """
    Adapts various input types to VideoSetConfig.

    Input: InputConfig
    Output: VideoSetConfig
    """

    async def execute(
        self,
        input: InputStageInput
    ) -> InputStageOutput:
        """Convert input to VideoSetConfig"""
        pass

    def validate(
        self,
        input: InputStageInput
    ) -> ValidationResult:
        """Validate input config"""
        # Check source_type is supported
        # Validate source_data has required fields
        # Validate options
        pass
```

### Parsing Stage Contract

```python
class ParsingStageInput(StageInput):
    """Input for ParsingStage"""
    data: VideoSetConfig  # type: ignore

class ParsingStageOutput(StageOutput):
    """Output from ParsingStage"""
    data: ParsedContent  # type: ignore

class ParsingStage(Stage):
    """
    Extracts structured content from VideoSetConfig.

    Input: VideoSetConfig
    Output: ParsedContent
    """

    async def execute(
        self,
        input: ParsingStageInput
    ) -> ParsingStageOutput:
        """Parse and structure content"""
        pass

    def validate(
        self,
        input: ParsingStageInput
    ) -> ValidationResult:
        """Validate video set config"""
        # Check all videos have scenes
        # Validate scene types
        # Check for required fields
        pass
```

### Script Generation Stage Contract

```python
class ScriptGenStageInput(StageInput):
    """Input for ScriptGenerationStage"""
    data: ParsedContent  # type: ignore

class ScriptGenStageOutput(StageOutput):
    """Output from ScriptGenerationStage"""
    data: VideoScript  # type: ignore

class ScriptGenerationStage(Stage):
    """
    Generates narration for each scene.

    Input: ParsedContent
    Output: VideoScript
    """

    async def execute(
        self,
        input: ScriptGenStageInput
    ) -> ScriptGenStageOutput:
        """Generate narration"""
        pass

    def validate(
        self,
        input: ScriptGenStageInput
    ) -> ValidationResult:
        """Validate parsed content"""
        # Check sections have content
        # Validate complexity level
        pass
```

### Audio Generation Stage Contract

```python
class AudioGenStageInput(StageInput):
    """Input for AudioGenerationStage"""
    data: VideoScript  # type: ignore

class AudioGenStageOutput(StageOutput):
    """Output from AudioGenerationStage"""
    data: AudioAssets  # type: ignore

class AudioGenerationStage(Stage):
    """
    Generates audio files using TTS.

    Input: VideoScript
    Output: AudioAssets
    """

    async def execute(
        self,
        input: AudioGenStageInput
    ) -> AudioGenStageOutput:
        """Generate TTS audio"""
        pass

    def validate(
        self,
        input: AudioGenStageInput
    ) -> ValidationResult:
        """Validate video script"""
        # Check all scenes have narration
        # Validate voice settings
        pass
```

### Video Generation Stage Contract

```python
class VideoGenStageInput(StageInput):
    """Input for VideoGenerationStage"""
    audio_assets: AudioAssets
    video_script: VideoScript  # Need both

class VideoGenStageOutput(StageOutput):
    """Output from VideoGenerationStage"""
    data: VideoAssets  # type: ignore

class VideoGenerationStage(Stage):
    """
    Renders video with audio.

    Input: AudioAssets + VideoScript
    Output: VideoAssets
    """

    async def execute(
        self,
        input: VideoGenStageInput
    ) -> VideoGenStageOutput:
        """Render and encode video"""
        pass

    def validate(
        self,
        input: VideoGenStageInput
    ) -> ValidationResult:
        """Validate audio assets and script"""
        # Check audio files exist
        # Validate timing data
        pass
```

### Output Stage Contract

```python
class OutputStageInput(StageInput):
    """Input for OutputStage"""
    data: VideoAssets  # type: ignore
    output_config: Dict[str, Any]

class OutputStageOutput(StageOutput):
    """Output from OutputStage"""
    data: PipelineResult  # type: ignore

class OutputStage(Stage):
    """
    Organizes and exports final output.

    Input: VideoAssets
    Output: PipelineResult
    """

    async def execute(
        self,
        input: OutputStageInput
    ) -> OutputStageOutput:
        """Export videos"""
        pass

    def validate(
        self,
        input: OutputStageInput
    ) -> ValidationResult:
        """Validate video assets"""
        # Check video files exist
        # Validate output directory
        pass
```

---

## Adapter Contracts

### Base Adapter Interface

```python
class InputAdapter(ABC):
    """Base class for input adapters"""

    @abstractmethod
    async def adapt(
        self,
        raw_input: Any
    ) -> VideoSetConfig:
        """Convert raw input to VideoSetConfig"""
        pass

    @abstractmethod
    def supports(self, input_type: str) -> bool:
        """Check if this adapter supports input type"""
        pass
```

### Document Adapter Contract

```python
class DocumentAdapter(InputAdapter):
    """
    Adapter for document inputs.

    Supported formats:
    - Markdown (.md)
    - Plain text (.txt)
    - PDF (.pdf)
    - Word (.docx)
    """

    async def adapt(
        self,
        raw_input: DocumentInput
    ) -> VideoSetConfig:
        """
        Convert document to VideoSetConfig.

        Steps:
        1. Extract text from document
        2. Parse into sections (headers, paragraphs, code blocks)
        3. Create scenes for each section
        4. Generate VideoSetConfig
        """
        pass

    def supports(self, input_type: str) -> bool:
        return input_type == "document"
```

### YouTube Adapter Contract

```python
class YouTubeAdapter(InputAdapter):
    """
    Adapter for YouTube videos.

    Extracts:
    - Transcript/captions
    - Chapters/timestamps
    - Key moments
    """

    async def adapt(
        self,
        raw_input: YouTubeInput
    ) -> VideoSetConfig:
        """
        Convert YouTube video to VideoSetConfig.

        Steps:
        1. Download transcript/captions
        2. Extract chapters or detect key moments
        3. Create scenes for each moment
        4. Generate VideoSetConfig
        """
        pass

    def supports(self, input_type: str) -> bool:
        return input_type == "youtube"
```

### Wizard Adapter Contract

```python
class WizardInput(BaseModel):
    """Input from wizard flow"""
    responses: Dict[str, Any]
    template: Optional[str] = None

class WizardAdapter(InputAdapter):
    """
    Adapter for wizard/interactive input.

    Guides user through:
    - Video purpose
    - Content selection
    - Scene creation
    - Customization
    """

    async def adapt(
        self,
        raw_input: WizardInput
    ) -> VideoSetConfig:
        """
        Convert wizard responses to VideoSetConfig.

        Steps:
        1. Apply template if selected
        2. Process user responses
        3. Generate scenes
        4. Create VideoSetConfig
        """
        pass

    def supports(self, input_type: str) -> bool:
        return input_type == "wizard"
```

---

## Event Contracts

### Event Base Class

```python
from datetime import datetime
from dataclasses import dataclass

@dataclass
class Event:
    """Base event class"""
    timestamp: datetime = field(default_factory=datetime.now)
    task_id: str = ""
```

### Progress Events

```python
@dataclass
class ProgressEvent(Event):
    """Progress update event"""
    stage: str
    progress: float  # 0.0 - 1.0
    message: str = ""

@dataclass
class StageStartEvent(Event):
    """Stage started event"""
    stage: str

@dataclass
class StageCompleteEvent(Event):
    """Stage completed event"""
    stage: str
    duration_seconds: float
    output_summary: Dict[str, Any] = field(default_factory=dict)

@dataclass
class StageErrorEvent(Event):
    """Stage error event"""
    stage: str
    error: str
    retry_count: int = 0
```

### Task Events

```python
@dataclass
class TaskCreatedEvent(Event):
    """Task created event"""
    input_type: str

@dataclass
class TaskStartedEvent(Event):
    """Task started event"""
    estimated_duration: float

@dataclass
class TaskCompletedEvent(Event):
    """Task completed event"""
    duration_seconds: float
    videos_generated: int

@dataclass
class TaskFailedEvent(Event):
    """Task failed event"""
    error: str
    failed_stage: str
```

### Artifact Events

```python
@dataclass
class ArtifactCreatedEvent(Event):
    """Artifact created event"""
    artifact_path: str
    artifact_type: str
    stage: str
    size_bytes: int
```

---

## Error Contracts

### Exception Hierarchy

```python
class PipelineError(Exception):
    """Base exception for pipeline errors"""

    def __init__(
        self,
        message: str,
        error_code: str = "PIPELINE_ERROR",
        details: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(message)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details
        }

class ValidationError(PipelineError):
    """Input validation failed"""

    def __init__(
        self,
        errors: List[str],
        field: Optional[str] = None
    ):
        self.errors = errors
        self.field = field
        super().__init__(
            message=f"Validation failed: {errors}",
            error_code="VALIDATION_ERROR",
            details={"errors": errors, "field": field}
        )

class StageError(PipelineError):
    """Stage execution failed"""

    def __init__(
        self,
        stage: str,
        message: str,
        cause: Optional[Exception] = None
    ):
        self.stage = stage
        self.cause = cause
        super().__init__(
            message=f"Stage {stage} failed: {message}",
            error_code="STAGE_ERROR",
            details={"stage": stage, "cause": str(cause) if cause else None}
        )

class TaskNotFoundError(PipelineError):
    """Task not found"""

    def __init__(self, task_id: str):
        self.task_id = task_id
        super().__init__(
            message=f"Task {task_id} not found",
            error_code="TASK_NOT_FOUND",
            details={"task_id": task_id}
        )

class RetryExhaustedError(PipelineError):
    """Retry attempts exhausted"""

    def __init__(
        self,
        attempts: int,
        last_error: Exception
    ):
        self.attempts = attempts
        self.last_error = last_error
        super().__init__(
            message=f"Failed after {attempts} retry attempts",
            error_code="RETRY_EXHAUSTED",
            details={
                "attempts": attempts,
                "last_error": str(last_error)
            }
        )

class ResourceError(PipelineError):
    """Resource error (disk, memory, etc.)"""

    def __init__(
        self,
        resource: str,
        message: str
    ):
        self.resource = resource
        super().__init__(
            message=f"Resource error ({resource}): {message}",
            error_code="RESOURCE_ERROR",
            details={"resource": resource}
        )
```

### Error Response Format

```python
class ErrorResponse(BaseModel):
    """Standard error response"""

    error_code: str
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)
    task_id: Optional[str] = None
    stage: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)

    @classmethod
    def from_exception(
        cls,
        exc: PipelineError,
        task_id: Optional[str] = None,
        stage: Optional[str] = None
    ) -> 'ErrorResponse':
        """Create from exception"""
        return cls(
            error_code=exc.error_code,
            message=exc.message,
            details=exc.details,
            task_id=task_id,
            stage=stage
        )
```

---

## Configuration Contracts

### Pipeline Configuration

```python
class PipelineConfig(BaseModel):
    """Pipeline-wide configuration"""

    # Stage configuration
    stages: List[str] = Field(
        default=[
            "input",
            "parsing",
            "script_generation",
            "audio_generation",
            "video_generation",
            "output"
        ],
        description="Stages to execute in order"
    )

    # Retry configuration
    retry_enabled: bool = True
    retry_max_attempts: int = Field(default=3, ge=1, le=10)
    retry_base_delay: float = Field(default=1.0, ge=0.1)
    retry_max_delay: float = Field(default=60.0, ge=1.0)
    retry_exponential_base: float = Field(default=2.0, ge=1.0)

    # Timeout configuration
    stage_timeout_seconds: Dict[str, int] = Field(
        default_factory=lambda: {
            "input": 300,           # 5 min
            "parsing": 180,         # 3 min
            "script_generation": 600,  # 10 min (AI)
            "audio_generation": 900,   # 15 min (TTS)
            "video_generation": 3600,  # 60 min (rendering)
            "output": 300           # 5 min
        }
    )

    # Resource limits
    max_memory_mb: int = Field(default=4096, ge=512)
    max_disk_gb: int = Field(default=50, ge=1)
    max_concurrent_tasks: int = Field(default=4, ge=1, le=16)

    # Event configuration
    event_bus_enabled: bool = True
    progress_update_interval: float = Field(
        default=1.0,
        ge=0.1,
        description="Progress update interval in seconds"
    )

    # State management
    state_backend: Literal["json", "sqlite"] = "json"
    state_directory: str = ".video-gen/tasks"
    artifact_directory: str = ".video-gen/artifacts"

    # Cleanup
    auto_cleanup_on_success: bool = False
    auto_cleanup_on_failure: bool = False
    keep_artifacts: bool = True
    artifact_retention_days: int = Field(default=30, ge=1)
```

### Stage-Specific Configuration

```python
class AudioGenConfig(BaseModel):
    """Audio generation configuration"""

    tts_service: Literal["edge", "google", "aws"] = "edge"
    default_voice: str = "male"
    speaking_rate: float = Field(default=1.0, ge=0.5, le=2.0)
    audio_format: Literal["mp3", "wav", "ogg"] = "mp3"
    audio_quality: Literal["low", "medium", "high"] = "high"

class VideoGenConfig(BaseModel):
    """Video generation configuration"""

    resolution: Literal["720p", "1080p", "4k"] = "1080p"
    fps: int = Field(default=30, ge=24, le=60)
    codec: Literal["h264", "h265", "vp9"] = "h264"
    quality: Literal["low", "medium", "high", "ultra"] = "high"
    use_gpu: bool = True
```

---

## Validation Rules

### Input Validation

```python
class InputValidator:
    """Validates all inputs"""

    @staticmethod
    def validate_input_config(config: InputConfig) -> ValidationResult:
        """Validate InputConfig"""
        errors = []
        warnings = []

        # Validate source_data has required fields for source_type
        if config.source_type == "document":
            doc_input = DocumentInput(**config.source_data)
            # Will raise if invalid

        elif config.source_type == "youtube":
            yt_input = YouTubeInput(**config.source_data)
            # Will raise if invalid

        # Validate durations
        if config.target_duration < 10:
            errors.append("target_duration must be >= 10 seconds")

        if config.target_duration > 600:
            warnings.append("target_duration > 600s may take a long time")

        # Validate languages
        valid_langs = ["en", "es", "fr", "de", "it", "pt", "ja", "ko", "zh"]
        for lang in config.languages:
            if lang not in valid_langs:
                errors.append(f"Unsupported language: {lang}")

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
```

### Scene Validation

```python
class SceneValidator:
    """Validates scene configurations"""

    @staticmethod
    def validate_scene(scene: SceneConfig) -> ValidationResult:
        """Validate single scene"""
        errors = []
        warnings = []

        # Type-specific validation
        if scene.scene_type == "command":
            if "commands" not in scene.visual_content:
                errors.append(
                    f"Scene {scene.scene_id}: "
                    "command scene requires 'commands' field"
                )

        elif scene.scene_type == "list":
            if "items" not in scene.visual_content:
                errors.append(
                    f"Scene {scene.scene_id}: "
                    "list scene requires 'items' field"
                )

        # Duration validation
        if scene.min_duration > scene.max_duration:
            errors.append(
                f"Scene {scene.scene_id}: "
                f"min_duration ({scene.min_duration}) > "
                f"max_duration ({scene.max_duration})"
            )

        # Narration validation
        if scene.narration:
            word_count = len(scene.narration.split())
            estimated = word_count / 2.25  # 2.25 words/sec

            if estimated > scene.max_duration:
                warnings.append(
                    f"Scene {scene.scene_id}: "
                    f"Narration may exceed max_duration "
                    f"({word_count} words ≈ {estimated:.1f}s)"
                )

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
```

---

## Usage Examples

### Creating Input Config (CLI → Pipeline)

```python
from cli import parse_cli_args
from pipeline import PipelineOrchestrator

# CLI parses args
args = parse_cli_args()

# Convert to InputConfig
input_config = InputConfig(
    source_type="document",
    source_data=DocumentInput(
        path=args.document
    ).model_dump(),
    accent_color=args.color,
    voice=args.voice,
    output_dir=args.output
)

# Execute pipeline
orchestrator = PipelineOrchestrator(...)
result = await orchestrator.execute(input_config)
```

### Creating Input Config (Web → Pipeline)

```python
from fastapi import FastAPI, HTTPException
from app.models import ParseRequest

app = FastAPI()

@app.post("/api/create")
async def create_video(request: ParseRequest):
    # Convert to InputConfig
    input_config = InputConfig(
        source_type=request.input_type,
        source_data=request.model_dump(
            include={
                "document_path",
                "youtube_url",
                "wizard_data"
            },
            exclude_none=True
        ),
        accent_color=request.accent_color,
        voice=request.voice,
        use_ai=request.use_ai
    )

    # Execute pipeline
    orchestrator = get_orchestrator()
    result = await orchestrator.execute(input_config)

    return {"task_id": result.task_id}
```

### Stage Communication

```python
# Stage 1: Input → VideoSetConfig
input_stage = InputStage(...)
input_output = await input_stage.execute(
    InputStageInput(
        data=input_config,
        task_id="task_123"
    )
)
video_set_config = input_output.data

# Stage 2: VideoSetConfig → ParsedContent
parsing_stage = ParsingStage(...)
parsing_output = await parsing_stage.execute(
    ParsingStageInput(
        data=video_set_config,
        task_id="task_123"
    )
)
parsed_content = parsing_output.data

# And so on...
```

---

**Document Status:** Ready for Implementation
**Dependencies:** PIPELINE_ARCHITECTURE.md, STATE_MANAGEMENT_SPEC.md
**Next:** See MIGRATION_PLAN.md
