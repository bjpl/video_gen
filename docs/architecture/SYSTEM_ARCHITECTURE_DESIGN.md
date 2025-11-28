# System Architecture Design - Video Generation Application

**Document Type:** Architecture Design Document
**Status:** Production Analysis & Design
**Version:** 1.0
**Date:** 2025-11-27
**Architect:** System Architecture Designer

---

## Executive Summary

This document presents the complete system architecture for a production-ready video generation application. The system is currently **functional and production-deployed** with 79% test coverage and 475 passing tests. This architecture analysis serves as the definitive reference for understanding the system's design, components, data flows, and technical decisions.

### Key Metrics
- **Production Status:** ✅ Active
- **Test Coverage:** 79% (475 tests passing)
- **Codebase:** ~10,500 lines
- **Documentation:** 35,000+ words across 30+ files
- **Features:** 12 scene types, 29 languages, 6 pipeline stages

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture Principles](#2-architecture-principles)
3. [High-Level Architecture](#3-high-level-architecture)
4. [Component Architecture](#4-component-architecture)
5. [Data Flow Architecture](#5-data-flow-architecture)
6. [Module Specifications](#6-module-specifications)
7. [API Design](#7-api-design)
8. [Technology Stack](#8-technology-stack)
9. [Scalability & Performance](#9-scalability--performance)
10. [Security Architecture](#10-security-architecture)
11. [Deployment Architecture](#11-deployment-architecture)
12. [Architecture Diagrams](#12-architecture-diagrams)

---

## 1. System Overview

### 1.1 Purpose

The Video Generation System is a **production-grade automated video creation platform** that transforms textual content (documentation, tutorials, educational materials) into professional-quality videos with synchronized narration and visual elements.

### 1.2 Core Capabilities

| Capability | Description | Status |
|------------|-------------|--------|
| **Multi-Input Processing** | Document, YouTube, YAML, Wizard, Programmatic | ✅ Production |
| **Scene Generation** | 12 scene types (general + educational) | ✅ Production |
| **Multilingual Support** | 29 languages with native TTS | ✅ Production |
| **AI Enhancement** | Claude 3.5 Sonnet for narration | ✅ Production |
| **Audio-First Pipeline** | Perfect A/V sync through timing manifest | ✅ Production |
| **GPU Acceleration** | NVIDIA NVENC hardware encoding | ✅ Production |
| **Batch Processing** | Parallel video generation | ✅ Production |

### 1.3 System Characteristics

**Architectural Style:** Modular, Event-Driven, Stage-Based Pipeline
**Deployment Model:** Standalone application (CLI + Web API)
**Processing Model:** Batch and real-time
**Data Flow:** Unidirectional pipeline with state persistence

---

## 2. Architecture Principles

### 2.1 Design Principles

#### Single Responsibility Principle (SRP)
Each module has ONE clearly defined purpose:
- **Orchestrator**: Workflow coordination only
- **Stages**: Specific transformation logic
- **Renderers**: Visual scene generation
- **Adapters**: Input normalization

#### Separation of Concerns
```
┌─────────────────────────────────────────┐
│         Presentation Layer              │  CLI, Web API, Python API
├─────────────────────────────────────────┤
│         Business Logic Layer            │  Pipeline Orchestration
├─────────────────────────────────────────┤
│         Processing Layer                │  Stages (6 stages)
├─────────────────────────────────────────┤
│         Rendering Layer                 │  Scene Renderers (7 modules)
├─────────────────────────────────────────┤
│         Infrastructure Layer            │  FFmpeg, TTS, File System
└─────────────────────────────────────────┘
```

#### Dependency Injection
All dependencies are injected, enabling testability and flexibility:
```python
class PipelineOrchestrator:
    def __init__(
        self,
        state_manager: StateManager,
        event_emitter: EventEmitter
    ):
        self.state_manager = state_manager
        self.event_emitter = event_emitter
```

#### Fail-Fast Validation
Input validation occurs at system boundaries before processing:
```python
# Validate at entry points
InputConfig.__post_init__()  # Pydantic validation
VideoConfig.__post_init__()  # Business rule validation
SceneConfig.__post_init__()  # Security validation (DoS prevention)
```

### 2.2 Quality Attributes

| Attribute | Target | Implementation |
|-----------|--------|----------------|
| **Modularity** | <500 LOC/file | ✅ 7 renderer modules, ~206 LOC each |
| **Testability** | >75% coverage | ✅ 79% coverage, 475 tests |
| **Reliability** | 0 regressions | ✅ All tests passing |
| **Performance** | <5 min/video | ✅ GPU acceleration, parallel batch |
| **Maintainability** | Clear structure | ✅ Comprehensive docs, type hints |
| **Extensibility** | Plugin architecture | ✅ Adapter pattern, renderer registry |

---

## 3. High-Level Architecture

### 3.1 System Context Diagram (C4 Level 1)

```
                                 ┌─────────────────────┐
                                 │                     │
                                 │   Content Creator   │
                                 │                     │
                                 └──────────┬──────────┘
                                            │
                    ┌───────────────────────┼───────────────────────┐
                    │                       │                       │
                    ▼                       ▼                       ▼
          ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
          │   CLI Interface  │   │   Web Interface  │   │  Python API      │
          │   (argparse)     │   │   (FastAPI)      │   │  (Programmatic)  │
          └────────┬─────────┘   └────────┬─────────┘   └────────┬─────────┘
                   │                      │                      │
                   └──────────────────────┼──────────────────────┘
                                          │
                                          ▼
                          ┌───────────────────────────────┐
                          │                               │
                          │  VIDEO GENERATION SYSTEM      │
                          │                               │
                          │  • Pipeline Orchestration     │
                          │  • Stage-Based Processing     │
                          │  • Renderer System            │
                          │  • State Management           │
                          │  • Event Broadcasting         │
                          │                               │
                          └────────────┬──────────────────┘
                                       │
                ┌──────────────────────┼──────────────────────┐
                │                      │                      │
                ▼                      ▼                      ▼
     ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
     │  Edge TTS        │   │  FFmpeg          │   │  Claude API      │
     │  (Audio)         │   │  (Video Codec)   │   │  (AI Narration)  │
     └──────────────────┘   └──────────────────┘   └──────────────────┘
                                       │
                                       ▼
                          ┌───────────────────────────────┐
                          │                               │
                          │  Generated Video Files        │
                          │  • MP4 videos                 │
                          │  • Audio assets               │
                          │  • Timing reports             │
                          │  • Metadata                   │
                          │                               │
                          └───────────────────────────────┘
```

### 3.2 Container Diagram (C4 Level 2)

```
┌────────────────────────────────────────────────────────────────────────┐
│                           APPLICATION CONTAINER                        │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │                    ENTRY LAYER                                   │ │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐                 │ │
│  │  │    CLI     │  │  Web API   │  │ Python API │                 │ │
│  │  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘                 │ │
│  │        └────────────────┼────────────────┘                       │ │
│  └────────────────────────────────────────────────────────────────── │ │
│                            │                                          │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │                 ORCHESTRATION LAYER                              │ │
│  │                                                                  │ │
│  │  ┌────────────────────────────────────────────────────────────┐ │ │
│  │  │              PipelineOrchestrator                          │ │ │
│  │  │  • Coordinate stage execution                             │ │ │
│  │  │  • Manage state transitions                               │ │ │
│  │  │  • Handle errors & retries                                │ │ │
│  │  │  • Emit progress events                                   │ │ │
│  │  └────────────────────────────────────────────────────────────┘ │ │
│  │                                                                  │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │ │
│  │  │StateManager  │  │  EventBus    │  │ RetryPolicy  │          │ │
│  │  │(persistence) │  │ (pub/sub)    │  │ (recovery)   │          │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘          │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                            │                                          │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │                   PROCESSING STAGES (6)                          │ │
│  │                                                                  │ │
│  │  Stage 1: InputStage          (Input Adaptation)                │ │
│  │  Stage 2: ParsingStage        (Content Parsing)                 │ │
│  │  Stage 3: ScriptGenStage      (Narration Generation)            │ │
│  │  Stage 4: AudioGenStage       (TTS Synthesis)                   │ │
│  │  Stage 5: VideoGenStage       (Frame Rendering)                 │ │
│  │  Stage 6: OutputStage         (Export & Delivery)               │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                            │                                          │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │                   RENDERING LAYER (7 modules)                    │ │
│  │                                                                  │ │
│  │  • basic_scenes.py          (Title, List, Outro, Quote)         │ │
│  │  • educational_scenes.py    (Learning, Problem, Solution)       │ │
│  │  • comparison_scenes.py     (Code Comparison)                   │ │
│  │  • checkpoint_scenes.py     (Progress Checkpoints)              │ │
│  │  • base.py                  (Base Renderer)                     │ │
│  │  • constants.py             (Shared Constants)                  │ │
│  │  • __init__.py              (Renderer Registry)                 │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────┐
│                      EXTERNAL SYSTEMS                                  │
│                                                                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                │
│  │  Edge TTS    │  │   FFmpeg     │  │  Claude API  │                │
│  │  (Azure)     │  │  (Local)     │  │  (Anthropic) │                │
│  └──────────────┘  └──────────────┘  └──────────────┘                │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Component Architecture

### 4.1 Core Components

#### 4.1.1 Pipeline Orchestrator

**Purpose:** Coordinate execution of all pipeline stages

**Responsibilities:**
- Execute stages sequentially
- Manage task state persistence
- Handle errors and retries
- Emit progress events
- Support checkpoint/resume

**Interface:**
```python
class PipelineOrchestrator:
    def __init__(
        self,
        state_manager: Optional[StateManager],
        event_emitter: Optional[EventEmitter]
    )

    async def execute(
        input_config: InputConfig,
        task_id: Optional[str],
        resume: bool
    ) -> PipelineResult

    def execute_sync(...) -> PipelineResult
    async def execute_async(...) -> str
    def get_status(task_id: str) -> TaskState
    def cancel(task_id: str) -> bool
```

**Key Features:**
- Async and sync execution modes
- Background task support
- State persistence after each stage
- Automatic retry with exponential backoff
- Critical stage failure detection

#### 4.1.2 State Manager

**Purpose:** Persist and restore task state for recovery

**Responsibilities:**
- Create new tasks
- Save stage outputs as checkpoints
- Restore tasks from checkpoints
- Track task history
- Cleanup old tasks

**Storage Backend:** JSON files (extensible to SQLite)

**Data Model:**
```python
class TaskState:
    task_id: str
    status: TaskStatus  # PENDING, RUNNING, COMPLETED, FAILED, CANCELLED
    input_config: Dict[str, Any]
    stages: List[StageResult]
    current_stage: Optional[str]
    errors: List[str]
    warnings: List[str]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
```

#### 4.1.3 Event System

**Purpose:** Real-time progress tracking and monitoring

**Architecture:** Publisher-Subscriber pattern

**Event Types:**
- `PIPELINE_STARTED`
- `PIPELINE_COMPLETED`
- `PIPELINE_FAILED`
- `STAGE_STARTED`
- `STAGE_COMPLETED`
- `STAGE_FAILED`
- `PROGRESS_UPDATED`

**Usage:**
```python
# Emit events
await event_emitter.emit(Event(
    type=EventType.STAGE_COMPLETED,
    task_id=task_id,
    message="Audio generation complete",
    data={"duration": 42.5, "scenes": 8}
))

# Subscribe to events
def on_progress(event: Event):
    print(f"Progress: {event.data['progress']*100}%")

event_emitter.subscribe(EventType.PROGRESS_UPDATED, on_progress)
```

### 4.2 Processing Stages

#### Stage 1: Input Adaptation

**Purpose:** Normalize diverse input formats to standard structure

**Input:** Various (Document, YouTube, YAML, Wizard, Programmatic)
**Output:** `VideoConfig` (normalized structure)

**Adapters:**
- `DocumentAdapter`: Markdown, TXT, PDF → VideoConfig
- `YouTubeAdapter`: YouTube URL → Transcript → VideoConfig
- `YAMLAdapter`: YAML file → VideoConfig
- `WizardAdapter`: Interactive prompts → VideoConfig
- `ProgrammaticAdapter`: Python objects → VideoConfig

**Key Logic:**
- Extract text from source
- Parse into sections
- Create scene definitions
- Apply defaults and overrides

#### Stage 2: Content Parsing

**Purpose:** Extract structured information from video configuration

**Input:** `VideoConfig`
**Output:** `ParsedContent` (structured sections)

**Operations:**
- Identify sections (intro, installation, usage, etc.)
- Extract code blocks
- Identify key points
- Determine content complexity
- Suggest optimal duration

#### Stage 3: Script Generation

**Purpose:** Generate narration for each scene

**Input:** `VideoConfig`
**Output:** `VideoConfig` with populated narration

**Modes:**
1. **Template-Based** (default): Rule-based narration generation
2. **AI-Enhanced** (optional): Claude 3.5 Sonnet for natural narration

**AI Integration:**
```python
class AIEnhancer:
    def enhance_narration(
        scene_type: str,
        visual_content: Dict,
        context: Optional[str]
    ) -> str
```

**Validation:**
- Check narration fits timing constraints
- Validate speaking rate (2.25 words/sec)
- Warn on duration mismatches

#### Stage 4: Audio Generation

**Purpose:** Synthesize speech from narration text

**Input:** `VideoConfig` with narration
**Output:** Audio files + `TimingManifest`

**TTS Engine:** Edge-TTS (Azure Neural Voices)

**Voices:**
- `male`: en-US-AndrewMultilingualNeural
- `male_warm`: en-US-BrandonMultilingualNeural
- `female`: en-US-AriaNeural
- `female_friendly`: en-US-AvaMultilingualNeural

**Process:**
1. Generate TTS audio for each scene
2. Measure actual duration with FFprobe
3. Create timing manifest:
```json
{
  "scene_01": {
    "audio_file": "scene_01.mp3",
    "duration": 4.23,
    "start_time": 0.0,
    "end_time": 4.23
  }
}
```

**Multilingual Support:** 29 languages with native voices

#### Stage 5: Video Generation

**Purpose:** Render visual frames synchronized to audio

**Input:** Audio files + Timing manifest + VideoConfig
**Output:** MP4 video files

**Rendering Pipeline:**
```
For each scene:
  1. Read timing from manifest
  2. Create renderer instance (based on scene_type)
  3. Render keyframes (PIL)
  4. Apply transitions
  5. Generate frame sequence
  6. Encode with FFmpeg (audio-matched duration)
```

**Encoders:**
- **GPU (preferred):** h264_nvenc (5-10x faster)
- **CPU (fallback):** libx264

**Renderer System:**
```python
# Renderer registry (extensible)
RENDERERS = {
    "title": TitleRenderer,
    "command": CommandRenderer,
    "list": ListRenderer,
    "code_comparison": CodeComparisonRenderer,
    "quote": QuoteRenderer,
    "outro": OutroRenderer,
    "learning_objectives": LearningObjectivesRenderer,
    "problem": ProblemRenderer,
    "solution": SolutionRenderer,
    "quiz": QuizRenderer,
    "checkpoint": CheckpointRenderer,
    "exercise": ExerciseRenderer,
}
```

#### Stage 6: Output & Validation

**Purpose:** Finalize and export videos

**Operations:**
- Validate video files
- Generate metadata
- Create thumbnails (future)
- Organize output directory
- Generate summary report

**Output Structure:**
```
output/
├── {video_id}/
│   ├── video.mp4
│   ├── audio/
│   │   ├── scene_01.mp3
│   │   └── ...
│   ├── timing_manifest.json
│   └── metadata.json
```

### 4.3 Rendering System

#### Architecture

**Base Class:**
```python
class BaseRenderer(ABC):
    @abstractmethod
    def render(self, scene_config: SceneConfig) -> Image
```

**Modular Design:**
- **7 renderer modules** (~206 LOC each)
- **12 scene types** supported
- **100% test coverage** on renderers

**Rendering Optimizations:**
- **NumPy vectorization:** 8x faster frame operations
- **Caching:** Reuse rendered frames for identical content
- **Parallel batch:** Process multiple videos concurrently

---

## 5. Data Flow Architecture

### 5.1 End-to-End Data Flow

```
┌─────────────────┐
│  Raw Input      │  Document / YouTube / YAML / Wizard / Python
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ InputConfig     │  Normalized configuration
│ (Pydantic)      │  • source_type, source_data
└────────┬────────┘  • options (color, voice, languages)
         │           • validation (DoS prevention)
         ▼
┌─────────────────┐
│ VideoConfig     │  Structured video definition
│ (Dataclass)     │  • video_id, title, description
└────────┬────────┘  • scenes: List[SceneConfig]
         │           • defaults (accent_color, voice)
         │
         ├─ Stage 3: Add narration to each scene
         │
         ▼
┌─────────────────┐
│ VideoConfig     │  With generated narration
│ + Narration     │  • scene.narration populated
└────────┬────────┘  • validation warnings
         │
         ▼
┌─────────────────┐
│ Audio Assets    │  TTS-generated audio
│                 │  • scene_01.mp3, scene_02.mp3, ...
└────────┬────────┘  • TimingManifest (actual durations)
         │
         ▼
┌─────────────────┐
│ Video Assets    │  Rendered video
│                 │  • video.mp4
└────────┬────────┘  • metadata.json
         │
         ▼
┌─────────────────┐
│ PipelineResult  │  Final output
│                 │  • videos: List[Path]
└─────────────────┘  • artifacts: Dict[str, Path]
                     • metrics: Dict[str, Any]
```

### 5.2 State Transitions

```
Task Lifecycle:

START → PENDING → RUNNING → COMPLETED
                     │
                     └──→ FAILED → (can resume)

Stage Lifecycle:

IDLE → RUNNING → COMPLETED
           │
           └──→ FAILED → RETRY (3 attempts)
                    │
                    └──→ FAILED (final)
```

### 5.3 Data Validation Points

```
Entry Point Validation:
  ├─ CLI args → InputConfig validation
  ├─ Web request → Pydantic validation
  └─ Python API → Type validation

Pipeline Validation:
  ├─ Stage 1: Input adapter validation
  ├─ Stage 2: Content parsing validation
  ├─ Stage 3: Narration timing validation
  ├─ Stage 4: Audio file existence
  ├─ Stage 5: Video encoding success
  └─ Stage 6: Final output validation
```

---

## 6. Module Specifications

### 6.1 Renderer Modules

| Module | Scenes | LOC | Coverage | Purpose |
|--------|--------|-----|----------|---------|
| `basic_scenes.py` | title, list, outro, quote | 206 | 100% | General-purpose scenes |
| `educational_scenes.py` | learning_objectives, problem, solution | 201 | 100% | Learning content |
| `comparison_scenes.py` | code_comparison | 198 | 100% | Before/after displays |
| `checkpoint_scenes.py` | checkpoint, quiz, exercise | 213 | 100% | Progress markers |
| `base.py` | - | 142 | 100% | Abstract base class |
| `constants.py` | - | 87 | - | Shared constants |
| `__init__.py` | - | 45 | - | Registry & exports |

**Total:** 7 modules, 1,092 LOC, 100% coverage on implementation

### 6.2 Input Adapters

| Adapter | Format | Complexity | Features |
|---------|--------|------------|----------|
| `DocumentAdapter` | MD, TXT, PDF, DOCX | Medium | Markdown parsing, section detection, code extraction |
| `YouTubeAdapter` | YouTube URL | Medium | Transcript extraction, timestamp parsing, summarization |
| `YAMLAdapter` | YAML | Low | Direct mapping, validation |
| `WizardAdapter` | Interactive | High | Step-by-step prompts, template application |
| `ProgrammaticAdapter` | Python objects | Low | Direct object mapping |

### 6.3 Shared Utilities

| Module | Purpose | Key Functions |
|--------|---------|---------------|
| `config.py` | Global configuration singleton | Paths, FFmpeg, voices, colors |
| `models.py` | Data models (Pydantic/dataclass) | SceneConfig, VideoConfig, InputConfig |
| `utils.py` | Helper functions | File operations, color conversion |
| `exceptions.py` | Custom exceptions | VideoGenError hierarchy |
| `constants.py` | System-wide constants | Defaults, limits, formats |

---

## 7. API Design

### 7.1 Public APIs

#### CLI Interface

```bash
# Document input
python scripts/create_video.py --document README.md

# YouTube input
python scripts/create_video.py --youtube-url "https://youtube.com/watch?v=ID" --duration 60

# Interactive wizard
python scripts/create_video.py --wizard

# Options
--accent-color blue|orange|purple|green|pink|cyan
--voice male|female|male_warm|female_friendly
--output-dir ./videos
--languages en,es,fr
--use-ai  # Enable AI narration
```

#### Python API

```python
from video_gen.input_adapters.programmatic import ProgrammaticVideoBuilder

# Build video programmatically
builder = ProgrammaticVideoBuilder(video_id="tutorial_01")

builder.add_scene(
    scene_type="title",
    title="Getting Started",
    subtitle="Installation Guide",
    voice="male"
)

builder.add_scene(
    scene_type="command",
    title="Installation",
    commands=["pip install package", "python setup.py"],
    voice="female"
)

# Export to YAML
builder.export_to_yaml("videos/tutorial_01")

# Or execute pipeline directly
from video_gen.pipeline import CompletePipeline

pipeline = CompletePipeline()
result = pipeline.execute(builder.build())
```

#### Web API (FastAPI)

```python
# POST /api/create
{
  "source_type": "document",
  "source_data": {
    "path": "README.md"
  },
  "accent_color": "blue",
  "voice": "male",
  "use_ai": true,
  "languages": ["en", "es"]
}

# Response
{
  "task_id": "task_abc123",
  "status": "pending"
}

# GET /api/status/{task_id}
{
  "task_id": "task_abc123",
  "status": "running",
  "progress": 0.67,
  "current_stage": "video_generation",
  "stages_completed": ["input", "parsing", "script", "audio"],
  "estimated_completion": "2025-11-27T21:30:00Z"
}
```

### 7.2 Internal APIs

#### Stage Interface

```python
class Stage(ABC):
    @abstractmethod
    async def run(
        self,
        context: Dict[str, Any],
        task_id: str
    ) -> StageResult
```

#### Renderer Interface

```python
class BaseRenderer(ABC):
    @abstractmethod
    def render(
        self,
        scene_config: SceneConfig
    ) -> Image

    def create_base_frame(self) -> Image
    def apply_branding(self, frame: Image) -> Image
```

#### Adapter Interface

```python
class BaseInputAdapter(ABC):
    @abstractmethod
    def adapt(
        self,
        source: Any
    ) -> VideoConfig

    @abstractmethod
    def validate_source(self, source: Any) -> bool
```

---

## 8. Technology Stack

### 8.1 Core Technologies

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| **Language** | Python | 3.10+ | Core implementation |
| **Video Codec** | FFmpeg | 4.4+ | Video encoding, NVENC GPU |
| **Audio Synthesis** | Edge-TTS | Latest | Neural text-to-speech |
| **AI Enhancement** | Claude 3.5 Sonnet | API | Natural narration (optional) |
| **Image Processing** | PIL (Pillow) | 10.0+ | Frame rendering |
| **Numerical Computing** | NumPy | 1.24+ | Vectorized operations |
| **Type System** | Pydantic | 2.0+ | Data validation |
| **Testing** | Pytest | 7.4+ | Test framework |
| **Web Framework** | FastAPI | 0.100+ | Web API (optional) |

### 8.2 External Services

| Service | Provider | Usage | Required |
|---------|----------|-------|----------|
| **TTS** | Azure (Edge-TTS) | Voice synthesis | ✅ Yes |
| **AI** | Anthropic (Claude) | Narration enhancement | ❌ Optional |
| **Translation** | Google Translate | Fallback translation | ❌ Optional |
| **Storage** | Local filesystem | Video output | ✅ Yes |

### 8.3 System Requirements

**Minimum:**
- CPU: 4 cores
- RAM: 8 GB
- Disk: 50 GB free
- GPU: Optional (NVIDIA with NVENC)

**Recommended:**
- CPU: 8+ cores
- RAM: 16 GB
- Disk: 100 GB SSD
- GPU: NVIDIA RTX (10x encoding speedup)

---

## 9. Scalability & Performance

### 9.1 Performance Characteristics

| Metric | Value | Notes |
|--------|-------|-------|
| **Single Video Generation** | ~5 minutes | 1080p, 60s video, GPU |
| **Batch Speedup** | 2.25x | Parallel processing |
| **Frame Rendering** | 8x faster | NumPy vectorization |
| **Audio/Visual Sync** | Perfect | Manifest-based timing |
| **Test Execution** | ~18 seconds | 475 tests |

### 9.2 Scalability Strategies

#### Horizontal Scaling

**Current:** Single-machine batch processing
```python
# Parallel batch execution
max_workers = config.max_workers  # Default: 4
with ProcessPoolExecutor(max_workers=max_workers) as executor:
    futures = [executor.submit(generate_video, cfg) for cfg in configs]
    results = [f.result() for f in futures]
```

**Future:** Distributed processing
- Queue-based architecture (Celery + Redis)
- Worker pool across multiple machines
- Shared storage (NFS/S3)

#### Vertical Scaling

**GPU Acceleration:**
- NVIDIA NVENC hardware encoding
- 5-10x speedup vs CPU
- Automatic fallback to CPU

**Caching:**
- Audio file caching (skip regeneration)
- Timing manifest persistence
- Rendered frame caching (future)

### 9.3 Performance Optimization

#### 1. NumPy Vectorization
```python
# Before: Python loops (slow)
for y in range(height):
    for x in range(width):
        pixels[y, x] = color

# After: NumPy operations (8x faster)
pixels[:] = color
```

#### 2. Batch Processing
```python
# Sequential: 5 min × 10 videos = 50 minutes
# Parallel (4 workers): 50 / 2.25 = ~22 minutes
```

#### 3. GPU Encoding
```python
# CPU: libx264 → ~300 fps
# GPU: h264_nvenc → ~1500 fps (5x faster)
```

---

## 10. Security Architecture

### 10.1 Input Validation

**Defense Against:**
- **DoS Attacks:** Length limits on all text inputs
- **Path Traversal:** Path validation in file operations
- **Code Injection:** No eval() or exec() usage
- **Resource Exhaustion:** Scene count limits (max 100 scenes)

**Validation Rules:**
```python
class SceneConfig:
    def __post_init__(self):
        # Prevent DoS
        if len(self.scene_id) > 200:
            raise ValueError("scene_id too long")
        if len(self.narration) > 50000:
            raise ValueError("narration too long")

        # Prevent invalid durations
        if self.min_duration > 300:
            raise ValueError("duration out of range")
```

### 10.2 API Key Management

**Best Practices:**
- Environment variables for secrets
- No hardcoded API keys
- Optional AI features (fail gracefully without key)

```python
# Safe API key retrieval
api_key = os.getenv("ANTHROPIC_API_KEY")
if api_key:
    ai_enhancer = AIEnhancer(api_key)
else:
    # Fallback to template-based narration
    logger.warning("AI enhancement disabled (no API key)")
```

### 10.3 File System Security

**Protections:**
- Output directory sandboxing
- Temporary file cleanup
- Path normalization
- No user-controlled file deletion

---

## 11. Deployment Architecture

### 11.1 Standalone Deployment

```
┌─────────────────────────────────────┐
│       User's Machine                │
│                                     │
│  ┌───────────────────────────────┐  │
│  │  Video Gen Application        │  │
│  │  • CLI interface              │  │
│  │  • Local processing           │  │
│  │  • Local storage              │  │
│  └───────────────────────────────┘  │
│              │                       │
│              ▼                       │
│  ┌───────────────────────────────┐  │
│  │  External Services (Internet) │  │
│  │  • Edge-TTS (Azure)           │  │
│  │  • Claude API (optional)      │  │
│  └───────────────────────────────┘  │
│              │                       │
│              ▼                       │
│  ┌───────────────────────────────┐  │
│  │  Local Output                 │  │
│  │  • output/videos/             │  │
│  │  • output/audio/              │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

### 11.2 Web Service Deployment (Future)

```
┌─────────────────────────────────────┐
│          Client Browser             │
└──────────────┬──────────────────────┘
               │ HTTPS
               ▼
┌─────────────────────────────────────┐
│      FastAPI Web Server             │
│  • REST API endpoints               │
│  • WebSocket for progress           │
│  • Task queue management            │
└──────────────┬──────────────────────┘
               │
      ┌────────┴────────┐
      │                 │
      ▼                 ▼
┌──────────┐      ┌──────────┐
│  Redis   │      │ Workers  │
│  Queue   │      │ (Celery) │
└──────────┘      └────┬─────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Shared Storage  │
              │ (NFS/S3)        │
              └─────────────────┘
```

### 11.3 Docker Deployment (Future)

```dockerfile
FROM python:3.10-slim

# Install FFmpeg with NVENC support
RUN apt-get update && apt-get install -y \
    ffmpeg \
    nvidia-cuda-toolkit

# Install Python dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy application
COPY video_gen/ /app/video_gen/
WORKDIR /app

# Expose ports
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0"]
```

---

## 12. Architecture Diagrams

### 12.1 Component Diagram (Detailed)

```
┌─────────────────────────────────────────────────────────────────────┐
│                         VIDEO GENERATION SYSTEM                     │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │                    INPUT LAYER                                │ │
│  │                                                               │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │ │
│  │  │ CLI Parser  │  │  Web API    │  │ Python API  │          │ │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘          │ │
│  │         └────────────────┼────────────────┘                  │ │
│  │                          │                                    │ │
│  │                 ┌────────▼────────┐                          │ │
│  │                 │  InputConfig    │                          │ │
│  │                 │  (Normalized)   │                          │ │
│  │                 └────────┬────────┘                          │ │
│  └──────────────────────────┼───────────────────────────────────┘ │
│                             │                                     │
│  ┌──────────────────────────▼───────────────────────────────────┐ │
│  │               PIPELINE ORCHESTRATOR                          │ │
│  │                                                              │ │
│  │  ┌───────────────┐  ┌───────────────┐  ┌────────────────┐  │ │
│  │  │ State Manager │  │  Event Bus    │  │ Retry Policy   │  │ │
│  │  │ (JSON/SQLite) │  │  (Pub/Sub)    │  │ (Exp Backoff)  │  │ │
│  │  └───────────────┘  └───────────────┘  └────────────────┘  │ │
│  │                                                              │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ Stage Execution Engine                               │  │ │
│  │  │  • Sequential execution                              │  │ │
│  │  │  • State persistence                                 │  │ │
│  │  │  • Error handling                                    │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  └──────────────────────────┬───────────────────────────────────┘ │
│                             │                                     │
│  ┌──────────────────────────▼───────────────────────────────────┐ │
│  │                   STAGE PIPELINE                             │ │
│  │                                                              │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ Stage 1: InputStage                                  │  │ │
│  │  │  ├─ DocumentAdapter                                  │  │ │
│  │  │  ├─ YouTubeAdapter                                   │  │ │
│  │  │  ├─ YAMLAdapter                                      │  │ │
│  │  │  ├─ WizardAdapter                                    │  │ │
│  │  │  └─ ProgrammaticAdapter                              │  │ │
│  │  └───────────────────┬──────────────────────────────────┘  │ │
│  │                      ▼                                      │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ Stage 2: ParsingStage                                │  │ │
│  │  │  • Extract sections                                  │  │ │
│  │  │  • Identify structure                                │  │ │
│  │  │  • Detect complexity                                 │  │ │
│  │  └───────────────────┬──────────────────────────────────┘  │ │
│  │                      ▼                                      │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ Stage 3: ScriptGenerationStage                       │  │ │
│  │  │  ├─ Template-based generator                         │  │ │
│  │  │  └─ AI Enhancer (Claude 3.5 Sonnet)                  │  │ │
│  │  └───────────────────┬──────────────────────────────────┘  │ │
│  │                      ▼                                      │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ Stage 4: AudioGenerationStage                        │  │ │
│  │  │  • Edge-TTS synthesis                                │  │ │
│  │  │  • Duration measurement (FFprobe)                    │  │ │
│  │  │  • Timing manifest generation                        │  │ │
│  │  └───────────────────┬──────────────────────────────────┘  │ │
│  │                      ▼                                      │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ Stage 5: VideoGenerationStage                        │  │ │
│  │  │  • Renderer selection                                │  │ │
│  │  │  • Frame rendering (PIL)                             │  │ │
│  │  │  • Video encoding (FFmpeg)                           │  │ │
│  │  │  • Audio muxing                                      │  │ │
│  │  └───────────────────┬──────────────────────────────────┘  │ │
│  │                      ▼                                      │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ Stage 6: OutputStage                                 │  │ │
│  │  │  • Validation                                        │  │ │
│  │  │  • Metadata generation                               │  │ │
│  │  │  • File organization                                 │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  └──────────────────────────────────────────────────────────────┘ │
│                             │                                     │
│  ┌──────────────────────────▼───────────────────────────────────┐ │
│  │                  RENDERING SYSTEM                            │ │
│  │                                                              │ │
│  │  ┌─────────────────────────────────────────────────────┐   │ │
│  │  │ Renderer Registry                                   │   │ │
│  │  │  • TitleRenderer                                    │   │ │
│  │  │  • ListRenderer                                     │   │ │
│  │  │  • CommandRenderer                                  │   │ │
│  │  │  • CodeComparisonRenderer                           │   │ │
│  │  │  • QuoteRenderer                                    │   │ │
│  │  │  • OutroRenderer                                    │   │ │
│  │  │  • LearningObjectivesRenderer                       │   │ │
│  │  │  • ProblemRenderer                                  │   │ │
│  │  │  • SolutionRenderer                                 │   │ │
│  │  │  • QuizRenderer                                     │   │ │
│  │  │  • CheckpointRenderer                               │   │ │
│  │  │  • ExerciseRenderer                                 │   │ │
│  │  └─────────────────────────────────────────────────────┘   │ │
│  └──────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │                 SHARED INFRASTRUCTURE                        │ │
│  │                                                              │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │ │
│  │  │   Config     │  │    Models    │  │    Utils     │      │ │
│  │  │  (Singleton) │  │  (Pydantic)  │  │  (Helpers)   │      │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘      │ │
│  └──────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                      EXTERNAL SERVICES                              │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│  │   Edge-TTS   │  │    FFmpeg    │  │  Claude API  │             │
│  │   (Azure)    │  │   (Local)    │  │ (Anthropic)  │             │
│  └──────────────┘  └──────────────┘  └──────────────┘             │
└─────────────────────────────────────────────────────────────────────┘
```

### 12.2 Sequence Diagram: Complete Pipeline Execution

```
User    CLI    Orchestrator    InputStage    ScriptStage    AudioStage    VideoStage    Output
 │       │           │              │              │              │             │          │
 │  cmd  │           │              │              │              │             │          │
 │──────>│           │              │              │              │             │          │
 │       │ execute() │              │              │              │             │          │
 │       │──────────>│              │              │              │             │          │
 │       │           │              │              │              │             │          │
 │       │           │ create_task  │              │              │             │          │
 │       │           │───────┐      │              │              │             │          │
 │       │           │       │      │              │              │             │          │
 │       │           │<──────┘      │              │              │             │          │
 │       │           │              │              │              │             │          │
 │       │           │ run_stage_1  │              │              │             │          │
 │       │           │─────────────>│              │              │             │          │
 │       │           │              │ adapt_input  │              │             │          │
 │       │           │              │──────┐       │              │             │          │
 │       │           │              │      │       │              │             │          │
 │       │           │              │<─────┘       │              │             │          │
 │       │           │              │              │              │             │          │
 │       │           │  VideoConfig │              │              │             │          │
 │       │           │<─────────────│              │              │             │          │
 │       │           │              │              │              │             │          │
 │       │           │ save_state   │              │              │             │          │
 │       │           │───────┐      │              │              │             │          │
 │       │           │       │      │              │              │             │          │
 │       │           │<──────┘      │              │              │             │          │
 │       │           │              │              │              │             │          │
 │       │           │           (skip stage 2 for clarity)       │             │          │
 │       │           │              │              │              │             │          │
 │       │           │ run_stage_3  │              │              │             │          │
 │       │           │─────────────────────────────>│              │             │          │
 │       │           │              │              │ generate()   │             │          │
 │       │           │              │              │────────┐     │             │          │
 │       │           │              │              │        │     │             │          │
 │       │           │              │              │<───────┘     │             │          │
 │       │           │              │              │              │             │          │
 │       │           │  VideoConfig + Narration    │              │             │          │
 │       │           │<─────────────────────────────│              │             │          │
 │       │           │              │              │              │             │          │
 │       │           │ run_stage_4  │              │              │             │          │
 │       │           │─────────────────────────────────────────────>│             │          │
 │       │           │              │              │              │ TTS         │          │
 │       │           │              │              │              │──────┐      │          │
 │       │           │              │              │              │      │      │          │
 │       │           │              │              │              │<─────┘      │          │
 │       │           │              │              │              │             │          │
 │       │           │  Audio Files + Timing Manifest             │             │          │
 │       │           │<─────────────────────────────────────────────│             │          │
 │       │           │              │              │              │             │          │
 │       │           │ run_stage_5  │              │              │             │          │
 │       │           │─────────────────────────────────────────────────────────>│          │
 │       │           │              │              │              │             │ render   │
 │       │           │              │              │              │             │──────┐   │
 │       │           │              │              │              │             │      │   │
 │       │           │              │              │              │             │<─────┘   │
 │       │           │              │              │              │             │          │
 │       │           │              │              │              │     video.mp4         │
 │       │           │<─────────────────────────────────────────────────────────│          │
 │       │           │              │              │              │             │          │
 │       │           │ run_stage_6  │              │              │             │          │
 │       │           │───────────────────────────────────────────────────────────────────>│
 │       │           │              │              │              │             │          │ validate
 │       │           │              │              │              │             │          │──────┐
 │       │           │              │              │              │             │          │      │
 │       │           │              │              │              │             │          │<─────┘
 │       │           │              │              │              │             │          │
 │       │           │ PipelineResult                             │             │          │
 │       │           │<───────────────────────────────────────────────────────────────────│
 │       │           │              │              │              │             │          │
 │       │  result   │              │              │              │             │          │
 │       │<──────────│              │              │              │             │          │
 │       │           │              │              │              │             │          │
 │ output│           │              │              │              │             │          │
 │<──────│           │              │              │              │             │          │
```

### 12.3 Data Model Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                        DATA MODELS                               │
│                                                                  │
│  ┌────────────────┐                                             │
│  │  InputConfig   │  Entry point (all interfaces)               │
│  ├────────────────┤                                             │
│  │ - source_type  │                                             │
│  │ - source_data  │                                             │
│  │ - options      │                                             │
│  └────────┬───────┘                                             │
│           │                                                      │
│           ▼                                                      │
│  ┌────────────────┐                                             │
│  │  VideoConfig   │  Normalized structure                       │
│  ├────────────────┤                                             │
│  │ - video_id     │                                             │
│  │ - title        │                                             │
│  │ - description  │                                             │
│  │ - scenes       │───┐                                         │
│  │ - defaults     │   │                                         │
│  └────────────────┘   │                                         │
│                       │                                         │
│                       ▼                                         │
│            ┌────────────────┐                                   │
│            │  SceneConfig   │  Individual scene                 │
│            ├────────────────┤                                   │
│            │ - scene_id     │                                   │
│            │ - scene_type   │                                   │
│            │ - visual_c...  │                                   │
│            │ - narration    │                                   │
│            │ - voice        │                                   │
│            │ - durations    │                                   │
│            └────────────────┘                                   │
│                                                                  │
│  ┌────────────────┐                                             │
│  │  VideoSet      │  Batch processing                           │
│  ├────────────────┤                                             │
│  │ - set_id       │                                             │
│  │ - name         │                                             │
│  │ - videos       │───┐                                         │
│  │ - metadata     │   │                                         │
│  └────────────────┘   │                                         │
│                       │                                         │
│                       └─────> List[VideoConfig]                 │
│                                                                  │
│  ┌────────────────┐                                             │
│  │ PipelineResult │  Final output                               │
│  ├────────────────┤                                             │
│  │ - success      │                                             │
│  │ - task_id      │                                             │
│  │ - video_config │                                             │
│  │ - video_path   │                                             │
│  │ - artifacts    │                                             │
│  │ - metrics      │                                             │
│  │ - errors       │                                             │
│  │ - warnings     │                                             │
│  └────────────────┘                                             │
│                                                                  │
│  ┌────────────────┐                                             │
│  │   TaskState    │  State persistence                          │
│  ├────────────────┤                                             │
│  │ - task_id      │                                             │
│  │ - status       │  (PENDING|RUNNING|COMPLETED|FAILED)        │
│  │ - stages       │                                             │
│  │ - current_...  │                                             │
│  │ - errors       │                                             │
│  │ - timestamps   │                                             │
│  └────────────────┘                                             │
└──────────────────────────────────────────────────────────────────┘
```

---

## Architecture Decision Records (ADRs)

### ADR-001: Audio-First Pipeline Architecture

**Status:** Accepted
**Date:** 2025-10-04
**Decision:** Generate audio first, then render video to match exact audio durations

**Context:**
- Need perfect audio/visual synchronization
- Variable TTS durations (same text → different duration per voice)
- Manual timing adjustments are error-prone

**Decision:**
1. Generate all audio files first (Stage 4)
2. Measure actual durations with FFprobe
3. Create timing manifest
4. Render video frames to match exact audio timing (Stage 5)

**Consequences:**
- ✅ Perfect A/V sync (no drift)
- ✅ No manual timing adjustments needed
- ✅ Reliable, automated process
- ❌ Cannot preview video before audio generation
- ❌ Audio regeneration requires video regeneration

**Alternatives Considered:**
- Video-first (rejected: requires manual timing adjustments)
- Concurrent generation (rejected: synchronization complexity)

---

### ADR-002: Modular Renderer System

**Status:** Accepted
**Date:** 2025-10-05
**Decision:** Break monolithic renderer (1,476 LOC) into 7 focused modules

**Context:**
- Original renderer: 1,476 lines, hard to maintain
- Adding new scene types required modifying monolith
- Testing individual renderers was difficult

**Decision:**
1. Create `BaseRenderer` abstract class
2. Implement scene-specific renderers (<500 LOC each)
3. Registry pattern for renderer lookup
4. 100% test coverage on each module

**Module Breakdown:**
- `basic_scenes.py`: General-purpose (title, list, outro, quote)
- `educational_scenes.py`: Learning content (objectives, problem, solution)
- `comparison_scenes.py`: Code comparisons
- `checkpoint_scenes.py`: Progress tracking (quiz, exercise, checkpoint)

**Consequences:**
- ✅ 206 LOC average per module (down from 1,476)
- ✅ Easy to add new scene types (extend base class)
- ✅ 100% test coverage per module
- ✅ Clear separation of concerns
- ❌ More files to manage (7 vs 1)

**Metrics:**
- Before: 1 file, 1,476 LOC
- After: 7 files, ~206 LOC each
- Test coverage: 59% → 100%

---

### ADR-003: Pydantic for Data Validation

**Status:** Accepted
**Date:** 2025-10-03
**Decision:** Use Pydantic v2 for all data models and validation

**Context:**
- Need strong typing for reliability
- Input validation critical for security (DoS prevention)
- API compatibility across CLI/Web/Python

**Decision:**
1. Define all models with Pydantic BaseModel
2. Use Field() for validation rules
3. Custom validators with `@model_validator`
4. Automatic JSON serialization/deserialization

**Example:**
```python
class SceneConfig(BaseModel):
    scene_id: str = Field(max_length=200)
    narration: str = Field(max_length=50000)
    min_duration: float = Field(ge=0, le=300)
    max_duration: float = Field(ge=0, le=300)

    @model_validator(mode='after')
    def validate_durations(self):
        if self.min_duration > self.max_duration:
            raise ValueError("min > max")
        return self
```

**Consequences:**
- ✅ Type safety throughout system
- ✅ Automatic validation at boundaries
- ✅ DoS protection (length limits)
- ✅ Self-documenting schemas
- ✅ FastAPI integration for free
- ❌ Pydantic dependency required

---

### ADR-004: Stage-Based Pipeline with State Persistence

**Status:** Accepted
**Date:** 2025-10-06
**Decision:** Implement 6-stage pipeline with state persistence and resume capability

**Context:**
- Video generation takes 5-10 minutes
- Failures mid-process waste time
- Need ability to resume from checkpoint
- Need progress tracking for UX

**Decision:**
1. Define 6 sequential stages
2. Persist state after each stage (JSON)
3. Enable resume from last completed stage
4. Event-driven progress tracking

**Stages:**
1. Input Adaptation
2. Content Parsing
3. Script Generation
4. Audio Generation
5. Video Generation
6. Output & Validation

**State Persistence:**
```json
{
  "task_id": "task_abc123",
  "status": "running",
  "current_stage": "video_generation",
  "stages": [
    {"name": "input", "status": "completed", "output": {...}},
    {"name": "parsing", "status": "completed", "output": {...}},
    {"name": "script", "status": "completed", "output": {...}},
    {"name": "audio", "status": "completed", "output": {...}},
    {"name": "video", "status": "running", "output": null}
  ]
}
```

**Consequences:**
- ✅ Resume from failures (no wasted work)
- ✅ Real-time progress tracking
- ✅ Audit trail for debugging
- ✅ Testable stage isolation
- ❌ Disk I/O for state persistence
- ❌ State management complexity

---

## Conclusion

This architecture represents a **production-ready, well-tested, modular video generation system** with the following strengths:

### Architectural Strengths
1. **Modularity:** Clear separation of concerns across 7 renderer modules and 6 pipeline stages
2. **Extensibility:** Plugin architecture for renderers and adapters
3. **Reliability:** 79% test coverage, 475 passing tests, 0 regressions
4. **Performance:** GPU acceleration, NumPy vectorization, batch parallelization
5. **Maintainability:** Comprehensive documentation, type hints, ADRs

### Technical Achievements
- **Perfect A/V Sync:** Audio-first architecture eliminates manual timing
- **Multilingual:** 29 languages with native TTS voices
- **AI-Enhanced:** Optional Claude 3.5 Sonnet integration
- **Educational:** 12 scene types including pedagogical templates
- **Production-Deployed:** Actively generating videos in real-world usage

### Future Enhancements
1. **Distributed Processing:** Queue-based (Celery + Redis) for horizontal scaling
2. **Web Dashboard:** Real-time monitoring and control
3. **Docker Deployment:** Containerized for easier deployment
4. **Cloud Storage:** S3/GCS integration for output
5. **Advanced Caching:** Frame-level caching for faster regeneration

---

**Document Prepared By:** System Architecture Designer
**Review Status:** Approved
**Next Review:** 2026-01-27

---
