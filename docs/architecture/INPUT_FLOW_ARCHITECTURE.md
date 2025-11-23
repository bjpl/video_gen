# Unified Input Flow Architecture

**Status:** Approved
**Version:** 1.0.0
**Date:** 2025-11-22
**Author:** System Architecture Designer

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Design Principles](#design-principles)
4. [Unified Input Flow Design](#unified-input-flow-design)
5. [Component Architecture](#component-architecture)
6. [State Management Patterns](#state-management-patterns)
7. [API Contracts](#api-contracts)
8. [UI/UX Wireframes](#uiux-wireframes)
9. [Accessibility Requirements](#accessibility-requirements)
10. [Implementation Roadmap](#implementation-roadmap)

---

## Executive Summary

This document defines the unified architecture for all input source type flows in the video generation system. The design establishes consistent UX patterns across Document, YouTube, Wizard, and Programmatic input methods while maintaining the flexibility required for each input type's unique requirements.

### Key Architectural Decisions

| Decision | Rationale |
|----------|-----------|
| Single Entry Point Pattern | Reduces cognitive load, enables progressive disclosure |
| Adapter Strategy Pattern | Allows input-specific logic while maintaining unified interface |
| Real-time Validation | Provides immediate feedback, prevents invalid submissions |
| Progressive Enhancement | Core functionality works without JS; enhanced UX with modern browsers |
| Component-Based UI | Maximizes reuse, ensures visual consistency |

---

## Architecture Overview

### System Context (C4 Level 1)

```
+--------------------------------------------------------------------------------+
|                              VIDEO GENERATION SYSTEM                            |
+--------------------------------------------------------------------------------+
|                                                                                |
|  +------------------+     +------------------+     +------------------+        |
|  |    WEB CLIENT    |     |   CLI CLIENT     |     | PROGRAMMATIC API |        |
|  | (Browser/Mobile) |     | (Terminal)       |     | (Python/REST)    |        |
|  +--------+---------+     +--------+---------+     +--------+---------+        |
|           |                        |                        |                  |
|           +------------------------+------------------------+                  |
|                                    |                                           |
|                                    v                                           |
|  +------------------------------------------------------------------------+   |
|  |                    UNIFIED INPUT CONTROLLER                             |   |
|  |  +-------------+  +-------------+  +-------------+  +-------------+     |   |
|  |  | Document    |  | YouTube     |  | Wizard      |  | Programmatic|     |   |
|  |  | Handler     |  | Handler     |  | Handler     |  | Handler     |     |   |
|  |  +------+------+  +------+------+  +------+------+  +------+------+     |   |
|  |         |                |                |                |            |   |
|  |         +----------------+----------------+----------------+            |   |
|  |                                   |                                     |   |
|  |                                   v                                     |   |
|  |  +---------------------------------------------------------------------+|   |
|  |  |                    INPUT ADAPTER REGISTRY                           ||   |
|  |  | - DocumentAdapter    - YouTubeAdapter                               ||   |
|  |  | - InteractiveWizard  - ProgrammaticAdapter  - YAMLFileAdapter       ||   |
|  |  +---------------------------------------------------------------------+|   |
|  +------------------------------------------------------------------------+   |
|                                    |                                           |
|                                    v                                           |
|  +------------------------------------------------------------------------+   |
|  |                         VideoSet (Unified Output)                       |   |
|  +------------------------------------------------------------------------+   |
|                                    |                                           |
|                                    v                                           |
|  +------------------------------------------------------------------------+   |
|  |                    PIPELINE ORCHESTRATOR                                |   |
|  |  Input Stage -> Script Gen -> Audio Gen -> Video Gen -> Output Stage   |   |
|  +------------------------------------------------------------------------+   |
+--------------------------------------------------------------------------------+
```

### Container Diagram (C4 Level 2)

```
+-----------------------------------------------------------------------------------+
|                                    Frontend Layer                                  |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  +------------------------+  +------------------------+  +--------------------+   |
|  |  Unified Create View   |  |  Input Type Selector   |  |  Preview Panel     |   |
|  |  (create-unified.html) |  |  (InputTypeCard)       |  |  (PreviewRenderer) |   |
|  +------------------------+  +------------------------+  +--------------------+   |
|           |                           |                           |               |
|           +---------------------------+---------------------------+               |
|                                       |                                           |
|                                       v                                           |
|  +-------------------------------------------------------------------------------+|
|  |                           Input Flow Components                               ||
|  | +----------------+ +----------------+ +----------------+ +----------------+    ||
|  | | DocumentUpload | | YouTubeParser  | | WizardForm     | | JSONEditor     |    ||
|  | | - File drop    | | - URL input    | | - Step wizard  | | - Code editor  |    ||
|  | | - URL input    | | - Preview      | | - Templates    | | - Validation   |    ||
|  | | - Preview      | | - Extract      | | - Review       | | - Preview      |    ||
|  | +----------------+ +----------------+ +----------------+ +----------------+    ||
|  +-------------------------------------------------------------------------------+|
|                                       |                                           |
+-----------------------------------------------------------------------------------+
                                        |
                                        v
+-----------------------------------------------------------------------------------+
|                                   Backend Layer                                    |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  +------------------------+  +------------------------+  +---------------------+  |
|  |  FastAPI Application   |  |  Input Controller      |  |  Validation Service |  |
|  |  (/api/parse/*)        |  |  (UnifiedInputHandler) |  |  (InputValidator)   |  |
|  +------------------------+  +------------------------+  +---------------------+  |
|           |                           |                           |               |
|           +---------------------------+---------------------------+               |
|                                       |                                           |
|                                       v                                           |
|  +-------------------------------------------------------------------------------+|
|  |                           Input Adapter Layer                                 ||
|  | +----------------+ +----------------+ +----------------+ +----------------+    ||
|  | |DocumentAdapter | | YouTubeAdapter | |InteractiveWiz | |ProgrammaticAdp|    ||
|  | | - parse_md     | | - fetch_trans  | | - collect_data| | - validate_json|    ||
|  | | - extract_sect | | - extract_key  | | - apply_templ | | - transform    |    ||
|  | | - gen_scenes   | | - create_scene | | - gen_scenes  | | - gen_scenes   |    ||
|  | +----------------+ +----------------+ +----------------+ +----------------+    ||
|  +-------------------------------------------------------------------------------+|
|                                       |                                           |
|                                       v                                           |
|  +-------------------------------------------------------------------------------+|
|  |                              VideoSet Output                                  ||
|  |  { set_id, name, description, videos: [VideoConfig], metadata }               ||
|  +-------------------------------------------------------------------------------+|
+-----------------------------------------------------------------------------------+
```

---

## Design Principles

### 1. Unified Entry Point

All input flows converge to a single entry point that provides:
- Consistent navigation patterns
- Progressive disclosure of complexity
- Clear visual hierarchy

### 2. Input Type Abstraction

Each input type implements the `InputAdapter` interface:

```python
class InputAdapter(ABC):
    @abstractmethod
    async def adapt(self, source: Any, **kwargs) -> InputAdapterResult:
        """Convert input to VideoSet"""
        pass

    async def validate_source(self, source: Any) -> bool:
        """Validate input before processing"""
        pass

    def supports_format(self, format_type: str) -> bool:
        """Check format compatibility"""
        pass
```

### 3. Real-time Validation

All inputs validated at multiple levels:
- **Client-side:** Immediate format/size checks
- **Server-side:** Security, business rules
- **Adapter-level:** Source-specific validation

### 4. Progressive Enhancement

```
Base Experience (HTML/CSS only):
  - Form submission works
  - Server-side rendering
  - Full functionality

Enhanced Experience (JavaScript enabled):
  - Real-time validation
  - Drag-and-drop uploads
  - Live previews
  - Progress indicators
```

### 5. Accessibility First

All components designed with WCAG 2.1 AA compliance:
- Keyboard navigation
- Screen reader support
- High contrast modes
- Focus management

---

## Unified Input Flow Design

### Flow State Machine

```
                    +---------------+
                    |    START      |
                    +-------+-------+
                            |
                            v
                    +---------------+
                    | SELECT INPUT  |  <-- User chooses input type
                    |    TYPE       |
                    +-------+-------+
                            |
            +---------------+---------------+---------------+
            |               |               |               |
            v               v               v               v
    +-------+---+   +-------+---+   +-------+---+   +-------+---+
    | DOCUMENT  |   | YOUTUBE   |   | WIZARD    |   |PROGRAMMATIC|
    | FLOW      |   | FLOW      |   | FLOW      |   | FLOW      |
    +-------+---+   +-------+---+   +-------+---+   +-------+---+
            |               |               |               |
            +---------------+---------------+---------------+
                            |
                            v
                    +---------------+
                    |   CONFIGURE   |  <-- Common configuration
                    |   OPTIONS     |      (color, voice, etc.)
                    +-------+-------+
                            |
                            v
                    +---------------+
                    |   VALIDATE    |  <-- Real-time validation
                    |   & PREVIEW   |
                    +-------+-------+
                            |
                            v
                    +---------------+
                    |   GENERATE    |  <-- Submit to pipeline
                    +-------+-------+
                            |
                            v
                    +---------------+
                    |   COMPLETE    |
                    +---------------+
```

### Input Type Flows

#### Document Flow

```
+-----------------------------------------------------------------------+
|                         DOCUMENT INPUT FLOW                            |
+-----------------------------------------------------------------------+
|                                                                       |
|  Step 1: Source Selection                                             |
|  +----------------------------+  +----------------------------+       |
|  |     File Upload Zone       |  |      URL Input             |       |
|  | +------------------------+ |  | +------------------------+ |       |
|  | |   Drag & Drop Here     | |  | | https://example.com/... | |       |
|  | |   or Click to Browse   | |  | +------------------------+ |       |
|  | |   .md .txt .pdf .docx  | |  |                            |       |
|  | +------------------------+ |  |   [GitHub] [Raw URL]       |       |
|  +----------------------------+  +----------------------------+       |
|                                                                       |
|  Step 2: Document Preview                                             |
|  +-------------------------------------------------------------------+|
|  | Document Structure:                                                ||
|  | +---------------------------------------------------------------+ ||
|  | | # Title Detected                                              | ||
|  | | ## Section 1 -> Scene: title                                  | ||
|  | | ## Section 2 -> Scene: command (code blocks detected)         | ||
|  | | ## Section 3 -> Scene: list (bullet points detected)          | ||
|  | | [Outro will be auto-generated]                                | ||
|  | +---------------------------------------------------------------+ ||
|  +-------------------------------------------------------------------+|
|                                                                       |
|  Step 3: Configure Options                                            |
|  +-------------------+  +-------------------+  +-------------------+  |
|  | Videos: [1-10]    |  | Color: [Select]   |  | Voice: [Select]   |  |
|  +-------------------+  +-------------------+  +-------------------+  |
|  | [ ] Split by H2   |  | [ ] Use AI Narr.  |  | Languages: [+]    |  |
|  +-------------------+  +-------------------+  +-------------------+  |
+-----------------------------------------------------------------------+
```

#### YouTube Flow

```
+-----------------------------------------------------------------------+
|                         YOUTUBE INPUT FLOW                             |
+-----------------------------------------------------------------------+
|                                                                       |
|  Step 1: Video Selection                                              |
|  +-------------------------------------------------------------------+|
|  | YouTube URL or Video ID:                                          ||
|  | +---------------------------------------------------------------+ ||
|  | | https://youtube.com/watch?v=...           [Paste] [Validate]  | ||
|  | +---------------------------------------------------------------+ ||
|  +-------------------------------------------------------------------+|
|                                                                       |
|  Step 2: Video Preview (after validation)                             |
|  +-------------------------------------------------------------------+|
|  | +---------------+  Video Title: "Introduction to Python"          ||
|  | | [Thumbnail]   |  Duration: 12:34                                ||
|  | |               |  Channel: @PythonTutorials                      ||
|  | +---------------+  Transcript: Available (English)                ||
|  +-------------------------------------------------------------------+|
|                                                                       |
|  Step 3: Segment Selection                                            |
|  +-------------------------------------------------------------------+|
|  | [x] 0:00-1:30   Introduction to async programming                 ||
|  | [x] 1:30-3:45   Why use async/await                               ||
|  | [ ] 3:45-6:20   Basic async syntax                                ||
|  | [x] 6:20-8:15   Practical example - web scraping                  ||
|  | [ ] 8:15-10:30  Common mistakes and solutions                     ||
|  +-------------------------------------------------------------------+|
|                                                                       |
|  Step 4: Configure (same as Document)                                 |
+-----------------------------------------------------------------------+
```

#### Wizard Flow

```
+-----------------------------------------------------------------------+
|                          WIZARD INPUT FLOW                             |
+-----------------------------------------------------------------------+
|                                                                       |
|  Progress: [=====>                    ] Step 2 of 5                   |
|                                                                       |
|  Step 1: Video Basics                                                 |
|  +-------------------------------------------------------------------+|
|  | What is your video about?                                         ||
|  | +---------------------------------------------------------------+ ||
|  | | Python decorators tutorial                                    | ||
|  | +---------------------------------------------------------------+ ||
|  |                                                                    |
|  | Suggested Title: "Python Decorators Tutorial"                     ||
|  | +---------------------------------------------------------------+ ||
|  | | [Accept] or customize:                                        | ||
|  | +---------------------------------------------------------------+ ||
|  +-------------------------------------------------------------------+|
|                                                                       |
|  Step 2: Content Type Selection                                       |
|  +-------------------------------------------------------------------+|
|  | +----------------+  +----------------+  +----------------+        ||
|  | |   Tutorial     |  |   Overview     |  |Troubleshooting |        ||
|  | | Step-by-step   |  | Feature tour   |  | Problem/Fix    |        ||
|  | +----------------+  +----------------+  +----------------+        ||
|  | +----------------+  +----------------+  +----------------+        ||
|  | |   Comparison   |  | Best Practices |  |    Custom      |        ||
|  | |   A vs B       |  | Tips & tricks  |  | Build your own |        ||
|  | +----------------+  +----------------+  +----------------+        ||
|  +-------------------------------------------------------------------+|
|                                                                       |
|  Step 3: Scene Builder (template-guided)                              |
|  +-------------------------------------------------------------------+|
|  | Template: Tutorial (5 scenes)                                     ||
|  |                                                                    |
|  | 1. [Title]    "Python Decorators Explained"     [Edit]           ||
|  | 2. [Command]  "What are decorators"             [Edit]           ||
|  | 3. [Command]  "Basic syntax"                    [Edit]           ||
|  | 4. [List]     "Practical examples"              [Edit]           ||
|  | 5. [Outro]    "Master Decorators Today"         [Edit]           ||
|  |                                                                    |
|  | [+ Add Scene] [Reorder] [Remove]                                  ||
|  +-------------------------------------------------------------------+|
|                                                                       |
|  Step 4: Review & Confirm                                             |
|  +-------------------------------------------------------------------+|
|  | Video Summary:                                                    ||
|  | - Title: Python Decorators Explained                              ||
|  | - Scenes: 5                                                       ||
|  | - Est. Duration: 58 seconds                                       ||
|  | - Voice: Male (Andrew)                                            ||
|  | - Color: Purple                                                   ||
|  |                                                                    |
|  |                    [Back] [Generate Video]                        ||
|  +-------------------------------------------------------------------+|
+-----------------------------------------------------------------------+
```

#### Programmatic Flow

```
+-----------------------------------------------------------------------+
|                       PROGRAMMATIC INPUT FLOW                          |
+-----------------------------------------------------------------------+
|                                                                       |
|  Input Method: [JSON Editor] [YAML Upload] [API Reference]            |
|                                                                       |
|  +-------------------------------------------------------------------+|
|  | JSON Editor:                                          [Validate]  ||
|  | +---------------------------------------------------------------+ ||
|  | | {                                                             | ||
|  | |   "set_id": "my_video_set",                                   | ||
|  | |   "set_name": "Tutorial Series",                              | ||
|  | |   "videos": [                                                 | ||
|  | |     {                                                         | ||
|  | |       "video_id": "video_01",                                 | ||
|  | |       "title": "Getting Started",                             | ||
|  | |       "scenes": [...]                                         | ||
|  | |     }                                                         | ||
|  | |   ]                                                           | ||
|  | | }                                                             | ||
|  | +---------------------------------------------------------------+ ||
|  +-------------------------------------------------------------------+|
|                                                                       |
|  Validation Results:                                                  |
|  +-------------------------------------------------------------------+|
|  | [OK] Schema valid                                                 ||
|  | [OK] 1 video, 3 scenes detected                                   ||
|  | [WARN] Scene 2 narration exceeds recommended length               ||
|  +-------------------------------------------------------------------+|
|                                                                       |
|  Preview Panel:                                                       |
|  +-------------------------------------------------------------------+|
|  | +---------------+  Video: Getting Started                         ||
|  | | [Scene 1]     |  Scenes: 3                                      ||
|  | | Title         |  Duration: ~45s                                 ||
|  | +---------------+                                                 ||
|  +-------------------------------------------------------------------+|
+-----------------------------------------------------------------------+
```

---

## Component Architecture

### Frontend Component Hierarchy

```
UnifiedCreateView
  |
  +-- InputTypeSelectorPanel
  |     +-- InputTypeCard (Document)
  |     +-- InputTypeCard (YouTube)
  |     +-- InputTypeCard (Wizard)
  |     +-- InputTypeCard (Programmatic)
  |
  +-- InputFlowContainer
  |     +-- DocumentInputFlow
  |     |     +-- FileDropZone
  |     |     +-- URLInputField
  |     |     +-- DocumentPreview
  |     |     +-- StructureAnalyzer
  |     |
  |     +-- YouTubeInputFlow
  |     |     +-- URLInputField
  |     |     +-- VideoPreview
  |     |     +-- TranscriptSegmentPicker
  |     |
  |     +-- WizardInputFlow
  |     |     +-- ProgressIndicator
  |     |     +-- WizardStepContainer
  |     |     +-- TemplateSelector
  |     |     +-- SceneBuilder
  |     |     +-- ReviewPanel
  |     |
  |     +-- ProgrammaticInputFlow
  |           +-- JSONEditor
  |           +-- YAMLUploader
  |           +-- SchemaValidator
  |           +-- CodePreview
  |
  +-- ConfigurationPanel
  |     +-- ColorPicker
  |     +-- VoiceSelector
  |     +-- LanguageSelector
  |     +-- AdvancedOptions
  |
  +-- PreviewPanel
  |     +-- SceneList
  |     +-- ScenePreview
  |     +-- DurationEstimator
  |
  +-- ActionBar
        +-- ValidationIndicator
        +-- GenerateButton
        +-- SaveDraftButton
```

### Shared Components

```python
# Reusable UI Components (Alpine.js/HTMX)

class FileDropZone:
    """Drag-and-drop file upload with preview"""
    props = {
        'accept': List[str],           # e.g., ['.md', '.txt', '.pdf']
        'max_size_mb': int,             # Default: 10
        'on_upload': Callable,
        'on_error': Callable,
    }

class URLInputField:
    """URL input with real-time validation"""
    props = {
        'placeholder': str,
        'validators': List[Callable],
        'on_valid': Callable,
        'debounce_ms': int,            # Default: 300
    }

class ProgressIndicator:
    """Multi-step progress bar"""
    props = {
        'steps': List[str],
        'current_step': int,
        'allow_navigation': bool,
    }

class ColorPicker:
    """Accent color selector"""
    props = {
        'colors': List[str],           # ['orange', 'blue', 'purple', ...]
        'selected': str,
        'on_change': Callable,
    }

class VoiceSelector:
    """Voice selection with preview"""
    props = {
        'voices': List[VoiceOption],
        'selected': str,
        'on_change': Callable,
        'preview_enabled': bool,
    }
```

---

## State Management Patterns

### Input Flow State Schema

```python
@dataclass
class InputFlowState:
    """Unified state for all input flows"""

    # Flow identification
    flow_type: Literal['document', 'youtube', 'wizard', 'programmatic']
    flow_id: str  # Unique session ID

    # Current step
    current_step: int
    total_steps: int
    step_history: List[int]  # For back navigation

    # Input data (type-specific)
    input_data: Union[
        DocumentInputData,
        YouTubeInputData,
        WizardInputData,
        ProgrammaticInputData
    ]

    # Common configuration
    config: InputConfiguration

    # Validation state
    validation_state: ValidationState

    # Preview data
    preview: Optional[PreviewData]

    # Draft persistence
    draft_id: Optional[str]
    last_saved: Optional[datetime]

@dataclass
class InputConfiguration:
    """Common configuration across all input types"""
    accent_color: str = 'blue'
    voice: str = 'male'
    languages: List[str] = field(default_factory=lambda: ['en'])
    use_ai_narration: bool = False
    target_duration: Optional[int] = 60
    output_format: str = 'mp4'

@dataclass
class ValidationState:
    """Validation state tracking"""
    is_valid: bool = False
    errors: List[ValidationError] = field(default_factory=list)
    warnings: List[ValidationWarning] = field(default_factory=list)
    last_validated: Optional[datetime] = None

@dataclass
class PreviewData:
    """Generated preview information"""
    video_count: int
    scene_count: int
    estimated_duration: float
    structure_preview: List[ScenePreview]
```

### State Transitions

```
                                         Document Flow
                                    +-------------------+
                                    |                   |
              +---------------------+  source_selected  +---------------------+
              |                     |                   |                     |
              v                     +-------------------+                     v
      +---------------+                                             +---------------+
      | file_uploaded |                                             | url_entered   |
      +-------+-------+                                             +-------+-------+
              |                                                             |
              +------------------------------+------------------------------+
                                             |
                                             v
                                    +--------+--------+
                                    | document_parsed |
                                    +--------+--------+
                                             |
                                             v
                                    +--------+--------+
                                    | preview_ready   |
                                    +--------+--------+
                                             |
                                             v
                                    +--------+--------+
                                    | configured      |
                                    +--------+--------+
                                             |
                                             v
                                    +--------+--------+
                                    | validated       |
                                    +--------+--------+
                                             |
                                             v
                                    +--------+--------+
                                    | generating      |
                                    +--------+--------+
                                             |
                                             v
                                    +--------+--------+
                                    | complete        |
                                    +--------+--------+
```

### State Persistence Strategy

```python
class InputFlowStateManager:
    """Manages state persistence for input flows"""

    def __init__(self, storage_backend: StorageBackend):
        self.storage = storage_backend
        self.auto_save_interval = 30  # seconds

    async def save_draft(self, state: InputFlowState) -> str:
        """Save current state as draft"""
        draft_id = state.draft_id or generate_draft_id()
        await self.storage.save(
            key=f"draft:{draft_id}",
            data=state.to_dict(),
            ttl=timedelta(days=7)
        )
        return draft_id

    async def load_draft(self, draft_id: str) -> Optional[InputFlowState]:
        """Load draft state"""
        data = await self.storage.get(f"draft:{draft_id}")
        if data:
            return InputFlowState.from_dict(data)
        return None

    async def cleanup_expired_drafts(self):
        """Remove expired drafts"""
        await self.storage.delete_expired(prefix="draft:")
```

---

## API Contracts

### Unified Input API Endpoint

```python
# POST /api/input/process
# Unified endpoint for all input types

class UnifiedInputRequest(BaseModel):
    """Unified input request model"""

    input_type: Literal['document', 'youtube', 'wizard', 'programmatic']

    # Type-specific source data
    source: Union[
        DocumentSource,
        YouTubeSource,
        WizardSource,
        ProgrammaticSource
    ]

    # Common configuration
    config: InputConfig

    # Processing options
    options: ProcessingOptions = ProcessingOptions()

class DocumentSource(BaseModel):
    """Document input source"""
    content: Optional[str] = None      # Raw content
    file_path: Optional[str] = None    # Local file path
    url: Optional[HttpUrl] = None      # Remote URL

    @model_validator(mode='after')
    def validate_source(self):
        if not any([self.content, self.file_path, self.url]):
            raise ValueError("At least one of content, file_path, or url required")
        return self

class YouTubeSource(BaseModel):
    """YouTube input source"""
    url: Optional[HttpUrl] = None
    video_id: Optional[str] = None
    segments: Optional[List[TimeRange]] = None  # Selected segments

class WizardSource(BaseModel):
    """Wizard input source"""
    template: Optional[str] = None
    responses: Dict[str, Any]
    scenes: List[WizardScene]

class ProgrammaticSource(BaseModel):
    """Programmatic input source"""
    video_set: VideoSetSchema

class InputConfig(BaseModel):
    """Common configuration"""
    accent_color: str = Field(default='blue', pattern='^(orange|blue|purple|green|pink|cyan)$')
    voice: str = Field(default='male')
    voices: Optional[List[str]] = None
    languages: List[str] = Field(default=['en'])
    use_ai_narration: bool = False
    target_duration: Optional[int] = Field(default=60, ge=10, le=600)
    video_count: int = Field(default=1, ge=1, le=20)
    split_by_h2: bool = False

class ProcessingOptions(BaseModel):
    """Processing options"""
    async_mode: bool = True           # Background processing
    generate_preview: bool = True      # Generate preview before full processing
    validate_only: bool = False        # Only validate, don't process
    draft_id: Optional[str] = None     # Resume from draft
```

### Response Contracts

```python
class UnifiedInputResponse(BaseModel):
    """Unified response for input processing"""

    success: bool
    task_id: Optional[str] = None

    # Validation results
    validation: ValidationResult

    # Preview (if requested and valid)
    preview: Optional[PreviewResult] = None

    # Processing status
    status: ProcessingStatus

    # Error information
    error: Optional[ErrorDetail] = None

class ValidationResult(BaseModel):
    """Validation result details"""
    is_valid: bool
    errors: List[ValidationError] = []
    warnings: List[ValidationWarning] = []

class PreviewResult(BaseModel):
    """Preview information"""
    video_count: int
    scenes: List[ScenePreview]
    estimated_duration: float
    structure: ContentStructure

class ProcessingStatus(BaseModel):
    """Processing status"""
    state: Literal['pending', 'validating', 'processing', 'complete', 'failed']
    progress: float = 0.0  # 0.0 to 1.0
    stage: Optional[str] = None
    message: Optional[str] = None
```

### Validation API

```python
# POST /api/input/validate
# Real-time validation endpoint

class ValidationRequest(BaseModel):
    """Request for real-time validation"""
    input_type: str
    partial_data: Dict[str, Any]  # Partial input for progressive validation
    field: Optional[str] = None   # Specific field to validate

class ValidationResponse(BaseModel):
    """Validation response"""
    is_valid: bool
    field_errors: Dict[str, List[str]]
    global_errors: List[str]
    suggestions: List[str]
```

### Preview API

```python
# POST /api/input/preview
# Generate preview without full processing

class PreviewRequest(BaseModel):
    """Preview generation request"""
    input_type: str
    source: Dict[str, Any]
    config: InputConfig

class PreviewResponse(BaseModel):
    """Preview response"""
    success: bool
    preview: PreviewResult
    estimated_processing_time: float
```

---

## UI/UX Wireframes

### Main Input Selection Screen

```
+------------------------------------------------------------------+
|                                                                  |
|  [Logo]  Create New Video                    [Draft] [History]   |
|                                                                  |
+------------------------------------------------------------------+
|                                                                  |
|  Choose how you want to create your video:                       |
|                                                                  |
|  +------------------------+  +------------------------+          |
|  |    [Document Icon]     |  |    [YouTube Icon]      |          |
|  |                        |  |                        |          |
|  |      Document          |  |       YouTube          |          |
|  |                        |  |                        |          |
|  | Upload README, docs,   |  | Extract from video    |          |
|  | or paste URL           |  | transcripts           |          |
|  +------------------------+  +------------------------+          |
|                                                                  |
|  +------------------------+  +------------------------+          |
|  |    [Wizard Icon]       |  |    [Code Icon]         |          |
|  |                        |  |                        |          |
|  |       Wizard           |  |     Programmatic       |          |
|  |                        |  |                        |          |
|  | Guided step-by-step    |  | JSON/YAML for power   |          |
|  | creation               |  | users                  |          |
|  +------------------------+  +------------------------+          |
|                                                                  |
|  ---- Or import existing project ----                            |
|                                                                  |
|  [Resume Draft v] [Import YAML] [Paste JSON]                     |
|                                                                  |
+------------------------------------------------------------------+
```

### Document Input Flow Screen

```
+------------------------------------------------------------------+
|                                                                  |
|  [<] Back    Document Input    Step 1 of 3    [Save Draft]       |
|                                                                  |
+------------------------------------------------------------------+
|                                                                  |
|  Upload your document or paste a URL:                            |
|                                                                  |
|  +------------------------------------------------------------+  |
|  |                                                            |  |
|  |     +------------------------------------------+           |  |
|  |     |                                          |           |  |
|  |     |     Drop files here                      |           |  |
|  |     |     or click to browse                   |           |  |
|  |     |                                          |           |  |
|  |     |     Supports: .md .txt .pdf .docx        |           |  |
|  |     |     Max size: 10MB                       |           |  |
|  |     |                                          |           |  |
|  |     +------------------------------------------+           |  |
|  |                                                            |  |
|  |                    --- OR ---                              |  |
|  |                                                            |  |
|  |  URL: [____________________________________________]       |  |
|  |       [GitHub Raw] [Paste from clipboard]                  |  |
|  |                                                            |  |
|  +------------------------------------------------------------+  |
|                                                                  |
|  Document Preview:                                               |
|  +------------------------------------------------------------+  |
|  |  No document loaded. Upload a file or enter a URL above.   |  |
|  +------------------------------------------------------------+  |
|                                                                  |
|                                        [Cancel] [Next: Configure]|
|                                                                  |
+------------------------------------------------------------------+
```

### Configuration Panel (Common)

```
+------------------------------------------------------------------+
|                                                                  |
|  Configuration                                                   |
|                                                                  |
+------------------------------------------------------------------+
|                                                                  |
|  Visual Style                                                    |
|  +------------------------------------------------------------+  |
|  |  Accent Color:                                             |  |
|  |  [O] Orange  [O] Blue  [O] Purple  [O] Green  [O] Pink     |  |
|  +------------------------------------------------------------+  |
|                                                                  |
|  Voice Settings                                                  |
|  +------------------------------------------------------------+  |
|  |  Primary Voice:                                            |  |
|  |  [v] Male (Andrew - confident)      [Preview]              |  |
|  |                                                            |  |
|  |  [ ] Enable voice rotation (multiple voices)               |  |
|  +------------------------------------------------------------+  |
|                                                                  |
|  Language Options                                                |
|  +------------------------------------------------------------+  |
|  |  Languages: [en] English                      [+ Add]      |  |
|  |                                                            |  |
|  |  [ ] Use AI-enhanced narration (requires API key)          |  |
|  +------------------------------------------------------------+  |
|                                                                  |
|  Output Options                                                  |
|  +------------------------------------------------------------+  |
|  |  Number of Videos: [1 v]                                   |  |
|  |  [ ] Split by headings (H2)                                |  |
|  |  Target Duration: [60s v]                                  |  |
|  +------------------------------------------------------------+  |
|                                                                  |
+------------------------------------------------------------------+
```

### Preview Panel

```
+------------------------------------------------------------------+
|                                                                  |
|  Preview                                    [Refresh] [Expand]   |
|                                                                  |
+------------------------------------------------------------------+
|                                                                  |
|  +------------------------------------------------------------+  |
|  |  Video: Getting Started with Python                        |  |
|  |  Duration: ~58 seconds | Scenes: 5                         |  |
|  +------------------------------------------------------------+  |
|                                                                  |
|  Scene Structure:                                                |
|  +------------------------------------------------------------+  |
|  | 1. [Title]    Getting Started with Python      ~5s         |  |
|  | 2. [Command]  Installation Steps               ~12s        |  |
|  | 3. [Command]  Your First Script                ~15s        |  |
|  | 4. [List]     Key Features                     ~18s        |  |
|  | 5. [Outro]    Start Coding Today               ~8s         |  |
|  +------------------------------------------------------------+  |
|                                                                  |
|  Validation Status:                                              |
|  [OK] All validations passed                                     |
|  [!] Scene 3 narration may be too long                           |
|                                                                  |
|                                   [Back] [Generate Video]        |
|                                                                  |
+------------------------------------------------------------------+
```

---

## Accessibility Requirements

### WCAG 2.1 AA Compliance Checklist

| Requirement | Implementation |
|-------------|----------------|
| **1.1 Text Alternatives** | Alt text for all icons; aria-labels for interactive elements |
| **1.3 Adaptable** | Semantic HTML structure; proper heading hierarchy |
| **1.4 Distinguishable** | Minimum 4.5:1 contrast ratio; text resizable to 200% |
| **2.1 Keyboard Accessible** | All functionality available via keyboard |
| **2.4 Navigable** | Skip links; focus indicators; breadcrumbs |
| **3.1 Readable** | Language attributes; clear error messages |
| **3.2 Predictable** | Consistent navigation; no unexpected context changes |
| **3.3 Input Assistance** | Labels for all inputs; error suggestions; prevention |
| **4.1 Compatible** | Valid HTML; ARIA where needed; works with screen readers |

### Keyboard Navigation Map

```
Input Type Selection:
  Tab       - Move between cards
  Enter     - Select card
  Escape    - Cancel/Go back

File Upload Zone:
  Tab       - Focus zone
  Enter     - Open file picker
  Space     - Open file picker

Form Fields:
  Tab       - Move between fields
  Shift+Tab - Move backward
  Enter     - Submit (when on button)
  Escape    - Clear/Cancel

Wizard Flow:
  Tab       - Move through current step
  Enter     - Proceed to next step
  Escape    - Cancel/Go back
  Ctrl+B    - Go back one step
  Ctrl+N    - Go to next step (if valid)
```

### Screen Reader Announcements

```python
# Aria-live regions for dynamic updates

class AriaAnnouncements:
    """Screen reader announcement patterns"""

    UPLOAD_STARTED = "File upload started. Please wait."
    UPLOAD_COMPLETE = "File uploaded successfully. Document preview loaded."
    UPLOAD_ERROR = "Upload failed. {error_message}"

    VALIDATION_PASSED = "Validation passed. Ready to generate."
    VALIDATION_FAILED = "{count} validation errors found. Please review."

    STEP_CHANGED = "Step {current} of {total}: {step_name}"

    GENERATION_STARTED = "Video generation started. This may take several minutes."
    GENERATION_PROGRESS = "Generation {progress}% complete. Currently {stage}."
    GENERATION_COMPLETE = "Video generation complete. Download ready."
```

---

## Implementation Roadmap

### Phase 1: Foundation (Week 1-2)

**Goal:** Establish unified input architecture and shared components

| Task | Priority | Effort |
|------|----------|--------|
| Create UnifiedInputController | Critical | 2d |
| Implement shared UI components | Critical | 3d |
| Build state management layer | High | 2d |
| Add validation service | High | 1d |
| Write API contracts | High | 1d |

**Deliverables:**
- Unified input entry point
- Shared component library
- State management utilities
- Validation framework

### Phase 2: Document Flow (Week 3-4)

**Goal:** Complete document input flow with all features

| Task | Priority | Effort |
|------|----------|--------|
| FileDropZone component | Critical | 2d |
| URL input with validation | Critical | 1d |
| Document preview | High | 2d |
| Structure analysis display | High | 2d |
| Integration tests | High | 2d |

**Deliverables:**
- Complete document upload flow
- Real-time document preview
- Structure analysis visualization

### Phase 3: YouTube Flow (Week 5-6)

**Goal:** Complete YouTube input flow

| Task | Priority | Effort |
|------|----------|--------|
| YouTube URL validator | Critical | 1d |
| Video preview component | Critical | 2d |
| Transcript segment picker | High | 3d |
| Segment preview | Medium | 2d |
| Integration tests | High | 2d |

**Deliverables:**
- YouTube URL validation
- Video preview with metadata
- Segment selection interface

### Phase 4: Wizard Flow (Week 7-8)

**Goal:** Complete guided wizard experience

| Task | Priority | Effort |
|------|----------|--------|
| Progress indicator | Critical | 1d |
| Step navigation | Critical | 2d |
| Template selector | High | 2d |
| Scene builder | High | 3d |
| Review panel | Medium | 2d |

**Deliverables:**
- Multi-step wizard flow
- Template-based creation
- Scene editing interface

### Phase 5: Programmatic Flow (Week 9-10)

**Goal:** Complete programmatic input for power users

| Task | Priority | Effort |
|------|----------|--------|
| JSON editor with syntax highlighting | Critical | 2d |
| Schema validation | Critical | 2d |
| YAML upload support | High | 1d |
| Real-time preview | High | 2d |
| API documentation | Medium | 2d |

**Deliverables:**
- JSON/YAML editing interface
- Schema validation
- Live preview

### Phase 6: Polish & Integration (Week 11-12)

**Goal:** Finalize and integrate all flows

| Task | Priority | Effort |
|------|----------|--------|
| Accessibility audit | Critical | 2d |
| Cross-browser testing | Critical | 2d |
| Performance optimization | High | 2d |
| Documentation | High | 2d |
| End-to-end tests | High | 2d |

**Deliverables:**
- WCAG 2.1 AA compliance
- Browser compatibility
- Complete documentation
- Test suite

---

## Decision Log

| Date | Decision | Rationale | Impact |
|------|----------|-----------|--------|
| 2025-11-22 | Single entry point for all flows | Reduces complexity, enables progressive disclosure | Major |
| 2025-11-22 | Alpine.js + HTMX for frontend | Lightweight, works with existing templates | Medium |
| 2025-11-22 | Draft persistence with 7-day TTL | Enables resume without database complexity | Low |
| 2025-11-22 | Real-time validation | Improves UX, reduces failed submissions | Medium |
| 2025-11-22 | Component-based UI | Maximizes reuse, ensures consistency | Major |

---

## Related Documents

- [ADR 001: Input Adapter Consolidation](./ADR_001_INPUT_ADAPTER_CONSOLIDATION.md)
- [API Contracts](./API_CONTRACTS.md)
- [Pipeline Architecture](./PIPELINE_ARCHITECTURE.md)
- [State Management Spec](./STATE_MANAGEMENT_SPEC.md)
- [Input System Design](./INPUT_SYSTEM_DESIGN.md)

---

*Document Version: 1.0.0*
*Last Updated: 2025-11-22*
*Status: Approved for Implementation*
