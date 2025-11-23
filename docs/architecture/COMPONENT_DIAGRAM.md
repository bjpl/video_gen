# Video_Gen Component Diagram & Relationships

## 1. High-Level System Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                           VIDEO_GEN SYSTEM                            │
│                                                                        │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                    PIPELINE ORCHESTRATION                        │ │
│  │                                                                   │ │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │ │
│  │  │  Pipeline    │───▶│    State     │───▶│    Event     │      │ │
│  │  │ Orchestrator │    │   Manager    │    │   Emitter    │      │ │
│  │  └──────────────┘    └──────────────┘    └──────────────┘      │ │
│  │         │                                                        │ │
│  │         │ registers                                              │ │
│  │         ▼                                                        │ │
│  │  ┌──────────────────────────────────────────────────────────┐  │ │
│  │  │                   STAGE REGISTRY                          │  │ │
│  │  │  [Stage 1] → [Stage 2] → [Stage 3] → ... → [Stage N]    │  │ │
│  │  └──────────────────────────────────────────────────────────┘  │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                      PROCESSING STAGES                           │ │
│  │                                                                   │ │
│  │  Stage 1         Stage 2        Stage 3        Stage 4          │ │
│  │  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐      │ │
│  │  │  Input  │───▶│ Parsing │───▶│ Script  │───▶│  Audio  │──┐   │ │
│  │  │ Adapter │    │         │    │   Gen   │    │   Gen   │  │   │ │
│  │  └─────────┘    └─────────┘    └─────────┘    └─────────┘  │   │ │
│  │                                                              │   │ │
│  │  Stage 5         Stage 6                                    │   │ │
│  │  ┌─────────┐    ┌─────────┐                                │   │ │
│  │  │  Video  │◀───│ Output  │◀───────────────────────────────┘   │ │
│  │  │   Gen   │    │ Handler │                                    │ │
│  │  └─────────┘    └─────────┘                                    │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                      INPUT ADAPTERS                              │ │
│  │                                                                   │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │ │
│  │  │Document  │  │ YouTube  │  │   YAML   │  │Programma-│        │ │
│  │  │ Adapter  │  │ Adapter  │  │ Adapter  │  │tic API   │        │ │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │ │
│  │       │              │              │              │             │ │
│  │       └──────────────┴──────────────┴──────────────┘             │ │
│  │                           │                                       │ │
│  │                           ▼                                       │ │
│  │                  ┌─────────────────┐                             │ │
│  │                  │   VideoSet      │                             │ │
│  │                  └─────────────────┘                             │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                    SHARED COMPONENTS                             │ │
│  │                                                                   │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │ │
│  │  │  Models  │  │  Config  │  │Exception │  │Constants │        │ │
│  │  │          │  │(Singleton)│  │Hierarchy │  │  Utils   │        │ │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                   EXTERNAL DEPENDENCIES                          │ │
│  │                                                                   │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │ │
│  │  │Edge TTS  │  │  FFmpeg  │  │  NumPy   │  │scripts/  │        │ │
│  │  │  (TTS)   │  │ (Video)  │  │  (Math)  │  │(Render)  │        │ │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │ │
│  │                                                 ⚠️               │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

## 2. Data Flow Diagram

```
┌─────────────┐
│   USER      │
│   INPUT     │
└──────┬──────┘
       │
       ▼
┌──────────────────────────────────────────┐
│  INPUT ADAPTER (Stage 1)                 │
│  ┌────────────────────────────────────┐  │
│  │ Select adapter based on input_type │  │
│  │ - document → DocumentAdapter       │  │
│  │ - youtube → YouTubeAdapter         │  │
│  │ - yaml → YAMLFileAdapter           │  │
│  └────────────────────────────────────┘  │
└──────────────┬───────────────────────────┘
               │ VideoConfig
               ▼
┌──────────────────────────────────────────┐
│  CONTENT PARSING (Stage 2)               │
│  ┌────────────────────────────────────┐  │
│  │ Parse and structure content        │  │
│  │ Extract sections, lists, code      │  │
│  └────────────────────────────────────┘  │
└──────────────┬───────────────────────────┘
               │ Structured Content
               ▼
┌──────────────────────────────────────────┐
│  SCRIPT GENERATION (Stage 3)             │
│  ┌────────────────────────────────────┐  │
│  │ Generate narration text            │  │
│  │ Enhance with AI (optional)         │  │
│  └────────────────────────────────────┘  │
└──────────────┬───────────────────────────┘
               │ VideoConfig + Scripts
               ▼
┌──────────────────────────────────────────┐
│  AUDIO GENERATION (Stage 4)              │
│  ┌────────────────────────────────────┐  │
│  │ For each scene:                    │  │
│  │  1. Call Edge TTS                  │  │
│  │  2. Save MP3                       │  │
│  │  3. Measure duration (FFmpeg)      │  │
│  │  4. Update scene.audio_file        │  │
│  └────────────────────────────────────┘  │
└──────────────┬───────────────────────────┘
               │ VideoConfig + Audio Files
               ▼
┌──────────────────────────────────────────┐
│  VIDEO GENERATION (Stage 5)              │
│  ┌────────────────────────────────────┐  │
│  │ For each scene:                    │  │
│  │  1. Render keyframes (NumPy)       │  │
│  │  2. Create transitions             │  │
│  │  3. Encode video (FFmpeg+NVENC)    │  │
│  └────────────────────────────────────┘  │
└──────────────┬───────────────────────────┘
               │ Video Segments
               ▼
┌──────────────────────────────────────────┐
│  OUTPUT HANDLING (Stage 6)               │
│  ┌────────────────────────────────────┐  │
│  │ 1. Concatenate segments            │  │
│  │ 2. Add audio tracks                │  │
│  │ 3. Generate timing report          │  │
│  │ 4. Export final video              │  │
│  └────────────────────────────────────┘  │
└──────────────┬───────────────────────────┘
               │
               ▼
        ┌─────────────┐
        │FINAL VIDEO  │
        │   (.mp4)    │
        └─────────────┘
```

## 3. Context Propagation

Each stage receives a **context dictionary** that accumulates artifacts:

```python
# Stage 1: Input Adapter
context = {
    "task_id": "task_abc123",
    "input_config": InputConfig(...),
    "config": Config()
}

# After Stage 1
context["video_config"] = VideoConfig(...)
context["input_metadata"] = {...}

# After Stage 2
context["parsed_content"] = {...}

# After Stage 3
context["video_config"] = VideoConfig(...)  # Updated with scripts

# After Stage 4
context["audio_dir"] = Path("audio/video_id_audio/")
context["timing_report"] = Path("audio/video_id_audio/timing_report.json")
context["video_config"] = VideoConfig(...)  # Updated with audio_file paths

# After Stage 5
context["video_segments"] = [Path(...), Path(...)]

# After Stage 6
context["final_video_path"] = Path("output/final_video.mp4")
```

## 4. Class Hierarchy

### 4.1 Pipeline Classes

```
EventEmitter
    └── (used by all stages for progress tracking)

StateManager
    └── manages TaskState objects

TaskState
    ├── status: TaskStatus (enum)
    ├── stages: Dict[str, StageState]
    └── methods: start_stage(), complete_stage(), fail_stage()

PipelineOrchestrator
    ├── state_manager: StateManager
    ├── event_emitter: EventEmitter
    ├── stages: List[Stage]
    └── methods: register_stage(), execute(), execute_sync()
```

### 4.2 Stage Hierarchy

```
Stage (ABC)
    ├── name: str
    ├── event_emitter: EventEmitter
    ├── execute(context) -> StageResult  (abstract)
    └── run(context, task_id) -> StageResult  (wrapper)

    ├── InputStage
    │   └── adapters: Dict[str, InputAdapter]
    │
    ├── ParsingStage
    │   └── parser: ContentParser
    │
    ├── ScriptGenerationStage
    │   └── enhancer: AIEnhancer
    │
    ├── AudioGenerationStage
    │   └── generator: UnifiedAudioGenerator
    │
    ├── VideoGenerationStage
    │   └── generator: UnifiedVideoGenerator
    │
    ├── OutputStage
    │   └── exporter: VideoExporter
    │
    └── ValidationStage
        └── validators: List[Validator]
```

### 4.3 Adapter Hierarchy

```
InputAdapter (ABC)
    ├── name: str
    ├── description: str
    ├── adapt(source, **kwargs) -> InputAdapterResult  (abstract)
    └── validate_source(source) -> bool

    ├── DocumentAdapter
    │   ├── supported_formats: {.pdf, .docx, .txt, .md}
    │   └── methods: _read_document_content(), _parse_markdown_structure()
    │
    ├── YouTubeAdapter
    │   └── methods: _extract_video_id(), _fetch_transcript()
    │
    ├── YAMLFileAdapter
    │   └── methods: _load_yaml(), _validate_schema()
    │
    ├── ProgrammaticAdapter
    │   └── methods: _convert_dict_to_videoconfig()
    │
    └── InteractiveWizard
        └── methods: _prompt_user(), _build_config()
```

### 4.4 Model Hierarchy

```
@dataclass SceneConfig
    ├── scene_id: str
    ├── scene_type: Literal[...]
    ├── narration: str
    ├── visual_content: Dict
    ├── voice: str
    ├── min_duration: float
    ├── max_duration: float
    └── runtime fields: audio_file, final_duration, warnings

@dataclass VideoConfig
    ├── video_id: str
    ├── title: str
    ├── scenes: List[SceneConfig]
    ├── accent_color: str
    └── runtime fields: total_duration, audio_dir, video_file

@dataclass InputConfig
    ├── input_type: Literal["document", "youtube", "yaml", "programmatic"]
    ├── source: str
    ├── accent_color: str
    ├── voice: str
    └── options: auto_generate, skip_review, resume_from

@dataclass VideoSet
    ├── set_id: str
    ├── name: str
    └── videos: List[VideoConfig]

@dataclass PipelineResult
    ├── success: bool
    ├── task_id: str
    ├── video_config: VideoConfig
    ├── video_path: Path
    ├── timing_report: Path
    └── metadata: duration, scene_count, errors, warnings
```

## 5. Sequence Diagram: Complete Pipeline Execution

```
User          Pipeline      StateManager    Stage1    Stage2    ...    StageN    EventEmitter
 │                │              │             │         │               │            │
 │  execute()     │              │             │         │               │            │
 ├───────────────▶│              │             │         │               │            │
 │                │              │             │         │               │            │
 │                │ create/load  │             │         │               │            │
 │                ├─────────────▶│             │         │               │            │
 │                │ TaskState    │             │         │               │            │
 │                │◀─────────────┤             │         │               │            │
 │                │              │             │         │               │            │
 │                │                    emit PIPELINE_STARTED              │            │
 │                ├────────────────────────────────────────────────────────────────▶│
 │                │              │             │         │               │            │
 │                │ start_stage  │             │         │               │            │
 │                ├─────────────▶│             │         │               │            │
 │                │              │             │         │               │            │
 │                │           run(context, task_id)      │               │            │
 │                ├──────────────────────────▶│         │               │            │
 │                │              │             │         │               │            │
 │                │              │        emit STAGE_STARTED             │            │
 │                │              │             ├─────────────────────────────────────▶│
 │                │              │             │         │               │            │
 │                │              │      execute(context) │               │            │
 │                │              │             │         │               │            │
 │                │              │             │ work... │               │            │
 │                │              │             │         │               │            │
 │                │              │        emit STAGE_COMPLETED           │            │
 │                │              │             ├─────────────────────────────────────▶│
 │                │              │             │         │               │            │
 │                │              │   StageResult         │               │            │
 │                │◀──────────────────────────┤         │               │            │
 │                │              │             │         │               │            │
 │                │ complete_stage             │         │               │            │
 │                ├─────────────▶│             │         │               │            │
 │                │              │             │         │               │            │
 │                │              │             │    [Repeat for Stage2...StageN]     │
 │                │              │             │         │               │            │
 │                │              │             │         │          run()│            │
 │                ├───────────────────────────────────────────────────▶│            │
 │                │              │             │         │               │            │
 │                │              │             │         │         work...│            │
 │                │              │             │         │               │            │
 │                │              │             │         │   StageResult │            │
 │                │◀───────────────────────────────────────────────────┤            │
 │                │              │             │         │               │            │
 │                │                    emit PIPELINE_COMPLETED            │            │
 │                ├────────────────────────────────────────────────────────────────▶│
 │                │              │             │         │               │            │
 │PipelineResult  │              │             │         │               │            │
 │◀───────────────┤              │             │         │               │            │
```

## 6. Dependency Injection Points

### Current Implementation (Hardcoded Dependencies)

```python
class InputStage(Stage):
    def __init__(self, event_emitter=None):
        super().__init__("input_adaptation", event_emitter)
        # ❌ Hardcoded - creates adapters internally
        self.adapters = {
            "document": DocumentAdapter(),
            "youtube": YouTubeAdapter(),
            "yaml": YAMLFileAdapter(),
            "programmatic": ProgrammaticAdapter(),
        }
```

### Recommended Implementation (Dependency Injection)

```python
class InputStage(Stage):
    def __init__(
        self,
        adapters: Optional[Dict[str, InputAdapter]] = None,
        event_emitter: Optional[EventEmitter] = None
    ):
        super().__init__("input_adaptation", event_emitter)
        # ✅ Injectable - allows testing with mocks
        self.adapters = adapters or self._default_adapters()

    def _default_adapters(self) -> Dict[str, InputAdapter]:
        """Factory method for default adapters."""
        return {
            "document": DocumentAdapter(),
            "youtube": YouTubeAdapter(),
            "yaml": YAMLFileAdapter(),
            "programmatic": ProgrammaticAdapter(),
        }
```

### Benefits:
1. **Testability**: Can inject mock adapters for testing
2. **Flexibility**: Can swap adapters at runtime
3. **Extensibility**: Easy to add custom adapters
4. **Separation of Concerns**: Stage doesn't know about adapter implementation

## 7. Event Flow

```
Pipeline Execution
    │
    ├─▶ PIPELINE_STARTED
    │       └─▶ Listeners: UI progress bar, logger, metrics
    │
    ├─▶ STAGE_STARTED (Stage 1: Input)
    │       └─▶ Update UI: "Reading input..."
    │
    ├─▶ STAGE_PROGRESS (Stage 1: 50%)
    │       └─▶ Update progress bar
    │
    ├─▶ STAGE_COMPLETED (Stage 1)
    │       └─▶ Update UI: "Input processed ✓"
    │
    ├─▶ STATE_SAVED
    │       └─▶ Log checkpoint
    │
    ├─▶ STAGE_STARTED (Stage 2: Parsing)
    │       └─▶ Update UI: "Parsing content..."
    │
    ├─▶ VALIDATION_WARNING
    │       └─▶ Show warning to user
    │
    ├─▶ STAGE_COMPLETED (Stage 2)
    │
    ├─▶ AUDIO_GENERATING (Scene 1/10)
    │       └─▶ Update UI: "Generating audio 1/10"
    │
    ├─▶ AUDIO_GENERATED (Scene 1)
    │       └─▶ Update progress
    │
    │   [Repeat for all scenes]
    │
    ├─▶ VIDEO_RENDERING (Scene 1/10)
    │       └─▶ Update UI: "Rendering video 1/10"
    │
    ├─▶ VIDEO_RENDERED (Scene 1)
    │       └─▶ Update progress
    │
    └─▶ PIPELINE_COMPLETED
            └─▶ Show final result, display video path
```

## 8. State Persistence

### TaskState JSON Structure

```json
{
  "task_id": "task_abc123def",
  "input_config": {
    "input_type": "document",
    "source": "inputs/guide.md",
    "accent_color": "blue",
    "voice": "male"
  },
  "status": "completed",
  "current_stage": null,
  "overall_progress": 1.0,
  "stages": {
    "input_adaptation": {
      "name": "input_adaptation",
      "status": "completed",
      "progress": 1.0,
      "started_at": "2025-10-05T10:00:00",
      "completed_at": "2025-10-05T10:00:15",
      "error": null,
      "artifacts": {
        "video_config": "/state/task_abc123def/video_config.json"
      }
    },
    "audio_generation": {
      "name": "audio_generation",
      "status": "completed",
      "progress": 1.0,
      "started_at": "2025-10-05T10:01:00",
      "completed_at": "2025-10-05T10:03:45",
      "artifacts": {
        "audio_dir": "/audio/unified_system/video_abc_audio",
        "timing_report": "/audio/unified_system/video_abc_audio/timing_report.json"
      }
    }
  },
  "created_at": "2025-10-05T09:59:00",
  "started_at": "2025-10-05T10:00:00",
  "completed_at": "2025-10-05T10:15:30",
  "result": {
    "success": true,
    "video_path": "/output/final_video.mp4",
    "total_duration": 120.5,
    "scene_count": 10
  },
  "errors": [],
  "warnings": ["Scene 3: Narration truncated to fit max_duration"]
}
```

### Resume Logic

```python
# Pipeline Orchestrator - execute()
if resume and self.state_manager.exists(task_id):
    task_state = self.state_manager.load(task_id)  # Load from disk
    completed_stages = task_state.get_completed_stages()  # ["input", "parsing"]

    # Find index of last completed stage
    last_completed = completed_stages[-1]
    start_index = self.stages.index(self.stage_map[last_completed]) + 1

    # Execute remaining stages
    for stage in self.stages[start_index:]:
        result = await stage.run(context, task_id)
        # ...
```

## 9. Extension Points

### Adding a New Stage

```python
# 1. Create new stage class
class CustomStage(Stage):
    def __init__(self, event_emitter=None):
        super().__init__("custom_processing", event_emitter)

    async def execute(self, context: Dict[str, Any]) -> StageResult:
        # Custom logic here
        return StageResult(
            success=True,
            stage_name=self.name,
            artifacts={"custom_output": "..."}
        )

# 2. Register in pipeline
pipeline = PipelineOrchestrator()
pipeline.register_stage(CustomStage())

# 3. Execute
result = await pipeline.execute(input_config)
```

### Adding a New Input Adapter

```python
# 1. Implement InputAdapter interface
class CustomAdapter(InputAdapter):
    def __init__(self):
        super().__init__(name="custom", description="Custom input source")

    async def adapt(self, source: Any, **kwargs) -> InputAdapterResult:
        # Parse custom format
        video_set = self._parse_custom_format(source)
        return InputAdapterResult(success=True, video_set=video_set)

# 2. Register adapter
input_stage = InputStage()
input_stage.adapters["custom"] = CustomAdapter()

# 3. Use in InputConfig
input_config = InputConfig(input_type="custom", source="path/to/custom.xyz")
```

### Adding a New Event Listener

```python
# 1. Define listener function
async def my_progress_listener(event: Event):
    if event.type == EventType.STAGE_PROGRESS:
        print(f"[{event.stage}] {event.progress:.0%} - {event.message}")

# 2. Register listener
event_emitter = EventEmitter()
event_emitter.on_async(EventType.STAGE_PROGRESS, my_progress_listener)

# 3. Create pipeline with custom emitter
pipeline = PipelineOrchestrator(event_emitter=event_emitter)
```

---

**Generated by:** Claude Code Architecture Analysis Agent
**Date:** 2025-10-05
