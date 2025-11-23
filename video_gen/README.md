# Video Generation Pipeline - Core System

Production-ready video generation pipeline with state management, error recovery, and progress tracking.

## Architecture

```
video_gen/
├── pipeline/              # Core orchestration engine
│   ├── orchestrator.py   # Main pipeline coordinator
│   ├── stage.py          # Base stage class
│   ├── state_manager.py  # Task state persistence
│   └── events.py         # Event system for progress tracking
├── stages/               # Stage implementations
│   ├── validation_stage.py
│   ├── audio_generation_stage.py
│   └── ...
├── shared/              # Common utilities
│   ├── models.py        # Data models
│   ├── config.py        # Configuration
│   └── exceptions.py    # Custom exceptions
└── __init__.py          # Public API
```

## Key Features

### 1. Pipeline Orchestrator
- **Automatic stage execution** - No manual intervention between steps
- **State persistence** - Resume from failures
- **Progress tracking** - Real-time updates via events
- **Error recovery** - Intelligent retry and fallback logic

### 2. Stage System
- **Modular design** - Each stage is independent
- **Consistent interface** - All stages follow same pattern
- **Event emission** - Progress updates and status changes
- **Error handling** - Comprehensive error catching and reporting

### 3. State Management
- **Task persistence** - Save state after each stage
- **Resume capability** - Continue from last completed stage
- **Progress tracking** - Monitor overall and per-stage progress
- **Task querying** - List and filter tasks by status

### 4. Event System
- **Real-time updates** - Stream progress to UI/CLI
- **Flexible listeners** - Sync and async event handlers
- **Type-safe events** - Structured event data
- **Global and targeted** - Listen to all events or specific types

## Usage

### Basic Example

```python
from video_gen import PipelineOrchestrator
from video_gen.shared.models import InputConfig, VideoConfig, SceneConfig
from video_gen.stages import ValidationStage, AudioGenerationStage

# Create orchestrator
orchestrator = PipelineOrchestrator()

# Register stages
orchestrator.register_stages([
    ValidationStage(),
    AudioGenerationStage(),
    # Add more stages...
])

# Create input configuration
input_config = InputConfig(
    input_type="document",
    source="README.md",
    accent_color="blue",
    voice="male"
)

# Execute pipeline
result = orchestrator.execute_sync(input_config)

print(f"Success: {result.success}")
print(f"Video: {result.video_path}")
print(f"Duration: {result.total_duration}s")
```

### Async Execution

```python
import asyncio

async def main():
    orchestrator = PipelineOrchestrator()
    # ... register stages ...

    # Execute asynchronously
    result = await orchestrator.execute(input_config)

    # Or run in background
    task_id = await orchestrator.execute_async(input_config)

    # Check status later
    status = orchestrator.get_status(task_id)
    print(f"Progress: {status.overall_progress:.0%}")

asyncio.run(main())
```

### Event Listening

```python
from video_gen.pipeline.events import EventType

# Create orchestrator
orchestrator = PipelineOrchestrator()

# Register event listener
def on_progress(event):
    print(f"[{event.stage}] {event.progress:.0%} - {event.message}")

orchestrator.event_emitter.on(EventType.STAGE_PROGRESS, on_progress)

# Execute pipeline - progress updates will be printed
result = orchestrator.execute_sync(input_config)
```

### Resume from Failure

```python
# First attempt (may fail)
result1 = orchestrator.execute_sync(input_config, task_id="my_task")

if not result1.success:
    # Fix the issue, then resume
    result2 = orchestrator.execute_sync(
        input_config,
        task_id="my_task",
        resume=True  # Resume from last completed stage
    )
```

## Creating Custom Stages

```python
from video_gen.pipeline import Stage, StageResult

class MyCustomStage(Stage):
    def __init__(self, event_emitter=None):
        super().__init__("my_custom_stage", event_emitter)

    async def execute(self, context):
        # Validate required context
        self.validate_context(context, ["required_key"])

        # Emit progress
        await self.emit_progress(
            context["task_id"],
            0.5,
            "Halfway done"
        )

        # Do work...
        result_data = await self.do_work()

        # Return result
        return StageResult(
            success=True,
            stage_name=self.name,
            artifacts={"output": result_data},
            metadata={"processed": True}
        )
```

## Data Models

### InputConfig
Configuration for pipeline input:
- `input_type`: "document" | "youtube" | "wizard" | "yaml" | "programmatic"
- `source`: File path, URL, or data
- `accent_color`: Visual theme color
- `voice`: TTS voice identifier
- `languages`: List of language codes
- `auto_generate`: Auto-proceed through stages
- `resume_from`: Task ID to resume

### VideoConfig
Complete video specification:
- `video_id`: Unique identifier
- `title`: Video title
- `description`: Video description
- `scenes`: List of SceneConfig objects
- `accent_color`: Theme color
- Runtime fields: `total_duration`, `audio_dir`, `video_file`, etc.

### SceneConfig
Individual scene specification:
- `scene_id`: Unique scene identifier
- `scene_type`: "title" | "command" | "list" | "outro" | etc.
- `narration`: Text to speak
- `visual_content`: Scene-specific visual data
- `voice`: Voice for this scene
- `min_duration` / `max_duration`: Duration constraints

### PipelineResult
Final pipeline output:
- `success`: Boolean success flag
- `task_id`: Task identifier
- `video_config`: Complete video configuration
- `video_path`: Path to final video
- `audio_dir`: Path to audio files
- `timing_report`: Path to timing report
- `errors`: List of errors
- `warnings`: List of warnings

## State Management

### Task States
- `PENDING` - Task created but not started
- `RUNNING` - Currently executing
- `PAUSED` - Execution paused (can resume)
- `COMPLETED` - Successfully completed
- `FAILED` - Failed with errors
- `CANCELLED` - Manually cancelled

### State Persistence
States are automatically saved to `output/state/{task_id}.json`:

```json
{
  "task_id": "task_abc123",
  "status": "completed",
  "overall_progress": 1.0,
  "current_stage": "audio_generation",
  "stages": {
    "validation": {
      "status": "completed",
      "progress": 1.0,
      "artifacts": {...}
    },
    "audio_generation": {
      "status": "completed",
      "progress": 1.0,
      "artifacts": {...}
    }
  },
  "errors": [],
  "warnings": []
}
```

## Event Types

- `PIPELINE_STARTED` - Pipeline execution started
- `PIPELINE_COMPLETED` - Pipeline completed successfully
- `PIPELINE_FAILED` - Pipeline failed
- `STAGE_STARTED` - Stage started
- `STAGE_PROGRESS` - Stage progress update
- `STAGE_COMPLETED` - Stage completed
- `STAGE_FAILED` - Stage failed
- `VALIDATION_WARNING` / `VALIDATION_ERROR` - Validation issues
- `AUDIO_GENERATING` / `AUDIO_GENERATED` - Audio generation
- `VIDEO_RENDERING` / `VIDEO_RENDERED` - Video rendering
- `STATE_SAVED` / `STATE_RESTORED` - State operations

## Configuration

Global configuration in `shared/config.py`:

```python
from video_gen.shared.config import config

# Access configuration
print(config.video_width)  # 1920
print(config.video_fps)    # 30
print(config.get_voice("male"))  # Edge TTS voice ID
print(config.get_color("blue"))  # RGB tuple
```

## Error Handling

All errors inherit from `VideoGenError`:
- `StageError` - Stage execution failure
- `ValidationError` - Validation failure
- `StateError` - State management failure
- `ConfigError` - Configuration error
- `AudioGenerationError` - Audio generation failure
- `VideoGenerationError` - Video generation failure

## Testing

```bash
# Run tests
cd video_gen
pytest tests/test_pipeline.py -v

# Run demo
python tests/demo_pipeline.py
```

## Integration with Existing Scripts

The pipeline orchestrator uses existing scripts as stages:

1. **Input Adaptation** → Uses `document_to_programmatic.py`, `youtube_to_programmatic.py`, etc.
2. **Content Parsing** → Uses existing parsing logic
3. **Script Generation** → Uses `generate_script_from_yaml.py`
4. **Audio Generation** → Uses `unified_video_system.py` audio logic
5. **Video Generation** → Uses `generate_videos_from_timings_v3_simple.py`
6. **Output Handling** → New stage for final export

## Migration Path

1. **Phase 1** (Current): Core pipeline infrastructure ✅
   - Orchestrator
   - State management
   - Event system
   - Base stages

2. **Phase 2** (Next): Wrap existing scripts as stages
   - InputAdaptationStage (wraps document/youtube parsers)
   - ScriptGenerationStage (wraps script generators)
   - VideoGenerationStage (wraps video renderers)

3. **Phase 3**: Refactor to native implementations
   - Replace script wrappers with native Python
   - Optimize for async execution
   - Add advanced features

## Next Steps

1. Implement remaining stages:
   - `InputAdaptationStage` - Parse input sources
   - `ScriptGenerationStage` - Generate narration scripts
   - `VideoGenerationStage` - Render videos
   - `OutputStage` - Export and deliver

2. Add CLI interface:
   - `video-gen create --from document:README.md`
   - One command, complete pipeline

3. Integrate with Web UI:
   - Update `app/main.py` to use orchestrator
   - Stream events via SSE
   - Real-time progress tracking

4. Advanced features:
   - Parallel video generation
   - Cloud storage integration
   - Distributed processing
   - ML-powered narration

## License

See project root for license information.
