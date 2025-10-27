# Architecture FAQ

**Frequently Asked Questions about the Unified Pipeline Architecture**

---

## Table of Contents

1. [Design Decisions](#design-decisions)
2. [Implementation Questions](#implementation-questions)
3. [Migration Questions](#migration-questions)
4. [Performance Questions](#performance-questions)
5. [Testing Questions](#testing-questions)
6. [Deployment Questions](#deployment-questions)

---

## Design Decisions

### Q: Why 6 stages instead of fewer?

**A:** Clear separation of concerns, easier testing, better error recovery.

**Detailed Explanation:**

Each stage has a single, well-defined responsibility:

1. **Input Adaptation:** Normalize different input formats
2. **Content Parsing:** Extract structured content
3. **Script Generation:** Create narration
4. **Audio Generation:** TTS synthesis
5. **Video Generation:** Visual rendering
6. **Output Handling:** File organization

**Benefits:**
- Each stage can be tested independently
- Failures can be recovered from specific stages
- Stages can be optimized separately
- Easy to add new stages (e.g., thumbnail generation)

**Why not fewer stages?**
- Combining stages creates tight coupling
- Error recovery becomes harder
- Testing becomes more complex

**Example:**
If audio generation fails, you don't need to re-run parsing or script generation.

---

### Q: Why both JSON and SQLite for state storage?

**A:** JSON for simple cases, SQLite for production with queries.

**Detailed Explanation:**

**JSON Storage:**
- Simple file-based persistence
- Easy debugging (human-readable)
- No database setup required
- Perfect for development and small-scale

**SQLite Storage:**
- SQL queries for filtering/searching
- Better performance with many tasks
- ACID transactions
- Indexes for fast lookups

**When to use each:**
- Development: JSON
- Testing: JSON
- Production (< 100 tasks): JSON
- Production (> 100 tasks): SQLite
- Need to query tasks: SQLite

**Example:**
```python
# Development
storage = JSONStorageBackend(Path(".video-gen/tasks"))

# Production
storage = SQLiteStorageBackend(Path(".video-gen/tasks.db"))
```

---

### Q: Why event-driven architecture?

**A:** Real-time progress updates, loose coupling, extensibility.

**Detailed Explanation:**

**Benefits:**

1. **Real-Time Updates:**
   - Web UI can show live progress
   - CLI can display real-time status
   - External systems can monitor execution

2. **Loose Coupling:**
   - Stages don't know about subscribers
   - Easy to add new event handlers
   - No circular dependencies

3. **Extensibility:**
   - Add metrics collection without changing stages
   - Add logging without modifying code
   - Add webhooks for external integration

**Example:**
```python
# Metrics collector subscribes to events
class MetricsCollector:
    def __init__(self, event_bus):
        event_bus.subscribe(StageCompleteEvent, self.on_stage_complete)

    async def on_stage_complete(self, event):
        # Record stage duration
        await self.record_metric(event.stage, event.duration)

# No changes to stage code needed!
```

---

### Q: Why Pydantic instead of plain dataclasses?

**A:** Type validation, serialization, and self-documenting schemas.

**Detailed Explanation:**

**Pydantic Advantages:**

1. **Runtime Type Validation:**
   ```python
   class InputConfig(BaseModel):
       target_duration: int = Field(ge=10, le=600)  # 10-600 seconds

   # This raises ValidationError automatically
   InputConfig(target_duration=5)  # Too short!
   ```

2. **Automatic Serialization:**
   ```python
   config.model_dump()  # → dict
   config.model_dump_json()  # → JSON string
   InputConfig.model_validate(data)  # From dict
   ```

3. **Self-Documenting:**
   ```python
   class InputConfig(BaseModel):
       voice: str = Field(
           default="male",
           pattern="^(male|female|male_warm|female_friendly)$",
           description="Voice to use for narration"
       )

   # Auto-generates JSON schema
   print(InputConfig.model_json_schema())
   ```

4. **Better Error Messages:**
   ```
   ValidationError: 1 validation error for InputConfig
   target_duration
     Input should be greater than or equal to 10 [type=greater_than_equal]
   ```

**vs. Dataclasses:**
- Dataclasses: Only type hints (not validated)
- Pydantic: Validates at runtime

---

### Q: Why async/await everywhere?

**A:** IO-bound operations benefit from concurrency.

**Detailed Explanation:**

**Video generation is IO-bound:**
- TTS API calls (network)
- FFmpeg encoding (subprocess)
- File I/O (disk)

**Async Benefits:**

1. **Better Concurrency:**
   ```python
   # Generate 10 audio files concurrently
   tasks = [generate_tts(scene) for scene in scenes]
   results = await asyncio.gather(*tasks)
   ```

2. **Non-Blocking Event Emission:**
   ```python
   # Emit progress without blocking stage execution
   event_bus.emit(ProgressEvent(...))  # Fire and forget
   ```

3. **Scales Better:**
   - Handle multiple pipeline executions concurrently
   - Better resource utilization
   - Lower memory footprint

**When async doesn't help:**
- CPU-bound operations (use multiprocessing instead)
- Single sequential task

**Example Performance:**
```
Sync (sequential):  10 TTS calls × 2s = 20s
Async (concurrent): 10 TTS calls × 2s = ~2s (10x faster!)
```

---

## Implementation Questions

### Q: Where do I start implementing?

**A:** Follow IMPLEMENTATION_CHECKLIST.md Sprint 1.

**Detailed Order:**

1. **Create Package Structure** (15 min)
   ```bash
   mkdir -p video_gen/{pipeline,stages,shared,storage}
   ```

2. **Implement Data Models** (2-3 hours)
   - `video_gen/shared/models.py`
   - Start with `InputConfig`, `VideoSetConfig`
   - Write tests for each model

3. **Implement Base Classes** (1-2 hours)
   - `video_gen/stages/base.py`
   - `Stage` ABC with `execute()`, `validate()`

4. **Implement StateManager** (4-6 hours)
   - `video_gen/pipeline/state_manager.py`
   - Start with JSON backend
   - Test persistence

5. **Implement EventBus** (2-3 hours)
   - `video_gen/pipeline/events.py`
   - Simple pub/sub

6. **Implement PipelineOrchestrator** (4-6 hours)
   - `video_gen/pipeline/orchestrator.py`
   - Basic execute flow

**Key: Test as you go!**

---

### Q: How do I test async code?

**A:** Use `pytest-asyncio` and `@pytest.mark.asyncio`.

**Example:**
```python
import pytest

@pytest.mark.asyncio
async def test_orchestrator_execute():
    """Test pipeline execution"""
    orchestrator = PipelineOrchestrator(...)

    result = await orchestrator.execute(
        InputConfig(
            source_type="document",
            source_data={"path": "test.md"}
        )
    )

    assert result.status == "success"
    assert len(result.videos) > 0
```

**Testing async with mocks:**
```python
@pytest.mark.asyncio
async def test_stage_with_mock():
    """Test stage with mocked dependencies"""
    from unittest.mock import AsyncMock

    mock_tts = AsyncMock(return_value="audio.mp3")
    stage = AudioGenerationStage(tts_service=mock_tts)

    output = await stage.execute(input)

    mock_tts.assert_called_once()
```

---

### Q: How do I handle errors in async code?

**A:** Use try/except with proper cleanup.

**Pattern:**
```python
async def execute_stage(self, stage, task):
    """Execute stage with error handling"""
    try:
        # Update state
        await self.state.start_stage(task.id, stage.name)

        # Execute
        output = await stage.execute(input)

        # Save output
        await self.state.complete_stage(task.id, stage.name, output)

        return output

    except Exception as e:
        # Save error state
        await self.state.fail_stage(task.id, stage.name, str(e))

        # Re-raise
        raise StageError(stage.name, str(e)) from e
```

**Cleanup with async context managers:**
```python
async with self.resource_pool.acquire() as resource:
    # Use resource
    result = await resource.process(data)
    # Automatically released even if exception
```

---

### Q: How do I reuse existing code?

**A:** Extract to shared modules, then wrap in new stages.

**Example: Reusing TTS Logic**

```python
# 1. Extract existing TTS logic to shared module
# video_gen/shared/tts.py
async def generate_tts(text: str, voice: str) -> str:
    """
    Generate TTS audio.
    Extracted from scripts/unified_video_system.py
    """
    # Original TTS code here
    pass

# 2. Use in new stage
# video_gen/stages/audio_gen_stage.py
from video_gen.shared.tts import generate_tts

class AudioGenerationStage(Stage):
    async def execute(self, input):
        audio_files = []
        for scene in input.data.scenes:
            audio_file = await generate_tts(
                scene.narration,
                scene.voice
            )
            audio_files.append(audio_file)
        return AudioGenStageOutput(...)

# 3. Old scripts can also use shared module
# scripts/generate_all_videos_unified_v2.py
from video_gen.shared.tts import generate_tts
# Replace duplicated TTS logic with import
```

**Benefits:**
- No code duplication
- Single source of truth
- Both old and new systems benefit from fixes

---

## Migration Questions

### Q: Do I need to migrate everything at once?

**A:** No! Use feature flags for gradual migration.

**Phased Migration:**

**Phase 1: Foundation (No User Impact)**
```python
# Build new system alongside old
# No feature flags needed yet
video_gen/
  pipeline/
  stages/
  shared/
scripts/  # Old scripts unchanged
```

**Phase 2: Input Adapters (Optional)**
```python
# Feature flag for new adapters
if FeatureFlags.USE_NEW_INPUT_ADAPTERS:
    adapter = AdapterRegistry().get_adapter("document")
    config = await adapter.adapt(raw_input)
else:
    # Old code path
    from scripts.document_to_programmatic import parse_document
    config = parse_document(raw_input)
```

**Phase 3: Full Pipeline (Gradual)**
```python
# Percentage-based rollout
if random.randint(0, 100) < NEW_PIPELINE_PERCENTAGE:
    orchestrator = PipelineOrchestrator()
    result = await orchestrator.execute(config)
else:
    # Old multi-script workflow
    result = old_workflow(config)
```

**Phase 4: New Default**
```python
# New pipeline is default, old is opt-out
if FeatureFlags.USE_OLD_PIPELINE:
    result = old_workflow(config)
else:
    orchestrator = PipelineOrchestrator()
    result = await orchestrator.execute(config)
```

**Phase 5: Deprecation**
```python
# Old code removed, only new pipeline exists
orchestrator = PipelineOrchestrator()
result = await orchestrator.execute(config)
```

---

### Q: How do I test new and old systems produce same output?

**A:** Parallel validation tests.

**Pattern:**
```python
@pytest.mark.parametrize("input_file", [
    "test1.md",
    "test2.md",
    "README.md"
])
async def test_old_vs_new_equivalence(input_file):
    """Verify new system produces same output as old"""

    # Run old system
    old_result = run_old_document_parser(input_file)

    # Run new system
    adapter = DocumentAdapter()
    new_result = await adapter.adapt(DocumentInput(path=input_file))

    # Compare outputs
    assert_video_configs_equivalent(old_result, new_result)

def assert_video_configs_equivalent(old, new):
    """Compare video configs for equivalence"""
    # Compare structure
    assert len(old.videos) == len(new.videos)

    # Compare scenes
    for old_video, new_video in zip(old.videos, new.videos):
        assert len(old_video.scenes) == len(new_video.scenes)

        for old_scene, new_scene in zip(old_video.scenes, new_video.scenes):
            # Allow minor differences in formatting
            assert old_scene.scene_type == new_scene.scene_type
            assert old_scene.narration.strip() == new_scene.narration.strip()
```

---

### Q: What if migration breaks something?

**A:** Easy rollback with feature flags.

**Rollback Procedure:**

**If new system has bugs:**
```bash
# Disable feature flag
export USE_NEW_PIPELINE=false

# Restart services
systemctl restart video-gen-web

# Verify old system works
python scripts/generate_all_videos_unified_v2.py
```

**If new system has performance issues:**
```bash
# Reduce rollout percentage
export NEW_PIPELINE_PERCENTAGE=0  # Back to 0%

# Monitor
tail -f logs/pipeline.log

# Gradually increase when fixed
export NEW_PIPELINE_PERCENTAGE=10  # 10% of users
```

**If data corruption:**
```bash
# Stop all pipelines
killall python

# Restore from backup
cp .video-gen/tasks.backup.db .video-gen/tasks.db

# Re-enable old system
export USE_NEW_PIPELINE=false
```

---

## Performance Questions

### Q: How fast will the new system be?

**A:** 50-67% faster than old multi-script workflow.

**Performance Breakdown:**

**Old System (Multi-Script):**
```
1. Create video config      →  30s
2. Generate script          →  60s
3. Generate audio           → 120s
4. Generate video           → 240s
5. Manual file management   →  30s
--------------------------------
Total: 480s (8 minutes)
```

**New System (Unified Pipeline):**
```
1. Input adaptation         →  10s (parallel)
2. Content parsing          →  10s
3. Script generation        →  40s (optimized)
4. Audio generation         →  90s (concurrent TTS)
5. Video generation         → 180s (GPU optimized)
6. Output handling          →  10s
--------------------------------
Total: 240s (4 minutes) → 50% faster
```

**Key Optimizations:**
1. **Concurrent TTS:** Generate multiple audio files in parallel
2. **Optimized Parsing:** Single pass instead of multiple
3. **GPU Utilization:** Better FFmpeg encoding
4. **No Manual Steps:** Automatic file management

---

### Q: Can I run multiple videos in parallel?

**A:** Yes! Use BatchOrchestrator.

**Example:**
```python
from video_gen.pipeline import BatchOrchestrator

configs = [
    InputConfig(source_type="document", source_data={"path": "doc1.md"}),
    InputConfig(source_type="document", source_data={"path": "doc2.md"}),
    InputConfig(source_type="document", source_data={"path": "doc3.md"}),
]

batch = BatchOrchestrator(max_parallel=4)
results = await batch.execute_batch(configs)

# Generates 3 videos concurrently (4 max)
```

**Resource Management:**
```python
class BatchOrchestrator:
    def __init__(self, max_parallel: int = 4):
        self.semaphore = asyncio.Semaphore(max_parallel)

    async def execute_batch(self, configs):
        async def run_with_semaphore(config):
            async with self.semaphore:
                orchestrator = PipelineOrchestrator()
                return await orchestrator.execute(config)

        tasks = [run_with_semaphore(c) for c in configs]
        return await asyncio.gather(*tasks)
```

---

### Q: How do I optimize video rendering?

**A:** Use GPU, optimize FFmpeg settings, cache frames.

**Optimizations:**

**1. GPU Acceleration:**
```python
# Use h264_nvenc for NVIDIA GPUs
ffmpeg_args = [
    "-c:v", "h264_nvenc",  # GPU encoding
    "-preset", "p4",        # Medium quality
    "-b:v", "5M",          # 5 Mbps bitrate
]
```

**2. Caching:**
```python
class CachingVideoStage(VideoGenerationStage):
    def __init__(self, cache):
        self.cache = cache

    async def execute(self, input):
        # Check cache
        cache_key = self._compute_key(input)
        cached = await self.cache.get(cache_key)
        if cached:
            return cached

        # Render
        result = await super().execute(input)

        # Cache result
        await self.cache.set(cache_key, result)
        return result
```

**3. Parallel Rendering:**
```python
# Render multiple scenes concurrently
tasks = [render_scene(scene) for scene in scenes]
rendered_scenes = await asyncio.gather(*tasks)
```

---

## Testing Questions

### Q: What's the testing strategy?

**A:** Test pyramid: Unit → Integration → E2E.

**Testing Levels:**

**1. Unit Tests (80% of tests)**
```python
# Test individual components in isolation
def test_input_config_validation():
    with pytest.raises(ValidationError):
        InputConfig(source_type=123)  # Invalid

@pytest.mark.asyncio
async def test_state_manager_create_task():
    manager = StateManager(JSONStorageBackend(...))
    task = await manager.create_task({...})
    assert task.status == TaskStatus.PENDING
```

**2. Integration Tests (15% of tests)**
```python
# Test components working together
@pytest.mark.asyncio
async def test_orchestrator_with_real_stages():
    orchestrator = PipelineOrchestrator(
        state_manager=StateManager(...),
        event_bus=EventBus()
    )
    orchestrator.register_stage(InputStage())
    orchestrator.register_stage(ParsingStage())

    result = await orchestrator.execute(config)
    assert result.status == "success"
```

**3. E2E Tests (5% of tests)**
```python
# Test complete user workflows
@pytest.mark.e2e
async def test_document_to_video_workflow():
    """Complete workflow: document → video"""
    # Create video from document
    result = await Pipeline.create(
        "test_document.md",
        output_dir="./test_output"
    )

    # Verify video exists
    assert Path(result.videos[0]).exists()

    # Verify video is valid
    assert get_video_duration(result.videos[0]) > 0
```

**Coverage Targets:**
- Unit tests: 90%
- Integration tests: 85%
- E2E tests: 70%
- Overall: 80%+

---

### Q: How do I test event-driven code?

**A:** Use event capture and assertions.

**Pattern:**
```python
@pytest.mark.asyncio
async def test_orchestrator_emits_progress_events():
    """Verify progress events are emitted"""
    event_bus = EventBus()
    orchestrator = PipelineOrchestrator(event_bus=event_bus)

    # Capture events
    events_received = []

    async def capture_event(event):
        events_received.append(event)

    event_bus.subscribe(ProgressEvent, capture_event)

    # Execute pipeline
    await orchestrator.execute(config)

    # Verify events
    assert len(events_received) > 0
    assert all(isinstance(e, ProgressEvent) for e in events_received)
    assert events_received[0].progress == 0.0
    assert events_received[-1].progress == 1.0
```

---

## Deployment Questions

### Q: How do I deploy this to production?

**A:** Use Docker, environment variables, and monitoring.

**Deployment Checklist:**

**1. Configuration:**
```bash
# .env
PIPELINE_STATE_BACKEND=sqlite
PIPELINE_STATE_DIRECTORY=/data/tasks
PIPELINE_ARTIFACT_DIRECTORY=/data/artifacts
PIPELINE_MAX_CONCURRENT_TASKS=4
USE_NEW_PIPELINE=true
```

**2. Docker:**
```dockerfile
FROM python:3.10-slim

# Install FFmpeg
RUN apt-get update && apt-get install -y ffmpeg

# Install Python dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy code
COPY video_gen/ /app/video_gen/
WORKDIR /app

# Run web server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0"]
```

**3. Monitoring:**
```python
# Add metrics collection
from prometheus_client import Counter, Histogram

pipeline_executions = Counter(
    'pipeline_executions_total',
    'Total pipeline executions'
)

stage_duration = Histogram(
    'stage_duration_seconds',
    'Stage execution duration',
    ['stage_name']
)

# In orchestrator
async def _execute_stage(self, stage, task):
    start = time.time()
    try:
        result = await stage.execute(input)
        pipeline_executions.inc()
        stage_duration.labels(stage_name=stage.name).observe(
            time.time() - start
        )
        return result
    except Exception as e:
        # ...
```

---

### Q: How do I scale horizontally?

**A:** Use task queue and worker processes.

**Architecture:**
```
                    ┌─────────────┐
                    │   Web UI    │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  Task Queue │
                    │   (Redis)   │
                    └──────┬──────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
   ┌─────────┐       ┌─────────┐       ┌─────────┐
   │ Worker 1│       │ Worker 2│       │ Worker 3│
   └─────────┘       └─────────┘       └─────────┘
```

**Implementation:**
```python
# Use Celery for task distribution
from celery import Celery

app = Celery('video_gen', broker='redis://localhost')

@app.task
async def execute_pipeline(config_dict):
    """Execute pipeline task"""
    config = InputConfig(**config_dict)
    orchestrator = PipelineOrchestrator()
    result = await orchestrator.execute(config)
    return result.model_dump()

# Web UI submits tasks
@app.post("/api/create")
async def create_video(request: ParseRequest):
    task = execute_pipeline.delay(request.model_dump())
    return {"task_id": task.id}
```

---

**Have more questions?** Add them to this FAQ or ask in #video-gen-dev!

**Document Version:** 1.0
**Last Updated:** 2025-10-04
**Maintained By:** Architecture Team
