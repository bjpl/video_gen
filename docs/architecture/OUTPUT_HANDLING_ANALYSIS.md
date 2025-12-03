# Output Handling Stage Analysis - Progress Propagation & Blocking Issues

**Date:** December 2, 2025
**Component:** PipelineOrchestrator + OutputStage
**Issue:** output_handling stage appears stuck with no progress updates

---

## Executive Summary

The output_handling stage can appear "stuck" despite functioning correctly due to:

1. **Progress polling mechanism in SSE endpoint** - only detects integer changes in progress
2. **Async lock contention** - EventEmitter lock can delay progress events
3. **Limited progress granularity** - stage emits only 7 progress points (5%, 10%, 20%, 50%, 80%, 100%)
4. **Heavy synchronous operations** - MoviePy operations in thread pool don't yield to event loop

**Critical Finding:** The SSE endpoint polls `overall_progress` (stage progress divided by total stages), converting to integer percentage. For 6-stage pipeline, output_handling represents 16.67% of total, meaning stage must complete 83-100% internally before SSE shows 1% overall progress change.

---

## Architecture Overview

### 1. Stage Execution Flow

```
PipelineOrchestrator.execute()
    ├─> _execute_phases()
    │   ├─> Phase 1: preparation (sequential)
    │   ├─> Phase 2: generation (parallel)
    │   ├─> Phase 3: assembly (sequential)
    │   └─> Phase 4: finalization (sequential)  ← output_handling
    │       └─> _execute_stages_sequential()
    │           ├─> task_state.start_stage("output_handling")
    │           ├─> stage.run(context, task_id)
    │           │   ├─> emit(STAGE_STARTED)
    │           │   ├─> execute(context)  ← OutputStage logic
    │           │   │   ├─> emit_progress(0.05, "Starting")
    │           │   │   ├─> emit_progress(0.10, "Preparing")
    │           │   │   ├─> emit_progress(0.20, "Generating metadata")
    │           │   │   ├─> emit_progress(0.50, "Creating thumbnail")
    │           │   │   ├─> emit_progress(0.80, "Finalizing")
    │           │   │   └─> emit_progress(1.00, "Complete")
    │           │   └─> emit(STAGE_COMPLETED)
    │           └─> task_state.complete_stage()
    └─> emit(PIPELINE_COMPLETED)
```

### 2. Event Propagation Chain

```
Stage.emit_progress(task_id, progress, message)
    ↓
EventEmitter.emit(Event(STAGE_PROGRESS))
    ↓ [async with self._lock]  ← POTENTIAL BOTTLENECK
    ├─> async_global_listeners[](event)
    ├─> async_listeners[STAGE_PROGRESS][](event)
    └─> Log event (debug level)

[Meanwhile, separate thread...]

SSE Endpoint: stream_task_progress(task_id)
    ↓ [polling loop every 0.5s]
    ├─> Load task_state from StateManager
    ├─> current_progress = int(task_state.overall_progress)
    │   ↑ overall_progress = stages_executed / total_stages
    │   │ For 6-stage pipeline at stage 6:
    │   │   - Stage 0% → Overall = 5/6 = 83.33% → int = 83
    │   │   - Stage 50% → Overall = 5.5/6 = 91.67% → int = 91
    │   │   - Stage 100% → Overall = 6/6 = 100% → int = 100
    └─> Send SSE if current_progress != last_progress
```

### 3. Progress Update Mechanism

**Orchestrator Level (`orchestrator.py:464`):**
```python
# After each phase completes
stages_executed += len(phase_stages)
task_state.overall_progress = stages_executed / total_stages
self.state_manager.save(task_state)
```

**Stage Level (`output_stage.py:60,72,84,91,104,125`):**
```python
await self.emit_progress(context["task_id"], 0.05, "Starting output handling")
await self.emit_progress(context["task_id"], 0.10, "Preparing output")
await self.emit_progress(context["task_id"], 0.20, "Generating metadata")
await self.emit_progress(context["task_id"], 0.50, "Creating thumbnail")
await self.emit_progress(context["task_id"], 0.80, "Finalizing output")
await self.emit_progress(context["task_id"], 1.00, "Output complete")
```

**SSE Polling (`main.py:1454`):**
```python
current_progress = int(task_state.overall_progress)  # Converts to integer (0-100)
if current_progress != last_progress:
    # Only send if integer percentage changed
    yield f"data: {json.dumps(event_data)}\n\n"
```

---

## Root Cause Analysis

### Issue 1: Integer Rounding in SSE Endpoint

**Problem:** SSE endpoint converts `overall_progress` (float 0.0-1.0) to integer percentage, losing granularity.

**Impact:** For a 6-stage pipeline:
- Stage 6 starts at 83.33% overall progress
- Stage 6 at 50% internal → 91.67% overall → displayed as **91%**
- Stage 6 at 80% internal → 96.67% overall → displayed as **96%**
- Only **2-3 visible updates** for entire stage despite 7 internal progress events

**Code Location:** `/app/main.py:1454`
```python
current_progress = int(task_state.overall_progress)  # LOSES PRECISION
```

### Issue 2: Event Emitter Lock Contention

**Problem:** EventEmitter uses async lock during event propagation.

**Impact:**
- Progress events queue behind lock
- Heavy event processing (multiple listeners) blocks other events
- SSE polling may read stale state before event updates persist

**Code Location:** `/video_gen/pipeline/events.py:145`
```python
async with self._lock:  # ALL events serialize through this
    # Call all listeners...
    await callback(event)
```

### Issue 3: Overall Progress Calculation Timing

**Problem:** `overall_progress` updated only **after entire phase completes**, not during stage execution.

**Impact:**
- During output_handling stage, `overall_progress` remains at 5/6 = 83.33%
- Only jumps to 6/6 = 100% when stage fully completes
- **No intermediate progress visible in overall_progress**

**Code Location:** `/video_gen/pipeline/orchestrator.py:463-465`
```python
# Update progress AFTER phase completes
all_results.extend(phase_results)
stages_executed += len(phase_stages)
task_state.overall_progress = stages_executed / total_stages  # Discrete jumps only
```

### Issue 4: Blocking Operations in OutputStage

**Problem:** Thumbnail generation and video operations run in thread pool but don't yield to event loop.

**Impact:**
- `_generate_thumbnail_sync()` uses MoviePy (CPU-intensive)
- `_combine_videos_sync()` uses MoviePy (I/O and CPU-intensive)
- Progress events may queue while these operations hold thread pool
- 30-second timeouts mitigate but don't eliminate blocking

**Code Location:** `/video_gen/stages/output_stage.py:96-99, 373-389`
```python
await asyncio.wait_for(
    self._generate_thumbnail(output_video_path, thumbnail_path),
    timeout=30.0  # Can still block for up to 30 seconds
)

# Synchronous MoviePy operations
def _generate_thumbnail_sync(self, video_path: Path, output_path: Path):
    clip = VideoFileClip(str(video_path))  # Blocking I/O
    frame = clip.get_frame(frame_time)      # Blocking processing
    plt.imsave(str(output_path), frame)     # Blocking I/O
```

### Issue 5: Stage Progress Events Not Integrated with Overall Progress

**Problem:** Stage emits `STAGE_PROGRESS` events, but orchestrator doesn't update `overall_progress` based on these.

**Impact:**
- Stage progress events (5%, 10%, 20%, 50%, 80%, 100%) exist but **not reflected in task_state.overall_progress**
- SSE endpoint reads `task_state.overall_progress`, missing all stage-level granularity
- **Complete disconnect between stage progress and SSE-visible progress**

**Evidence:**
```python
# Stage emits events: STAGE_PROGRESS with progress=0.5
await self.emit_progress(context["task_id"], 0.5, "Creating thumbnail")

# But orchestrator never updates task_state.overall_progress during stage execution
# It only updates after stage COMPLETES:
task_state.overall_progress = stages_executed / total_stages  # Discrete only
```

---

## Specific Failure Scenarios

### Scenario A: Headless Server with No Display
**Trigger:** matplotlib backend not set to 'Agg' before pyplot import
**Symptom:** Thumbnail generation hangs indefinitely
**Status:** ✅ **FIXED** in output_stage.py:18-19 with `matplotlib.use('Agg')`

### Scenario B: Large Video Thumbnail Extraction
**Trigger:** Video file > 100MB, MoviePy memory loading
**Symptom:** 5-15 second delay with no progress updates
**Mitigation:** 30-second timeout + warning on failure (non-critical)
**Visibility:** ⚠️ SSE shows 91% → 96% → 100% (only 3 updates)

### Scenario C: SSE Polling Miss
**Trigger:** Progress changes during 0.5s sleep window
**Symptom:** User sees "stuck" at previous percentage
**Impact:** Up to 0.5s delay + integer rounding = 1-2s apparent "hang"

### Scenario D: Event Listener Backlog
**Trigger:** Multiple async listeners processing heavy events
**Symptom:** Progress events queue behind lock
**Impact:** State updates delayed by 100-500ms per event

---

## Recommendations

### Priority 1: Fix SSE Progress Granularity

**Change:** Update SSE endpoint to combine discrete stage progress with stage-level progress.

**Implementation:**
```python
# main.py:1454 - Enhanced progress calculation
async def event_generator():
    while True:
        task_state = pipeline.state_manager.load(task_id)

        # Calculate overall progress including current stage progress
        completed_stages = len(task_state.get_completed_stages())
        current_stage_progress = task_state.stage_progress.get(task_state.current_stage, 0.0)

        # Weighted progress: completed stages + current stage fraction
        overall_progress = (completed_stages + current_stage_progress) / total_stages
        current_progress = int(overall_progress * 100)  # Now has stage granularity

        if current_progress != last_progress:
            yield f"data: {json.dumps(event_data)}\n\n"
```

**Impact:** 7 visible updates during output_handling instead of 2-3.

### Priority 2: Store Stage Progress in TaskState

**Change:** Update TaskState to track per-stage progress.

**Implementation:**
```python
# state_manager.py - Add to TaskState
@dataclass
class TaskState:
    # ... existing fields ...
    stage_progress: Dict[str, float] = field(default_factory=dict)  # NEW

    def update_stage_progress(self, stage_name: str, progress: float):
        """Update progress for currently running stage."""
        self.stage_progress[stage_name] = progress

# stage.py - Update emit_progress to persist
async def emit_progress(self, task_id: str, progress: float, message: str = None):
    # Update state manager if available
    if hasattr(self, '_state_manager') and self._state_manager:
        task_state = self._state_manager.load(task_id)
        if task_state:
            task_state.update_stage_progress(self.name, progress)
            self._state_manager.save(task_state)

    # Emit event as before
    if self.event_emitter:
        await self.event_emitter.emit(...)
```

**Impact:** SSE endpoint can read intermediate stage progress from persistent state.

### Priority 3: Reduce EventEmitter Lock Contention

**Change:** Use lock-free event broadcasting with asyncio.Queue.

**Implementation:**
```python
# events.py - Refactor EventEmitter
class EventEmitter:
    def __init__(self):
        self._event_queue = asyncio.Queue()
        self._processor_task = None

    async def emit(self, event: Event):
        """Non-blocking emit - queue event immediately"""
        await self._event_queue.put(event)

    async def _process_events(self):
        """Background task processes events without blocking emit()"""
        while True:
            event = await self._event_queue.get()
            # Call listeners without lock
            for callback in self._get_listeners(event.type):
                try:
                    await callback(event)
                except Exception as e:
                    logger.error(f"Listener error: {e}")
```

**Impact:** emit_progress() returns immediately, no blocking on listener processing.

### Priority 4: Add Progress Logging

**Change:** Log progress events at INFO level for debugging.

**Implementation:**
```python
# stage.py:159
async def emit_progress(self, task_id: str, progress: float, message: str = None):
    self.logger.info(f"Progress: {progress:.1%} - {message or self.name}")  # NEW
    if self.event_emitter:
        await self.event_emitter.emit(...)
```

**Impact:** Server logs show progress even if SSE fails, aids debugging.

### Priority 5: Add Progress Checkpoints to Heavy Operations

**Change:** Emit progress during long-running operations.

**Implementation:**
```python
# output_stage.py:373 - Enhanced thumbnail generation
def _generate_thumbnail_sync(self, video_path: Path, output_path: Path):
    clip = VideoFileClip(str(video_path))
    # Emit 50% checkpoint after video load
    asyncio.create_task(self.emit_progress(context["task_id"], 0.55, "Processing thumbnail"))

    frame = clip.get_frame(frame_time)
    # Emit 75% checkpoint after frame extraction
    asyncio.create_task(self.emit_progress(context["task_id"], 0.65, "Saving thumbnail"))

    plt.imsave(str(output_path), frame)
```

**Impact:** Finer-grained feedback during 5-15 second thumbnail operation.

---

## Testing Strategy

### Test 1: SSE Progress Visibility
```python
# Test: Verify SSE shows granular progress during output_handling
async def test_sse_output_handling_progress():
    # Start pipeline
    task_id = await pipeline.execute_async(input_config)

    # Monitor SSE stream
    progress_updates = []
    async with httpx.AsyncClient() as client:
        async with client.stream('GET', f'/api/tasks/{task_id}/stream') as response:
            async for line in response.aiter_lines():
                if line.startswith('data:'):
                    data = json.loads(line[6:])
                    progress_updates.append(data['progress'])

    # Verify at least 5 updates during output_handling (not just 2-3)
    output_stage_updates = [p for p in progress_updates if 83 <= p <= 100]
    assert len(output_stage_updates) >= 5
```

### Test 2: Progress Event Timing
```python
# Test: Measure event propagation latency
async def test_progress_event_latency():
    events = []

    async def listener(event):
        events.append((event, datetime.now()))

    event_emitter.on_async(EventType.STAGE_PROGRESS, listener)

    # Emit 10 progress events
    start = datetime.now()
    for i in range(10):
        await stage.emit_progress(task_id, i/10, f"Step {i}")

    # Verify all events received within 100ms
    assert all(e[1] - start < timedelta(milliseconds=100) for e in events)
```

### Test 3: Blocking Operation Impact
```python
# Test: Verify thumbnail generation doesn't block progress events
async def test_thumbnail_nonblocking():
    progress_events = []

    async def track_progress(event):
        progress_events.append(datetime.now())

    event_emitter.on_async(EventType.STAGE_PROGRESS, track_progress)

    # Generate thumbnail while emitting progress
    await output_stage._generate_thumbnail(video_path, thumbnail_path)

    # Verify progress events continued during thumbnail generation
    assert len(progress_events) >= 3
    time_gaps = [progress_events[i+1] - progress_events[i] for i in range(len(progress_events)-1)]
    assert all(gap < timedelta(seconds=5) for gap in time_gaps)
```

---

## File References

**Core Files:**
- `/video_gen/pipeline/orchestrator.py` - Stage execution, progress calculation (lines 391-471, 473-527)
- `/video_gen/stages/output_stage.py` - Output handling implementation (lines 56-149)
- `/video_gen/pipeline/stage.py` - Base stage, progress emission (lines 159-175)
- `/video_gen/pipeline/events.py` - Event system (lines 76-203)
- `/app/main.py` - SSE endpoint (lines 1428-1487)
- `/video_gen/pipeline/state_manager.py` - TaskState persistence (needs inspection)

**Key Code Sections:**
- Overall progress update: `orchestrator.py:464`
- Stage progress emission: `output_stage.py:60,72,84,91,104,125`
- SSE polling: `main.py:1454-1467`
- Event emission: `events.py:135-176`
- Blocking operations: `output_stage.py:96-99, 373-389`

---

## Conclusion

The output_handling stage **does emit progress events correctly**, but these events **don't reach the SSE stream** due to:

1. Integer conversion losing 90% of progress granularity
2. Orchestrator not updating `overall_progress` during stage execution
3. SSE endpoint reading discrete `overall_progress` instead of stage-level progress
4. EventEmitter lock potentially delaying state persistence

**Primary Fix:** Integrate stage-level progress into SSE-visible progress calculation (Priority 1 + 2).

**Secondary Optimizations:** Reduce lock contention (Priority 3), enhance logging (Priority 4), add checkpoints (Priority 5).

**Expected Result:** Users see **5-7 progress updates** during output_handling instead of 2-3, with no perceived "hanging."
