# SSE Streaming Flow Analysis - video_gen App

## Executive Summary

This document analyzes the Server-Sent Events (SSE) streaming architecture in the video_gen application, documenting the complete flow from backend event emission to frontend browser updates, and identifying potential failure points.

**Status**: System uses **polling-based SSE** (not true event-driven streaming)
**Primary Issue**: The output_stage can hang because SSE endpoints poll state files rather than receiving direct event notifications.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                    BACKEND EVENT FLOW                            │
└──────────────────────────────────────────────────────────────────┘

output_stage.py (OutputStage)
    ↓ calls await self.emit_progress(task_id, 0.05, "Starting...")
    ↓
stage.py (Stage.emit_progress)
    ↓ creates Event(type=STAGE_PROGRESS, task_id, stage, progress, message)
    ↓ await self.event_emitter.emit(event)
    ↓
events.py (EventEmitter.emit)
    ↓ async with self._lock:
    ↓ logger.debug(f"Event emitted: {event}")
    ↓ calls all registered listeners (global + type-specific)
    ↓ [NO SSE LISTENERS REGISTERED - Events logged only]
    ↓
orchestrator.py (PipelineOrchestrator)
    ↓ Updates TaskState after each stage
    ↓ task_state.overall_progress = stages_executed / total_stages
    ↓ self.state_manager.save(task_state)  ← State written to disk
    ↓
state_manager.py (StateManager)
    ↓ Saves TaskState to JSON file in temp directory
    ↓ File: /tmp/video_gen_state/{task_id}.json


┌──────────────────────────────────────────────────────────────────┐
│                    SSE POLLING FLOW                              │
└──────────────────────────────────────────────────────────────────┘

Browser requests: GET /api/tasks/{task_id}/stream
    ↓
main.py:stream_task_progress()
    ↓ async def event_generator():
    ↓     pipeline = get_pipeline()
    ↓
    ↓     # Check if task exists
    ↓     task_state = pipeline.state_manager.load(task_id)  ← READ FROM DISK
    ↓     if not task_state:
    ↓         yield error and return
    ↓
    ↓     last_progress = -1
    ↓
    ↓     # POLLING LOOP (every 0.5 seconds)
    ↓     while True:
    ↓         task_state = pipeline.state_manager.load(task_id)  ← RE-READ FROM DISK
    ↓         current_progress = int(task_state.overall_progress)
    ↓
    ↓         if current_progress != last_progress:
    ↓             event_data = {
    ↓                 "task_id": task_id,
    ↓                 "status": task_state.status.value,
    ↓                 "progress": current_progress,
    ↓                 "message": task_state.current_stage
    ↓             }
    ↓             yield f"data: {json.dumps(event_data)}\n\n"  ← SSE FORMAT
    ↓
    ↓         if task_state.status in ["completed", "failed", "cancelled"]:
    ↓             break
    ↓
    ↓         await asyncio.sleep(0.5)  ← POLL INTERVAL
    ↓
    ↓ return StreamingResponse(
    ↓     event_generator(),
    ↓     media_type="text/event-stream",
    ↓     headers={
    ↓         "Cache-Control": "no-cache",
    ↓         "X-Accel-Buffering": "no",
    ↓         "Connection": "keep-alive"
    ↓     }
    ↓ )


┌──────────────────────────────────────────────────────────────────┐
│                    FRONTEND SSE CLIENT                           │
└──────────────────────────────────────────────────────────────────┘

static/js/utils/sse-client.js (SSEClient class)
    ↓ new EventSource(`/api/tasks/${taskId}/stream`)
    ↓
    ↓ eventSource.onopen → state = 'connected'
    ↓
    ↓ eventSource.onmessage → receives SSE data
    ↓     const data = JSON.parse(event.data)
    ↓     if (this._onMessage) {
    ↓         this._onMessage(data, event)  ← Call registered handler
    ↓     }
    ↓
    ↓ eventSource.onerror → handles disconnection
    ↓     Attempts exponential backoff reconnection
    ↓
static/js/components/progress-indicator.js (ProgressIndicator)
    ↓ this.sseClient = new SSEClient({...})
    ↓ this.sseClient.onMessage((data) => {
    ↓     this.handleProgressUpdate(data)  ← Update UI
    ↓ })
    ↓ this.sseClient.connect(`/api/tasks/${taskId}/stream`)
    ↓
    ↓ handleProgressUpdate(data):
    ↓     this.progress = data.progress
    ↓     this.statusMessage = data.message
    ↓     [Updates DOM elements with Alpine.js reactivity]
```

---

## Detailed Component Analysis

### 1. Backend Event Emission (events.py)

**Location**: `video_gen/pipeline/events.py`

**EventEmitter Class**:
- Manages synchronous and asynchronous event listeners
- Thread-safe with `asyncio.Lock`
- Supports global listeners and type-specific listeners
- Event types: `STAGE_STARTED`, `STAGE_PROGRESS`, `STAGE_COMPLETED`, etc.

**Key Issue**:
```python
async def emit(self, event: Event):
    """Emit an event to all registered listeners."""
    if not self._enabled:
        return

    async with self._lock:
        logger.debug(f"Event emitted: {event}")  # ← Only logs

        # Call global listeners (NONE REGISTERED FOR SSE)
        for callback in self._global_listeners:
            callback(event)

        # Call type-specific listeners (NONE REGISTERED FOR SSE)
        if event.type in self._listeners:
            for callback in self._listeners[event.type]:
                callback(event)
```

**Problem**: No SSE-specific listeners are registered. Events are emitted but not connected to the SSE response streams.

---

### 2. Stage Progress Emission (stage.py)

**Location**: `video_gen/pipeline/stage.py`

```python
async def emit_progress(self, task_id: str, progress: float, message: str = None):
    """Emit progress update event."""
    if self.event_emitter:
        await self.event_emitter.emit(Event(
            type=EventType.STAGE_PROGRESS,
            task_id=task_id,
            stage=self.name,
            progress=progress,
            message=message or f"{self.name}: {progress:.0%}"
        ))
```

**Used in output_stage.py**:
```python
async def _handle_complete_video(self, context: Dict[str, Any]) -> StageResult:
    # Emit progress immediately
    await self.emit_progress(context["task_id"], 0.05, "Starting output handling")

    # ... validation ...
    await self.emit_progress(context["task_id"], 0.1, "Preparing output")

    # ... work ...
    await self.emit_progress(context["task_id"], 0.2, "Generating metadata")

    # ... more work ...
    await self.emit_progress(context["task_id"], 0.5, "Creating thumbnail")
```

**Flow**: These events are emitted but only logged. They don't reach the SSE stream directly.

---

### 3. State Persistence (state_manager.py)

**Location**: `video_gen/pipeline/state_manager.py`

```python
class StateManager:
    """Handles task persistence via JSON files."""

    def save(self, task_state: TaskState):
        """Save task state to disk."""
        state_file = self.state_dir / f"{task_state.task_id}.json"
        with open(state_file, 'w') as f:
            json.dump(task_state.to_dict(), f, indent=2)

    def load(self, task_id: str) -> Optional[TaskState]:
        """Load task state from disk."""
        state_file = self.state_dir / f"{task_id}.json"
        if not state_file.exists():
            return None
        with open(state_file, 'r') as f:
            data = json.load(f)
        return TaskState.from_dict(data)
```

**State Updates in Orchestrator**:
```python
# orchestrator.py
async def _execute_stages_sequential(...):
    for stage in stages:
        # Update state before stage
        task_state.start_stage(stage.name)
        self.state_manager.save(task_state)  # ← WRITE TO DISK

        # Execute stage
        result = await stage.run(context, task_id)

        # Update state after stage
        task_state.complete_stage(stage.name, result.artifacts)
        self.state_manager.save(task_state)  # ← WRITE TO DISK
```

**Critical Detail**: State is saved to disk multiple times during execution. SSE polling reads these files.

---

### 4. SSE Polling Endpoint (main.py)

**Location**: `app/main.py:1428-1487`

```python
@app.get("/api/tasks/{task_id}/stream")
async def stream_task_progress(task_id: str):
    """
    Stream real-time progress via Server-Sent Events.
    Now uses pipeline event system for real-time updates.
    """
    async def event_generator():
        pipeline = get_pipeline()

        # Check if task exists
        task_state = pipeline.state_manager.load(task_id)  # ← DISK READ #1
        if not task_state:
            yield f"data: {json.dumps({'error': 'Task not found'})}\n\n"
            return

        last_progress = -1

        # POLLING LOOP - runs every 0.5 seconds
        while True:
            try:
                # Reload state from disk
                task_state = pipeline.state_manager.load(task_id)  # ← DISK READ #N
                if not task_state:
                    break

                current_progress = int(task_state.overall_progress)

                # Send update if progress changed
                if current_progress != last_progress:
                    last_progress = current_progress

                    event_data = {
                        "task_id": task_id,
                        "status": _map_status(task_state.status.value),
                        "progress": current_progress,
                        "message": task_state.current_stage or "Processing..."
                    }

                    yield f"data: {json.dumps(event_data)}\n\n"  # ← SSE FORMAT

                # Stop if completed or failed
                if task_state.status.value in ["completed", "failed", "cancelled"]:
                    break

                await asyncio.sleep(0.5)  # ← POLL EVERY 500ms

            except Exception as e:
                logger.error(f"Error streaming progress: {e}")
                break

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive"
        }
    )
```

**Alternative Endpoint** (`/api/videos/jobs/{job_id}/events`):
- Located at `main.py:2071-2169`
- Similar polling approach
- Includes more detailed stage information
- Same 0.5 second poll interval

---

### 5. Frontend SSE Client (sse-client.js)

**Location**: `app/static/js/utils/sse-client.js`

```javascript
class SSEClient {
    constructor(options = {}) {
        this.options = {
            maxRetries: options.maxRetries || 5,
            baseDelay: options.baseDelay || 1000,
            maxDelay: options.maxDelay || 30000,
            autoReconnect: options.autoReconnect !== false
        };
        this.state = 'disconnected';
    }

    connect(url, options = {}) {
        this.url = url;
        this.state = 'connecting';
        this._createConnection();
        return this;
    }

    _createConnection() {
        this.eventSource = new EventSource(this.url);  // ← Browser native SSE

        this.eventSource.onopen = (event) => {
            console.log('[SSEClient] Connection established');
            this.state = 'connected';
            this.retryCount = 0;
            if (this._onOpen) this._onOpen(event);
        };

        this.eventSource.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (this._onMessage) {
                    this._onMessage(data, event);  // ← Call registered handler
                }

                // Auto-close on completion
                if (data.status === 'complete' || data.status === 'failed') {
                    this.close();
                }
            } catch (parseError) {
                console.error('[SSEClient] Failed to parse message:', parseError);
            }
        };

        this.eventSource.onerror = (error) => {
            console.error('[SSEClient] Connection error:', error);
            if (this.eventSource.readyState === EventSource.CLOSED) {
                this._handleDisconnect(error);
            }
        };
    }

    _attemptReconnect() {
        // Exponential backoff reconnection
        const delay = Math.min(
            this.options.baseDelay * Math.pow(2, this.retryCount - 1),
            this.options.maxDelay
        );

        setTimeout(() => {
            if (this.state !== 'closed') {
                this._createConnection();
            }
        }, delay);
    }
}
```

**Features**:
- Auto-reconnect with exponential backoff (1s → 2s → 4s → ... → 30s max)
- Max 5 retry attempts by default
- Graceful error handling
- Connection state tracking

---

### 6. Frontend Progress Indicator (progress-indicator.js)

**Location**: `app/static/js/components/progress-indicator.js`

```javascript
// Alpine.js component
const ProgressIndicator = {
    sseClient: null,
    connectionState: 'disconnected',

    connectSSE(taskId) {
        // Close existing connection
        if (this.sseClient) {
            this.sseClient.close();
        }

        this.connectionState = 'connecting';

        // Create SSE client
        this.sseClient = new SSEClient({
            maxRetries: 5,
            baseDelay: 1000,
            maxDelay: 10000,
            autoReconnect: true
        });

        this.sseClient
            .onOpen(() => {
                console.log('[ProgressIndicator] SSE connection opened');
                this.connectionState = 'connected';
            })
            .onMessage((data) => {
                this.handleProgressUpdate(data);  // ← Update UI
            })
            .onError((error) => {
                console.error('[ProgressIndicator] SSE error:', error);
                this.connectionState = 'disconnected';

                // Fallback to polling after 3 SSE failures
                if (this.retryCount >= 3 && this.isProcessing) {
                    this.startPolling(taskId);
                }
            })
            .connect(`${this.streamEndpoint}/${taskId}/stream`);
    },

    handleProgressUpdate(data) {
        console.log('[ProgressIndicator] Progress update:', data);

        this.progress = data.progress || 0;
        this.statusMessage = data.message || '';
        this.timeElapsed = data.time_elapsed;
        this.timeRemaining = data.time_remaining;

        // Handle stage updates
        if (data.stages) {
            this.stages = data.stages;
        }

        // Handle completion
        if (data.status === 'complete' || data.status === 'completed') {
            this.handleComplete(data);
        } else if (data.status === 'failed') {
            this.handleError(data);
        }
    },

    async startPolling(taskId) {
        // Fallback mechanism if SSE fails
        console.log('[ProgressIndicator] Falling back to polling');

        const poll = async () => {
            if (!this.isProcessing || this.isComplete) return;

            try {
                const response = await fetch(`${this.streamEndpoint}/${taskId}`);
                if (response.ok) {
                    const data = await response.json();
                    this.handleProgressUpdate(data);

                    if (data.status !== 'complete' && data.status !== 'failed') {
                        setTimeout(poll, 1500);  // Poll every 1.5s
                    }
                }
            } catch (error) {
                console.error('[ProgressIndicator] Polling error:', error);
                setTimeout(poll, 3000);  // Retry after 3s
            }
        };

        poll();
    }
};
```

**UI Updates**:
- Uses Alpine.js reactivity (`x-data`, `x-model`, etc.)
- Updates progress bars, status messages, stage indicators
- Falls back to HTTP polling if SSE fails repeatedly
- Handles completion and error states

---

## Critical Failure Points

### 1. **Event Emission Disconnect** (HIGH SEVERITY)

**Problem**: Events are emitted but never connected to SSE streams.

```python
# output_stage.py emits events
await self.emit_progress(task_id, 0.5, "Creating thumbnail")

# events.py logs but doesn't propagate to SSE
logger.debug(f"Event emitted: {event}")  # ← Only logging happens

# SSE endpoint never sees these events - it polls state files instead
task_state = pipeline.state_manager.load(task_id)  # ← Reads from disk
```

**Impact**:
- SSE updates delayed by poll interval (500ms)
- Events emitted during thumbnail generation not seen until next poll
- Real-time progress appears "laggy"

**Why output_stage hangs on headless servers**:
- Thumbnail generation uses matplotlib/moviepy with GUI dependencies
- If these block on headless systems, emit_progress calls execute
- But SSE endpoint doesn't see progress until thumbnail completes
- Frontend appears hung until next successful state file write

---

### 2. **File I/O Bottleneck** (MEDIUM SEVERITY)

**Problem**: Every SSE poll reads JSON from disk.

```python
# Runs every 0.5 seconds per connected client
while True:
    task_state = pipeline.state_manager.load(task_id)  # ← Disk I/O
    # ... send update ...
    await asyncio.sleep(0.5)
```

**Impact**:
- High I/O load with multiple clients
- Potential race conditions if state file is being written during read
- Latency spikes on slow disks
- No batching or caching

---

### 3. **Progress Granularity Loss** (MEDIUM SEVERITY)

**Problem**: Only detects progress changes, not all events.

```python
# SSE polls for integer progress changes
current_progress = int(task_state.overall_progress)

if current_progress != last_progress:
    # Only sends when progress changes by 1%
    yield f"data: {json.dumps(event_data)}\n\n"
```

**Impact**:
- Sub-stage progress (0.1 → 0.2 → 0.5) collapsed to single update
- Fine-grained status messages ("Generating metadata", "Creating thumbnail") potentially missed
- User sees fewer updates than backend emits

---

### 4. **Async Generator Cleanup** (LOW-MEDIUM SEVERITY)

**Problem**: Event generator may not clean up properly on client disconnect.

```python
async def event_generator():
    pipeline = get_pipeline()
    task_state = pipeline.state_manager.load(task_id)

    while True:
        # ... polling loop ...
        await asyncio.sleep(0.5)

    # No explicit cleanup or finally block for client disconnect
```

**Impact**:
- Generator continues polling after client disconnects (until timeout)
- Wastes resources on abandoned connections
- No notification to backend that client is gone

---

### 5. **Matplotlib Backend on Headless Servers** (HIGH SEVERITY)

**Problem**: Thumbnail generation uses matplotlib with potential GUI dependencies.

```python
# output_stage.py:18-19
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend

# output_stage.py:378
from moviepy import VideoFileClip
import matplotlib.pyplot as plt

plt.imsave(str(output_path), frame)  # ← Can hang on headless systems
```

**Impact**:
- If matplotlib still tries to initialize GUI (despite 'Agg' backend)
- Process blocks waiting for display server
- State file never gets updated with progress past this point
- SSE polls stale state indefinitely
- Frontend appears frozen

**Mitigations in place**:
- 30-second timeout on thumbnail generation (line 96-102)
- Thumbnail is optional (logged warning if fails)
- But if hang occurs in matplotlib import/init, timeout may not help

---

### 6. **No Heartbeat/Keepalive** (LOW SEVERITY)

**Problem**: SSE stream only sends when progress changes.

```python
if current_progress != last_progress:
    yield f"data: {json.dumps(event_data)}\n\n"

# If progress stalls, no SSE messages sent
await asyncio.sleep(0.5)  # Silent polling
```

**Impact**:
- Frontend can't distinguish between:
  - Backend working but no progress change
  - Backend hung/crashed
  - SSE connection silently closed
- No periodic "still alive" messages
- Proxies/load balancers may close idle connections

---

## Architectural Disconnects

### Gap #1: Event System Not Connected to SSE

```
┌─────────────────────────────────────────────────────┐
│  CURRENT ARCHITECTURE (DISCONNECTED)                │
├─────────────────────────────────────────────────────┤
│                                                     │
│  output_stage.emit_progress()                      │
│       ↓                                             │
│  EventEmitter.emit()                                │
│       ↓                                             │
│  logger.debug()  ← Events only logged              │
│       ↓                                             │
│  [NOTHING HAPPENS]                                  │
│                                                     │
│  Meanwhile...                                       │
│                                                     │
│  SSE endpoint polls every 500ms                    │
│       ↓                                             │
│  state_manager.load()  ← Reads from disk           │
│       ↓                                             │
│  yield SSE message if progress changed             │
│                                                     │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  EXPECTED ARCHITECTURE (CONNECTED)                  │
├─────────────────────────────────────────────────────┤
│                                                     │
│  output_stage.emit_progress()                      │
│       ↓                                             │
│  EventEmitter.emit()                                │
│       ↓                                             │
│  SSE listener callback  ← Direct connection        │
│       ↓                                             │
│  yield SSE message immediately                     │
│       ↓                                             │
│  Browser receives update in real-time              │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Gap #2: State File Intermediary

```
Events → EventEmitter → [DISCONNECTED]

            ↓ (separate path)

Orchestrator → StateManager → JSON file on disk
                                    ↓
                            SSE polls file
                                    ↓
                            Browser receives update
```

**Why this matters**:
- 500ms delay minimum (poll interval)
- File I/O latency added
- Events during long operations (thumbnail) not visible until operation completes
- No way to stream "still working" status during CPU-intensive tasks

---

## Recommendations

### High Priority

1. **Connect EventEmitter to SSE streams**:
   ```python
   # Register SSE clients as event listeners
   class SSEEventListener:
       def __init__(self, queue: asyncio.Queue):
           self.queue = queue

       async def handle_event(self, event: Event):
           await self.queue.put(event)

   # In SSE endpoint
   async def event_generator():
       queue = asyncio.Queue()
       listener = SSEEventListener(queue)

       # Register listener for this task
       pipeline.event_emitter.on_async(EventType.STAGE_PROGRESS, listener.handle_event)

       try:
           while True:
               event = await asyncio.wait_for(queue.get(), timeout=30.0)
               yield format_sse_message(event)
       finally:
           # Cleanup
           pipeline.event_emitter.off(EventType.STAGE_PROGRESS, listener.handle_event)
   ```

2. **Fix matplotlib/moviepy blocking on headless servers**:
   - Ensure matplotlib backend set BEFORE any imports
   - Add more aggressive timeout handling
   - Consider running thumbnail generation in subprocess with timeout
   - Test on actual headless environment

3. **Add SSE heartbeat**:
   ```python
   # Send keepalive every 15 seconds if no progress change
   last_message_time = time.time()

   while True:
       # ... existing logic ...

       if time.time() - last_message_time > 15.0:
           yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
           last_message_time = time.time()
   ```

### Medium Priority

4. **Implement event queue with fallback**:
   - Primary: Event-driven SSE (immediate updates)
   - Fallback: State file polling (if events missed)
   - Hybrid approach for reliability

5. **Add connection tracking**:
   ```python
   active_sse_connections = {}

   async def event_generator():
       connection_id = str(uuid.uuid4())
       active_sse_connections[task_id] = connection_id

       try:
           # ... SSE loop ...
       finally:
           active_sse_connections.pop(task_id, None)
   ```

6. **Cache state reads**:
   ```python
   # In StateManager
   def __init__(self):
       self._cache = {}
       self._cache_timeout = 1.0  # seconds

   def load(self, task_id: str, use_cache=True):
       if use_cache and task_id in self._cache:
           cached_state, cached_time = self._cache[task_id]
           if time.time() - cached_time < self._cache_timeout:
               return cached_state

       # Load from disk
       state = self._load_from_disk(task_id)
       self._cache[task_id] = (state, time.time())
       return state
   ```

### Low Priority

7. **Add SSE metrics/monitoring**:
   - Track active connections
   - Monitor poll frequency
   - Log disconnections and errors
   - Alert on stalled progress

8. **Improve error propagation**:
   - Send structured error events via SSE
   - Include error codes, recovery suggestions
   - Don't just close connection on error

---

## Testing Checklist

To verify SSE functionality:

1. **Test progress updates**:
   - Start video generation
   - Monitor browser console for SSE messages
   - Verify messages received every 0.5s (or when progress changes)
   - Check for gaps in progress reporting

2. **Test thumbnail generation**:
   - Generate video with thumbnail
   - Confirm SSE updates continue during thumbnail creation
   - Verify 30s timeout works on slow systems
   - Test on headless server (Docker without X11)

3. **Test connection resilience**:
   - Disconnect network mid-generation
   - Verify auto-reconnect works
   - Check fallback to HTTP polling
   - Ensure max retry limits respected

4. **Test concurrent clients**:
   - Open multiple browser tabs
   - Start generation in each
   - Monitor server load (CPU, I/O)
   - Check for resource leaks

5. **Test edge cases**:
   - Task not found (invalid task_id)
   - Task completed before SSE connects
   - Backend crashes mid-generation
   - State file corruption
   - Rapid progress changes (faster than poll interval)

---

## Conclusion

The video_gen SSE implementation uses a **polling-based approach** rather than true event-driven streaming. While functional, this architecture:

1. **Disconnects events from SSE**: Events emitted by stages don't directly reach SSE clients
2. **Introduces latency**: 500ms minimum delay due to polling
3. **Creates I/O overhead**: Disk reads on every poll for every client
4. **Masks hanging issues**: If a stage hangs (like thumbnail generation), SSE continues polling stale state

The **output_stage hanging issue on headless servers** is likely caused by matplotlib/moviepy GUI initialization blocking, which prevents state updates. The SSE endpoint then polls a frozen state file indefinitely.

**Immediate fix**: Ensure matplotlib backend is properly configured for headless operation (already attempted with `matplotlib.use('Agg')`), and test in actual headless Docker environment.

**Long-term fix**: Connect EventEmitter directly to SSE streams for true real-time updates, eliminating polling delays and file I/O overhead.
