# Video Generation Pipeline - Visual Flow Diagrams

**Companion to:** PIPELINE_ANALYSIS_REPORT.md
**Date:** October 9, 2025

---

## 1. High-Level Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│                         VIDEO GENERATION PIPELINE                       │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                                                                 │  │
│  │  InputConfig                                                    │  │
│  │  • input_type: document/youtube/yaml/programmatic              │  │
│  │  • source: path/url/data                                       │  │
│  │  • accent_color, voice, languages                              │  │
│  │  • use_ai_narration: bool                                      │  │
│  │                                                                 │  │
│  └────────────────────────┬────────────────────────────────────────┘  │
│                           │                                            │
│                           ↓                                            │
│  ╔═════════════════════════════════════════════════════════════════╗  │
│  ║ PipelineOrchestrator                                            ║  │
│  ║ • Manages stage execution                                       ║  │
│  ║ • Maintains shared context dictionary                           ║  │
│  ║ • Handles errors and resume                                     ║  │
│  ║ • Persists state after each stage                               ║  │
│  ╚═════════════════════════════════════════════════════════════════╝  │
│                           │                                            │
│                           ↓                                            │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ Stage 1: InputStage (input_adaptation)                          │  │
│  │ ────────────────────────────────────────                        │  │
│  │ IN:  input_config                                               │  │
│  │ OUT: video_config (VideoConfig with scenes)                     │  │
│  │      input_metadata                                             │  │
│  └────────────────────────┬────────────────────────────────────────┘  │
│                           │                                            │
│                           ↓                                            │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ Stage 2: ParsingStage (content_parsing)                         │  │
│  │ ───────────────────────────────────────                         │  │
│  │ IN:  video_config                                               │  │
│  │ OUT: video_config (enriched with parsed_content)                │  │
│  └────────────────────────┬────────────────────────────────────────┘  │
│                           │                                            │
│                           ↓                                            │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ Stage 3: ScriptGenerationStage (script_generation)              │  │
│  │ ──────────────────────────────────────────────                  │  │
│  │ IN:  video_config, input_config (for AI flag)                   │  │
│  │ OUT: video_config (with scene.narration populated)              │  │
│  └────────────────────────┬────────────────────────────────────────┘  │
│                           │                                            │
│                           ↓                                            │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ Stage 4: AudioGenerationStage (audio_generation)                │  │
│  │ ────────────────────────────────────────────                    │  │
│  │ IN:  video_config                                               │  │
│  │ OUT: audio_dir (Path to MP3 files)                              │  │
│  │      timing_report (JSON with scene timings)                    │  │
│  │      video_config (with audio_file, durations)                  │  │
│  └────────────────────────┬────────────────────────────────────────┘  │
│                           │                                            │
│                           ↓                                            │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ Stage 5: VideoGenerationStage (video_generation)                │  │
│  │ ────────────────────────────────────────────                    │  │
│  │ IN:  video_config, audio_dir, timing_report                     │  │
│  │ OUT: final_video_path (rendered MP4)                            │  │
│  │      video_dir (intermediate files)                             │  │
│  └────────────────────────┬────────────────────────────────────────┘  │
│                           │                                            │
│                           ↓                                            │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ Stage 6: OutputStage (output_handling)                          │  │
│  │ ──────────────────────────────────────                          │  │
│  │ IN:  final_video_path, video_dir, video_config                  │  │
│  │ OUT: output_dir (organized outputs)                             │  │
│  │      metadata_path (JSON metadata)                              │  │
│  │      thumbnail_path (JPG thumbnail)                             │  │
│  └────────────────────────┬────────────────────────────────────────┘  │
│                           │                                            │
│                           ↓                                            │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                                                                 │  │
│  │  PipelineResult                                                 │  │
│  │  • success: bool                                                │  │
│  │  • video_path: Path                                             │  │
│  │  • total_duration: float                                        │  │
│  │  • scene_count: int                                             │  │
│  │  • errors: List[str]                                            │  │
│  │  • warnings: List[str]                                          │  │
│  │                                                                 │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Context Flow Detailed

```
CONTEXT DICTIONARY EVOLUTION
═══════════════════════════════════════════════════════════════════════

Initial State (Orchestrator.execute, line 129-134):
┌─────────────────────────────────────────────────────────────┐
│ context = {                                                 │
│   "task_id": "task_abc123def456",                           │
│   "input_config": InputConfig(...),                         │
│   "config": config  # System config                         │
│ }                                                           │
└─────────────────────────────────────────────────────────────┘
                          │
                          ↓ InputStage.execute()
┌─────────────────────────────────────────────────────────────┐
│ context = {                                                 │
│   "task_id": "task_abc123def456",                           │
│   "input_config": InputConfig(...),                         │
│   "config": config,                                         │
│   ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓      │
│   ┃ "video_config": VideoConfig(                  ┃      │
│   ┃   video_id="doc_abc123",                      ┃      │
│   ┃   title="How the Internet Works",             ┃      │
│   ┃   scenes=[SceneConfig(...), ...]              ┃      │
│   ┃ ),                                            ┃      │
│   ┃ "input_metadata": {...}                       ┃      │
│   ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛      │
│ }                                                           │
└─────────────────────────────────────────────────────────────┘
                          │
                          ↓ ParsingStage.execute()
┌─────────────────────────────────────────────────────────────┐
│ context["video_config"] MUTATED IN-PLACE:                  │
│   • scenes[i].visual_content["parsed_content"] added        │
│                                                             │
│ (No new keys added to context)                             │
└─────────────────────────────────────────────────────────────┘
                          │
                          ↓ ScriptGenerationStage.execute()
┌─────────────────────────────────────────────────────────────┐
│ context["video_config"] MUTATED IN-PLACE:                  │
│   • scenes[i].narration = "Generated narration text..."     │
│                                                             │
│ (No new keys added to context)                             │
└─────────────────────────────────────────────────────────────┘
                          │
                          ↓ AudioGenerationStage.execute()
┌─────────────────────────────────────────────────────────────┐
│ context = {                                                 │
│   ... (existing keys) ...,                                  │
│   ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓      │
│   ┃ "audio_dir": Path("output/audio/.../abc_audio") ┃      │
│   ┃ "timing_report": Path(".../timing_report.json") ┃      │
│   ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛      │
│ }                                                           │
│                                                             │
│ context["video_config"] MUTATED IN-PLACE:                  │
│   • scenes[i].audio_file = Path("scene_01.mp3")             │
│   • scenes[i].actual_audio_duration = 5.2                   │
│   • scenes[i].final_duration = 6.2                          │
│   • total_duration = 45.8                                   │
└─────────────────────────────────────────────────────────────┘
                          │
                          ↓ VideoGenerationStage.execute()
┌─────────────────────────────────────────────────────────────┐
│ context = {                                                 │
│   ... (existing keys) ...,                                  │
│   ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓      │
│   ┃ "final_video_path": Path(".../abc_final.mp4")   ┃      │
│   ┃ "video_dir": Path("output/video/abc")           ┃      │
│   ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛      │
│ }                                                           │
└─────────────────────────────────────────────────────────────┘
                          │
                          ↓ OutputStage.execute()
┌─────────────────────────────────────────────────────────────┐
│ context = {                                                 │
│   ... (existing keys) ...,                                  │
│   ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓      │
│   ┃ "output_dir": Path("final_output/abc")          ┃      │
│   ┃ "metadata_path": Path(".../metadata.json")      ┃      │
│   ┃ "thumbnail_path": Path(".../thumbnail.jpg")     ┃      │
│   ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛      │
│ }                                                           │
└─────────────────────────────────────────────────────────────┘
                          │
                          ↓ Orchestrator._build_pipeline_result()
┌─────────────────────────────────────────────────────────────┐
│ PipelineResult(                                             │
│   success=True,                                             │
│   video_path=context["final_video_path"],                   │
│   audio_dir=context["audio_dir"],                           │
│   timing_report=context["timing_report"],                   │
│   ...                                                       │
│ )                                                           │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Error Handling Flow

```
ERROR HANDLING HIERARCHY
════════════════════════════════════════════════════════════════════

Level 1: Stage Internal Error
─────────────────────────────
┌──────────────────────────────────────────────────────────────────┐
│ AudioGenerationStage.execute()                                   │
│                                                                  │
│   try:                                                           │
│       await edge_tts.Communicate(...).save()  ← Error occurs     │
│   except Exception as e:                                         │
│       raise AudioGenerationError(...)  ← Wrapped with context    │
└──────────────────────────────────────────────────────────────────┘
                           │
                           ↓
Level 2: Stage.run() Wrapper
─────────────────────────────
┌──────────────────────────────────────────────────────────────────┐
│ Stage.run() (base class, line 77-157)                           │
│                                                                  │
│   try:                                                           │
│       result = await self.execute(context)  ← Calls stage        │
│   except Exception as e:                                         │
│       ⚠️ Catch ALL exceptions                                    │
│       • Log error with traceback                                 │
│       • Emit STAGE_FAILED event                                  │
│       • Return StageResult(success=False, error=str(e))          │
│                                                                  │
│   ✅ Never propagates exceptions (returns failed result)         │
└──────────────────────────────────────────────────────────────────┘
                           │
                           ↓
Level 3: Orchestrator Decision
───────────────────────────────
┌──────────────────────────────────────────────────────────────────┐
│ Orchestrator.execute() (line 153-192)                           │
│                                                                  │
│   result = await stage.run(context, task_id)                    │
│                                                                  │
│   if not result.success:                                         │
│       • Update task_state.fail_stage(stage.name, result.error)   │
│       • Save state to disk                                       │
│       • Check: _should_abort_on_failure(stage.name)?             │
│           YES → break (abort pipeline)                           │
│           NO  → continue (try next stage)                        │
└──────────────────────────────────────────────────────────────────┘
                           │
                           ↓
Level 4: Pipeline Completion
─────────────────────────────
┌──────────────────────────────────────────────────────────────────┐
│ Orchestrator.execute() (line 194-233)                           │
│                                                                  │
│   • Determine final status:                                      │
│       pipeline_success = all stages succeeded                    │
│                                                                  │
│   • Update task_state:                                           │
│       status = COMPLETED or FAILED                               │
│       completed_at = now()                                       │
│                                                                  │
│   • Build PipelineResult:                                        │
│       success = pipeline_success                                 │
│       errors = task_state.errors                                 │
│       warnings = task_state.warnings                             │
│                                                                  │
│   • Emit event: PIPELINE_COMPLETED or PIPELINE_FAILED            │
│                                                                  │
│   • Return PipelineResult (never raises exception to caller)     │
└──────────────────────────────────────────────────────────────────┘

CRITICAL STAGE LOGIC (orchestrator.py, line 353-370):
──────────────────────────────────────────────────────
Critical stages (MUST succeed):
  • input_adaptation   ← No video config = fatal
  • content_parsing    ← Corrupt content = fatal
  • audio_generation   ← No audio = no video

Non-critical stages (CAN fail):
  • script_generation  ← Can use template narration
  • video_generation   ← Could use fallback renderer
  • output_handling    ← Video exists, just not organized
```

---

## 4. State Persistence & Resume Flow

```
STATE PERSISTENCE FLOW
═══════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────┐
│ StateManager (state_manager.py)                                │
│ ───────────────────────────────────────                         │
│ • Storage: JSON files in config.state_dir/                     │
│ • Format: {task_id}.json                                        │
│ • Operations: save(), load(), exists(), delete()                │
└─────────────────────────────────────────────────────────────────┘

EXECUTION WITH STATE SAVES:
────────────────────────────

1. Pipeline Start
   ┌──────────────────────────────────────────────┐
   │ orchestrator.execute(input_config)           │
   │ • Generate task_id = "task_abc123"           │
   │ • Create TaskState(status=PENDING)           │
   │ • Register all 6 stages                      │
   │ • SAVE STATE (initial.json)                  │
   └──────────────────────────────────────────────┘
                    │
                    ↓
2. Stage 1 Execution
   ┌──────────────────────────────────────────────┐
   │ task_state.start_stage("input_adaptation")   │
   │ • status = RUNNING                           │
   │ • started_at = now()                         │
   │ • SAVE STATE                                 │
   └──────────────────────────────────────────────┘
                    │
                    ↓ InputStage.run()
   ┌──────────────────────────────────────────────┐
   │ task_state.complete_stage(                   │
   │   "input_adaptation",                        │
   │   artifacts={"video_config": "...", ...}     │
   │ )                                            │
   │ • status = COMPLETED                         │
   │ • completed_at = now()                       │
   │ • progress = 1.0                             │
   │ • SAVE STATE (stage 1 done) ✓                │
   └──────────────────────────────────────────────┘
                    │
                    ↓
3. Stage 2, 3 Complete...
   [Same pattern: start → run → complete → SAVE STATE]
                    │
                    ↓
4. Stage 4 FAILS
   ┌──────────────────────────────────────────────┐
   │ task_state.fail_stage(                       │
   │   "audio_generation",                        │
   │   error="TTS API timeout"                    │
   │ )                                            │
   │ • status = FAILED                            │
   │ • error = "TTS API timeout"                  │
   │ • SAVE STATE (failure recorded) ✓            │
   │                                              │
   │ Pipeline aborts (critical stage failed)      │
   └──────────────────────────────────────────────┘

RESUME EXECUTION:
─────────────────

5. Resume Call
   ┌──────────────────────────────────────────────┐
   │ orchestrator.execute(                        │
   │   input_config,                              │
   │   task_id="task_abc123",  ← SAME ID          │
   │   resume=True             ← ENABLE RESUME    │
   │ )                                            │
   └──────────────────────────────────────────────┘
                    │
                    ↓
6. State Restoration
   ┌──────────────────────────────────────────────┐
   │ task_state = state_manager.load("task_abc")  │
   │                                              │
   │ completed_stages = [                         │
   │   "input_adaptation",    ← Skip              │
   │   "content_parsing",     ← Skip              │
   │   "script_generation"    ← Skip              │
   │ ]                                            │
   │                                              │
   │ last_completed = "script_generation"         │
   │ start_index = 3 + 1 = 4  ← Resume from here  │
   └──────────────────────────────────────────────┘
                    │
                    ↓
7. Resume from Stage 4
   ┌──────────────────────────────────────────────┐
   │ for stage in stages[4:]:  ← Start at index 4 │
   │     await stage.run()                        │
   │                                              │
   │ Stage 4: audio_generation (RETRY) ✓          │
   │ Stage 5: video_generation (NEW)   ✓          │
   │ Stage 6: output_handling (NEW)    ✓          │
   │                                              │
   │ Pipeline COMPLETED ✓                         │
   └──────────────────────────────────────────────┘

CONTEXT RESTORATION:
────────────────────
❓ How is context restored?

Currently: NOT FULLY RESTORED
• Context starts fresh each execution
• Artifacts stored in TaskState.stages[].artifacts (as strings)
• ⚠️ VideoConfig objects are NOT restored from state

Recommendation: Enhance resume to restore context from artifacts
```

---

## 5. Event Emission Flow

```
EVENT EMISSION ARCHITECTURE
═══════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────┐
│ EventEmitter (events.py)                                        │
│ ────────────────────────                                        │
│ • Pub/Sub pattern                                               │
│ • Async event handlers                                          │
│ • Event types: PIPELINE_*, STAGE_*                              │
└─────────────────────────────────────────────────────────────────┘

EVENT TYPES:
────────────
PIPELINE_STARTED      → Pipeline execution begins
PIPELINE_COMPLETED    → All stages succeeded
PIPELINE_FAILED       → Pipeline aborted or failed
STAGE_STARTED         → Stage begins execution
STAGE_PROGRESS        → Stage progress update (0.0-1.0)
STAGE_COMPLETED       → Stage finished successfully
STAGE_FAILED          → Stage encountered error

EMISSION POINTS IN CODE:
────────────────────────

Orchestrator.execute() (orchestrator.py):
┌─────────────────────────────────────────────────────────────────┐
│ Line 122-127: PIPELINE_STARTED                                  │
│   → Emitted at pipeline start                                   │
│   → Data: input_config                                          │
│                                                                 │
│ Line 216-226: PIPELINE_COMPLETED or PIPELINE_FAILED             │
│   → Emitted after all stages                                    │
│   → Data: duration, success, stages_completed, stages_failed    │
│                                                                 │
│ Line 246-250: PIPELINE_FAILED (unexpected error)                │
│   → Emitted on exception                                        │
│   → Data: error message                                         │
└─────────────────────────────────────────────────────────────────┘

Stage.run() (stage.py):
┌─────────────────────────────────────────────────────────────────┐
│ Line 95-101: STAGE_STARTED                                      │
│   → Emitted before stage.execute()                              │
│   → Data: stage name, progress=0.0                              │
│                                                                 │
│ Line 116-124: STAGE_COMPLETED                                   │
│   → Emitted after successful execution                          │
│   → Data: stage name, progress=1.0, metadata                    │
│                                                                 │
│ Line 142-149: STAGE_FAILED                                      │
│   → Emitted on exception                                        │
│   → Data: error message                                         │
└─────────────────────────────────────────────────────────────────┘

Stage.emit_progress() (stage.py):
┌─────────────────────────────────────────────────────────────────┐
│ Line 159-175: STAGE_PROGRESS                                    │
│   → Called manually by stages during long operations            │
│   → Data: progress value (0.0-1.0), custom message              │
│                                                                 │
│ Example usage in AudioGenerationStage:                          │
│   await self.emit_progress(task_id, 0.5, "Generating audio...") │
└─────────────────────────────────────────────────────────────────┘

USAGE EXAMPLE:
──────────────
# Subscribe to events
async def on_progress(event: Event):
    print(f"Progress: {event.progress:.0%} - {event.message}")

event_emitter.on(EventType.STAGE_PROGRESS, on_progress)

# Execute pipeline
result = await orchestrator.execute(input_config)

# Events will be emitted automatically during execution
```

---

## 6. Critical Bottleneck Visualization

```
PERFORMANCE PROFILE (3-Scene Video)
═══════════════════════════════════════════════════════════════════

Stage Timeline (Sequential):
─────────────────────────────

InputStage           [█]                                    0.5s
ParsingStage         [█]                                    0.3s
ScriptGeneration     [████]                                 2.0s
AudioGeneration      [████████████████████████]            15.0s  ← BOTTLENECK #1
VideoGeneration      [████████████████████████████████████] 45.0s  ← BOTTLENECK #2
OutputStage          [███]                                  1.2s
                     ├──┼──┼──┼──┼──┼──┼──┼──┼──┼──┼──┼──┼
                     0  5 10 15 20 25 30 35 40 45 50 55 60  (seconds)

Total: ~64 seconds

AUDIO GENERATION BOTTLENECK (Current Sequential):
──────────────────────────────────────────────────

Scene 1: [████████] 5s
Scene 2:           [████████] 5s
Scene 3:                     [████████] 5s
         ├────────┼────────┼────────┼
         0        5       10       15  (seconds)

Total: 15 seconds (5s per scene × 3 scenes)

AUDIO GENERATION OPTIMIZED (Parallel):
───────────────────────────────────────

Scene 1: [████████] 5s
Scene 2: [████████] 5s
Scene 3: [████████] 5s
         ├────────┼
         0        5  (seconds)

Total: 5 seconds (max scene duration)

SPEEDUP: 3x faster (15s → 5s)
TOTAL PIPELINE: 64s → 54s (16% improvement)

For 10 scenes:
  Sequential: 50s
  Parallel:    5s (longest scene)
  SPEEDUP: 10x faster
  TOTAL PIPELINE: 95s → 50s (47% improvement)
```

---

## 7. Data Model Relationships

```
DATA MODEL CLASS DIAGRAM
═══════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────┐
│ InputConfig                                                     │
│ ───────────────────────────────────────────────────────────────│
│ • input_type: Literal["document", "youtube", "yaml", ...]      │
│ • source: str                                                   │
│ • accent_color: str = "blue"                                    │
│ • voice: str = "male"                                           │
│ • languages: List[str] = ["en"]                                 │
│ • use_ai_narration: bool = False                                │
│ • video_count: int = 1                                          │
│ • split_by_h2: bool = False                                     │
└─────────────────────────────────────────────────────────────────┘
                           │
                           │ 1:1 (adapted to)
                           ↓
┌─────────────────────────────────────────────────────────────────┐
│ VideoConfig                                                     │
│ ───────────────────────────────────────────────────────────────│
│ • video_id: str                                                 │
│ • title: str                                                    │
│ • description: str                                              │
│ • accent_color: str = "blue"                                    │
│ • version: str = "v2.0"                                         │
│ • voices: List[str] = ["male"]  # Voice rotation                │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ Runtime Fields (populated during pipeline):                │ │
│ │ • total_duration: float = 0.0                               │ │
│ │ • audio_dir: Path | None                                    │ │
│ │ • video_file: Path | None                                   │ │
│ │ • final_file: Path | None                                   │ │
│ └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                           │
                           │ 1:N (contains)
                           ↓
┌─────────────────────────────────────────────────────────────────┐
│ SceneConfig                                                     │
│ ───────────────────────────────────────────────────────────────│
│ • scene_id: str                                                 │
│ • scene_type: Literal["title", "command", "list", ...]         │
│ • narration: str                                                │
│ • visual_content: Dict[str, Any]                                │
│ • voice: str = "male"                                           │
│ • min_duration: float = 3.0                                     │
│ • max_duration: float = 15.0                                    │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ Runtime Fields (populated by stages):                       │ │
│ │ • actual_audio_duration: float | None                       │ │
│ │ • final_duration: float | None                              │ │
│ │ • audio_file: Path | None                                   │ │
│ │ • warnings: List[str] = []                                  │ │
│ └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘

PIPELINE EXECUTION MODEL:
─────────────────────────

┌─────────────────────────────────────────────────────────────────┐
│ TaskState                                                       │
│ ───────────────────────────────────────────────────────────────│
│ • task_id: str                                                  │
│ • input_config: Dict[str, Any]                                  │
│ • status: TaskStatus                                            │
│ • current_stage: str | None                                     │
│ • overall_progress: float                                       │
│ • created_at: datetime                                          │
│ • started_at: datetime | None                                   │
│ • completed_at: datetime | None                                 │
│ • result: Dict[str, Any] | None                                 │
│ • errors: List[str]                                             │
│ • warnings: List[str]                                           │
└─────────────────────────────────────────────────────────────────┘
                           │
                           │ 1:N (tracks)
                           ↓
┌─────────────────────────────────────────────────────────────────┐
│ StageState                                                      │
│ ───────────────────────────────────────────────────────────────│
│ • name: str                                                     │
│ • status: TaskStatus                                            │
│ • progress: float                                               │
│ • started_at: datetime | None                                   │
│ • completed_at: datetime | None                                 │
│ • error: str | None                                             │
│ • artifacts: Dict[str, str]  # Generated files                  │
│ • metadata: Dict[str, Any]                                      │
└─────────────────────────────────────────────────────────────────┘

FINAL RESULT MODEL:
───────────────────

┌─────────────────────────────────────────────────────────────────┐
│ PipelineResult                                                  │
│ ───────────────────────────────────────────────────────────────│
│ • success: bool                                                 │
│ • task_id: str                                                  │
│ • video_config: VideoConfig                                     │
│ • video_path: Path | None                                       │
│ • audio_dir: Path | None                                        │
│ • timing_report: Path | None                                    │
│ • total_duration: float                                         │
│ • scene_count: int                                              │
│ • generation_time: float                                        │
│ • timestamp: datetime                                           │
│ • errors: List[str]                                             │
│ • warnings: List[str]                                           │
└─────────────────────────────────────────────────────────────────┘
```

---

## 8. Stage Dependencies Graph

```
STAGE DEPENDENCY GRAPH
═══════════════════════════════════════════════════════════════════

Legend:
  ━━━→  Required dependency (stage MUST provide this)
  ┈┈→  Optional dependency (stage can provide this)
  [?]   Validation check

┌──────────────┐
│ InputStage   │
│              │
│ Provides:    │
│ • video_config ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
│ • input_metadata ┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┐    │
└──────────────┘                              │    │
                                              │    │
                                              ↓    ↓
                           ┌──────────────────────────────────┐
                           │ ParsingStage                     │
                           │                                  │
                           │ Requires:                        │
                           │ • video_config ━━━━━━━━━━━━━━━━━│
                           │                                  │
                           │ Provides:                        │
                           │ • video_config (enriched) ━━━━━━━│━━┓
                           └──────────────────────────────────┘  │
                                                                 │
                                                                 ↓
                              ┌─────────────────────────────────────────┐
                              │ ScriptGenerationStage                   │
                              │                                         │
                              │ Requires:                               │
                              │ • video_config ━━━━━━━━━━━━━━━━━━━━━━━━│
                              │ • input_config (for use_ai_narration)   │
                              │ [?] Check: scenes not empty             │
                              │                                         │
                              │ Provides:                               │
                              │ • video_config (with narration) ━━━━━━━━│━━┓
                              └─────────────────────────────────────────┘  │
                                                                           │
                                                                           ↓
                                     ┌────────────────────────────────────────────┐
                                     │ AudioGenerationStage                       │
                                     │                                            │
                                     │ Requires:                                  │
                                     │ • video_config ━━━━━━━━━━━━━━━━━━━━━━━━━━━│
                                     │ [?] Check: scene.narration populated       │
                                     │                                            │
                                     │ Provides:                                  │
                                     │ • audio_dir ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━│━━┓
                                     │ • timing_report ━━━━━━━━━━━━━━━━━━━━━━━━━━│━━│━┓
                                     │ • video_config (with audio metadata) ━━━━━━│━━│━│━┓
                                     └────────────────────────────────────────────┘  │ │ │
                                                                                     │ │ │
                                                                                     ↓ ↓ ↓
                                            ┌────────────────────────────────────────────────┐
                                            │ VideoGenerationStage                           │
                                            │                                                │
                                            │ Requires:                                      │
                                            │ • video_config ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━│
                                            │ • audio_dir ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━│
                                            │ • timing_report ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━│
                                            │                                                │
                                            │ Provides:                                      │
                                            │ • final_video_path ━━━━━━━━━━━━━━━━━━━━━━━━━━━│━┓
                                            │ • video_dir ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━│━│━┓
                                            └────────────────────────────────────────────────┘ │ │
                                                                                               │ │
                                                                                               ↓ ↓
                                                         ┌────────────────────────────────────────────┐
                                                         │ OutputStage                                │
                                                         │                                            │
                                                         │ Requires:                                  │
                                                         │ • video_config ━━━━━━━━━━━━━━━━━━━━━━━━━━│
                                                         │ • final_video_path OR scene_videos ━━━━━━━│
                                                         │ • video_dir ━━━━━━━━━━━━━━━━━━━━━━━━━━━━│
                                                         │                                            │
                                                         │ Provides:                                  │
                                                         │ • output_dir                               │
                                                         │ • metadata_path                            │
                                                         │ • thumbnail_path                           │
                                                         └────────────────────────────────────────────┘

VALIDATION POINTS:
──────────────────
✓ InputStage validates input_config exists and has valid input_type
✓ All stages validate required context keys using self.validate_context()
✗ ScriptGenerationStage should validate scenes are not empty (MISSING)
✓ AudioGenerationStage assumes narration exists (valid assumption)
✓ VideoGenerationStage validates all 3 required inputs
✓ OutputStage handles both new workflow (final_video_path) and legacy (scene_videos)
```

---

**Document Created By:** Claude Code Analysis Agent
**Date:** October 9, 2025
**Version:** 1.0
**Companion Document:** PIPELINE_ANALYSIS_REPORT.md
