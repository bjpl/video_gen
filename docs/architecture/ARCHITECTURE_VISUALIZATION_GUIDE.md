# Architecture Visualization Guide - Video_Gen System

**Version:** 2.0.0
**Date:** 2025-10-06
**Purpose:** Visual guide to system architecture with detailed diagrams

---

## Document Navigation

This guide complements other architecture documents:
- **ARCHITECTURE_ANALYSIS.md** - Detailed technical analysis and metrics
- **QUICK_SUMMARY.md** - Executive summary and quick reference
- **PIPELINE_ARCHITECTURE.md** - Pipeline design and specifications
- **COMPONENT_DIAGRAM.md** - Component relationships and interfaces
- **DETAILED_SEQUENCE_DIAGRAMS.md** - Complete sequence flows
- **DESIGN_DECISIONS.md** - Rationale and trade-offs

---

## Table of Contents

1. [System Overview Diagrams](#1-system-overview-diagrams)
2. [Component Interaction Maps](#2-component-interaction-maps)
3. [Data Transformation Visualizations](#3-data-transformation-visualizations)
4. [State Lifecycle Diagrams](#4-state-lifecycle-diagrams)
5. [Performance and Timing Diagrams](#5-performance-and-timing-diagrams)
6. [Extension and Integration Points](#6-extension-and-integration-points)

---

## 1. System Overview Diagrams

### 1.1 30,000-Foot View: Complete System

```
┌────────────────────────────────────────────────────────────────────────────┐
│                     VIDEO_GEN: AI-Powered Video Generator                  │
│                         From Text to Talking Videos                        │
└────────────────────────────────────────────────────────────────────────────┘

                                   ┌───────────┐
                                   │  INPUTS   │
                                   └─────┬─────┘
                                         │
         ┌───────────────┬───────────────┼───────────────┬───────────────┐
         │               │               │               │               │
    ┌────▼────┐     ┌───▼────┐     ┌───▼────┐     ┌───▼────┐     ┌───▼────┐
    │Document │     │YouTube │     │  YAML  │     │ Python │     │Wizard  │
    │PDF,DOCX,│     │ Video  │     │ Config │     │  Dict  │     │ CLI    │
    │ MD, TXT │     │  URL   │     │  File  │     │  API   │     │Prompts │
    └────┬────┘     └───┬────┘     └───┬────┘     └───┬────┘     └───┬────┘
         │              │              │              │              │
         └──────────────┴──────────────┴──────────────┴──────────────┘
                                      │
                                      ▼
                          ┌───────────────────────┐
                          │   PIPELINE ENGINE     │
                          │                       │
                          │  6-Stage Sequential   │
                          │  Processing Pipeline  │
                          │                       │
                          │  • State Persistence  │
                          │  • Resume Capability  │
                          │  • Event Streaming    │
                          │  • Error Recovery     │
                          └───────────┬───────────┘
                                      │
         ┌────────────────────────────┼────────────────────────────┐
         │                            │                            │
    ┌────▼─────┐               ┌─────▼──────┐              ┌─────▼──────┐
    │  Audio   │               │   Video    │              │  Output    │
    │ Files    │               │  Segments  │              │  Metadata  │
    │          │               │            │              │            │
    │ MP3s +   │               │ MP4 scenes │              │ Timing     │
    │ Timing   │               │ rendered   │              │ Reports    │
    └────┬─────┘               └─────┬──────┘              └─────┬──────┘
         │                            │                            │
         └────────────────────────────┼────────────────────────────┘
                                      │
                                      ▼
                          ┌───────────────────────┐
                          │   FINAL OUTPUT        │
                          │                       │
                          │  • MP4 Video File     │
                          │  • Timing Reports     │
                          │  • Metadata JSON      │
                          │  • Scene Artifacts    │
                          └───────────────────────┘

KEY METRICS:
• Time: 2-8 minutes for 10-scene video
• Stages: 6 sequential steps with checkpoints
• Resume: Can restart from any completed stage
• Quality: 1080p @ 30fps with NVENC encoding
• Voices: 27+ TTS voices, multi-language support
```

---

### 1.2 Pipeline Flow with Timing

```
┌─────────────────────────────────────────────────────────────────────────┐
│              PIPELINE EXECUTION WITH TIMING BREAKDOWN                    │
└─────────────────────────────────────────────────────────────────────────┘

STAGE 1: INPUT ADAPTATION
│ ▓░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │  5-15s  (14% progress)
│
│ • Select and execute adapter (document/YouTube/YAML)
│ • Parse input format
│ • Extract structure
│ • Create VideoConfig with scenes
│ • Apply defaults (accent color, voice)
│
│ Output: VideoConfig (normalized structure)
│ Checkpoint: state/task_xyz/stage_1.json
└─────────────────────────────────────────────────────────────────────────┘

STAGE 2: CONTENT PARSING
│ ▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │  5-10s  (28% progress)
│
│ • Extract sections, headings, lists
│ • Identify document structure
│ • Create scene templates
│ • Map content to scene types
│
│ Output: ParsedContent (structured sections)
│ Checkpoint: state/task_xyz/stage_2.json
└─────────────────────────────────────────────────────────────────────────┘

STAGE 3: SCRIPT GENERATION
│ ▓▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │  10-30s (42% progress)
│
│ • Generate narration text for each scene
│ • Optional AI enhancement (Claude/GPT)
│ • Validate timing constraints (min/max duration)
│ • Check narration length
│
│ Output: VideoConfig with narration scripts
│ Checkpoint: state/task_xyz/stage_3.json
└─────────────────────────────────────────────────────────────────────────┘

STAGE 4: AUDIO GENERATION (LONGEST STAGE)
│ ▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │  30s-2min (71% progress)
│
│ For each scene (1 to N):
│   • Call Edge TTS API (2-5s per scene)
│   • Save MP3 audio file
│   • Probe audio duration with FFmpeg
│   • Update scene.audio_file
│   • Check timing constraints
│   • Emit AUDIO_GENERATED event
│
│ Generate timing report (JSON)
│
│ Output: Audio directory + timing_report.json
│ Checkpoint: state/task_xyz/stage_4.json
└─────────────────────────────────────────────────────────────────────────┘

STAGE 5: VIDEO GENERATION (SECOND LONGEST)
│ ▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │  1-5min  (90% progress)
│
│ For each scene (1 to N):
│   • Render keyframes with PIL (scene-specific)
│   • Apply NumPy-accelerated blending (10x faster)
│   • Create smooth transitions (crossfade, slide)
│   • Encode video with FFmpeg + NVENC GPU
│   • Mux audio track
│   • Save MP4 segment
│   • Emit VIDEO_RENDERED event
│
│ Output: Video segments (scene_1.mp4, scene_2.mp4, ...)
│ Checkpoint: state/task_xyz/stage_5.json
└─────────────────────────────────────────────────────────────────────────┘

STAGE 6: OUTPUT HANDLING (FINALIZATION)
│ ▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │  10-30s  (100% progress)
│
│ • Concatenate video segments (FFmpeg concat)
│ • Organize output files (output/ directory)
│ • Generate metadata JSON
│ • Create timing report summary
│ • Optional delivery (upload, notification)
│
│ Output: final_video.mp4 + metadata
│ Checkpoint: state/task_xyz/complete.json
└─────────────────────────────────────────────────────────────────────────┘

TOTAL TIME: 2-8 minutes (varies by scene count and complexity)

PROGRESS BREAKDOWN:
  0% │ Pipeline started
 14% │ Input adapted
 28% │ Content parsed
 42% │ Scripts generated
 71% │ Audio generated  ◀── Longest wait
 90% │ Video rendered
100% │ Output finalized ✅

PERFORMANCE FACTORS:
• Scene count (more scenes = longer time)
• Network speed (affects TTS API calls)
• GPU availability (3-5x faster with NVENC)
• Content complexity (detailed scenes take longer to render)
• AI enhancement (adds 2-10s per scene if enabled)
```

---

## 2. Component Interaction Maps

### 2.1 Module Dependency Graph

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    MODULE DEPENDENCY HIERARCHY                           │
│                    (Arrows show "depends on" relationships)              │
└─────────────────────────────────────────────────────────────────────────┘

                          ┌─────────────────┐
                          │     shared/     │
                          │                 │
                          │ • models.py     │
                          │ • config.py     │
                          │ • exceptions.py │
                          │ • constants.py  │
                          │ • utils.py      │
                          └─────────────────┘
                                   ▲
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
         ┌──────────┴─────┐   ┌───┴──────┐   ┌──┴──────────┐
         │   pipeline/    │   │ renderers/│   │input_adapters/
         │                │   │           │   │              │
         │ • orchestrator │   │ • basic   │   │ • document   │
         │ • stage        │   │ • edu     │   │ • youtube    │
         │ • state_mgr    │   │ • compare │   │ • yaml       │
         │ • events       │   │ • check   │   │ • programmatic
         └────────────────┘   └───────────┘   └──────────────┘
                 ▲                   ▲
                 │                   │
         ┌───────┴───────┐    ┌──────┴──────┐
         │   stages/     │    │ generators/ │
         │               │    │             │
         │ • input       │────│• audio      │
         │ • parsing     │    │• video      │
         │ • script_gen  │    │             │
         │ • audio_gen   │    └─────────────┘
         │ • video_gen   │
         │ • output      │
         │ • validation  │
         └───────────────┘

DEPENDENCY RULES:
✅ Shared depends on nothing (foundation layer)
✅ Pipeline depends only on shared (core orchestration)
✅ Stages depend on pipeline + shared (business logic)
✅ Generators depend on shared (utility modules)
✅ Renderers depend on shared (scene rendering)
✅ Input adapters depend on shared (data transformation)

VIOLATIONS TO AVOID:
❌ Circular dependencies (A → B → A)
❌ Stages depending on other stages directly
❌ Shared depending on higher-level modules
❌ Generators depending on stages

COUPLING METRICS:
• Shared: Afferent=10, Efferent=0 (Stable ✅)
• Pipeline: Afferent=6, Efferent=2 (Stable ✅)
• Stages: Afferent=1, Efferent=5 (Unstable ✅ - expected for leaf nodes)
```

---

### 2.2 Communication Patterns

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    INTER-COMPONENT COMMUNICATION                         │
└─────────────────────────────────────────────────────────────────────────┘

1. SYNCHRONOUS CALLS (Direct method invocation)
   ─────────────────────────────────────────────

   Pipeline ──────────> Stage.execute(context)
      │                      │
      │                      ▼
      │                 Business Logic
      │                      │
      │                      ▼
      └◀────────────── StageResult


2. ASYNCHRONOUS EVENTS (Pub/Sub pattern)
   ────────────────────────────────────

   Stage ───emit()──────> EventEmitter ───notify()──> Listeners
                                │                         │
                                ├─────────────────────────┼─> UI Progress Bar
                                │                         │
                                ├─────────────────────────┼─> Logger
                                │                         │
                                └─────────────────────────┴─> Metrics Collector


3. STATE PERSISTENCE (File I/O)
   ────────────────────────────

   Pipeline ────save_state()──> StateManager ──write_json()──> Filesystem
                                      │                             │
                                      │                             ▼
                                      │                      state/task_xyz.json
                                      │                             │
                                      └◀──────read_json()───────────┘


4. CONTEXT PROPAGATION (Shared dictionary)
   ───────────────────────────────────────

   Pipeline ──context──> Stage 1 ──context+result──> Stage 2 ──context+...──> Stage N
                            │                            │
                         execute()                    execute()
                            │                            │
                         modify                        modify
                         context                       context


COMMUNICATION METRICS:
• Direct Calls: 95% (synchronous, predictable)
• Events: 5% (async progress updates)
• File I/O: After each stage (checkpointing)
• Context Size: Grows from ~100 bytes to ~10KB through pipeline
```

---

## 3. Data Transformation Visualizations

### 3.1 VideoConfig Evolution Through Pipeline

```
┌─────────────────────────────────────────────────────────────────────────┐
│           HOW VideoConfig EVOLVES THROUGH THE PIPELINE                   │
└─────────────────────────────────────────────────────────────────────────┘

STAGE 0: INPUT
──────────────
User provides: "inputs/guide.md" (Markdown file)


STAGE 1: INPUT ADAPTATION (DocumentAdapter)
──────────────────────────────────────────────
VideoConfig {
  video_id: "guide_abc123"
  title: "Python Guide"
  description: "Complete Python Tutorial"
  accent_color: "blue"                    ◀── Default applied
  voices: ["male"]                        ◀── Default applied
  scenes: [
    SceneConfig {
      scene_id: "scene_1"
      scene_type: "title"
      narration: ""                       ◀── NOT YET GENERATED
      visual_content: {
        title: "Python Guide",
        subtitle: "Learn Python"
      }
      voice: "male"
      min_duration: 3.0
      max_duration: 15.0
      // Runtime fields (not yet populated):
      audio_file: null
      final_duration: null
      warnings: []
    },
    SceneConfig { ... },  // 9 more scenes
  ]
  // Runtime fields:
  total_duration: 0.0
  audio_dir: null
  video_file: null
}


STAGE 2: CONTENT PARSING
─────────────────────────
VideoConfig {
  // ... same as before ...
  scenes: [
    SceneConfig {
      // Enhanced visual_content based on parsing:
      visual_content: {
        title: "Python Guide",
        subtitle: "Learn Python",
        sections: ["Variables", "Functions", "Classes"]  ◀── NEW
      }
    }
  ]
}


STAGE 3: SCRIPT GENERATION
──────────────────────────
VideoConfig {
  scenes: [
    SceneConfig {
      narration: "Welcome to the Python Guide. In this tutorial, you'll learn about variables, functions, and classes."  ◀── GENERATED
      visual_content: { ... }
    },
    SceneConfig {
      narration: "Let's start with variables. A variable is a container for storing data values."  ◀── GENERATED
    }
  ]
}


STAGE 4: AUDIO GENERATION
─────────────────────────
VideoConfig {
  audio_dir: Path("audio/unified_system/guide_abc123_audio/")  ◀── NEW
  scenes: [
    SceneConfig {
      narration: "Welcome to the Python Guide..."
      audio_file: Path("audio/.../scene_1.mp3")         ◀── NEW
      actual_audio_duration: 4.2                        ◀── NEW (measured)
      final_duration: 4.2                               ◀── NEW
      warnings: []                                      ◀── May have warnings
    },
    SceneConfig {
      audio_file: Path("audio/.../scene_2.mp3")
      actual_audio_duration: 6.8
      final_duration: 6.8
      warnings: []
    }
  ]
  total_duration: 120.5                                 ◀── NEW (sum of scenes)
}


STAGE 5: VIDEO GENERATION
─────────────────────────
VideoConfig {
  // Audio fields remain the same
  video_file: Path("output/guide_abc123_complete.mp4")  ◀── NEW
  generation_timestamp: "2025-10-06T10:15:30Z"          ◀── NEW
}


STAGE 6: OUTPUT HANDLING
────────────────────────
VideoConfig {
  final_file: Path("output/final_video.mp4")            ◀── NEW (concatenated)
  // All other fields remain
}

FINAL STATE: Complete VideoConfig with all runtime fields populated
──────────────────────────────────────────────────────────────────────

VideoConfig {
  video_id: "guide_abc123"
  title: "Python Guide"
  description: "Complete Python Tutorial"
  accent_color: "blue"
  voices: ["male"]
  scenes: [10 fully populated SceneConfig objects]
  total_duration: 120.5
  audio_dir: Path("audio/unified_system/guide_abc123_audio/")
  video_file: Path("output/guide_abc123_complete.mp4")
  final_file: Path("output/final_video.mp4")
  generation_timestamp: "2025-10-06T10:15:30Z"
}

This VideoConfig can be:
• Serialized to JSON for state persistence
• Used to generate new videos with modified settings
• Analyzed for metrics and reporting
• Cached for incremental regeneration
```

---

## 4. State Lifecycle Diagrams

### 4.1 TaskState State Machine

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     TASK STATE MACHINE                                   │
│                     (Finite State Automaton)                             │
└─────────────────────────────────────────────────────────────────────────┘

                          ┌─────────────┐
                          │   START     │
                          └──────┬──────┘
                                 │
                                 │ create_task()
                                 ▼
                          ┌─────────────┐
                    ┌────▶│   PENDING   │◀────┐
                    │     └──────┬──────┘     │
                    │            │            │
                    │            │ execute()  │
                    │            ▼            │
         resume()   │     ┌─────────────┐    │ pause()
         after fail │     │   RUNNING   │────┘
                    │     └──────┬──────┘
                    │            │
                    │       ┌────┴────┐
                    │       │         │
                    │    success    failure
                    │       │         │
                    │       ▼         ▼
                    │  ┌─────────┐ ┌─────────┐
                    │  │COMPLETED│ │ FAILED  │
                    │  └─────────┘ └────┬────┘
                    │                   │
                    └───────────────────┘

STATE DESCRIPTIONS:
───────────────────

PENDING:
  • Task created but not started
  • All stages are idle
  • Can be started with execute()

RUNNING:
  • Currently executing stages
  • Some stages may be completed, others in progress
  • State saved after each stage completion
  • Can transition to COMPLETED or FAILED

COMPLETED:
  • All stages finished successfully
  • Final video generated
  • Immutable (cannot change state)

FAILED:
  • One or more stages failed after retries
  • State preserved at failure point
  • Can resume with execute(resume=True)

TRANSITIONS:
────────────

create_task():      START → PENDING
execute():          PENDING → RUNNING
stage_complete():   RUNNING → RUNNING (progress++)
all_stages_done():  RUNNING → COMPLETED
stage_fail():       RUNNING → FAILED
resume():           FAILED → RUNNING (from last completed stage)
```

---

### 4.2 Stage State Transitions

```
┌─────────────────────────────────────────────────────────────────────────┐
│                  PER-STAGE STATE TRANSITIONS                             │
└─────────────────────────────────────────────────────────────────────────┘

Each of the 6 stages has its own lifecycle:

                          ┌──────────┐
                          │   IDLE   │  (Initial state)
                          └────┬─────┘
                               │
                               │ start_stage()
                               ▼
                          ┌──────────┐
                    ┌────▶│ RUNNING  │────┐
                    │     └────┬─────┘    │
                    │          │          │
                    │     execute()       │ exception
                    │          │          │
                    │     ┌────┴────┐     │
                    │     │         │     │
                    │  success   failure  │
                    │     │         │     │
                    │     ▼         ▼     ▼
                    │  ┌────────┐ ┌──────────┐
                    │  │COMPLETE│ │  FAILED  │
                    │  └────────┘ └────┬─────┘
                    │                  │
                    │                  │ retry
                    └──────────────────┘

STAGE METADATA:
───────────────

StageState {
  name: "audio_generation"
  status: "completed"
  progress: 1.0
  started_at: "2025-10-06T10:01:00Z"
  completed_at: "2025-10-06T10:03:45Z"
  duration_seconds: 165
  error: null
  artifacts: {
    audio_dir: "audio/unified_system/video_abc_audio",
    timing_report: "audio/.../timing_report.json"
  }
  retry_count: 0
}

PARALLEL STAGE STATES:
──────────────────────

At any point in pipeline execution:

✅ Completed Stages: COMPLETED (immutable)
🔵 Current Stage:    RUNNING (being executed)
⏸️  Future Stages:    IDLE (not yet started)
❌ Failed Stages:    FAILED (if retries exhausted)

Example snapshot during execution:

┌──────────────────────────────────────────────┐
│ Stage 1: Input      │ COMPLETED │ ✅         │
│ Stage 2: Parsing    │ COMPLETED │ ✅         │
│ Stage 3: Script     │ COMPLETED │ ✅         │
│ Stage 4: Audio      │ RUNNING   │ 🔵 45%    │
│ Stage 5: Video      │ IDLE      │ ⏸️         │
│ Stage 6: Output     │ IDLE      │ ⏸️         │
└──────────────────────────────────────────────┘
```

---

## 5. Performance and Timing Diagrams

### 5.1 Performance Bottleneck Analysis

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    WHERE TIME IS SPENT (10-scene video)                  │
└─────────────────────────────────────────────────────────────────────────┘

STAGE TIMING BREAKDOWN:
───────────────────────

Stage 1: Input          ▓░░░░░░░░░░░░░░░░░░░░░░░  5-15s    ( 5%)
Stage 2: Parsing        ▓░░░░░░░░░░░░░░░░░░░░░░░  5-10s    ( 5%)
Stage 3: Script Gen     ▓▓░░░░░░░░░░░░░░░░░░░░░░  10-30s   (10%)
Stage 4: Audio Gen      ▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░  30s-2min (30%) ◀── #2 Bottleneck
Stage 5: Video Gen      ▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░  1-5min   (45%) ◀── #1 Bottleneck
Stage 6: Output         ▓░░░░░░░░░░░░░░░░░░░░░░░  10-30s   ( 5%)

TOTAL: 2-8 minutes


BOTTLENECK DEEP DIVE:
────────────────────

1. VIDEO GENERATION (45% of total time)
   ────────────────────────────────────

   Per-Scene Breakdown (1920x1080):
   • Keyframe rendering:     10-30s  (60% - scene complexity dependent)
   • Transition blending:     2-5s   (15% - NumPy accelerated)
   • FFmpeg encoding:        10-20s  (25% - NVENC GPU / CPU fallback)

   Optimization Opportunities:
   ✅ Already using NumPy (10x faster than pure PIL)
   ✅ Already using NVENC GPU encoding (3-5x faster than CPU)
   💡 Could parallelize scene rendering (future: 2-3x speedup)
   💡 Could cache unchanged scenes (future: skip regeneration)


2. AUDIO GENERATION (30% of total time)
   ────────────────────────────────────

   Per-Scene Breakdown:
   • TTS API call:           2-5s   (70% - network latency)
   • MP3 file save:          <0.1s  ( 5% - disk I/O)
   • FFmpeg duration probe:  0.2s   (10% - subprocess overhead)
   • Constraint validation:  <0.1s  ( 5%)

   Current: Sequential (scene 1 → scene 2 → ...)
   Time: 10 scenes × 3s = 30 seconds

   Optimization Opportunities:
   ✅ Could use asyncio.gather() for parallel TTS calls
      → Potential: 10 scenes in ~5 seconds (6x speedup)
   💡 Could batch similar narrations
   💡 Could cache audio for unchanged narrations


MINOR STAGES (25% of total time):
──────────────────────────────────

Stage 1 (Input):
  • File I/O: 1-5s (large PDFs)
  • Parsing: 2-10s (complex documents)
  ✅ Already optimized, hard to improve further

Stage 2 (Parsing):
  • Markdown parsing: 1-3s
  • Structure detection: 2-5s
  ✅ Lightweight, acceptable performance

Stage 3 (Script Generation):
  • Template-based: 5-10s
  • AI enhancement (optional): +2-10s per scene
  💡 Cache AI-enhanced scripts

Stage 6 (Output):
  • FFmpeg concat: 5-10s (lossless merging)
  • File organization: <1s
  • Metadata generation: <1s
  ✅ Near-optimal, concat is fastest merge method


PERFORMANCE SUMMARY:
────────────────────

Current Performance:      2-8 minutes
With Parallel Audio:      1.5-7 minutes  (20% improvement)
With Parallel Video:      1-4 minutes    (50% improvement)
With Both Optimizations:  0.5-3 minutes  (75% improvement)

Trade-offs:
• Parallelization adds complexity
• Harder to track progress (which scene is rendering?)
• Higher resource usage (CPU/GPU/Network)
• Harder to debug failures

Recommendation: Implement parallel audio first (easier, good ROI)
```

---

## 6. Extension and Integration Points

### 6.1 How to Add New Components

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     EXTENSION POINTS GUIDE                               │
└─────────────────────────────────────────────────────────────────────────┘

1. ADDING A NEW INPUT TYPE
   ───────────────────────

   Step 1: Implement InputAdapter interface
   ────────────────────────────────────────
   from video_gen.input_adapters.base import InputAdapter, InputAdapterResult

   class GitHubIssueAdapter(InputAdapter):
       """Adapter for GitHub issues."""

       def __init__(self):
           super().__init__(
               name="github_issue",
               description="GitHub issue as video outline"
           )

       async def adapt(self, issue_url: str, **kwargs) -> InputAdapterResult:
           # Fetch issue from GitHub API
           issue_data = await self._fetch_issue(issue_url)

           # Create VideoConfig from issue
           video_config = VideoConfig(
               video_id=f"issue_{issue_data['number']}",
               title=issue_data['title'],
               scenes=self._create_scenes_from_issue(issue_data)
           )

           return InputAdapterResult(
               success=True,
               video_set=VideoSet(videos=[video_config])
           )

   Step 2: Register adapter in InputStage
   ───────────────────────────────────────
   input_stage = InputStage()
   input_stage.adapters["github_issue"] = GitHubIssueAdapter()

   Step 3: Use in InputConfig
   ──────────────────────────
   input_config = InputConfig(
       input_type="github_issue",
       source="https://github.com/user/repo/issues/123"
   )


2. ADDING A NEW PIPELINE STAGE
   ────────────────────────────

   Step 1: Inherit from Stage base class
   ──────────────────────────────────────
   from video_gen.pipeline.stage import Stage, StageResult

   class TranslationStage(Stage):
       """Translate narration to multiple languages."""

       def __init__(self, event_emitter=None):
           super().__init__("translation", event_emitter)
           self.target_languages = ["es", "fr", "de"]

       async def execute(self, context: Dict[str, Any]) -> StageResult:
           video_config = context["video_config"]

           for scene in video_config.scenes:
               # Translate narration
               for lang in self.target_languages:
                   scene.narration_translations[lang] = (
                       await translate(scene.narration, lang)
                   )

           return StageResult(
               success=True,
               stage_name=self.name,
               artifacts={"translations": len(self.target_languages)}
           )

   Step 2: Register in pipeline
   ─────────────────────────────
   pipeline = PipelineOrchestrator()
   pipeline.register_stage(TranslationStage())

   # Insert at specific position (e.g., after script generation)
   pipeline.stages.insert(3, TranslationStage())


3. ADDING A NEW SCENE TYPE
   ────────────────────────

   Step 1: Create renderer function
   ─────────────────────────────────
   # video_gen/renderers/custom_scenes.py
   from PIL import Image, ImageDraw

   def create_diagram_keyframes(scene_config, width, height, accent_color):
       """Render diagram scene with custom graphics."""

       frames = []

       # Create base frame
       img = Image.new("RGB", (width, height), "#1a1a1a")
       draw = ImageDraw.Draw(img)

       # Draw diagram elements
       # ... custom rendering logic ...

       frames.append(img)
       return frames

   Step 2: Register renderer
   ─────────────────────────
   # video_gen/renderers/__init__.py
   from .custom_scenes import create_diagram_keyframes

   RENDERER_MAP = {
       "diagram": create_diagram_keyframes,
       # ... other renderers
   }

   Step 3: Use in scene configuration
   ──────────────────────────────────
   scene = SceneConfig(
       scene_id="scene_1",
       scene_type="diagram",  # ◀── New type
       visual_content={
           "diagram_type": "flowchart",
           "nodes": [...],
           "edges": [...]
       }
   )


4. ADDING EVENT LISTENERS
   ───────────────────────

   Step 1: Define handler function
   ────────────────────────────────
   async def analytics_handler(event: Event):
       """Send events to analytics service."""
       if event.type == EventType.STAGE_COMPLETED:
           await send_to_analytics({
               "event": "stage_completed",
               "stage": event.stage,
               "duration": event.duration
           })

   Step 2: Subscribe to events
   ───────────────────────────
   from video_gen.pipeline.events import event_emitter, EventType

   event_emitter.on_async(EventType.STAGE_COMPLETED, analytics_handler)
   event_emitter.on_async(EventType.PIPELINE_FAILED, error_handler)


5. ADDING CUSTOM VALIDATORS
   ─────────────────────────

   Step 1: Create validator
   ────────────────────────
   from video_gen.stages.validation_stage import Validator

   class CustomValidator(Validator):
       def validate(self, context: Dict) -> ValidationResult:
           errors = []

           video_config = context.get("video_config")
           if not video_config:
               errors.append("Missing video_config in context")

           # Custom validation logic
           if len(video_config.scenes) > 50:
               errors.append("Too many scenes (max 50)")

           return ValidationResult(
               is_valid=len(errors) == 0,
               errors=errors
           )

   Step 2: Register validator
   ──────────────────────────
   validation_stage = ValidationStage()
   validation_stage.add_validator(CustomValidator())
```

---

## Summary: Using These Diagrams

### For Understanding the System:
1. Start with **Section 1** (System Overview) for big picture
2. Read **Section 2** (Component Interactions) for relationships
3. Study **Section 3** (Data Transformations) for data flow
4. Review **Section 4** (State Lifecycle) for state management
5. Analyze **Section 5** (Performance) for optimization opportunities
6. Reference **Section 6** (Extensions) when adding features

### For Debugging:
- Use **Component Interaction Maps** to trace call paths
- Use **Sequence Diagrams** (DETAILED_SEQUENCE_DIAGRAMS.md) for step-by-step execution
- Use **State Lifecycle** to understand current task state
- Use **Performance Diagrams** to identify bottlenecks

### For New Developers:
- Read in order: Overview → Components → Data Flow → State → Performance
- Keep **Extension Points** as reference when adding features
- Refer to **DESIGN_DECISIONS.md** for "why" behind choices
- Use **QUICK_SUMMARY.md** for quick reference

---

**Document Status:** Comprehensive visualization guide completed
**Coverage:** System overview, components, data flow, state, performance, extensions
**Related Docs:** See other architecture/*.md files for detailed analysis
**Maintenance:** Update diagrams when adding new stages or major components

**Generated:** 2025-10-06 by Claude Code Architecture Enhancement Agent
