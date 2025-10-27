# Detailed Sequence Diagrams - Video_Gen System

**Version:** 2.0.0
**Date:** 2025-10-06
**Purpose:** Comprehensive sequence diagrams for all system flows

---

## Table of Contents

1. [Complete Pipeline Execution](#1-complete-pipeline-execution)
2. [Stage-by-Stage Detailed Flows](#2-stage-by-stage-detailed-flows)
3. [Error Handling and Recovery](#3-error-handling-and-recovery)
4. [State Management Lifecycle](#4-state-management-lifecycle)
5. [Event Flow and Progress Tracking](#5-event-flow-and-progress-tracking)
6. [Adapter Selection and Execution](#6-adapter-selection-and-execution)

---

## 1. Complete Pipeline Execution

### 1.1 Full End-to-End Flow

```
User       CLI/API    Pipeline      StateManager  InputStage  ParseStage  ScriptStage  AudioStage  VideoStage  OutputStage  EventEmitter
 │           │           │               │            │           │            │            │           │            │             │
 │ execute   │           │               │            │           │            │            │           │            │             │
 ├──────────>│           │               │            │           │            │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │ create    │               │            │           │            │            │           │            │             │
 │           │ pipeline  │               │            │           │            │            │           │            │             │
 │           ├──────────>│               │            │           │            │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │  execute( │               │            │           │            │            │           │            │             │
 │           │    input) │               │            │           │            │            │           │            │             │
 │           ├──────────>│               │            │           │            │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │ create_task() │            │           │            │            │           │            │             │
 │           │           ├──────────────>│            │           │            │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │  TaskState    │            │           │            │            │           │            │             │
 │           │           │  (task_xyz)   │            │           │            │            │           │            │             │
 │           │           │<──────────────┤            │           │            │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │ emit(PIPELINE_STARTED)     │           │            │            │           │            │             │
 │           │           ├────────────────────────────────────────────────────────────────────────────────────────────────────────>│
 │           │           │               │            │           │            │            │           │            │             │
 │           │  progress │               │            │           │            │            │           │            │             │
 │           │  0%       │               │            │           │            │            │           │            │             │
 │           │<──────────┤               │            │           │            │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │────────── STAGE 1: INPUT ADAPTATION ─────────────────────────────────────────────────────────────────>│
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │ start_stage(  │            │           │            │            │           │            │             │
 │           │           │   "input")    │            │           │            │            │           │            │             │
 │           │           ├──────────────>│            │           │            │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │ emit(STAGE_STARTED, "input")          │            │            │           │            │             │
 │           │           ├────────────────────────────────────────────────────────────────────────────────────────────────────────>│
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │ run(context,  │            │           │            │            │           │            │             │
 │           │           │     task_xyz) │            │           │            │            │           │            │             │
 │           │           ├──────────────────────────>│           │            │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │               │         execute()      │            │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │               │         • Select adapter (document/youtube/yaml)│           │            │             │
 │           │           │               │         • Parse input  │            │            │           │            │             │
 │           │           │               │         • Create VideoConfig       │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │               │  StageResult           │            │            │           │            │             │
 │           │           │               │  (video_config)        │            │            │           │            │             │
 │           │           │<──────────────────────────┤           │            │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │ save_stage_   │            │           │            │            │           │            │             │
 │           │           │   output()    │            │           │            │            │           │            │             │
 │           │           ├──────────────>│            │           │            │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │  context["video_config"] = VideoConfig│            │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │ emit(STAGE_COMPLETED, "input", progress=0.14)      │            │           │            │             │
 │           │           ├────────────────────────────────────────────────────────────────────────────────────────────────────────>│
 │           │           │               │            │           │            │            │           │            │             │
 │           │  progress │               │            │           │            │            │           │            │             │
 │           │  14%      │               │            │           │            │            │           │            │             │
 │           │<──────────┤               │            │           │            │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │────────── STAGE 2: CONTENT PARSING ──────────────────────────────────────────────────────────────────>│
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │ run(context)  │            │           │            │            │           │            │             │
 │           │           ├───────────────────────────────────────>│            │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │               │            │      execute()         │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │               │            │      • Extract sections│            │           │            │             │
 │           │           │               │            │      • Identify structure           │           │            │             │
 │           │           │               │            │      • Create scene templates       │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │               │            │  StageResult           │            │           │            │             │
 │           │           │<───────────────────────────────────────┤            │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │  context["parsed_content"] = {...}     │            │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │ emit(STAGE_COMPLETED, "parsing", progress=0.28)     │            │           │            │             │
 │           │           ├────────────────────────────────────────────────────────────────────────────────────────────────────────>│
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │────────── STAGE 3: SCRIPT GENERATION ─────────────────────────────────────────────────────────────────>│
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │ run(context)  │            │           │            │            │           │            │             │
 │           │           ├──────────────────────────────────────────────────>│            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │               │            │           │       execute()         │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │               │            │           │       • Generate narration          │            │             │
 │           │           │               │            │           │       • AI enhance (optional)       │            │             │
 │           │           │               │            │           │       • Validate timing constraints │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │               │            │           │       StageResult       │           │            │             │
 │           │           │<──────────────────────────────────────────────────┤            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │  context["video_config"] updated with scripts      │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │ emit(STAGE_COMPLETED, "script_gen", progress=0.42) │            │           │            │             │
 │           │           ├────────────────────────────────────────────────────────────────────────────────────────────────────────>│
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │────────── STAGE 4: AUDIO GENERATION (Longest Stage) ───────────────────────────────────────────────────>│
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │ run(context)  │            │           │            │            │           │            │             │
 │           │           ├─────────────────────────────────────────────────────────────────>│           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │               │            │           │            │       execute()        │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │               │            │           │            │       For each scene:  │            │             │
 │           │           │               │            │           │            │       ┌──────────────┐│            │             │
 │           │           │               │            │           │            │       │1. TTS call   ││            │             │
 │           │           │               │            │           │            │       │  (Edge TTS)  ││            │             │
 │           │           │               │            │           │            │       │              ││            │             │
 │           │           │ emit(AUDIO_GENERATING, scene_1)        │            │       │2. Save MP3   ││            │             │
 │           │           ├────────────────────────────────────────────────────────────────────────────────────────────────────────>│
 │           │           │               │            │           │            │       │              ││            │             │
 │           │  progress │               │            │           │            │       │3. Measure    ││            │             │
 │           │  Scene 1  │               │            │           │            │       │   duration   ││            │             │
 │           │<──────────┤               │            │           │            │       │  (FFmpeg)    ││            │             │
 │           │           │               │            │           │            │       │              ││            │             │
 │           │           │               │            │           │            │       │4. Update     ││            │             │
 │           │           │               │            │           │            │       │   scene      ││            │             │
 │           │           │               │            │           │            │       └──────────────┘│            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │               │            │           │            │       ... (repeat for N scenes)    │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │               │            │           │            │       StageResult     │            │             │
 │           │           │               │            │           │            │       (audio_dir,     │            │             │
 │           │           │               │            │           │            │        timing_report) │            │             │
 │           │           │<─────────────────────────────────────────────────────────────┤           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │  context["audio_dir"] = Path("audio/...")          │            │           │            │             │
 │           │           │  context["timing_report"] = Path("timing.json")    │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │ emit(STAGE_COMPLETED, "audio_gen", progress=0.71)  │            │           │            │             │
 │           │           ├────────────────────────────────────────────────────────────────────────────────────────────────────────>│
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │────────── STAGE 5: VIDEO GENERATION (Second Longest) ──────────────────────────────────────────────────>│
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │ run(context)  │            │           │            │            │           │            │             │
 │           │           ├────────────────────────────────────────────────────────────────────────────>│            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │               │            │           │            │            │      execute()         │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │               │            │           │            │            │      For each scene:   │             │
 │           │           │               │            │           │            │            │      ┌──────────────┐ │             │
 │           │           │               │            │           │            │            │      │1. Render     │ │             │
 │           │           │               │            │           │            │            │      │   keyframes  │ │             │
 │           │           │               │            │           │            │            │      │   (PIL+NumPy)│ │             │
 │           │           │ emit(VIDEO_RENDERING, scene_1)         │            │            │      │              │ │             │
 │           │           ├────────────────────────────────────────────────────────────────────────────────────────────────────────>│
 │           │           │               │            │           │            │            │      │2. Apply      │ │             │
 │           │  progress │               │            │           │            │            │      │   transitions│ │             │
 │           │  Scene 1  │               │            │           │            │            │      │              │ │             │
 │           │<──────────┤               │            │           │            │            │      │3. Encode     │ │             │
 │           │           │               │            │           │            │            │      │   (FFmpeg+   │ │             │
 │           │           │               │            │           │            │            │      │    NVENC)    │ │             │
 │           │           │               │            │           │            │            │      │              │ │             │
 │           │           │               │            │           │            │            │      │4. Save MP4   │ │             │
 │           │           │               │            │           │            │            │      └──────────────┘ │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │               │            │           │            │            │      ... (repeat)    │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │               │            │           │            │            │      StageResult     │             │
 │           │           │               │            │           │            │            │      (video_segments)│             │
 │           │           │<────────────────────────────────────────────────────────────────────────┤            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │  context["video_segments"] = [Path(...), ...]      │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │ emit(STAGE_COMPLETED, "video_gen", progress=0.90)  │            │           │            │             │
 │           │           ├────────────────────────────────────────────────────────────────────────────────────────────────────────>│
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │────────── STAGE 6: OUTPUT HANDLING (Finalization) ────────────────────────────────────────────────────>│
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │ run(context)  │            │           │            │            │           │            │             │
 │           │           ├───────────────────────────────────────────────────────────────────────────────────────>│             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │               │            │           │            │            │           │       execute()          │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │               │            │           │            │            │           │       • Concatenate      │
 │           │           │               │            │           │            │            │           │         segments         │
 │           │           │               │            │           │            │            │           │       • Organize files   │
 │           │           │               │            │           │            │            │           │       • Generate metadata│
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │               │            │           │            │            │           │       StageResult        │
 │           │           │               │            │           │            │            │           │       (final_video_path) │
 │           │           │<───────────────────────────────────────────────────────────────────────────────────────┤             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │  context["final_video_path"] = Path("output/video.mp4")        │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │ complete_task()            │           │            │            │           │            │             │
 │           │           ├──────────────>│            │           │            │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │           │           │ emit(PIPELINE_COMPLETED, success=True)│            │            │           │            │             │
 │           │           ├────────────────────────────────────────────────────────────────────────────────────────────────────────>│
 │           │           │               │            │           │            │            │           │            │             │
 │           │  Pipeline │               │            │           │            │            │           │            │             │
 │           │  Result   │               │            │           │            │            │           │            │             │
 │           │<──────────┤               │            │           │            │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
 │  Complete │           │               │            │           │            │            │           │            │             │
 │<──────────┤           │               │            │           │            │            │           │            │             │
 │           │           │               │            │           │            │            │           │            │             │
```

**Key Metrics:**
- **Total Stages:** 6 (7 if validation included)
- **Average Stage Duration:** 30s - 2min (varies by content complexity)
- **Longest Stages:** Audio Generation (30s-2min), Video Generation (1-5min)
- **Total Pipeline Time:** 2-8 minutes for typical 10-20 scene video
- **Checkpoints:** After each stage completion
- **Events Emitted:** 20-50+ events depending on scene count

---

## 2. Stage-by-Stage Detailed Flows

### 2.1 Input Adaptation Stage (Detailed)

```
InputStage          DocumentAdapter      YouTubeAdapter      YAMLAdapter      Config          EventEmitter
    │                      │                    │                 │                │                 │
    │ execute(context)     │                    │                 │                │                 │
    │                      │                    │                 │                │                 │
    │ Get input_type       │                    │                 │                │                 │
    │ from context         │                    │                 │                │                 │
    │                      │                    │                 │                │                 │
    │ if "document":       │                    │                 │                │                 │
    ├─────────────────────>│                    │                 │                │                 │
    │                      │                    │                 │                │                 │
    │                      │ validate_source()  │                 │                │                 │
    │                      │ • Check file exists│                 │                │                 │
    │                      │ • Check format     │                 │                │                 │
    │                      │   (.md, .pdf, etc) │                 │                │                 │
    │                      │                    │                 │                │                 │
    │                      │ if PDF:            │                 │                │                 │
    │                      │   extract_pdf()    │                 │                │                 │
    │                      │ if DOCX:           │                 │                │                 │
    │                      │   extract_docx()   │                 │                │                 │
    │                      │ if MD/TXT:         │                 │                │                 │
    │                      │   read_text()      │                 │                │                 │
    │                      │                    │                 │                │                 │
    │                      │ parse_structure()  │                 │                │                 │
    │                      │ • Extract headings │                 │                │                 │
    │                      │ • Identify sections│                 │                │                 │
    │                      │ • Extract lists    │                 │                │                 │
    │                      │ • Extract code     │                 │                │                 │
    │                      │                    │                 │                │                 │
    │                      │ create_video_      │                 │                │                 │
    │                      │   config()         │                 │                │                 │
    │                      │ • Generate scenes  │                 │                │                 │
    │                      │ • Set scene types  │                 │                │                 │
    │                      │ • Apply defaults   │                 │                │                 │
    │                      │                    │                 │                │                 │
    │                      │ InputAdapterResult │                 │                │                 │
    │                      │ (video_set)        │                 │                │                 │
    │<─────────────────────┤                    │                 │                │                 │
    │                      │                    │                 │                │                 │
    │ elif "youtube":      │                    │                 │                │                 │
    ├──────────────────────────────────────────>│                 │                │                 │
    │                      │                    │                 │                │                 │
    │                      │                    │ extract_video_  │                │                 │
    │                      │                    │   id(url)       │                │                 │
    │                      │                    │                 │                │                 │
    │                      │                    │ fetch_transcript│                │                 │
    │                      │                    │ (video_id)      │                │                 │
    │                      │                    │ • Get captions  │                │                 │
    │                      │                    │ • Parse timing  │                │                 │
    │                      │                    │ • Extract text  │                │                 │
    │                      │                    │                 │                │                 │
    │                      │                    │ create_scenes() │                │                 │
    │                      │                    │ • Split by time │                │                 │
    │                      │                    │ • Group segments│                │                 │
    │                      │                    │                 │                │                 │
    │                      │                    │ InputAdapter    │                │                 │
    │                      │                    │   Result        │                │                 │
    │<──────────────────────────────────────────┤                 │                │                 │
    │                      │                    │                 │                │                 │
    │ elif "yaml":         │                    │                 │                │                 │
    ├───────────────────────────────────────────────────────────>│                │                 │
    │                      │                    │                 │                │                 │
    │                      │                    │                 │ load_yaml()    │                 │
    │                      │                    │                 │ validate_      │                 │
    │                      │                    │                 │   schema()     │                 │
    │                      │                    │                 │                │                 │
    │                      │                    │                 │ InputAdapter   │                 │
    │                      │                    │                 │   Result       │                 │
    │<───────────────────────────────────────────────────────────┤                │                 │
    │                      │                    │                 │                │                 │
    │ Extract VideoConfig  │                    │                 │                │                 │
    │ from result          │                    │                 │                │                 │
    │                      │                    │                 │                │                 │
    │ Apply global config  │                    │                 │                │                 │
    ├─────────────────────────────────────────────────────────────────────────────>│                 │
    │                      │                    │                 │                │                 │
    │ Config values        │                    │                 │                │                 │
    │ (accent_color,       │                    │                 │                │                 │
    │  voice, dirs)        │                    │                 │                │                 │
    │<─────────────────────────────────────────────────────────────────────────────┤                 │
    │                      │                    │                 │                │                 │
    │ Update VideoConfig   │                    │                 │                │                 │
    │                      │                    │                 │                │                 │
    │ emit(STAGE_PROGRESS, │                    │                 │                │                 │
    │      progress=1.0)   │                    │                 │                │                 │
    ├──────────────────────────────────────────────────────────────────────────────────────────────>│
    │                      │                    │                 │                │                 │
    │ Return StageResult   │                    │                 │                │                 │
    │ (video_config,       │                    │                 │                │                 │
    │  metadata)           │                    │                 │                │                 │
    │                      │                    │                 │                │                 │
```

**Design Decisions:**
- **Why multiple adapters?** Each input format requires different parsing logic (PDF extraction vs YouTube API calls)
- **Why strategy pattern?** Makes it easy to add new input types without modifying InputStage
- **Why validate first?** Fail-fast principle - catch errors before expensive processing

---

### 2.2 Audio Generation Stage (Detailed with Voice Rotation)

```
AudioStage      EdgeTTS API      FFmpeg      VoiceRotator      FileSystem      EventEmitter
    │               │              │              │                 │                 │
    │ execute()     │              │              │                 │                 │
    │               │              │              │                 │                 │
    │ Get scenes    │              │              │                 │                 │
    │ from context  │              │              │                 │                 │
    │               │              │              │                 │                 │
    │ Initialize    │              │              │                 │                 │
    │ voice rotation│              │              │                 │                 │
    ├──────────────────────────────────────────>│                 │                 │
    │               │              │              │                 │                 │
    │               │              │              │ if len(voices) > 1:              │
    │               │              │              │   rotate = True │                 │
    │               │              │              │ else:           │                 │
    │               │              │              │   use single    │                 │
    │               │              │              │                 │                 │
    │ FOR EACH SCENE (1 to N):    │              │                 │                 │
    │               │              │              │                 │                 │
    │ Get next voice│              │              │                 │                 │
    │ for scene     │              │              │                 │                 │
    ├──────────────────────────────────────────>│                 │                 │
    │               │              │              │                 │                 │
    │               │              │              │ get_next_voice()│                 │
    │               │              │              │ • Round-robin   │                 │
    │               │              │              │ • voice_index++ │                 │
    │               │              │              │                 │                 │
    │ voice_name    │              │              │                 │                 │
    │<──────────────────────────────────────────┤                 │                 │
    │               │              │              │                 │                 │
    │ emit(AUDIO_   │              │              │                 │                 │
    │   GENERATING, │              │              │                 │                 │
    │   scene_N,    │              │              │                 │                 │
    │   voice)      │              │              │                 │                 │
    ├──────────────────────────────────────────────────────────────────────────────>│
    │               │              │              │                 │                 │
    │ Call TTS API  │              │              │                 │                 │
    ├─────────────>│              │              │                 │                 │
    │               │              │              │                 │                 │
    │               │ communicate()│              │                 │                 │
    │               │ • Send text  │              │                 │                 │
    │               │ • Send voice │              │                 │                 │
    │               │ • Send rate  │              │                 │                 │
    │               │              │              │                 │                 │
    │               │ ... processing (~2-5s per scene) ...         │                 │
    │               │              │              │                 │                 │
    │ audio_data    │              │              │                 │                 │
    │ (MP3 bytes)   │              │              │                 │                 │
    │<─────────────┤              │              │                 │                 │
    │               │              │              │                 │                 │
    │ Save MP3 file │              │              │                 │                 │
    ├─────────────────────────────────────────────────────────────>│                 │
    │               │              │              │                 │                 │
    │               │              │              │                 │ write_file()    │
    │               │              │              │                 │ (scene_N.mp3)   │
    │               │              │              │                 │                 │
    │ file_path     │              │              │                 │                 │
    │<─────────────────────────────────────────────────────────────┤                 │
    │               │              │              │                 │                 │
    │ Measure       │              │              │                 │                 │
    │ duration      │              │              │                 │                 │
    ├────────────────────────────>│              │                 │                 │
    │               │              │              │                 │                 │
    │               │              │ ffprobe      │                 │                 │
    │               │              │ scene_N.mp3  │                 │                 │
    │               │              │              │                 │                 │
    │ duration_sec  │              │              │                 │                 │
    │<────────────────────────────┤              │                 │                 │
    │               │              │              │                 │                 │
    │ Update scene  │              │              │                 │                 │
    │ • audio_file  │              │              │                 │                 │
    │ • final_dur   │              │              │                 │                 │
    │ • actual_dur  │              │              │                 │                 │
    │               │              │              │                 │                 │
    │ Check timing  │              │              │                 │                 │
    │ constraints   │              │              │                 │                 │
    │               │              │              │                 │                 │
    │ if actual_dur < min_duration:│              │                 │                 │
    │   scene.warnings.append("Too short")       │                 │                 │
    │ if actual_dur > max_duration:│              │                 │                 │
    │   scene.warnings.append("Truncated")       │                 │                 │
    │   final_duration = max_duration            │                 │                 │
    │               │              │              │                 │                 │
    │ emit(AUDIO_   │              │              │                 │                 │
    │   GENERATED,  │              │              │                 │                 │
    │   scene_N,    │              │              │                 │                 │
    │   duration)   │              │              │                 │                 │
    ├──────────────────────────────────────────────────────────────────────────────>│
    │               │              │              │                 │                 │
    │ END FOR       │              │              │                 │                 │
    │               │              │              │                 │                 │
    │ Generate      │              │              │                 │                 │
    │ timing report │              │              │                 │                 │
    │ (JSON)        │              │              │                 │                 │
    │               │              │              │                 │                 │
    │ timing_data = {              │              │                 │                 │
    │   "total_duration": sum(...),│              │                 │                 │
    │   "scene_count": N,          │              │                 │                 │
    │   "warnings": [...],         │              │                 │                 │
    │   "scenes": [...]            │              │                 │                 │
    │ }               │              │              │                 │                 │
    │               │              │              │                 │                 │
    │ Save timing   │              │              │                 │                 │
    │ report        │              │              │                 │                 │
    ├─────────────────────────────────────────────────────────────>│                 │
    │               │              │              │                 │                 │
    │               │              │              │                 │ write_json()    │
    │               │              │              │                 │ (timing_        │
    │               │              │              │                 │  report.json)   │
    │               │              │              │                 │                 │
    │ Return        │              │              │                 │                 │
    │ StageResult   │              │              │                 │                 │
    │ (audio_dir,   │              │              │                 │                 │
    │  timing_      │              │              │                 │                 │
    │  report)      │              │              │                 │                 │
    │               │              │              │                 │                 │
```

**Performance Characteristics:**
- **TTS Call:** 2-5 seconds per scene (network dependent)
- **File Write:** <100ms per MP3
- **Duration Probe:** ~200ms per file
- **Total per Scene:** ~3-6 seconds
- **For 10 scenes:** ~30-60 seconds total
- **Parallelizable?** Yes, with `asyncio.gather()` - can reduce to 5-10 seconds for 10 scenes

**Trade-offs:**
- **Sequential (current):** Simpler, easier to debug, predictable progress
- **Parallel (future):** Faster, but harder to track progress and handle errors

---

## 3. Error Handling and Recovery

### 3.1 Stage Failure and Retry Flow

```
Pipeline      Stage         RetryPolicy    StateManager    EventEmitter
    │             │               │              │               │
    │ run_stage() │               │              │               │
    ├────────────>│               │              │               │
    │             │               │              │               │
    │             │ execute()     │              │               │
    │             │               │              │               │
    │             │ ... work ...  │              │               │
    │             │               │              │               │
    │             │ ❌ EXCEPTION  │              │               │
    │             │ (Network      │              │               │
    │             │  timeout)     │              │               │
    │             │               │              │               │
    │ Exception   │               │              │               │
    │<────────────┤               │              │               │
    │             │               │              │               │
    │ retry_      │               │              │               │
    │ execute()   │               │              │               │
    ├──────────────────────────>│              │               │
    │             │               │              │               │
    │             │               │ Attempt 1    │               │
    │             │               │ execute()    │               │
    │             │               ├─────────────>│               │
    │             │               │              │               │
    │             │               │ ❌ FAIL      │               │
    │             │               │              │               │
    │             │               │ wait(1s)     │               │
    │             │               │ (base delay) │               │
    │             │               │              │               │
    │             │               │ emit(STAGE_  │               │
    │             │               │   RETRY,     │               │
    │             │               │   attempt=1) │               │
    │             │               ├──────────────────────────────>│
    │             │               │              │               │
    │             │               │ Attempt 2    │               │
    │             │               │ execute()    │               │
    │             │               ├─────────────>│               │
    │             │               │              │               │
    │             │               │ ❌ FAIL      │               │
    │             │               │              │               │
    │             │               │ wait(2s)     │               │
    │             │               │ (2^1 * base) │               │
    │             │               │              │               │
    │             │               │ emit(STAGE_  │               │
    │             │               │   RETRY,     │               │
    │             │               │   attempt=2) │               │
    │             │               ├──────────────────────────────>│
    │             │               │              │               │
    │             │               │ Attempt 3    │               │
    │             │               │ execute()    │               │
    │             │               ├─────────────>│               │
    │             │               │              │               │
    │             │               │ ✅ SUCCESS!  │               │
    │             │               │              │               │
    │             │               │ StageResult  │               │
    │             │               │<─────────────┤               │
    │             │               │              │               │
    │ StageResult │               │              │               │
    │<──────────────────────────┤              │               │
    │             │               │              │               │
    │ save_stage_ │               │              │               │
    │ output()    │               │              │               │
    ├───────────────────────────────────────────>│               │
    │             │               │              │               │
    │             │               │              │ checkpoint    │
    │             │               │              │ saved         │
    │             │               │              │               │
    │ continue... │               │              │               │
    │             │               │              │               │
```

**Retry Strategy:**
- **Max Attempts:** 3 (configurable)
- **Backoff:** Exponential (1s, 2s, 4s)
- **Max Delay:** 60s (prevents excessive waits)
- **Retryable Errors:** Network timeouts, temporary file locks, API rate limits
- **Non-Retryable:** Invalid input, missing dependencies, permission denied

---

### 3.2 Complete Pipeline Failure and Resume

```
User      Pipeline      StateManager      FileSystem
 │            │               │                 │
 │ execute()  │               │                 │
 ├───────────>│               │                 │
 │            │               │                 │
 │            │ Stages 1-3    │                 │
 │            │ complete ✅   │                 │
 │            │               │                 │
 │            │ Stage 4       │                 │
 │            │ (audio) ❌    │                 │
 │            │ FAILS         │                 │
 │            │               │                 │
 │            │ fail_task()   │                 │
 │            ├──────────────>│                 │
 │            │               │                 │
 │            │               │ save_state()    │
 │            │               │ task_xyz.json   │
 │            │               ├────────────────>│
 │            │               │                 │
 │            │               │                 │ {
 │            │               │                 │   "status": "failed",
 │            │               │                 │   "current_stage": "audio",
 │            │               │                 │   "completed": ["input", "parsing", "script"],
 │            │               │                 │   "error": "Network timeout",
 │            │               │                 │   "artifacts": {
 │            │               │                 │     "video_config": "...",
 │            │               │                 │     "parsed_content": "..."
 │            │               │                 │   }
 │            │               │                 │ }
 │            │               │                 │
 │ PipelineResult             │                 │
 │ (success=False,            │                 │
 │  error="...",              │                 │
 │  task_id="xyz")            │                 │
 │<───────────┤               │                 │
 │            │               │                 │
 │            │               │                 │
 │ ────────── LATER: USER RESUMES ─────────────│
 │            │               │                 │
 │ execute(   │               │                 │
 │   resume=  │               │                 │
 │   "xyz")   │               │                 │
 ├───────────>│               │                 │
 │            │               │                 │
 │            │ restore_task()│                 │
 │            ├──────────────>│                 │
 │            │               │                 │
 │            │               │ load_state()    │
 │            │               │ task_xyz.json   │
 │            │               ├────────────────>│
 │            │               │                 │
 │            │               │ TaskState       │
 │            │               │<────────────────┤
 │            │               │                 │
 │            │ TaskState     │                 │
 │            │<──────────────┤                 │
 │            │               │                 │
 │            │ Get completed │                 │
 │            │ stages:       │                 │
 │            │ [input,       │                 │
 │            │  parsing,     │                 │
 │            │  script]      │                 │
 │            │               │                 │
 │            │ Start from    │                 │
 │            │ Stage 4       │                 │
 │            │ (audio)       │                 │
 │            │               │                 │
 │            │ execute       │                 │
 │            │ stages[3:]    │                 │
 │            │ • audio ✅    │                 │
 │            │ • video ✅    │                 │
 │            │ • output ✅   │                 │
 │            │               │                 │
 │ Pipeline   │               │                 │
 │ Result     │               │                 │
 │ (success=  │               │                 │
 │  True)     │               │                 │
 │<───────────┤               │                 │
 │            │               │                 │
```

**Resume Capability Benefits:**
- **Save Time:** Don't re-run completed stages (can save 2-5 minutes)
- **Save Cost:** Don't re-call expensive APIs (TTS, AI enhancement)
- **Reliability:** Network hiccups don't require full restart
- **User Experience:** Transparent recovery, minimal intervention

---

## 4. State Management Lifecycle

### 4.1 Task State Transitions

```
StateManager        FileSystem          TaskState Object
     │                   │                      │
     │ create_task()     │                      │
     │                   │                      │
     │                   │                      │ new TaskState()
     │                   │                      │ • status = PENDING
     │                   │                      │ • stages = {}
     │                   │                      │ • created_at = now()
     │                   │                      │
     │ save_task()       │                      │
     ├──────────────────>│                      │
     │                   │                      │
     │                   │ write_json()         │
     │                   │ state/task_xyz.json  │
     │                   │                      │
     │ TaskState         │                      │
     │<──────────────────┤                      │
     │                   │                      │
     │ ──────────────── STAGE 1 STARTS ────────│
     │                   │                      │
     │ start_stage()     │                      │
     │                   │                      │
     │                   │                      │ update_state()
     │                   │                      │ • current_stage = "input"
     │                   │                      │ • stages["input"] = {
     │                   │                      │     status: RUNNING,
     │                   │                      │     started_at: now()
     │                   │                      │   }
     │                   │                      │
     │ save_task()       │                      │
     ├──────────────────>│                      │
     │                   │                      │
     │ ──────────────── STAGE 1 COMPLETES ─────│
     │                   │                      │
     │ complete_stage()  │                      │
     │                   │                      │
     │                   │                      │ update_state()
     │                   │                      │ • stages["input"] = {
     │                   │                      │     status: COMPLETED,
     │                   │                      │     completed_at: now(),
     │                   │                      │     artifacts: {...}
     │                   │                      │   }
     │                   │                      │ • overall_progress = 0.14
     │                   │                      │
     │ save_task()       │                      │
     ├──────────────────>│                      │
     │                   │                      │
     │ ──────────────── REPEAT FOR ALL STAGES ─│
     │                   │                      │
     │ ──────────────── ALL STAGES COMPLETE ───│
     │                   │                      │
     │ complete_task()   │                      │
     │                   │                      │
     │                   │                      │ update_state()
     │                   │                      │ • status = COMPLETED
     │                   │                      │ • completed_at = now()
     │                   │                      │ • overall_progress = 1.0
     │                   │                      │ • result = {
     │                   │                      │     video_path: "...",
     │                   │                      │     total_duration: 120.5
     │                   │                      │   }
     │                   │                      │
     │ save_task()       │                      │
     ├──────────────────>│                      │
     │                   │                      │
```

**State Persistence Format (JSON):**
```json
{
  "task_id": "task_abc123",
  "status": "completed",
  "current_stage": null,
  "overall_progress": 1.0,
  "created_at": "2025-10-06T10:00:00Z",
  "started_at": "2025-10-06T10:00:05Z",
  "completed_at": "2025-10-06T10:08:30Z",
  "input_config": {
    "input_type": "document",
    "source": "inputs/guide.md",
    "accent_color": "blue",
    "voice": "male"
  },
  "stages": {
    "input_adaptation": {
      "name": "input_adaptation",
      "status": "completed",
      "progress": 1.0,
      "started_at": "2025-10-06T10:00:05Z",
      "completed_at": "2025-10-06T10:00:20Z",
      "duration_seconds": 15,
      "error": null,
      "artifacts": {
        "video_config": "state/task_abc123/video_config.json",
        "metadata": {
          "scene_count": 10,
          "document_pages": 5
        }
      }
    },
    "audio_generation": {
      "name": "audio_generation",
      "status": "completed",
      "progress": 1.0,
      "started_at": "2025-10-06T10:01:00Z",
      "completed_at": "2025-10-06T10:03:45Z",
      "duration_seconds": 165,
      "error": null,
      "artifacts": {
        "audio_dir": "audio/unified_system/video_abc_audio",
        "timing_report": "audio/unified_system/video_abc_audio/timing_report.json"
      }
    }
  },
  "result": {
    "success": true,
    "video_path": "output/final_video_abc.mp4",
    "total_duration": 120.5,
    "scene_count": 10
  },
  "errors": [],
  "warnings": [
    "Scene 3: Narration truncated to fit max_duration"
  ]
}
```

---

## 5. Event Flow and Progress Tracking

### 5.1 Event Types and Hierarchy

```
EventEmitter
     │
     ├─► PIPELINE_STARTED
     │    • Emitted when: Pipeline execution begins
     │    • Data: task_id, input_config, total_stages
     │    • Use case: Initialize UI progress bar
     │
     ├─► STAGE_STARTED
     │    • Emitted when: Stage begins execution
     │    • Data: task_id, stage_name, stage_index, estimated_duration
     │    • Use case: Update UI with current stage
     │
     ├─► STAGE_PROGRESS
     │    • Emitted when: Stage reports progress (0.0-1.0)
     │    • Data: task_id, stage_name, progress, message
     │    • Use case: Update stage-specific progress bar
     │
     ├─► STAGE_COMPLETED
     │    • Emitted when: Stage finishes successfully
     │    • Data: task_id, stage_name, duration, artifacts
     │    • Use case: Mark stage complete, show checkmark
     │
     ├─► STAGE_FAILED
     │    • Emitted when: Stage fails after retries
     │    • Data: task_id, stage_name, error, retry_count
     │    • Use case: Show error message, offer retry
     │
     ├─► STAGE_RETRY
     │    • Emitted when: Stage is being retried
     │    • Data: task_id, stage_name, attempt, max_attempts, delay
     │    • Use case: Show "Retrying in Xs..." message
     │
     ├─► AUDIO_GENERATING
     │    • Emitted when: TTS generation starts for a scene
     │    • Data: task_id, scene_id, scene_index, total_scenes, voice
     │    • Use case: Show "Generating audio for scene X/Y"
     │
     ├─► AUDIO_GENERATED
     │    • Emitted when: TTS generation completes for a scene
     │    • Data: task_id, scene_id, duration, file_path
     │    • Use case: Update per-scene progress
     │
     ├─► VIDEO_RENDERING
     │    • Emitted when: Video rendering starts for a scene
     │    • Data: task_id, scene_id, scene_index, total_scenes
     │    • Use case: Show "Rendering scene X/Y"
     │
     ├─► VIDEO_RENDERED
     │    • Emitted when: Video rendering completes for a scene
     │    • Data: task_id, scene_id, file_path
     │    • Use case: Update per-scene progress
     │
     ├─► VALIDATION_WARNING
     │    • Emitted when: Non-fatal validation issue found
     │    • Data: task_id, stage_name, warning_message, severity
     │    • Use case: Show warning icon, log issue
     │
     ├─► STATE_SAVED
     │    • Emitted when: Task state checkpoint saved
     │    • Data: task_id, checkpoint_path, stage_name
     │    • Use case: Log checkpoint for debugging
     │
     ├─► PIPELINE_COMPLETED
     │    • Emitted when: All stages complete successfully
     │    • Data: task_id, total_duration, result
     │    • Use case: Show completion message, display video
     │
     └─► PIPELINE_FAILED
          • Emitted when: Pipeline fails and cannot continue
          • Data: task_id, failed_stage, error, can_resume
          • Use case: Show error, offer resume option
```

### 5.2 Event Subscription and Handling

```
EventEmitter      UIProgressBar      Logger      MetricsCollector
     │                  │               │                │
     │ subscribe(       │               │                │
     │   STAGE_STARTED, │               │                │
     │   handler)       │               │                │
     │<─────────────────┤               │                │
     │                  │               │                │
     │ subscribe(       │               │                │
     │   STAGE_PROGRESS,│               │                │
     │   handler)       │               │                │
     │<─────────────────┤               │                │
     │                  │               │                │
     │ subscribe(       │               │                │
     │   PIPELINE_*,    │               │                │
     │   log_handler)   │               │                │
     │<─────────────────────────────────┤                │
     │                  │               │                │
     │ subscribe(       │               │                │
     │   STAGE_COMPLETED│               │                │
     │   metrics_handler│               │                │
     │<──────────────────────────────────────────────────┤
     │                  │               │                │
     │ ──────────── PIPELINE EXECUTES ────────────────> │
     │                  │               │                │
     │ emit(            │               │                │
     │   STAGE_STARTED, │               │                │
     │   "audio")       │               │                │
     │                  │               │                │
     ├─────────────────>│               │                │
     │                  │               │                │
     │                  │ update_ui()   │                │
     │                  │ • Show "Audio Generation"     │
     │                  │ • Reset progress bar          │
     │                  │               │                │
     ├──────────────────────────────────>│                │
     │                  │               │                │
     │                  │               │ log.info()      │
     │                  │               │ "Stage audio    │
     │                  │               │  started"       │
     │                  │               │                │
     │ emit(            │               │                │
     │   STAGE_PROGRESS,│               │                │
     │   0.5)           │               │                │
     │                  │               │                │
     ├─────────────────>│               │                │
     │                  │               │                │
     │                  │ update_bar()  │                │
     │                  │ • Set to 50%  │                │
     │                  │               │                │
     │ emit(            │               │                │
     │   STAGE_COMPLETED│               │                │
     │   "audio",       │               │                │
     │   duration=120s) │               │                │
     │                  │               │                │
     ├─────────────────>│               │                │
     │                  │               │                │
     │                  │ show_check()  │                │
     │                  │ • Green ✓     │                │
     │                  │               │                │
     ├──────────────────────────────────>│                │
     │                  │               │                │
     │                  │               │ log.info()      │
     │                  │               │ "Stage completed│
     │                  │               │  in 120s"       │
     │                  │               │                │
     ├──────────────────────────────────────────────────>│
     │                  │               │                │
     │                  │               │                │ record_metric()
     │                  │               │                │ • stage: "audio"
     │                  │               │                │ • duration: 120s
     │                  │               │                │
```

**Event Design Principles:**
- **Async-First:** All handlers are async to prevent blocking
- **Fire-and-Forget:** Emitter doesn't wait for handlers
- **Error Isolation:** Handler exceptions don't affect pipeline
- **Type-Safe:** EventType enum prevents typos
- **Extensible:** Easy to add new event types

---

## 6. Adapter Selection and Execution

### 6.1 Input Type Detection and Routing

```
InputStage      InputConfig      AdapterFactory      Adapters
    │                │                  │                 │
    │ execute(       │                  │                 │
    │   context)     │                  │                 │
    │                │                  │                 │
    │ Get InputConfig│                  │                 │
    │ from context   │                  │                 │
    ├───────────────>│                  │                 │
    │                │                  │                 │
    │ input_type =   │                  │                 │
    │ "document"     │                  │                 │
    │<───────────────┤                  │                 │
    │                │                  │                 │
    │ Get adapter    │                  │                 │
    │ for type       │                  │                 │
    ├────────────────────────────────────>│                 │
    │                │                  │                 │
    │                │                  │ if "document":  │
    │                │                  │   return        │
    │                │                  │   DocumentAdapter()
    │                │                  │ elif "youtube": │
    │                │                  │   return        │
    │                │                  │   YouTubeAdapter()
    │                │                  │ elif "yaml":    │
    │                │                  │   return        │
    │                │                  │   YAMLAdapter() │
    │                │                  │                 │
    │ adapter        │                  │                 │
    │<────────────────────────────────────┤                 │
    │                │                  │                 │
    │ validate_      │                  │                 │
    │ source()       │                  │                 │
    ├──────────────────────────────────────────────────────>│
    │                │                  │                 │
    │                │                  │                 │ Check:
    │                │                  │                 │ • File exists?
    │                │                  │                 │ • Format supported?
    │                │                  │                 │ • Permissions OK?
    │                │                  │                 │
    │ valid = True   │                  │                 │
    │<──────────────────────────────────────────────────────┤
    │                │                  │                 │
    │ adapt(source)  │                  │                 │
    ├──────────────────────────────────────────────────────>│
    │                │                  │                 │
    │                │                  │                 │ execute_adapter()
    │                │                  │                 │ • Parse input
    │                │                  │                 │ • Create VideoConfig
    │                │                  │                 │ • Apply defaults
    │                │                  │                 │
    │ InputAdapter   │                  │                 │
    │ Result         │                  │                 │
    │ (video_set)    │                  │                 │
    │<──────────────────────────────────────────────────────┤
    │                │                  │                 │
    │ Extract        │                  │                 │
    │ VideoConfig    │                  │                 │
    │                │                  │                 │
    │ Return         │                  │                 │
    │ StageResult    │                  │                 │
    │                │                  │                 │
```

**Adapter Selection Strategy:**
- **Explicit:** User specifies `input_type` in InputConfig
- **Auto-Detection (Future):** Could infer from file extension or URL pattern
- **Validation:** Each adapter validates source before attempting parse
- **Error Handling:** Invalid source fails fast with clear error message

---

**Document Status:** Comprehensive sequence diagrams completed
**Coverage:** Complete pipeline, all stages, error handling, state management, events, adapters
**Use Cases:** Architecture understanding, debugging, onboarding new developers
**Next Steps:** Refer to COMPONENT_DIAGRAM.md for static architecture views

**Generated:** 2025-10-06 by Claude Code Architecture Enhancement Agent
