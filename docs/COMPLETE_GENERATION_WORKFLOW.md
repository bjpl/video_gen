# Complete Video Generation Workflow

**Version:** 2.0
**Date:** November 27, 2025
**Status:** Production Ready

---

## Executive Summary

The video_gen system implements a sophisticated **6-stage pipeline** that transforms various input sources into professional videos with perfect audio-visual synchronization. The workflow is **audio-first**, meaning audio is generated first and video frames are rendered to match the exact timing, ensuring perfect synchronization.

---

## 🎯 High-Level Workflow

```
INPUT → PARSE → SCRIPT → AUDIO → VIDEO → OUTPUT
```

1. **INPUT**: Accept document, YouTube URL, YAML, wizard, or programmatic input
2. **PARSE**: Extract structure and content from source
3. **SCRIPT**: Generate narration (template or AI-enhanced)
4. **AUDIO**: Synthesize speech and measure timing
5. **VIDEO**: Render frames to match audio duration
6. **OUTPUT**: Encode and deliver final video

---

## 📋 Detailed Stage-by-Stage Workflow

### Stage 1: Input Processing

**Entry Points:**
- `scripts/create_video.py` - Master CLI entry point
- `app/main.py` - Web UI (FastAPI)
- `video_gen.input_adapters.ProgrammaticAdapter` - Python API

**Process:**
```python
# User provides input via one of 5 methods:
1. Document: python create_video.py --document README.md
2. YouTube: python create_video.py --youtube "python tutorial"
3. Wizard: python create_video.py --wizard
4. YAML: python create_video.py --yaml inputs/my_video.yaml
5. API: from video_gen import ProgrammaticAdapter
```

**Adapters** (`video_gen/input_adapters/`):
- `DocumentAdapter`: Parses markdown/PDF/text files
- `YouTubeAdapter`: Extracts transcripts from videos
- `YAMLFileAdapter`: Loads YAML configurations
- `WizardAdapter`: Interactive Q&A interface
- `ProgrammaticAdapter`: Direct Python objects

**Output:** `VideoConfig` object with structured scenes

---

### Stage 2: Content Parsing

**Module:** `video_gen/stages/parsing_stage.py`

**Process:**
1. **Structure Analysis**
   - Extract headings (H1/H2/H3)
   - Identify sections and subsections
   - Detect code blocks, lists, quotes

2. **Scene Mapping**
   - Title scenes from H1 headings
   - List scenes from bullet points
   - Command scenes from code blocks
   - Quote scenes from blockquotes

3. **Content Chunking**
   - Split long sections into manageable scenes
   - Apply AI-powered intelligent splitting (6 strategies)
   - Maintain narrative flow

**Example Transformation:**
```markdown
# Getting Started        → Title Scene
- Install Python        → List Scene (item 1)
- Setup environment     → List Scene (item 2)
```python
print("Hello")          → Command Scene
```

**Output:** `ParsedContent` with scene assignments

---

### Stage 3: Script Generation

**Module:** `video_gen/stages/script_generation_stage.py`

**Process:**

#### Template-Based Generation (Default)
```python
# NarrationGenerator creates scripts from templates:
- Title: "{title}. {subtitle}."
- List: "Here are {count} important items..."
- Command: "Run this command to {action}..."
- Outro: "{message}. {call_to_action}"
```

#### AI Enhancement (Optional)
```python
# AIScriptEnhancer with Claude 3.5 Sonnet:
1. Send template narration + context
2. Receive enhanced, natural narration
3. Apply scene position awareness
4. Ensure appropriate pacing
```

**Features:**
- **28+ languages** with native TTS voices
- **Voice rotation** (4 professional voices)
- **Cost tracking** ($0.015/1K tokens Sonnet 4.5)
- **Fallback** to templates if AI unavailable

**Output:** Complete narration text for each scene

---

### Stage 4: Audio Generation (Critical Stage)

**Module:** `video_gen/stages/audio_generation_stage.py`

**This is the KEY stage that drives all timing!**

**Process:**
```python
for scene in video_config.scenes:
    # 1. Select voice (with rotation support)
    voice = voices[scene_index % len(voices)]

    # 2. Generate TTS audio
    edge_tts.Communicate(
        text=scene.narration,
        voice="en-US-AriaNeural",  # Or other voices
        rate="+0%",
        volume="+0%"
    ).save(f"{scene_id}.mp3")

    # 3. Measure ACTUAL audio duration
    actual_duration = get_audio_duration(audio_file)

    # 4. Calculate final scene duration
    scene.final_duration = max(
        scene.min_duration,           # Minimum time
        actual_duration + 1.0          # Audio + 1s padding
    )
```

**Voice Options:**
- `male`: en-US-BrianNeural
- `male_warm`: en-US-ChristopherNeural
- `female`: en-US-AriaNeural
- `female_friendly`: en-US-JennyNeural

**Timing Report Generated:**
```json
{
  "video_id": "my_video",
  "total_duration": 45.7,
  "scenes": [
    {
      "scene_id": "scene_01",
      "audio_duration": 5.2,
      "final_duration": 6.2,
      "audio_file": "scene_01.mp3"
    }
  ]
}
```

**Output:** Audio files + timing report (JSON)

---

### Stage 5: Video Generation

**Module:** `video_gen/stages/video_generation_stage.py`
**Engine:** `video_gen/video_generator/unified.py`

**Process:**

#### Frame Rendering (PIL-based templates)
```python
# For each scene, create keyframes:
1. Start frame (0% animation)
2. End frame (100% animation)

# Example for Title Scene:
- Badge animation (slides down)
- Title fade-in with underline
- Subtitle appearance
```

#### Interpolation & Animation
```python
# Generate intermediate frames:
for frame in range(total_frames):
    progress = ease_out_cubic(frame / total_frames)
    current_frame = blend_frames(
        start_frame,
        end_frame,
        progress
    )
```

#### Frame Timing (Audio-Driven)
```python
# Each scene gets exact frames based on audio:
scene_frames = int(scene.final_duration * FPS)

# Breakdown:
- Transition in: 0.5s (15 frames)
- Animation: 1.0s (30 frames)
- Hold: remaining time
- Transition out: 0.5s (15 frames)
```

#### Rendering Pipeline
```python
# 1. Render frames to temp directory
for scene in scenes:
    render_scene_frames(scene, timing_report)

# 2. Encode video with FFmpeg
ffmpeg -r 30 -i frame_%05d.png \
       -c:v h264_nvenc \       # GPU encoding
       -preset p4 \            # Quality preset
       -crf 23 \               # Visual quality
       temp_video.mp4

# 3. Mux with audio
ffmpeg -i temp_video.mp4 \
       -i audio_combined.mp3 \
       -c:v copy -c:a aac \
       final_video.mp4
```

**Optimizations:**
- **NumPy blending**: 10x faster than PIL
- **GPU encoding**: 5-10x faster with NVENC
- **Parallel processing**: 2.25x speedup for batches
- **Smart caching**: Reuse common frames

**Output:** Final MP4 video file

---

### Stage 6: Output & Delivery

**Module:** `video_gen/stages/output_stage.py`

**Process:**
1. **File Organization**
   ```
   output/
   ├── video_id/
   │   ├── final_video.mp4
   │   ├── timing_report.json
   │   ├── metadata.json
   │   └── audio/
   │       └── *.mp3
   ```

2. **Metadata Generation**
   ```json
   {
     "video_id": "my_video",
     "title": "Getting Started Guide",
     "duration": 45.7,
     "resolution": "1920x1080",
     "fps": 30,
     "codec": "h264",
     "scenes": 5,
     "generated_at": "2025-11-27T10:30:00Z"
   }
   ```

3. **Delivery Options**
   - Local file system
   - Web UI streaming
   - API response
   - Cloud storage (S3/GCS)

**Output:** Organized video package

---

## 🎬 Scene Types & Renderers

The system supports **12 scene types** with specialized renderers:

### Basic Scenes (`renderers/basic_scenes.py`)
1. **Title** - Opening cards with badge animation
2. **Command** - Terminal-style code display
3. **List** - Numbered/bulleted items
4. **Outro** - Closing with call-to-action

### Educational Scenes (`renderers/educational_scenes.py`)
5. **Learning Objectives** - Goals and outcomes
6. **Problem** - Challenge presentation
7. **Solution** - Answer reveal
8. **Quiz** - Interactive questions
9. **Exercise** - Practice activities

### Comparison Scenes (`renderers/comparison_scenes.py`)
10. **Code Comparison** - Side-by-side code
11. **Quote** - Testimonials and citations

### Progress Scenes (`renderers/checkpoint_scenes.py`)
12. **Checkpoint** - Progress indicators

---

## 🔄 Data Flow & Transformations

```
1. Raw Input (any format)
   ↓
2. VideoConfig (normalized)
   ├── title: str
   ├── scenes: List[Scene]
   └── config: Dict
   ↓
3. Scene + Narration
   ├── visual_content: Dict
   ├── narration: str
   └── voice: str
   ↓
4. Scene + Audio
   ├── audio_file: Path
   ├── audio_duration: float
   └── final_duration: float
   ↓
5. Rendered Frames
   ├── frame_000001.png
   ├── frame_000002.png
   └── ...
   ↓
6. Final Video (MP4)
   ├── video_track: h264
   ├── audio_track: aac
   └── metadata: json
```

---

## ⚡ Performance Characteristics

| Stage | Duration | Bottleneck | Optimization |
|-------|----------|------------|--------------|
| Input | <1s | File I/O | Async loading |
| Parse | <1s | Regex | Compiled patterns |
| Script | 1-5s | AI API calls | Template fallback |
| Audio | 5-10s | TTS synthesis | Voice caching |
| Video | 20-30s | Frame rendering | NumPy + GPU |
| Output | <2s | File writing | Async I/O |

**Total Time:** ~40 seconds for 1-minute video

---

## 🚀 Execution Examples

### CLI Workflow
```bash
# Simple generation
python create_video.py --document README.md --voice female

# AI-enhanced with custom duration
python create_video.py --document guide.md --use-ai --duration 90

# From YouTube with accent color
python create_video.py --youtube "python tutorial" --accent-color blue
```

### Programmatic Workflow
```python
from video_gen import ProgrammaticAdapter, VideoConfig, Scene

# Create configuration
config = VideoConfig(
    title="My Video",
    scenes=[
        Scene(type="title", content={"title": "Welcome"}),
        Scene(type="list", content={"items": ["Item 1", "Item 2"]})
    ]
)

# Generate video
adapter = ProgrammaticAdapter()
result = adapter.adapt(config)
video_path = result.video_path
```

### Web UI Workflow
```python
# POST /api/generate
{
  "input_type": "document",
  "source": "README.md",
  "use_ai": true,
  "voice": "female",
  "language": "es"
}

# Response includes SSE for progress tracking
```

---

## 🔧 Configuration & Customization

### Environment Variables
```bash
ANTHROPIC_API_KEY=sk-xxx        # For AI narration
FFMPEG_PATH=/usr/local/bin/ffmpeg
VIDEO_OUTPUT_DIR=./output
AUDIO_OUTPUT_DIR=./audio
LOG_LEVEL=INFO
```

### Voice Configuration
```python
VOICE_MAP = {
    "male": "en-US-BrianNeural",
    "female": "en-US-AriaNeural",
    "es": "es-ES-AlvaroNeural",
    "fr": "fr-FR-HenriNeural",
    # ... 28+ languages
}
```

### Scene Timing
```python
DEFAULT_TIMING = {
    "min_duration": 3.0,    # Minimum scene time
    "max_duration": 30.0,   # Maximum scene time
    "padding": 1.0,         # Audio padding
    "transition": 0.5,      # Transition duration
    "animation": 1.0        # Animation duration
}
```

---

## 📊 Production Metrics

- **Test Coverage:** 79% (475 tests passing)
- **Performance:** 40s for 1-minute video
- **Languages:** 28+ with native TTS
- **Scene Types:** 12 specialized renderers
- **Voice Options:** 4 professional voices
- **GPU Speedup:** 5-10x with NVENC
- **Batch Processing:** 2.25x parallel speedup

---

## 🎯 Summary

The video generation workflow is a sophisticated pipeline that:

1. **Accepts any input format** through specialized adapters
2. **Generates narration** using templates or AI
3. **Creates audio first** to establish timing
4. **Renders video frames** to match audio duration
5. **Delivers professional videos** with perfect sync

The **audio-first architecture** is the key innovation that ensures perfect synchronization between narration and visuals, making this system production-ready for professional video generation.

---

*Generated by Video Gen Workflow Analysis*
*Last Updated: November 27, 2025*