# Modern Pipeline v2.0 - Complete Workflow Guide

## 🎯 Overview

The video generation system has been completely redesigned to use a modern, production-ready pipeline architecture. This guide explains the correct workflow and how to use all the features.

## 📋 Architecture

### Pipeline Stages (Automatic Execution)

The modern pipeline consists of 6 stages that execute automatically:

```
1. Input Stage         → Adapt various inputs to VideoConfig
2. Parsing Stage       → Parse and structure content
3. Script Generation   → Generate narration scripts
4. Audio Generation    → Generate TTS audio with timing
5. Video Generation    → Render video scenes
6. Output Stage        → Combine and export final video
```

### Key Components

```
video_gen/
├── pipeline/
│   ├── orchestrator.py           # Main pipeline orchestrator
│   ├── complete_pipeline.py      # Pre-configured 6-stage pipeline
│   ├── stage.py                  # Base stage class
│   ├── state_manager.py          # State persistence & recovery
│   └── events.py                 # Event system for tracking
│
├── shared/
│   ├── models.py                 # VideoConfig, SceneConfig, InputConfig
│   └── config.py                 # Configuration management
│
├── stages/                       # Individual pipeline stages
│   ├── input_stage.py
│   ├── parsing_stage.py
│   ├── script_generation_stage.py
│   ├── audio_generation_stage.py
│   ├── video_generation_stage.py
│   └── output_stage.py
│
└── scripts/                      # User-facing tools
    ├── create_video_auto.py      # CLI auto-orchestrator
    ├── create_from_template.py   # Template-based generation
    ├── python_set_builder.py     # Programmatic builder
    └── multilingual_builder.py   # Multilingual support
```

## 🚀 Three Ways to Generate Videos

### 1. Auto-Orchestrator (CLI)

**Best for:** Quick videos from documents or YouTube

```bash
cd scripts

# From document
python create_video_auto.py --from ../README.md --type document

# From YouTube
python create_video_auto.py --from "python tutorial" --type youtube

# Interactive wizard
python create_video_auto.py --type wizard

# With all options
python create_video_auto.py --from ../README.md --type document \
    --voice male_warm \
    --color purple \
    --duration 120 \
    --use-ai \
    --verbose
```

**Features:**
- ✅ Modern pipeline architecture
- ✅ Progress tracking with events
- ✅ State management (resume on failure)
- ✅ Verbose logging option
- ✅ Automatic error recovery

### 2. Template-Based Generation

**Best for:** Consistent, reusable video structures

```bash
cd scripts

# Use built-in template
python create_from_template.py --template tutorial
python create_from_template.py --template course
python create_from_template.py --template demo
python create_from_template.py --template multilingual

# List all templates
python create_from_template.py --list

# Use custom template script
python create_from_template.py --script ../my_template.py
```

**Built-in Templates:**

1. **Tutorial** (3 videos)
   - Introduction
   - Core Concepts
   - Practical Examples
   - Uses: title, list, outro scenes

2. **Course** (10 videos)
   - Full course structure
   - Learning objectives
   - Progressive lessons
   - Uses: learning_objectives scenes

3. **Demo** (1 video)
   - 30-second product demo
   - Quick setup guide
   - Uses: title, command, outro scenes

4. **Multilingual** (5 videos)
   - Global campaign
   - 5 languages (en, es, fr, de, ja)
   - Auto-translation support

### 3. Programmatic Builder (Python)

**Best for:** Dynamic content, databases, APIs

```python
from scripts.python_set_builder import VideoSetBuilder, SceneConfig

# Create builder
builder = VideoSetBuilder(
    set_id="my_series",
    set_name="My Video Series",
    defaults={
        'accent_color': 'blue',
        'voice': 'male',
        'target_duration': 120
    }
)

# Add videos programmatically
builder.add_video(
    video_id="intro",
    title="Introduction",
    scenes=[
        SceneConfig(
            scene_type='title',
            visual_content={'title': 'Welcome', 'subtitle': 'To My Series'},
            narration="Welcome to my video series.",
            min_duration=3.0,
            max_duration=6.0
        ),
        SceneConfig(
            scene_type='list',
            visual_content={
                'header': 'Topics Covered',
                'items': [
                    ('Topic 1', 'First topic'),
                    ('Topic 2', 'Second topic'),
                    ('Topic 3', 'Third topic')
                ]
            },
            narration="We'll cover three main topics in this series.",
            min_duration=8.0,
            max_duration=12.0
        )
    ]
)

# Export to YAML
builder.export_to_yaml("sets/my_series")

# Or generate directly
await builder.generate_set()
```

## 🎨 Scene Types Available

The modern pipeline supports 12 scene types:

### Basic Scenes
- `title` - Title card with main/subtitle
- `outro` - Closing scene
- `quote` - Quote or testimonial

### Educational Scenes
- `learning_objectives` - Course/lesson objectives
- `problem` - Problem statement
- `solution` - Solution explanation
- `checkpoint` - Progress check
- `quiz` - Quiz question
- `exercise` - Practice exercise

### Technical Scenes
- `command` - Terminal/code commands
- `code_comparison` - Before/after code
- `list` - Bulleted list

## 📊 Scene Configuration

Each scene has:

```python
SceneConfig(
    scene_id: str,              # Unique identifier
    scene_type: str,            # One of 12 types
    narration: str,             # TTS narration text
    visual_content: dict,       # Scene-specific content
    voice: str = "male",        # Voice selection
    min_duration: float = 3.0,  # Minimum scene length
    max_duration: float = 15.0  # Maximum scene length
)
```

## 🔄 Pipeline Execution Flow

### How It Works

1. **Input Configuration**
   ```python
   InputConfig(
       input_type='document',
       source='README.md',
       accent_color='blue',
       voice='male',
       languages=['en']
   )
   ```

2. **Pipeline Execution**
   ```python
   pipeline = create_complete_pipeline()
   result = await pipeline.execute(input_config)
   ```

3. **Result Object**
   ```python
   PipelineResult(
       success: bool,
       task_id: str,
       video_config: VideoConfig,
       video_path: Path,
       audio_dir: Path,
       timing_report: Path,
       total_duration: float,
       scene_count: int,
       generation_time: float,
       errors: List[str],
       warnings: List[str]
   )
   ```

### State Management

The pipeline automatically:
- ✅ Saves state after each stage
- ✅ Allows resuming from failures
- ✅ Tracks progress across stages
- ✅ Emits events for monitoring

```python
# Resume from last successful stage
result = await pipeline.execute(
    input_config,
    task_id="existing_task_id",
    resume=True
)

# Check task status
status = pipeline.get_status("task_id")
print(f"Progress: {status.overall_progress:.0%}")
print(f"Current stage: {status.current_stage}")
print(f"Completed: {status.get_completed_stages()}")
```

## 🎯 Best Practices

### 1. Use Templates for Consistency
```bash
# Good: Reusable template
python create_from_template.py --template tutorial

# Better: Custom template for your use case
python create_from_template.py --script my_custom_template.py
```

### 2. Programmatic for Dynamic Content
```python
# Generate from database
for product in db.query('SELECT * FROM products'):
    builder.add_video(
        video_id=f"product_{product.id}",
        title=product.name,
        scenes=[...]
    )
```

### 3. Use Verbose Mode for Debugging
```bash
python create_video_auto.py --from doc.md --type document --verbose
```

### 4. Leverage State Management
```bash
# If pipeline fails, resume from last stage
python create_video_auto.py --from doc.md --type document --resume
```

## 📁 Output Structure

```
output/
├── {task_id}/
│   ├── audio/
│   │   ├── scene_01.mp3
│   │   ├── scene_02.mp3
│   │   └── timings.json
│   ├── videos/
│   │   └── final_video.mp4
│   └── reports/
│       ├── timing_report.txt
│       └── generation_log.json
```

## 🔧 Configuration

### Global Config (`video_gen/shared/config.py`)
- Audio settings (TTS engine, voices)
- Video settings (resolution, fps)
- Output paths
- Default values

### Input Config (per video)
- Input type and source
- Visual preferences (color, voice)
- Language settings
- Output directory

## 🐛 Troubleshooting

### Pipeline Fails at Stage X
```bash
# Check verbose logs
python create_video_auto.py --from doc.md --type document --verbose

# Resume from last successful stage
# (pipeline saves state automatically)
```

### Scene Type Not Found
```python
# Use correct scene types from models.py
valid_types = [
    "title", "command", "list", "outro",
    "code_comparison", "quote",
    "learning_objectives", "problem",
    "solution", "checkpoint", "quiz", "exercise"
]
```

### Template Not Working
```bash
# List available templates
python create_from_template.py --list

# Check template script has 'builder' variable
# my_template.py must define:
# builder = VideoSetBuilder(...)
```

## 🚀 Migration from Old System

### Old Way (Deprecated)
```bash
# Old script with manual stages
python old_generate_video.py
python old_generate_audio.py
python old_combine.py
```

### New Way (Modern Pipeline)
```bash
# Single command, automatic pipeline
python create_video_auto.py --from doc.md --type document
```

### Old Python Builder
```python
# Old: Manual YAML creation
video_data = {...}
with open('video.yaml', 'w') as f:
    yaml.dump(video_data, f)
```

### New Python Builder
```python
# New: Programmatic builder
from scripts.python_set_builder import VideoSetBuilder

builder = VideoSetBuilder("my_id", "My Video")
builder.add_video(...)
builder.export_to_yaml("sets/my_id")
```

## 📚 Additional Resources

- **Pipeline Architecture**: `docs/architecture/PIPELINE_ARCHITECTURE.md`
- **Template System**: `docs/TEMPLATE_SYSTEM.md`
- **Scene Types**: `docs/NEW_SCENE_TYPES_GUIDE.md`
- **API Reference**: `docs/API_DESIGN.md`
- **Programmatic Guide**: `PROGRAMMATIC_GUIDE.md`

## ✅ Summary

**The Modern Pipeline v2.0 provides:**

1. ✅ **3 Generation Methods**: Auto-orchestrator, Templates, Programmatic
2. ✅ **6-Stage Pipeline**: Automatic execution with state management
3. ✅ **12 Scene Types**: Educational, technical, and basic scenes
4. ✅ **Template System**: Reusable structures with built-in templates
5. ✅ **Programmatic API**: Python builder for dynamic content
6. ✅ **State Management**: Resume from failures, progress tracking
7. ✅ **Event System**: Real-time monitoring and logging
8. ✅ **Error Recovery**: Intelligent retry and recovery logic

---

**Ready to start?**

```bash
# Quick test with template
cd scripts
python create_from_template.py --template tutorial

# Your own video
python create_video_auto.py --from ../README.md --type document
```
