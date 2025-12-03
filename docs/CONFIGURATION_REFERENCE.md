# Configuration Reference - Video Generation System

Complete reference for all configuration options, environment variables, and settings.

## Table of Contents

- [Environment Variables](#environment-variables)
- [YAML Configuration](#yaml-configuration)
- [Runtime Configuration](#runtime-configuration)
- [Advanced Settings](#advanced-settings)
- [Performance Tuning](#performance-tuning)

---

## Environment Variables

### Application Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ENVIRONMENT` | string | `development` | Environment mode: `development`, `staging`, `production` |
| `PORT` | integer | `8000` | HTTP server port |
| `LOG_LEVEL` | string | `INFO` | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `DEBUG` | boolean | `false` | Enable debug mode (never use in production) |

### AI Integration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ANTHROPIC_API_KEY` | string | `` | Anthropic API key for AI-enhanced narration |
| `CLAUDE_MODEL` | string | `claude-3-5-sonnet-20241022` | Claude model version |
| `OPENAI_API_KEY` | string | `` | OpenAI API key (alternative provider) |

### Performance

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `GPU_ENABLED` | boolean | `true` | Enable GPU acceleration (requires NVIDIA NVENC) |
| `PARALLEL_PROCESSING` | boolean | `true` | Enable parallel scene processing |
| `MAX_WORKERS` | integer | `0` | Maximum parallel workers (0 = auto-detect) |
| `QUALITY_PRESET` | string | `standard` | Quality preset: `draft`, `standard`, `high`, `ultra` |

### Paths

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `OUTPUT_DIR` | string | `outputs` | Base output directory |
| `CACHE_DIR` | string | `cache` | Cache directory for audio and frames |
| `INPUT_DIR` | string | `inputs` | Input files directory |
| `LOG_DIR` | string | `logs` | Log files directory |
| `FFMPEG_PATH` | string | `` | Custom FFmpeg binary path (empty = auto-detect) |

### Video Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `VIDEO_WIDTH` | integer | `1920` | Video width in pixels |
| `VIDEO_HEIGHT` | integer | `1080` | Video height in pixels |
| `VIDEO_FPS` | integer | `30` | Video framerate |
| `DEFAULT_VOICE` | string | `male` | Default TTS voice: `male`, `male_warm`, `female`, `female_friendly` |
| `DEFAULT_ACCENT_COLOR` | string | `blue` | Default theme color: `blue`, `purple`, `green`, `orange`, `red` |
| `DEFAULT_LANGUAGE` | string | `en` | Default language (ISO 639-1 code) |

### Audio Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `AUDIO_SAMPLE_RATE` | integer | `44100` | Audio sample rate in Hz |
| `AUDIO_BITRATE` | integer | `128` | Audio bitrate in kbps |

### FFmpeg Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `VIDEO_CODEC` | string | `h264_nvenc` | Video codec (GPU): `h264_nvenc`, `hevc_nvenc` |
| `FALLBACK_CODEC` | string | `libx264` | Fallback codec (CPU): `libx264`, `libx265` |
| `VIDEO_BITRATE` | integer | `8` | Video bitrate in Mbps |
| `ENCODING_PRESET` | string | `fast` | Encoding preset: `ultrafast`, `superfast`, `veryfast`, `faster`, `fast`, `medium`, `slow` |

### Content Parsing

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MAX_SCENES` | integer | `20` | Maximum scenes per video |
| `TARGET_DURATION` | integer | `120` | Target duration for auto-generated videos (seconds) |
| `YOUTUBE_LANGUAGE` | string | `en` | YouTube transcript language preference |

### Rate Limiting (Multi-User)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RATE_LIMIT_PER_MINUTE` | integer | `10` | API requests per minute per user |
| `MAX_CONCURRENT_JOBS` | integer | `3` | Maximum concurrent jobs per user |

### Database (Multi-User)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DATABASE_URL` | string | `` | PostgreSQL connection URL |

### Redis (Job Queue)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `REDIS_URL` | string | `` | Redis connection URL for job queue |

### Security

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECRET_KEY` | string | `` | Secret key for session encryption |
| `CORS_ORIGINS` | string | `` | CORS allowed origins (comma-separated) |

### Monitoring

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `METRICS_ENABLED` | boolean | `true` | Enable metrics collection |
| `METRICS_INTERVAL` | integer | `60` | Metrics export interval (seconds) |
| `SENTRY_DSN` | string | `` | Sentry DSN for error tracking |

---

## YAML Configuration

### Video Configuration Structure

```yaml
video:
  title: "Video Title"                    # Required
  accent_color: "blue"                    # Optional: blue, purple, green, orange, red
  use_ai_narration: false                 # Optional: use AI for narration
  target_language: "en"                   # Optional: ISO 639-1 language code

scenes:
  - type: title                           # Required
    title: "Scene Title"                  # Required for most types
    # ... scene-specific fields
```

### Scene Types Reference

#### Title Scene

```yaml
- type: title
  title: "Main Title"                     # Required
  subtitle: "Subtitle text"               # Optional
  key_message: "Key point"                # Optional
  voice: "male"                           # Optional: male, male_warm, female, female_friendly
```

#### Command Scene

```yaml
- type: command
  title: "Command Title"                  # Required
  description: "Command description"       # Optional
  commands:                               # Required (1-5 commands)
    - "$ command one"
    - "$ command two"
  voice: "female"                         # Optional
```

#### List Scene

```yaml
- type: list
  header: "List Header"                   # Required
  items:                                  # Required (1-5 items)
    - "First item"
    - "Second item"
    - "Third item"
  voice: "male_warm"                      # Optional
```

#### Code Comparison Scene

```yaml
- type: code_comparison
  title: "Comparison Title"               # Required
  before_code: "# Old code"               # Required
  after_code: "# New code"                # Required
  before_label: "Before"                  # Optional (default: "Before")
  after_label: "After"                    # Optional (default: "After")
  voice: "female_friendly"                # Optional
```

#### Quote Scene

```yaml
- type: quote
  quote_text: "Quote text here"           # Required
  author: "Author Name"                   # Optional
  voice: "male"                           # Optional
```

#### Outro Scene

```yaml
- type: outro
  main_text: "Thank You"                  # Required
  sub_text: "Subscribe for more"          # Optional
  voice: "female"                         # Optional
```

#### Educational Scenes

```yaml
# Learning Objectives
- type: learning_objectives
  title: "Learning Objectives"
  objectives:                             # Required (1-4 items)
    - "Understand X"
    - "Learn Y"

# Problem Scene
- type: problem
  title: "Problem"
  problem_text: "Description of problem"  # Required

# Solution Scene
- type: solution
  title: "Solution"
  solution_text: "Description of solution"  # Required

# Quiz Scene
- type: quiz
  question: "Question text?"              # Required
  options:                                # Required (2-4 options)
    - "Option A"
    - "Option B"
  correct_answer: 0                       # Required (0-indexed)

# Checkpoint Scene
- type: checkpoint
  title: "Checkpoint"
  checkpoint_text: "Review what we learned"  # Required

# Exercise Scene
- type: exercise
  title: "Exercise"
  instructions: "Complete this task"      # Required
```

### Complete Example

```yaml
video:
  title: "Complete Tutorial"
  accent_color: "purple"
  use_ai_narration: true
  target_language: "en"

scenes:
  - type: title
    title: "Introduction"
    subtitle: "Getting Started"
    key_message: "Learn the basics"
    voice: "male"

  - type: learning_objectives
    title: "What You'll Learn"
    objectives:
      - "Understand core concepts"
      - "Build your first project"
      - "Deploy to production"

  - type: command
    title: "Installation"
    description: "Set up your environment"
    commands:
      - "$ pip install -r requirements.txt"
      - "$ python setup.py"
    voice: "female"

  - type: code_comparison
    title: "Before and After"
    before_code: |
      # Old approach
      result = []
      for item in items:
          if condition:
              result.append(item)
    after_code: |
      # New approach
      result = [item for item in items if condition]
    before_label: "Imperative"
    after_label: "Pythonic"

  - type: problem
    title: "Common Challenge"
    problem_text: "How do we handle errors gracefully?"

  - type: solution
    title: "Error Handling"
    solution_text: "Use try-except blocks with specific exceptions"

  - type: quiz
    question: "What's the best way to handle multiple exceptions?"
    options:
      - "Multiple except blocks"
      - "Single except block catching all"
      - "No error handling"
    correct_answer: 0

  - type: checkpoint
    title: "Progress Check"
    checkpoint_text: "You now understand error handling basics"

  - type: exercise
    title: "Practice"
    instructions: "Refactor your code to include proper error handling"

  - type: outro
    main_text: "Great Job!"
    sub_text: "Continue to the next lesson"
```

---

## Runtime Configuration

### CLI Arguments

```bash
# create_video.py arguments
python scripts/create_video.py [OPTIONS]

Options:
  --yaml PATH                 YAML input file path
  --document PATH             Document file path (markdown)
  --youtube-url URL           YouTube video URL
  --wizard                    Interactive wizard mode
  --use-ai                    Enable AI-enhanced narration
  --voice VOICE               Voice: male, male_warm, female, female_friendly
  --color COLOR               Accent color: blue, purple, green, orange, red
  --language LANG             Target language (ISO 639-1)
  --duration SECONDS          Target duration for YouTube summaries
  --output-dir PATH           Custom output directory
  --verbose                   Enable verbose logging
  --help                      Show help message
```

### Programmatic API

```python
from video_gen.pipeline import VideoPipeline

# Create pipeline with custom config
pipeline = VideoPipeline(
    config={
        'gpu_enabled': True,
        'parallel_processing': True,
        'quality_preset': 'high',
        'output_dir': 'custom_output'
    }
)

# Execute pipeline
result = pipeline.execute('input.yaml')
```

---

## Advanced Settings

### GPU Configuration

```python
# Force CPU encoding
os.environ['GPU_ENABLED'] = 'false'

# Custom GPU device
os.environ['CUDA_VISIBLE_DEVICES'] = '0'  # Use first GPU
```

### Custom FFmpeg Path

```bash
# Linux/macOS
export FFMPEG_PATH=/usr/local/bin/ffmpeg

# Windows
set FFMPEG_PATH=C:\ffmpeg\bin\ffmpeg.exe
```

### Memory Optimization

```python
# Reduce memory usage
os.environ['PARALLEL_PROCESSING'] = 'false'
os.environ['MAX_WORKERS'] = '1'
os.environ['QUALITY_PRESET'] = 'draft'
```

---

## Performance Tuning

### Quality Presets

#### Draft
- **Use case**: Testing, previews
- **Speed**: Fastest
- **Quality**: Lower
- **Settings**: Low bitrate, fast encoding preset

#### Standard (Default)
- **Use case**: General purpose
- **Speed**: Fast
- **Quality**: Good
- **Settings**: 8 Mbps, fast preset

#### High
- **Use case**: Publication, sharing
- **Speed**: Medium
- **Quality**: Excellent
- **Settings**: 12 Mbps, medium preset

#### Ultra
- **Use case**: Professional production
- **Speed**: Slow
- **Quality**: Maximum
- **Settings**: 20 Mbps, slow preset

### Custom Quality Configuration

```bash
# High quality, slow encoding
export QUALITY_PRESET=ultra
export VIDEO_BITRATE=20
export ENCODING_PRESET=slow

# Fast encoding, lower quality
export QUALITY_PRESET=draft
export VIDEO_BITRATE=4
export ENCODING_PRESET=ultrafast
```

### Parallel Processing

```bash
# Enable parallel processing (faster for multiple scenes)
export PARALLEL_PROCESSING=true
export MAX_WORKERS=4  # Use 4 CPU cores

# Disable for memory-constrained systems
export PARALLEL_PROCESSING=false
export MAX_WORKERS=1
```

---

## Configuration Best Practices

### Development

```bash
ENVIRONMENT=development
DEBUG=true
LOG_LEVEL=DEBUG
AUTO_RELOAD=true
SHOW_ERROR_DETAILS=true
QUALITY_PRESET=draft
```

### Staging

```bash
ENVIRONMENT=staging
DEBUG=false
LOG_LEVEL=INFO
QUALITY_PRESET=standard
METRICS_ENABLED=true
```

### Production

```bash
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=WARNING
SHOW_ERROR_DETAILS=false
QUALITY_PRESET=high
METRICS_ENABLED=true
SENTRY_DSN=your-sentry-dsn
SECRET_KEY=your-secure-secret-key
```

---

## Configuration Validation

### Validate Environment

```python
from video_gen.shared.config import Config

# Load and validate configuration
config = Config()
print(f"Environment: {config.environment}")
print(f"GPU Enabled: {config.gpu_enabled}")
print(f"Quality: {config.quality_preset}")
```

### Check FFmpeg

```bash
# Verify FFmpeg installation
ffmpeg -version

# Check for NVENC support
ffmpeg -encoders 2>&1 | grep nvenc

# Test encoding
ffmpeg -f lavfi -i testsrc=duration=1:size=1920x1080:rate=30 \
  -c:v h264_nvenc test_output.mp4
```

---

## Troubleshooting Configuration Issues

### "API key not set" error

```bash
# Check if variable is set
echo $ANTHROPIC_API_KEY

# Set temporarily
export ANTHROPIC_API_KEY="sk-ant-api03-..."

# Set permanently in .env file
echo "ANTHROPIC_API_KEY=sk-ant-api03-..." >> .env
```

### "FFmpeg not found" error

```bash
# Check FFmpeg path
which ffmpeg

# Set custom path
export FFMPEG_PATH=/usr/local/bin/ffmpeg
```

### "GPU encoding failed" error

```bash
# Check NVENC support
ffmpeg -encoders 2>&1 | grep nvenc

# If not available, disable GPU
export GPU_ENABLED=false
```

---

**Configuration reference complete!** See `.env.example` for all available options.

*Last Updated: November 27, 2025*
