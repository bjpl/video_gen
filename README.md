# Video Generation System

Professional video production from text content through automated workflows with neural text-to-speech narration and synchronized visual rendering.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Technical Overview](#technical-overview)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Overview

This system automates the creation of professional-quality tutorial and documentation videos. It processes various input formats (markdown documents, YouTube transcripts, YAML configurations) and generates Full HD videos with synchronized narration, visual elements, and transitions.

The architecture employs an audio-first approach to ensure perfect synchronization between narration and visual content, eliminating manual timing adjustments.

## Features

### Input Processing
- **Document Parsing**: Converts markdown and documentation into structured video content
- **YouTube Integration**: Extracts and summarizes video transcripts
- **Programmatic API**: Python interface for automated batch generation
- **Interactive Wizard**: Guided creation process for manual content development
- **Web Interface**: Browser-based visual editor for scene-by-scene control

### Content Generation
- **Multiple Scene Types**: 12 different scene templates including title cards, code blocks, comparisons, and educational formats
- **Neural TTS**: High-quality text-to-speech with 4 professional voice options
- **Multilingual Support**: Generate content in 28+ languages with automatic translation
- **AI Enhancement**: Optional Claude API integration for natural narration (template-based fallback available)

### Video Production
- **Audio-First Architecture**: Generates narration first, then builds video to match exact timings
- **GPU Acceleration**: NVIDIA NVENC hardware encoding for 5-10x performance improvement
- **Batch Processing**: Parallel generation of multiple videos with progress tracking
- **Automated Workflow**: End-to-end pipeline from content to finished video

## Technical Overview

### Architecture

**Stage-Based Pipeline**
- Input Stage: Processes YAML, documents, YouTube URLs, or programmatic inputs
- Parsing Stage: Extracts structure and validates scene definitions
- Script Generation: Creates narration (template-based or AI-enhanced)
- Audio Generation: Synthesizes speech and measures precise durations
- Video Generation: Renders frames to match audio timing exactly
- Validation Stage: Performs health checks and quality validation
- Output Stage: Exports final video with metrics

**Core Technologies**
- Video Processing: FFmpeg with NVENC GPU encoding
- Audio Synthesis: Edge-TTS neural voices
- AI Integration: Claude 3.5 Sonnet (optional)
- Rendering: NumPy for optimized frame operations
- Testing: Pytest with 79% coverage across 474 tests

**Performance Characteristics**
- Single video generation: ~5 minutes
- Batch processing: 2.25x speedup with parallel execution
- Frame rendering: 8x faster with NumPy optimizations
- Perfect audio/visual sync through manifest-based timing

## Installation

<details>
<summary>Installation Steps</summary>

### Prerequisites

- Python 3.10+
- FFmpeg with NVENC support (GPU encoding recommended)
- Internet connection (for Edge-TTS voice downloads)
- Optional: Anthropic API key for AI-enhanced narration

### Setup

```bash
# Clone repository
git clone <repository-url>
cd video_gen

# Install dependencies
pip install -r requirements.txt

# Download bundled fonts (for cross-platform support)
python scripts/download_fonts.py

# Verify fonts are available
python scripts/check_fonts.py

# Optional: Configure AI narration
export ANTHROPIC_API_KEY="sk-ant-api03-..."  # Linux/Mac
# OR
set ANTHROPIC_API_KEY=sk-ant-api03-...       # Windows CMD
# OR
$env:ANTHROPIC_API_KEY="sk-ant-api03-..."    # Windows PowerShell

# Verify installation
python scripts/create_video.py --help
```

### First Run

FFmpeg will download Edge-TTS voices (~50MB) on first execution. Subsequent runs use cached voices.

</details>

## Usage

### For Portfolio Review

This project demonstrates:

**Software Architecture**
- Modular stage-based pipeline design
- Event-driven progress tracking
- State persistence between pipeline stages
- Extensible renderer system

**Development Practices**
- Comprehensive test coverage (79%, 474 tests)
- Type-safe Python with full type hints
- Separation of concerns across 7 renderer modules
- Clear API boundaries and interfaces

**Performance Engineering**
- GPU-accelerated video encoding
- Vectorized NumPy operations
- Parallel batch processing
- Intelligent caching strategies

### Quick Start

**From Existing Documentation**
```bash
# Parse markdown into video
python scripts/create_video.py --document README.md

# Generate audio and video
cd scripts
python generate_all_videos_unified_v2.py
python generate_videos_from_timings_v3_simple.py
```

**From YouTube Video**
```bash
# Create summary video from YouTube content
python scripts/create_video.py --youtube-url "https://youtube.com/watch?v=VIDEO_ID" --duration 60
```

**Interactive Creation**
```bash
# Launch guided wizard
python scripts/create_video.py --wizard
```

**Programmatic Generation**
```python
# Parse markdown content
from scripts.document_to_programmatic import parse_document_to_set
parse_document_to_set('README.md')

# Or fetch GitHub repository README
from scripts.document_to_programmatic import github_readme_to_video
github_readme_to_video('https://github.com/user/repo').export_to_yaml('sets/project')

# Generate videos
# cd scripts
# python generate_video_set.py ../sets/project
# python generate_videos_from_set.py ../output/project
```

**Web Interface**
```bash
# Launch browser-based editor
cd app
python main.py
# Navigate to http://localhost:8000
```

## Project Structure

```
video_gen/
├── scripts/                         # Automation and entry points
│   ├── create_video.py             # Main CLI interface
│   ├── python_set_builder.py      # Programmatic video builder
│   ├── document_to_programmatic.py # Document parser
│   └── generate_all_videos_unified_v2.py  # Audio generation
│
├── video_gen/                       # Core library
│   ├── renderers/                  # Scene rendering modules
│   │   ├── basic_scenes.py         # General-purpose scenes
│   │   ├── educational_scenes.py   # Learning content
│   │   ├── comparison_scenes.py    # Before/after displays
│   │   └── checkpoint_scenes.py    # Progress markers
│   │
│   ├── stages/                      # Pipeline stages
│   │   ├── input_stage.py          # Input processing
│   │   ├── audio_generation_stage.py  # TTS synthesis
│   │   ├── video_generation_stage.py  # Frame rendering
│   │   └── validation_stage.py     # Quality checks
│   │
│   ├── pipeline/                    # Pipeline orchestration
│   │   ├── orchestrator.py         # Stage coordination
│   │   ├── events.py               # Event system
│   │   └── state_manager.py        # State persistence
│   │
│   └── shared/                      # Utilities
│       ├── models.py               # Data models
│       ├── config.py               # Configuration
│       └── utils.py                # Helper functions
│
├── app/                             # Web interface (FastAPI)
│   ├── main.py                     # API server
│   └── input_adapters/             # Input processors
│
├── tests/                           # Test suite (79% coverage)
│   ├── test_renderers.py           # Renderer tests
│   ├── test_stages_coverage.py     # Pipeline tests
│   └── test_integration_comprehensive.py  # E2E tests
│
├── docs/                            # Documentation (50+ guides)
│   ├── THREE_INPUT_METHODS_GUIDE.md
│   ├── PROGRAMMATIC_GUIDE.md
│   └── PRODUCTION_READINESS.md
│
└── inputs/                          # Example templates
    ├── example_simple.yaml
    └── example_advanced.yaml
```

## Development

### Code Quality

**Testing**
- 474 passing tests across 24 test files
- 79% overall code coverage
- Component coverage: 95-100% (renderers), 75-85% (pipeline stages)
- Integration tests for end-to-end workflows

**Architecture Improvements**
- Refactored 1,476-line monolith into 7 focused modules (~206 lines each)
- Migrated from print statements to structured logging
- Centralized configuration through singleton pattern
- Modular renderer system for easy extensibility

### Running Tests

```bash
# Full test suite (~18 seconds)
pytest

# With coverage report
pytest --cov=video_gen --cov-report=html

# Specific test file
pytest tests/test_renderers.py

# Watch mode during development
pytest --watch
```

### Scene Types

Mix 12 available scene types:
- `title` - Opening slides and section headers
- `command` - Terminal commands and code blocks
- `list` - Numbered or bulleted content
- `code_comparison` - Side-by-side before/after code
- `quote` - Centered quotes with attribution
- `outro` - Closing call-to-action
- Educational: `learning_objectives`, `problem`, `solution`, `quiz`, `checkpoint`, `exercise`

### Voice Options

Four professional neural TTS voices:
- `male` (Andrew) - Professional, confident tone
- `male_warm` (Brandon) - Warm, engaging delivery
- `female` (Aria) - Clear, crisp articulation
- `female_friendly` (Ava) - Friendly, approachable style

### Customization

```yaml
# Example scene configuration
scenes:
  - type: title
    title: "Getting Started"
    subtitle: "Quick installation guide"
    voice: male

  - type: command
    title: "Installation"
    commands:
      - "pip install -r requirements.txt"
      - "python scripts/create_video.py --help"
    voice: female
```

### Performance Optimization

**GPU Acceleration**
- Automatic NVIDIA NVENC detection
- 5-10x faster encoding vs CPU
- Fallback to CPU if GPU unavailable

**Batch Processing**
```bash
# Generate multiple videos in parallel
python scripts/generate_videos_from_timings_v3_optimized.py
# Utilizes all available CPU cores
```

**Caching**
- Audio files cached between runs
- Timing manifests persisted
- Regeneration skipped for unchanged content

## Contributing

Contributions are welcome. This system is designed for:
- Technical content creators
- Developer advocates
- Course creators
- Documentation teams

Areas open for contribution:
- New scene type templates
- Additional input format parsers
- Visual theme variations
- Narration generation improvements

Please ensure:
- Tests pass and maintain coverage
- Code follows existing style (Black formatting, type hints)
- Documentation is updated
- New features include examples

## License

MIT License - See LICENSE file for details.

---

**Repository**: https://github.com/bjpl/video_gen
**Documentation**: Complete index at `DOCUMENTATION_INDEX.md`

Built with Python, FFmpeg, Edge-TTS, and NumPy for automated professional video production.
