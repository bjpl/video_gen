# Input Adapters

Unified input parsing system for video generation.

## Overview

All input types (documents, YouTube videos, YAML files, etc.) are parsed into a common `VideoSet` format, making it easy to work with any input source using a consistent API.

## Quick Start

```python
from app.input_adapters import DocumentAdapter

# Parse a markdown document
adapter = DocumentAdapter()
video_set = adapter.parse('README.md')

# Export to YAML for video generation
video_set.export_to_yaml('output/my_set')
```

## Available Adapters

| Adapter | Input Type | Use Case |
|---------|-----------|----------|
| `DocumentAdapter` | Markdown, text, URLs | Documentation, READMEs |
| `YouTubeAdapter` | YouTube URLs/IDs | Video transcripts |
| `YAMLAdapter` | YAML files | Configuration files |
| `ProgrammaticAdapter` | Python code/dicts | Programmatic creation |
| `WizardAdapter` | Interactive data | Wizard integration |

## Installation

```bash
# Core functionality
pip install pyyaml

# YouTube support
pip install youtube-transcript-api

# AI narration (optional)
pip install anthropic
```

## Examples

### Document Parsing
```python
from app.input_adapters import DocumentAdapter

adapter = DocumentAdapter(max_scenes=8)
video_set = adapter.parse(
    'https://github.com/user/repo/blob/main/README.md',
    accent_color='blue',
    voice='male'
)
video_set.export_to_yaml('output/readme_set')
```

### YouTube Parsing
```python
from app.input_adapters import YouTubeAdapter

adapter = YouTubeAdapter(target_duration=90)
video_set = adapter.parse('https://youtube.com/watch?v=VIDEO_ID')
video_set.export_to_yaml('output/youtube_set')
```

### YAML Parsing
```python
from app.input_adapters import YAMLAdapter

adapter = YAMLAdapter(generate_narration=True)
video_set = adapter.parse('inputs/video.yaml')
```

### Programmatic Creation
```python
from app.input_adapters import (
    ProgrammaticAdapter,
    create_title_scene,
    create_list_scene
)

adapter = ProgrammaticAdapter()
video_set = adapter.create_from_dict({
    'set': {
        'id': 'my_set',
        'name': 'My Video Set',
        'defaults': {'accent_color': 'purple'}
    },
    'videos': [{
        'video_id': 'intro',
        'title': 'Introduction',
        'scenes': [
            create_title_scene('Hello', 'World'),
            create_list_scene('Features', 'Overview', ['Fast', 'Easy', 'Free'])
        ]
    }]
})
```

### Factory Pattern
```python
from app.input_adapters import get_adapter

# Get any adapter by type
adapter = get_adapter('document', max_scenes=10)
video_set = adapter.parse('guide.md')
```

## Architecture

```
Input Source → Adapter.parse() → VideoSet → export_to_yaml() → YAML Files
```

All adapters:
- Inherit from `BaseInputAdapter`
- Implement `parse(source, **options) -> VideoSet`
- Return standardized `VideoSet` objects
- Export to YAML compatible with existing pipeline

## VideoSet Structure

```python
VideoSet
├── config: VideoSetConfig
│   ├── set_id: str
│   ├── set_name: str
│   ├── defaults: Dict
│   └── output: Dict
└── videos: List[VideoConfig]
    └── scenes: List[Dict]
```

## Custom Adapters

Create custom adapters by inheriting from `BaseInputAdapter`:

```python
from app.input_adapters import BaseInputAdapter, VideoSet, VideoConfig

class MyAdapter(BaseInputAdapter):
    def parse(self, source: str, **options) -> VideoSet:
        # 1. Read input
        data = self._read_source(source)

        # 2. Create scenes
        scenes = [
            self.create_scene('title', {'title': 'Hi', 'subtitle': 'World'})
        ]

        # 3. Create video
        video = VideoConfig(
            video_id='my_video',
            title='My Video',
            scenes=scenes
        )

        # 4. Return set
        return self.create_video_set(
            set_id='my_set',
            set_name='My Set',
            videos=[video]
        )
```

## Testing

```bash
# Run all tests
pytest tests/test_input_adapters.py -v

# Run specific adapter tests
pytest tests/test_input_adapters.py::TestDocumentAdapter -v

# Run examples
python -m app.input_adapters.examples
```

## Documentation

- **Full Guide**: `docs/INPUT_ADAPTERS.md`
- **Quick Reference**: `docs/INPUT_ADAPTERS_QUICK_REF.md`
- **Implementation Summary**: `docs/INPUT_ADAPTERS_IMPLEMENTATION_SUMMARY.md`

## API Integration

```python
from fastapi import FastAPI
from app.input_adapters import get_adapter

app = FastAPI()

@app.post("/api/parse")
async def parse_input(input_type: str, source: str):
    adapter = get_adapter(input_type)
    video_set = adapter.parse(source)
    return video_set.to_dict()
```

## Files

```
app/input_adapters/
├── __init__.py          # Exports and factory
├── base.py              # Base classes
├── document.py          # Document parsing
├── youtube.py           # YouTube parsing
├── yaml_file.py         # YAML parsing
├── programmatic.py      # Programmatic creation
├── wizard.py            # Wizard integration
├── examples.py          # Usage examples
└── README.md            # This file
```

## Features

✅ Unified interface across all input types
✅ Type-safe with dataclasses
✅ Comprehensive test coverage (17/17 tests passing)
✅ Export to YAML for existing pipeline
✅ Factory pattern for dynamic adapter loading
✅ Extensible architecture for new adapters
✅ Production-ready error handling
✅ Complete documentation

## License

Part of the video_gen project.
