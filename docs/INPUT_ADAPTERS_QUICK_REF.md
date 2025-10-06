# Input Adapters - Quick Reference

## Import

```python
from app.input_adapters import (
    DocumentAdapter,
    YouTubeAdapter,
    YAMLAdapter,
    ProgrammaticAdapter,
    get_adapter
)
```

## Quick Start

### Document Parsing
```python
adapter = DocumentAdapter()
video_set = adapter.parse('README.md')
video_set.export_to_yaml('output/my_set')
```

### YouTube Parsing
```python
adapter = YouTubeAdapter()
video_set = adapter.parse('https://youtube.com/watch?v=VIDEO_ID')
video_set.export_to_yaml('output/youtube_set')
```

### YAML Parsing
```python
adapter = YAMLAdapter()
video_set = adapter.parse('inputs/video.yaml')
```

### Programmatic
```python
adapter = ProgrammaticAdapter()
video_set = adapter.create_from_dict({
    'set': {'id': 'my_set', 'name': 'My Set'},
    'videos': [...]
})
```

## Factory Pattern

```python
# Get any adapter by type
adapter = get_adapter('document', max_scenes=8)
adapter = get_adapter('youtube', target_duration=90)
adapter = get_adapter('yaml', generate_narration=True)
```

## Common Options

```python
video_set = adapter.parse(
    source,
    set_id='custom_id',
    set_name='Custom Name',
    accent_color='purple',      # orange, blue, purple, green, pink, cyan
    voice='female',             # male, female
    target_duration=90,
    max_scenes=8
)
```

## VideoSet Operations

```python
# Access data
video_set.config.set_id
video_set.config.defaults
video_set.videos[0].scenes

# Export
video_set.export_to_yaml('output/path')

# Convert
data = video_set.to_dict()
```

## Adapter-Specific Features

### DocumentAdapter
- **Parses**: Markdown, text, GitHub URLs
- **Detects**: Sections, code blocks, lists
- **Creates**: Title, command, list, outro scenes

### YouTubeAdapter
- **Requires**: `pip install youtube-transcript-api`
- **Parses**: Video transcripts
- **Detects**: Commands, key points, segments
- **Creates**: Summary scenes from transcript

### YAMLAdapter
- **Parses**: Single videos or sets
- **Features**: Narration generation (optional)
- **Validates**: Scene structure

### ProgrammaticAdapter
- **Integrates**: VideoSetBuilder
- **Supports**: Python files, dicts, builders
- **Features**: Helper functions for scenes

## Scene Creation Helpers

```python
from app.input_adapters import (
    create_title_scene,
    create_command_scene,
    create_list_scene,
    create_outro_scene
)

scenes = [
    create_title_scene('Title', 'Subtitle'),
    create_command_scene('Header', 'Desc', ['$ cmd1', '$ cmd2']),
    create_list_scene('Header', 'Desc', ['Item 1', 'Item 2']),
    create_outro_scene('Thanks', 'Goodbye')
]
```

## Error Handling

```python
try:
    video_set = adapter.parse(source)
except FileNotFoundError:
    print("File not found")
except ValueError as e:
    print(f"Invalid input: {e}")
except ImportError as e:
    print(f"Missing dependency: {e}")
```

## Testing

```bash
# Run all tests
pytest tests/test_input_adapters.py -v

# Run specific adapter
pytest tests/test_input_adapters.py::TestDocumentAdapter -v

# With coverage
pytest tests/test_input_adapters.py --cov=app.input_adapters
```

## Complete Workflow

```python
# 1. Choose adapter
from app.input_adapters import get_adapter

adapter = get_adapter('document')

# 2. Parse input
video_set = adapter.parse(
    'README.md',
    accent_color='blue',
    voice='male'
)

# 3. Export to YAML
output_path = video_set.export_to_yaml('sets/my_set')

# 4. Generate videos
from scripts.generate_video_set import VideoSet as VSGen

generator = VSGen(output_path)
await generator.generate_set()
```

## Migration Guide

### Old Way
```python
from generate_script_from_document import generate_yaml_from_document
yaml_file = generate_yaml_from_document('README.md')
```

### New Way
```python
from app.input_adapters import DocumentAdapter
adapter = DocumentAdapter()
video_set = adapter.parse('README.md')
video_set.export_to_yaml('output/my_set')
```

## API Integration

```python
from fastapi import FastAPI
from app.input_adapters import get_adapter

app = FastAPI()

@app.post("/parse")
async def parse_input(input_type: str, source: str):
    adapter = get_adapter(input_type)
    video_set = adapter.parse(source)
    return video_set.to_dict()
```

## Custom Adapter Template

```python
from app.input_adapters import BaseInputAdapter, VideoSet, VideoConfig

class MyAdapter(BaseInputAdapter):
    def parse(self, source: str, **options) -> VideoSet:
        # 1. Read input
        content = self._read(source)

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

## Summary

| Adapter | Use Case | Input | Requires |
|---------|----------|-------|----------|
| **Document** | Markdown/text | Files, URLs | - |
| **YouTube** | Video transcripts | URLs, video IDs | youtube-transcript-api |
| **YAML** | Config files | .yaml files | - |
| **Programmatic** | Python code | .py files, dicts, builders | - |
| **Wizard** | Interactive | Wizard data | - |

All adapters:
- ✅ Return `VideoSet` objects
- ✅ Support custom options
- ✅ Export to YAML
- ✅ Full test coverage
- ✅ Consistent API
