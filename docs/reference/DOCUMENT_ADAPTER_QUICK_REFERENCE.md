# Document Adapter - Quick Reference

## Quick Start

```python
from video_gen.input_adapters.document import DocumentAdapter

adapter = DocumentAdapter()

# Generate video set from markdown
result = await adapter.adapt('README.md')

if result.success:
    video_set = result.video_set
    print(f"Generated {len(video_set.videos)} videos")
```

## Configuration Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `split_by_h2` | bool | `True` | Split into multiple videos by ## headings |
| `max_scenes_per_video` | int | `8` | Maximum scenes per video (includes title/outro) |
| `accent_color` | str | `'blue'` | Visual theme color |
| `voice` | str | `'male'` | Voice for narration |

## Supported Features

### Markdown Elements

| Element | Support | Scene Type | Notes |
|---------|---------|------------|-------|
| Headings (#-######) | ✅ | Various | ## creates new videos if split_by_h2=True |
| Bullet Lists | ✅ | `list` | Up to 3 levels of nesting |
| Numbered Lists | ✅ | `list` | With nesting support |
| Code Blocks | ✅ | `command` | All languages supported |
| Tables | ✅ | `comparison` | Basic markdown tables |
| Links | ✅ | - | Extracted to metadata |
| Images | ⚠️ | - | Planned for future |
| Bold/Italic | ⚠️ | - | Preserved in text |

### File Formats

| Format | Extension | Status |
|--------|-----------|--------|
| Markdown | `.md` | ✅ Full support |
| Text | `.txt` | ✅ Full support |
| PDF | `.pdf` | 🔜 Planned |
| DOCX | `.docx` | 🔜 Planned |

## Scene Types Generated

| Scene Type | Trigger | Description |
|------------|---------|-------------|
| `title` | Document start | First scene with title/subtitle |
| `list` | Bullet/numbered lists or text | List of items |
| `command` | Code blocks | Commands/code snippets |
| `comparison` | Tables | Comparison table data |
| `outro` | Document end | Closing scene |

## Common Patterns

### Single Video from Markdown
```python
result = await adapter.adapt(
    'docs.md',
    split_by_h2=False  # Keep as one video
)
```

### Multiple Videos (Split by Sections)
```python
result = await adapter.adapt(
    'docs.md',
    split_by_h2=True,  # One video per ## heading
    max_scenes_per_video=10
)
```

### Custom Styling
```python
result = await adapter.adapt(
    'docs.md',
    accent_color='purple',
    voice='female'
)
```

### From URL
```python
result = await adapter.adapt(
    'https://raw.githubusercontent.com/user/repo/main/README.md'
)
```

## Result Structure

```python
class InputAdapterResult:
    success: bool           # True if parsing succeeded
    video_set: VideoSet     # Generated video set (if successful)
    error: str              # Error message (if failed)
    metadata: dict          # Additional metadata
        - source: str       # Source file/URL
        - sections_found: int
        - videos_generated: int
        - video_count: int
        - total_sections: int
```

## Error Handling

```python
result = await adapter.adapt('document.md')

if not result.success:
    print(f"Error: {result.error}")
    # Handle error
else:
    # Process video_set
    pass
```

## Metadata Access

```python
result = await adapter.adapt('doc.md')

if result.success:
    metadata = result.metadata
    print(f"Source: {metadata['source']}")
    print(f"Sections: {metadata['sections_found']}")
    print(f"Videos: {metadata['videos_generated']}")
```

## Export Options

### Export to YAML
```python
video_set = result.video_set
output_dir = video_set.export_to_yaml('output/')

# Creates:
# output/
#   set_config.yaml
#   video1.yaml
#   video2.yaml
#   ...
```

### Access Video Data
```python
for video in video_set.videos:
    print(f"Video ID: {video.video_id}")
    print(f"Title: {video.title}")
    print(f"Scenes: {len(video.scenes)}")

    for scene in video.scenes:
        print(f"  {scene.scene_type}: {scene.narration}")
```

## Edge Cases Handled

- Empty documents → Creates minimal video with overview
- Missing sections → Creates default sections
- Malformed markdown → Parses available content
- Unclosed code blocks → Handles gracefully
- Empty sections → Skips or creates placeholder
- Links in headings → Extracts and stores
- Nested lists → Flattens intelligently
- Mixed list types → Combines properly

## Performance

| Document Size | Parse Time | Memory |
|---------------|------------|--------|
| Small (<100 lines) | <50ms | Minimal |
| Medium (100-500) | 50-150ms | Low |
| Large (500+) | 150-400ms | Moderate |

## Testing

```bash
# Run all tests
pytest tests/test_document_adapter_enhanced.py -v

# Run specific test class
pytest tests/test_document_adapter_enhanced.py::TestDocumentAdapterEdgeCases -v

# Run demo
python tests/demo_document_adapter.py
```

## Examples

### Example 1: Basic README
```markdown
# My Project

## Installation
```bash
npm install
```

## Features
- Fast
- Easy
- Secure
```

**Result**: 1 video with 4 scenes (title, installation, features, outro)

### Example 2: Documentation with Sections
```markdown
# Documentation

## Getting Started
Introduction text...

## API Reference
API documentation...

## Examples
Code examples...
```

**Result** (split_by_h2=True): 3 videos
- Video 1: Getting Started
- Video 2: API Reference
- Video 3: Examples

### Example 3: With Tables
```markdown
# Comparison

## Features

| Feature | Plan A | Plan B |
|---------|--------|--------|
| Users   | 1      | 10     |
| Storage | 1GB    | 100GB  |
```

**Result**: Comparison scene with table data

## Tips

1. **Use ## headings** for logical video splits
2. **Keep sections focused** (6-10 scenes optimal)
3. **Code blocks** work best with 4-8 lines
4. **Lists** should have 3-5 items
5. **Tables** limited to 3-4 rows for best display
6. **Test with demo** script before production use

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Empty result | Check file exists and has content |
| Too many videos | Set `split_by_h2=False` |
| Scenes cut off | Increase `max_scenes_per_video` |
| Missing code blocks | Ensure proper \`\`\` markers |
| Tables not parsed | Check markdown table syntax |

## Support

- See full documentation: `docs/DOCUMENT_ADAPTER_ENHANCEMENTS.md`
- Run demo: `python tests/demo_document_adapter.py`
- Tests: `tests/test_document_adapter_enhanced.py`

---

*Quick Reference v1.0 - 2025-10-05*
