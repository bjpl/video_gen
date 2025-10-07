# YouTube Adapter - Quick Reference

## Installation

```bash
pip install youtube-transcript-api
```

## Basic Usage

```python
from video_gen.input_adapters.youtube import YouTubeAdapter

adapter = YouTubeAdapter()

# Adapt a YouTube video
result = await adapter.adapt("https://www.youtube.com/watch?v=VIDEO_ID")

if result.success:
    video_set = result.video_set
    # Use video_set for video generation
else:
    print(f"Error: {result.error}")
```

## Supported URL Formats

```python
# All these work:
"https://www.youtube.com/watch?v=dQw4w9WgXcQ"
"https://youtu.be/dQw4w9WgXcQ"
"https://m.youtube.com/watch?v=dQw4w9WgXcQ"
"https://www.youtube.com/embed/dQw4w9WgXcQ"
"dQw4w9WgXcQ"  # Direct video ID
```

## Configuration Options

```python
await adapter.adapt(
    source="https://youtube.com/watch?v=...",
    language='en',           # Transcript language (default: 'en')
    scene_duration=12,       # Seconds per scene (default: 12)
    voice='male',           # 'male' or 'female' (default: 'male')
    accent_color='blue'     # Video theme color (default: 'blue')
)
```

## Common Languages

- `'en'` - English
- `'es'` - Spanish
- `'fr'` - French
- `'de'` - German
- `'ja'` - Japanese
- `'zh'` - Chinese
- `'ar'` - Arabic

## Scene Structure

Each video generates:
1. **Title Scene** - Introduction (3-5s)
2. **Content Scenes** - Key points as bullet lists (~12s each)
3. **Outro Scene** - Closing (3-5s)

## Error Handling

```python
result = await adapter.adapt(url)

if not result.success:
    if "youtube-transcript-api" in result.error:
        print("Install: pip install youtube-transcript-api")
    elif "Invalid YouTube URL" in result.error:
        print("Check URL format")
    elif "Transcripts are disabled" in result.error:
        print("Video has no transcripts")
    elif "No transcript found" in result.error:
        print("Try different language")
```

## Export to JSON

```python
import json

result = await adapter.adapt(url)
if result.success:
    with open('output.json', 'w') as f:
        json.dump(result.video_set.to_dict(), f, indent=2)
```

## Validation

```python
# Check if URL is valid
is_valid = await adapter.validate_source(url)

# Check if format is supported
supports = adapter.supports_format("youtube")  # True
```

## Example Output

For a video, you get:
```python
{
    'set_id': 'youtube_VIDEO_ID',
    'name': 'Video Title...',
    'videos': [
        {
            'video_id': 'youtube_VIDEO_ID',
            'title': 'Video Title...',
            'scenes': [
                # Title scene
                {'scene_type': 'title', ...},
                # Content scenes
                {'scene_type': 'list', 'visual_content': {'items': [...]}, ...},
                {'scene_type': 'list', 'visual_content': {'items': [...]}, ...},
                # Outro scene
                {'scene_type': 'outro', ...}
            ]
        }
    ]
}
```

## Tests

Run tests:
```bash
cd video_gen
python -m pytest tests/test_youtube_adapter.py -v
```

All 10 tests should pass ✓

## Files

- **Implementation**: `video_gen/input_adapters/youtube.py`
- **Tests**: `tests/test_youtube_adapter.py`
- **Examples**: `examples/youtube_adapter_example.py`
- **Documentation**: `docs/youtube_adapter_implementation.md`
