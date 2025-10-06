# YouTube Adapter Implementation Summary

## Overview

The YouTube Adapter has been fully implemented to extract video transcripts from YouTube and convert them into VideoSet structures for video generation.

**Location**: `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\video_gen\input_adapters\youtube.py`

## Features Implemented

### 1. Video ID Extraction
Supports multiple YouTube URL formats:
- Standard watch URLs: `https://www.youtube.com/watch?v=VIDEO_ID`
- Short URLs: `https://youtu.be/VIDEO_ID`
- Mobile URLs: `https://m.youtube.com/watch?v=VIDEO_ID`
- Embed URLs: `https://www.youtube.com/embed/VIDEO_ID`
- Direct video IDs: `VIDEO_ID` (11 characters)

### 2. Transcript Download
- Uses `youtube-transcript-api` library
- Supports multiple languages with fallback to auto-generated transcripts
- Graceful error handling for missing library

### 3. Scene Generation Strategy
The adapter converts transcripts into structured scenes:

#### Title Scene (scene_000)
- Created from the first text of the transcript
- Includes video ID in subtitle
- Duration: 3-5 seconds

#### Content Scenes (scene_001+)
- Groups transcript segments by time (default: 12 seconds per scene)
- Scene type: "list" with bullet points
- Extracts key points from transcript text
- Splits sentences into 3-4 bullet points per scene
- Duration: Adapts to actual transcript timing

#### Outro Scene (final scene)
- Standard thank you message
- Includes reference to original video
- Duration: 3-5 seconds

### 4. Configurable Parameters

```python
await adapter.adapt(
    source="https://www.youtube.com/watch?v=VIDEO_ID",
    language='en',           # Transcript language (default: 'en')
    scene_duration=12,       # Target seconds per scene (default: 12)
    voice='male',           # Voice for narration (default: 'male')
    accent_color='blue'     # Video accent color (default: 'blue')
)
```

### 5. Error Handling

Comprehensive error handling for:
- **Invalid URLs**: Returns error for non-YouTube URLs
- **Missing Library**: Friendly error message with installation instructions
- **Unavailable Transcripts**: Specific error when transcripts are disabled
- **No Transcript Found**: Error when requested language is unavailable
- **Video Unavailable**: Error for deleted or private videos

## Implementation Details

### Core Methods

#### `adapt(source, **kwargs) -> InputAdapterResult`
Main entry point that:
1. Validates the YouTube URL
2. Extracts video ID(s)
3. Downloads transcript using youtube-transcript-api
4. Creates VideoSet structure
5. Returns InputAdapterResult with success/error status

#### `_extract_video_ids(url) -> List[str]`
Parses various YouTube URL formats to extract video IDs.

#### `_create_video_config(video_id, transcript_data, ...) -> VideoConfig`
Creates a complete VideoConfig from transcript data including:
- Title generation from transcript
- Scene grouping by duration
- Title and outro scenes

#### `_create_scenes(transcript_data, scene_duration, voice) -> List[SceneConfig]`
Groups transcript segments into logical scenes based on:
- Target scene duration
- Sentence boundaries
- Time stamps from transcript

#### `_create_bullet_points(text, max_points) -> List[str]`
Converts transcript text into bullet points:
- Splits on sentence boundaries
- Takes evenly distributed sentences
- Capitalizes and formats text
- Limits to max_points (default: 4)

#### `_create_title(text, max_length) -> str`
Generates video title from transcript:
- Uses first text segment
- Capitalizes properly
- Truncates to max_length (default: 60 chars)

## Example Usage

### Basic Usage

```python
from video_gen.input_adapters.youtube import YouTubeAdapter

adapter = YouTubeAdapter()

# Adapt a YouTube video
result = await adapter.adapt("https://www.youtube.com/watch?v=dQw4w9WgXcQ")

if result.success:
    video_set = result.video_set
    print(f"Generated {len(video_set.videos)} video(s)")
    for video in video_set.videos:
        print(f"  - {video.title} ({len(video.scenes)} scenes)")
else:
    print(f"Error: {result.error}")
```

### With Custom Options

```python
# Spanish transcript, longer scenes, female voice, red accent
result = await adapter.adapt(
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    language='es',
    scene_duration=15,
    voice='female',
    accent_color='red'
)
```

### Export to JSON

```python
result = await adapter.adapt("https://www.youtube.com/watch?v=dQw4w9WgXcQ")

if result.success:
    video_set_dict = result.video_set.to_dict()

    import json
    with open('output.json', 'w') as f:
        json.dump(video_set_dict, f, indent=2)
```

## Example Output Structure

For a YouTube video with a 22-second transcript, the adapter generates:

```json
{
  "set_id": "youtube_dQw4w9WgXcQ",
  "name": "Welcome to this tutorial",
  "description": "Generated from YouTube video(s): dQw4w9WgXcQ",
  "videos": [
    {
      "video_id": "youtube_dQw4w9WgXcQ",
      "title": "Welcome to this tutorial",
      "description": "Video generated from YouTube transcript: dQw4w9WgXcQ",
      "accent_color": "blue",
      "scenes": [
        {
          "scene_id": "scene_000",
          "scene_type": "title",
          "narration": "Welcome to this tutorial",
          "visual_content": {
            "title": "Welcome to this tutorial",
            "subtitle": "From YouTube Video: dQw4w9WgXcQ"
          },
          "voice": "male",
          "min_duration": 3.0,
          "max_duration": 5.0
        },
        {
          "scene_id": "scene_001",
          "scene_type": "list",
          "narration": "Welcome to this tutorial Today we will learn about Python Python is a great language",
          "visual_content": {
            "title": "Key Points 1",
            "items": [
              "Welcome to this tutorial",
              "Today we will learn about Python",
              "Python is a great language"
            ]
          },
          "voice": "male",
          "min_duration": 8.0,
          "max_duration": 12.0
        },
        {
          "scene_id": "scene_002",
          "scene_type": "list",
          "narration": "Let's get started First we need to install Python Then we can write our first program",
          "visual_content": {
            "title": "Key Points 2",
            "items": [
              "Let's get started",
              "First we need to install Python",
              "Then we can write our first program"
            ]
          },
          "voice": "male",
          "min_duration": 8.0,
          "max_duration": 12.0
        },
        {
          "scene_id": "scene_003",
          "scene_type": "outro",
          "narration": "Thank you for watching! For more content, visit the original video.",
          "visual_content": {
            "title": "Thank You!",
            "message": "Visit the original video on YouTube",
            "video_id": "dQw4w9WgXcQ"
          },
          "voice": "male",
          "min_duration": 3.0,
          "max_duration": 5.0
        }
      ]
    }
  ],
  "metadata": {
    "source_type": "youtube",
    "video_ids": ["dQw4w9WgXcQ"],
    "language": "en",
    "source_url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
  }
}
```

## Testing

Comprehensive test suite with 10 tests covering:
- ✓ URL validation (multiple formats)
- ✓ Video ID extraction
- ✓ Title generation
- ✓ Bullet point creation
- ✓ Missing library handling
- ✓ Invalid URL handling
- ✓ Successful adaptation
- ✓ Transcript disabled error
- ✓ No transcript found error
- ✓ Format support checking

**Test Location**: `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\tests\test_youtube_adapter.py`

**All tests pass**: ✓ 10/10 passed

## Dependencies

- `youtube-transcript-api` (version 1.2.2 or higher)

Install with:
```bash
pip install youtube-transcript-api
```

If not installed, the adapter provides a graceful error message with installation instructions.

## Future Enhancements

Potential improvements for future iterations:

1. **Playlist Support**: Currently returns empty list for playlist URLs. Could be enhanced with youtube-dl or similar.

2. **Multiple Languages**: Generate videos in multiple languages from the same transcript.

3. **Scene Type Variation**: Add more scene types based on content analysis:
   - "quote" for notable statements
   - "checkpoint" for key milestones
   - "quiz" for question segments

4. **Timestamp Metadata**: Preserve original timestamps for reference.

5. **Speaker Detection**: If transcript has speaker information, vary voices.

6. **Content Analysis**: Use AI to better categorize scenes based on content.

## Integration

The YouTube adapter integrates seamlessly with the input adapter system:

```python
from video_gen.input_adapters import AdapterRegistry

# Register adapter
registry = AdapterRegistry()
registry.register(YouTubeAdapter())

# Use via registry
result = await registry.adapt("youtube", "https://youtube.com/watch?v=...")
```

## Status

✅ **COMPLETE** - Fully implemented and tested

All core functionality is working:
- URL parsing and validation
- Transcript extraction
- Scene generation
- Error handling
- Comprehensive test coverage
