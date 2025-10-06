# Unified Video Generator - Usage Guide

## Quick Start

### Installation

```bash
# Install dependencies
pip install numpy pillow

# Verify FFmpeg with NVENC support
ffmpeg -encoders | grep nvenc
```

### Basic Usage

```python
from video_gen.video_generator.unified import UnifiedVideoGenerator
from pathlib import Path

# Create generator in fast mode
generator = UnifiedVideoGenerator(
    mode="fast",
    output_dir=Path("./output/videos")
)

# Generate videos from timing reports
timing_reports = [
    Path("../audio/video1/timing_report.json"),
    Path("../audio/video2/timing_report.json"),
]

videos = generator.generate_from_timing_reports(timing_reports)

print(f"✓ Generated {len(videos)} videos:")
for video in videos:
    print(f"  - {video}")
```

## Modes Explained

### Fast Mode (Recommended)

Best for production use. Uses NumPy acceleration and GPU encoding.

```python
generator = UnifiedVideoGenerator(mode="fast")
```

**Performance:**
- Frame blending: 10x faster than PIL
- Video encoding: 3-5x faster with NVENC
- Memory usage: Low (efficient NumPy arrays)

**Requirements:**
- NumPy installed
- NVIDIA GPU with NVENC support
- FFmpeg with NVENC support

### Baseline Mode

Compatibility mode using PIL blending.

```python
generator = UnifiedVideoGenerator(mode="baseline")
```

**Performance:**
- Frame blending: Standard PIL speed
- Video encoding: CPU encoding
- Memory usage: Medium (PIL Image objects)

**Requirements:**
- Pillow (PIL) installed
- FFmpeg (standard)

### Parallel Mode

Best for batch processing multiple videos.

```python
generator = UnifiedVideoGenerator(mode="parallel")
videos = generator.generate_from_timing_reports(reports, parallel=True)
```

**Performance:**
- Concurrent scene processing
- Multi-core CPU utilization
- 2.8-4.4x speedup (8 cores)

**Requirements:**
- Same as fast mode
- Multiple CPU cores recommended

## Common Use Cases

### 1. Single Video Generation

```python
from video_gen.video_generator.unified import UnifiedVideoGenerator
from pathlib import Path

generator = UnifiedVideoGenerator(mode="fast", output_dir=Path("./videos"))

timing_report = Path("../audio/my_video/timing_report.json")
video = generator._generate_single_video(timing_report)

print(f"✓ Generated: {video}")
```

### 2. Batch Video Generation

```python
# Generate multiple videos
timing_reports = [
    Path("../audio/video1/timing_report.json"),
    Path("../audio/video2/timing_report.json"),
    Path("../audio/video3/timing_report.json"),
]

videos = generator.generate_from_timing_reports(timing_reports)

print(f"✓ Generated {len(videos)} videos")
```

### 3. Progress Tracking

```python
def progress_callback(stage, progress, message):
    percentage = int(progress * 100)
    bar = "#" * (percentage // 2)
    print(f"[{stage}] [{bar:<50}] {percentage}% - {message}")

generator = UnifiedVideoGenerator(
    mode="fast",
    progress_callback=progress_callback
)

videos = generator.generate_from_timing_reports(timing_reports)
```

### 4. Custom Output Directory

```python
from datetime import datetime

# Create timestamped output directory
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_dir = Path(f"./videos/batch_{timestamp}")

generator = UnifiedVideoGenerator(
    mode="fast",
    output_dir=output_dir
)
```

### 5. Error Handling

```python
try:
    videos = generator.generate_from_timing_reports(timing_reports)
    print(f"✓ Success: {len(videos)} videos")

except FileNotFoundError as e:
    print(f"✗ Missing file: {e}")

except RuntimeError as e:
    print(f"✗ Encoding failed: {e}")

except ValueError as e:
    print(f"✗ Invalid configuration: {e}")
```

## Timing Report Format

Your timing reports should follow this structure:

```json
{
  "video_id": "my_video_001",
  "title": "My Video Title",
  "total_duration": 30.0,
  "accent_color": [59, 130, 246],
  "scenes": [
    {
      "scene_id": "scene_001",
      "type": "title",
      "duration": 3.0,
      "audio_duration": 2.5,
      "visual_content": {
        "title": "Welcome",
        "subtitle": "To My Video"
      },
      "voice": "male"
    },
    {
      "scene_id": "scene_002",
      "type": "command",
      "duration": 5.0,
      "audio_duration": 4.5,
      "visual_content": {
        "header": "Installation",
        "description": "Install the package",
        "commands": [
          "$ pip install my-package",
          "→ Successfully installed"
        ]
      },
      "voice": "male"
    }
  ]
}
```

## Scene Types

### Title Scene

```json
{
  "type": "title",
  "visual_content": {
    "title": "Main Title",
    "subtitle": "Subtitle Text"
  }
}
```

### Command Scene

```json
{
  "type": "command",
  "visual_content": {
    "header": "Command Header",
    "description": "Description",
    "commands": [
      "$ python script.py",
      "→ Output here"
    ]
  }
}
```

### List Scene

```json
{
  "type": "list",
  "visual_content": {
    "header": "List Header",
    "description": "Description",
    "items": [
      "First item",
      "Second item",
      "Third item"
    ]
  }
}
```

### Outro Scene

```json
{
  "type": "outro",
  "visual_content": {
    "main_text": "Thank You",
    "sub_text": "Visit us at example.com"
  }
}
```

For more scene types, see [README.md](../video_gen/video_generator/README.md#supported-scene-types).

## Migrating from Legacy Scripts

### From v3_simple

**Old Code:**
```python
from generate_videos_from_timings_v3_simple import generate_all_videos_fast
videos = generate_all_videos_fast()
```

**New Code:**
```python
from video_gen.video_generator.unified import UnifiedVideoGenerator
generator = UnifiedVideoGenerator(mode="fast")
videos = generator.generate_from_timing_reports(timing_reports)
```

### From v3_optimized

**Old Code:**
```python
from generate_videos_from_timings_v3_optimized import generate_all_videos_with_audio
videos = generate_all_videos_with_audio()
```

**New Code:**
```python
from video_gen.video_generator.unified import UnifiedVideoGenerator
generator = UnifiedVideoGenerator(mode="parallel")
videos = generator.generate_from_timing_reports(timing_reports, parallel=True)
```

### From v2

**Old Code:**
```python
from generate_videos_from_timings_v2 import generate_all_videos_with_audio
videos = generate_all_videos_with_audio()
```

**New Code:**
```python
from video_gen.video_generator.unified import UnifiedVideoGenerator
generator = UnifiedVideoGenerator(mode="baseline")
videos = generator.generate_from_timing_reports(timing_reports)
```

## Performance Optimization

### 1. Use Fast Mode

```python
# Fastest option
generator = UnifiedVideoGenerator(mode="fast")
```

### 2. Enable Parallel Processing

```python
# For batch operations
generator = UnifiedVideoGenerator(mode="parallel")
videos = generator.generate_from_timing_reports(reports, parallel=True)
```

### 3. GPU Requirements

Ensure your system has:
- NVIDIA GPU (GTX 1050 or better)
- NVENC support enabled
- Latest NVIDIA drivers
- FFmpeg with NVENC support

Check NVENC availability:
```bash
ffmpeg -encoders | grep nvenc
```

### 4. Memory Management

For large batches, process in chunks:

```python
def process_in_chunks(reports, chunk_size=5):
    results = []
    for i in range(0, len(reports), chunk_size):
        chunk = reports[i:i+chunk_size]
        videos = generator.generate_from_timing_reports(chunk)
        results.extend(videos)
    return results

all_videos = process_in_chunks(timing_reports, chunk_size=5)
```

## Troubleshooting

### GPU Encoding Fails

**Problem:** `RuntimeError: Video encoding failed`

**Solutions:**
1. Check GPU availability:
   ```bash
   nvidia-smi
   ```

2. Verify NVENC support:
   ```bash
   ffmpeg -encoders | grep nvenc
   ```

3. Fall back to baseline mode:
   ```python
   generator = UnifiedVideoGenerator(mode="baseline")
   ```

### Import Errors

**Problem:** `ImportError: cannot import name 'create_title_keyframes'`

**Solution:** Ensure rendering functions are available:
```python
# Check if rendering functions are imported
from video_gen.video_generator.unified import UnifiedVideoGenerator
gen = UnifiedVideoGenerator(mode="fast")
print(f"Renderers available: {len(gen.renderers)}")
```

### Audio Sync Issues

**Problem:** Audio and video out of sync

**Solutions:**
1. Verify timing report durations:
   ```python
   # Check scene durations match audio
   for scene in timing_data['scenes']:
       assert scene['duration'] >= scene['audio_duration']
   ```

2. Check animation duration:
   ```python
   # Ensure ANIM_DURATION is consistent
   from video_gen.video_generator.unified import ANIM_DURATION
   print(f"Animation duration: {ANIM_DURATION}s")
   ```

### Memory Issues

**Problem:** Out of memory during rendering

**Solutions:**
1. Use parallel mode with limited workers:
   ```python
   # Process fewer videos concurrently
   generator = UnifiedVideoGenerator(mode="fast")
   videos = generator._generate_sequential(reports)  # One at a time
   ```

2. Clear frame arrays after encoding:
   ```python
   # Memory is cleared automatically, but you can force it
   import gc
   gc.collect()
   ```

## Command Line Usage

Use the compatibility wrapper for CLI:

```bash
# Fast mode
python scripts/generate_videos_from_timings_unified.py --mode fast

# Parallel mode
python scripts/generate_videos_from_timings_unified.py --mode optimized

# Baseline mode
python scripts/generate_videos_from_timings_unified.py --mode baseline
```

## Advanced Usage

### Custom FFmpeg Path

```python
generator = UnifiedVideoGenerator(
    mode="fast",
    ffmpeg_path="/usr/local/bin/ffmpeg"
)
```

### Custom Accent Colors

Accent colors are defined in timing reports:

```json
{
  "accent_color": [255, 107, 53]  // RGB values
}
```

Common colors:
- Blue: `[59, 130, 246]`
- Orange: `[255, 107, 53]`
- Purple: `[139, 92, 246]`
- Green: `[16, 185, 129]`
- Pink: `[236, 72, 153]`

### Extend with New Scene Types

1. Add renderer function:
```python
def create_my_scene_keyframes(param1, param2, accent_color):
    # Render scene
    return start_frame, end_frame
```

2. Register in generator:
```python
generator.renderers['my_scene'] = create_my_scene_keyframes
```

3. Add mapping in `_render_scene_keyframes()`:
```python
elif scene_type == 'my_scene':
    return renderer(
        visual.get('param1', ''),
        visual.get('param2', ''),
        accent_color
    )
```

## Best Practices

1. **Always use fast mode for production**
2. **Enable progress callbacks for long operations**
3. **Process large batches in chunks**
4. **Verify timing reports before generation**
5. **Handle errors gracefully**
6. **Test with baseline mode first**
7. **Monitor GPU temperature during batch processing**
8. **Keep FFmpeg updated for best performance**

## Resources

- [Full API Documentation](../video_gen/video_generator/README.md)
- [Test Suite](../tests/test_video_generator.py)
- [Consolidation Summary](./VIDEO_GENERATOR_CONSOLIDATION.md)
- [Legacy Scripts](../scripts/)

## Support

For issues and questions:
- Check [Troubleshooting](#troubleshooting) section
- Review [test examples](../tests/test_video_generator.py)
- See [consolidation summary](./VIDEO_GENERATOR_CONSOLIDATION.md)
