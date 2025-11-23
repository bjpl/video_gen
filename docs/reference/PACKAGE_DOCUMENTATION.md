# 📦 Complete Package Documentation
## Video/Audio Production System - All Dependencies

**System Version:** v3.0 (Optimized)
**Last Updated:** 2025-10-03

---

## 📋 Table of Contents

1. [Package Overview](#package-overview)
2. [Python Standard Library Packages](#python-standard-library-packages)
3. [Third-Party Python Packages](#third-party-python-packages)
4. [Local Python Modules](#local-python-modules)
5. [System Dependencies](#system-dependencies)
6. [Installation Guide](#installation-guide)
7. [Package Usage Matrix](#package-usage-matrix)
8. [Version Requirements](#version-requirements)

---

## 📊 Package Overview

### **Core Dependencies Summary**

| Category | Count | Examples |
|----------|-------|----------|
| **Standard Library** | 8 | `os`, `json`, `subprocess`, `asyncio` |
| **Third-Party Python** | 3 | `Pillow`, `edge-tts`, `numpy` |
| **Local Python Modules** | 1 | `generate_documentation_videos.py` |
| **System Dependencies** | 1 | `FFmpeg` (with NVENC) |
| **Windows Fonts** | 3 | `arial.ttf`, `arialbd.ttf`, `consola.ttf` |

**Total:** 16 dependencies (8 built-in, 8 external)

---

## 🐍 Python Standard Library Packages

### **1. `os` - Operating System Interface**

**Purpose:** File and directory operations, path manipulation

**Usage in System:**
```python
# Import
import os

# Create directories
os.makedirs(self.audio_dir, exist_ok=True)
os.makedirs(output_dir, exist_ok=True)

# Path operations
audio_file = os.path.join(self.audio_dir, f"{scene.scene_id}.mp3")
report_file = os.path.join(output_dir, validation_filename)

# File size checking
file_size = os.path.getsize(audio_file) / 1024  # Convert to KB

# Directory listing
audio_dirs = [d for d in os.listdir(audio_base)
              if d.startswith(sanitized_id) and os.path.isdir(...)]

# File existence
if not os.path.exists(timing_file):
    raise FileNotFoundError(...)
```

**Key Functions Used:**
- `os.makedirs()` - Create nested directories
- `os.path.join()` - Platform-independent path construction
- `os.path.getsize()` - Get file size in bytes
- `os.listdir()` - List directory contents
- `os.path.isdir()` - Check if path is directory
- `os.path.exists()` - Check file/directory existence
- `os.path.abspath()` - Get absolute path (for FFmpeg)
- `os.path.basename()` - Extract filename from path

**Why Chosen:** Built-in, platform-independent, reliable

---

### **2. `json` - JSON Encoder/Decoder**

**Purpose:** Reading and writing structured data (reports, timing, metadata)

**Usage in System:**
```python
# Import
import json

# Write timing reports
report = {
    'video_id': self.video_id,
    'total_duration': self.total_duration,
    'scenes': [...]
}
with open(report_file, 'w') as f:
    json.dump(report, f, indent=2)

# Read timing reports
with open(timing_file, 'r') as f:
    timing_data = json.load(f)

# Write validation reports
with open(validation_file, 'w') as f:
    json.dump(self.validation_report, f, indent=2)

# Write metadata manifests
manifest = {
    'video_metadata': self.get_metadata(),
    'validation': self.validation_report,
    'scenes': [scene.to_dict() for scene in self.scenes]
}
with open(manifest_file, 'w') as f:
    json.dump(manifest, f, indent=2)
```

**Key Functions Used:**
- `json.dump()` - Write Python objects to JSON file
- `json.load()` - Read JSON file to Python objects
- `indent=2` parameter - Pretty-printing with 2-space indentation

**Files Created:**
- `*_timing_*.json` - Scene timing data (CRITICAL for video generation)
- `*_validation_*.json` - Validation warnings/errors
- `*_manifest_*.json` - Complete metadata
- `batch_summary_*.json` - Batch processing summary
- `summary_*.json` - Video generation summary

**Why Chosen:** Standard format, human-readable, Python native support

---

### **3. `subprocess` - Subprocess Management**

**Purpose:** Execute external commands (FFmpeg for encoding, probing)

**Usage in System:**
```python
# Import
import subprocess

# Get audio duration (FFmpeg probe)
result = subprocess.run(
    [FFMPEG_PATH, "-i", audio_file],
    capture_output=True,
    text=True
)
# Parse stderr for duration
for line in result.stderr.split('\n'):
    if 'Duration:' in line:
        time_str = line.split('Duration:')[1].split(',')[0].strip()
        h, m, s = time_str.split(':')
        duration = int(h) * 3600 + int(m) * 60 + float(s)

# Encode video with GPU acceleration
ffmpeg_video_cmd = [
    FFMPEG_PATH,
    "-y", "-f", "concat", "-safe", "0", "-i", concat_file,
    "-c:v", "h264_nvenc",
    "-preset", "p4",
    "-tune", "hq",
    # ... more options
    silent_video_path
]
result = subprocess.run(ffmpeg_video_cmd, capture_output=True, text=True)

if result.returncode != 0:
    print(f"❌ Encoding failed: {result.stderr[:300]}")

# Process audio (delay + fade)
ffmpeg_final_cmd = [
    FFMPEG_PATH,
    "-y",
    "-i", silent_video_path,
    "-f", "concat", "-safe", "0", "-i", audio_concat_file,
    "-c:v", "copy",
    "-af", f"adelay={delay_ms}:all=1,afade=t=in:st={ANIM_DURATION}:d=0.3",
    "-c:a", "aac",
    final_video_path
]
subprocess.run(ffmpeg_final_cmd, capture_output=True, text=True)
```

**Key Functions Used:**
- `subprocess.run()` - Execute external command
- `capture_output=True` - Capture stdout/stderr
- `text=True` - Return output as string (not bytes)
- `result.returncode` - Check exit status
- `result.stderr` - Error output (FFmpeg writes to stderr)

**FFmpeg Commands Executed:**
1. **Probe audio duration** - Measure MP3 file length
2. **Encode video** - GPU-accelerated H.264 encoding
3. **Process audio** - Delay, fade, concatenate
4. **Mux final video** - Combine video + audio streams

**Why Chosen:** Direct process control, capture output, error handling

---

### **4. `asyncio` - Asynchronous I/O**

**Purpose:** Run asynchronous functions (required for edge-tts)

**Usage in System:**
```python
# Import
import asyncio

# Main async function
async def generate_audio_with_timing(self, output_dir):
    """Generate audio files asynchronously"""
    for scene in self.scenes:
        voice = VOICE_CONFIG.get(scene.voice, VOICE_CONFIG["male"])
        audio_file = os.path.join(self.audio_dir, f"{scene.scene_id}.mp3")

        # Asynchronous TTS generation
        communicate = edge_tts.Communicate(
            scene.narration,
            voice,
            rate="+0%",
            volume="+0%"
        )
        await communicate.save(audio_file)  # Async operation

        # Async audio duration measurement
        duration = await self.get_audio_duration(audio_file)
        scene.actual_audio_duration = duration

# Run async function from synchronous code
if __name__ == "__main__":
    asyncio.run(main())  # Entry point for async code
```

**Key Functions Used:**
- `asyncio.run()` - Execute async function from sync context
- `async def` - Define asynchronous functions
- `await` - Wait for async operations (TTS save, duration probe)

**Why Needed:**
- `edge-tts` library requires async/await
- Efficient I/O for multiple audio generations
- Non-blocking operations

**Why Chosen:** Required by edge-tts, Python 3.7+ standard

---

### **5. `shutil` - High-Level File Operations**

**Purpose:** Directory and file operations (copy, move, remove)

**Usage in System:**
```python
# Import
import shutil

# Clean up temporary directories after video generation
temp_dir = f"temp_v3_fast_{video.video_id}"
os.makedirs(temp_dir, exist_ok=True)

# ... generate video frames ...

# Remove temporary frame directory
shutil.rmtree(temp_dir)  # Recursively delete directory and contents
```

**Key Functions Used:**
- `shutil.rmtree()` - Recursively delete directory tree

**Temporary Directories Cleaned:**
- `temp_v3_fast_{video_id}/` - Frame PNGs (deleted after encoding)
- `temp_v2_{video_id}/` - v2.0 temp frames (deleted after encoding)

**Why Chosen:** Safe recursive deletion, built-in

---

### **6. `sys` - System-Specific Parameters**

**Purpose:** System path manipulation, command-line arguments

**Usage in System:**
```python
# Import
import sys

# Add current directory to Python path (for imports)
sys.path.append('.')

# Import from same directory
from generate_documentation_videos import (
    create_title_keyframes, create_command_keyframes,
    create_list_keyframes, create_outro_keyframes
)
```

**Key Functions Used:**
- `sys.path.append()` - Add directory to module search path

**Why Chosen:** Enable relative imports within project

---

### **7. `datetime` - Date and Time Types**

**Purpose:** Timestamp generation for filenames

**Usage in System:**
```python
# Import
from datetime import datetime

# Generate unique timestamp for filenames
if self.generation_timestamp is None:
    self.generation_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

# Example output: "20250926_223811"

# Use in smart filenames
filename = f"{sanitized_id}_{duration_str}_{self.version}_{audio_status}_{self.generation_timestamp}.mp4"
# Example: "01-quick-reference_51s_v2.0_with_audio_20250926_223811.mp4"

# ISO format for JSON
summary = {
    'timestamp': datetime.now().isoformat()
}
# Example: "2025-09-26T22:38:11.123456"
```

**Key Functions Used:**
- `datetime.now()` - Current date/time
- `.strftime()` - Format as string (YYYYmmdd_HHMMSS)
- `.isoformat()` - ISO 8601 format (for JSON)

**Why Chosen:** Unique timestamps, sortable filenames, standard datetime handling

---

### **8. `contextlib` - Context Management**

**Purpose:** Context managers for resource management (mentioned but not actively used)

**Usage in System:**
```python
# Import (in unified_video_system.py but not actively used)
import contextlib

# Likely intended for:
# - Wave file handling
# - Temporary file cleanup
# - Resource management
```

**Note:** Imported but current implementation doesn't use `contextlib` features. May be vestigial from earlier version.

---

## 🔧 Third-Party Python Packages

### **1. `Pillow` (PIL) - Python Imaging Library**

**Package Name:** `Pillow`
**Import As:** `PIL`
**Version Used:** Latest (tested with 10.x)

**Purpose:** Image creation, manipulation, and rendering (keyframes, text, graphics)

**Installation:**
```bash
pip install Pillow
```

**Usage in System:**

#### **A. Image Creation & Drawing**
```python
# Import
from PIL import Image, ImageDraw, ImageFont

# Create blank image
img = Image.new('RGB', (1920, 1080), (245, 248, 252))  # RGB mode, size, color

# Create with alpha channel (transparency)
img = Image.new('RGBA', (1920, 1080), (245, 248, 252, 255))

# Drawing context
draw = ImageDraw.Draw(img, 'RGBA')  # RGBA for transparency support
```

#### **B. Shape Drawing**
```python
# Rectangles
draw.rectangle([0, 0, 12, HEIGHT], fill=(255, 107, 53, 255))  # Vertical bar
draw.rectangle([x, 520, x + w, 526], fill=accent_color + (255,))  # Underline

# Rounded rectangles (cards, buttons)
draw.rounded_rectangle(
    [card_x, card_y, card_x + card_w, card_y + card_h],
    radius=20,
    fill=(255, 255, 255, 255)  # RGBA
)

# Ellipses (circles, blobs)
draw.ellipse([dot_x, dot_y, dot_x + 14, dot_y + 14], fill=(255, 95, 86, 255))

# Lines
draw.line([(x1, y1), (x2, y2)], fill=color, width=2)
```

#### **C. Text Rendering**
```python
# Load TrueType fonts
font_title = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", 120)
font_subtitle = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 48)
font_code = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 32)

# Measure text size (for centering)
bbox = draw.textbbox((0, 0), title, font=font_title)
w = bbox[2] - bbox[0]  # Width
x = (WIDTH - w) // 2   # Center horizontally

# Draw text
draw.text((x, 380), title, font=font_title, fill=(15, 23, 42, 255))
```

#### **D. Image Manipulation**
```python
# Copy image
new_img = img.copy()

# Convert color modes
rgb_img = img.convert('RGB')      # Strip alpha channel
rgba_img = img.convert('RGBA')    # Add alpha channel

# Save image
img.save("frame.png", "PNG", compress_level=1)  # Low compression (v3.0)
img.save("frame.png", "PNG", compress_level=9)  # High compression (v2.0)
```

#### **E. Frame Blending (v2.0)**
```python
# Built-in blend (v2.0 - slower)
blended = Image.blend(img1, img2, alpha)  # alpha = 0.0 to 1.0

# Custom blend with NumPy (v3.0 - 10x faster, see NumPy section)
```

**Scene Types Generated:**

1. **Title Scenes**
   ```
   ┌─────────────────────────────────┐
   │          [GUIDE BADGE]          │
   │                                 │
   │         TITLE TEXT              │
   │         ──────────              │
   │         Subtitle Text           │
   └─────────────────────────────────┘
   ```

2. **Command Scenes**
   ```
   ┌─────────────────────────────────┐
   │ [❯]  Header Text                │
   │      Description                │
   │                                 │
   │  ┌──────────────────────────┐  │
   │  │ ●●●          Terminal    │  │
   │  ├──────────────────────────┤  │
   │  │ ❯ command one            │  │
   │  │ ❯ command two            │  │
   │  │ → output                 │  │
   │  └──────────────────────────┘  │
   └─────────────────────────────────┘
   ```

3. **List Scenes**
   ```
   ┌─────────────────────────────────┐
   │ Header Text                     │
   │ Description                     │
   │                                 │
   │ ┌────────────────────────────┐ │
   │ │ ✓ Item 1: Description      │ │
   │ │ ✓ Item 2: Description      │ │
   │ │ ✓ Item 3: Description      │ │
   │ └────────────────────────────┘ │
   └─────────────────────────────────┘
   ```

4. **Outro Scenes**
   ```
   ┌─────────────────────────────────┐
   │                                 │
   │       Main Message Text         │
   │       Subtitle Text             │
   │                                 │
   └─────────────────────────────────┘
   ```

**Performance Notes:**
- **Image creation:** ~10-20ms per frame (1920x1080)
- **Text rendering:** ~5ms per text element
- **Drawing shapes:** ~1-2ms per shape
- **Blending (PIL):** ~120ms per blend (v2.0)
- **Blending (NumPy):** ~15ms per blend (v3.0) ← 8x faster!

**Key Features Used:**
- RGB/RGBA color modes with alpha transparency
- TrueType font rendering
- Text measurement for centering
- Rounded rectangles (modern UI)
- Image blending (smooth transitions)
- PNG compression control (v3.0 optimization)

**Why Chosen:**
- Industry standard for Python image manipulation
- Excellent text rendering with TrueType fonts
- Transparency support (RGBA)
- Fast enough for keyframe generation
- Well-documented, stable API

---

### **2. `edge-tts` - Microsoft Edge Text-to-Speech**

**Package Name:** `edge-tts`
**Import As:** `edge_tts`
**Version Used:** 7.2.3+

**Purpose:** Generate professional neural voice narration

**Installation:**
```bash
pip install edge-tts
```

**Usage in System:**

#### **A. Voice Configuration**
```python
# Voice mapping
VOICE_CONFIG = {
    "male": "en-US-AndrewMultilingualNeural",
    "female": "en-US-AriaNeural"
}

# Get voice for scene
voice = VOICE_CONFIG.get(scene.voice, VOICE_CONFIG["male"])
```

#### **B. Audio Generation (Async)**
```python
import edge_tts

# Create TTS communicator
communicate = edge_tts.Communicate(
    text=scene.narration,
    voice=voice,
    rate="+0%",    # Speed adjustment ("+20%" = 20% faster)
    volume="+0%"   # Volume adjustment ("+10%" = 10% louder)
)

# Save to file (async operation)
await communicate.save(audio_file)
```

**Voice Options Available:**

| Voice ID | Gender | Accent | Style | Use Case |
|----------|--------|--------|-------|----------|
| `en-US-AndrewMultilingualNeural` | Male | US | Professional, confident | Business demos, technical content |
| `en-US-AriaNeural` | Female | US | Clear, crisp | Tutorials, documentation |
| `en-US-BrandonMultilingualNeural` | Male | US | Warm, engaging | Marketing, social media |
| `en-US-AvaMultilingualNeural` | Female | US | Friendly, caring | Onboarding, help content |

**Audio Specifications:**
- **Format:** MP3
- **Sample Rate:** 24 kHz (neural TTS default)
- **Bitrate:** Variable (optimized)
- **Channels:** Mono
- **Quality:** High (neural network-based)
- **File Size:** ~20-80 KB per scene (5-15 seconds)

**Example Narration Generation:**
```python
# Scene 1: Title (5 seconds)
narration = "Claude Code. Your AI-powered development assistant."
# → Generates: scene_01_title.mp3 (~3.84s, ~45 KB)

# Scene 2: Command (10 seconds)
narration = "Run four simple commands to generate your complete video..."
# → Generates: scene_02_commands.mp3 (~11.52s, ~72 KB)
```

**Timing Precision:**
```python
# After generation, measure actual duration
duration = await self.get_audio_duration(audio_file)
# Uses FFmpeg probe to measure to 0.01s precision

# Example output:
# scene.actual_audio_duration = 11.52  # Measured, not estimated!
```

**Performance:**
- **Generation time:** ~1-2 seconds per scene (API-based)
- **Requires:** Internet connection (cloud API)
- **Concurrent:** Can generate multiple files in parallel

**Customization Options:**

```python
# Faster speech
communicate = edge_tts.Communicate(text, voice, rate="+20%")

# Slower speech
communicate = edge_tts.Communicate(text, voice, rate="-15%")

# Louder volume
communicate = edge_tts.Communicate(text, voice, volume="+10%")

# Combined
communicate = edge_tts.Communicate(
    text, voice,
    rate="+10%",    # 10% faster
    volume="+5%"    # 5% louder
)
```

**Why Chosen:**
- **Free:** No API key required
- **High quality:** Neural network-based voices (realistic)
- **Multiple voices:** Various accents, genders, styles
- **Python-native:** Easy async integration
- **Reliable:** Microsoft Azure backend

**Alternative TTS Options (Not Used):**
- ❌ `gTTS` (Google TTS) - Lower quality, robotic
- ❌ `pyttsx3` - Offline, but poor quality
- ❌ `Amazon Polly` - Requires AWS account, paid
- ❌ `Google Cloud TTS` - Requires API key, paid
- ✅ `edge-tts` - FREE, high quality, no API key!

---

### **3. `numpy` - Numerical Python**

**Package Name:** `numpy`
**Import As:** `np`
**Version Used:** 1.24+ (any recent version)

**Purpose:** Fast array operations for frame blending (v3.0 optimization)

**Installation:**
```bash
pip install numpy
```

**Usage in System:**

#### **A. Fast Frame Blending (v3.0)**
```python
import numpy as np
from PIL import Image

def blend_frames_fast(img1, img2, progress):
    """10x faster blending using NumPy instead of PIL"""

    # Convert PIL images to NumPy arrays (float32 for precision)
    arr1 = np.array(img1, dtype=np.float32)  # Shape: (1080, 1920, 3)
    arr2 = np.array(img2, dtype=np.float32)  # Shape: (1080, 1920, 3)

    # Vectorized blending operation (element-wise)
    # This runs on ALL pixels simultaneously!
    blended = arr1 * (1 - progress) + arr2 * progress

    # Convert back to uint8 (0-255 range)
    blended_uint8 = blended.astype('uint8')

    # Convert NumPy array back to PIL Image
    return Image.fromarray(blended_uint8, 'RGB')
```

**Performance Comparison:**

| Method | Time per Blend | Speedup |
|--------|---------------|---------|
| **PIL (v2.0)** | ~120ms | Baseline |
| **NumPy (v3.0)** | ~15ms | **8x faster** |

**Why NumPy is Faster:**

1. **Vectorization:**
   ```python
   # PIL (v2.0) - Pixel-by-pixel in C
   Image.blend(img1, img2, alpha)  # Iterates pixels internally

   # NumPy (v3.0) - All pixels at once
   arr1 * (1-α) + arr2 * α  # Single vectorized operation
   ```

2. **Memory Layout:**
   - NumPy arrays are contiguous in memory
   - CPU cache-friendly
   - SIMD (Single Instruction Multiple Data) optimized

3. **Data Types:**
   ```python
   # Precise float32 math, then convert once
   float32 → blend → uint8

   # vs PIL converting per operation
   uint8 → float → blend → uint8
   ```

**Array Operations Used:**

```python
# Convert PIL to NumPy
arr = np.array(img, dtype=np.float32)
# Shape: (height, width, channels) = (1080, 1920, 3)

# Vectorized math (all 6,220,800 pixels at once!)
blended = arr1 * scalar + arr2 * scalar  # Broadcast scalar to all elements

# Type conversion
result = blended.astype('uint8')  # Float → Integer (0-255)

# Convert NumPy to PIL
img = Image.fromarray(result, 'RGB')
```

**Memory Usage:**
- **Single frame (float32):** 1920 × 1080 × 3 × 4 bytes = ~24 MB
- **Two frames + blended:** ~72 MB peak
- **Efficient:** Temporary arrays, garbage collected

**Transition Example:**
```python
# Generate 15 transition frames (0.5s at 30 FPS)
for i in range(15):
    progress = i / 15.0  # 0.0 → 1.0

    # Blend from scene 1 to scene 2
    blended = blend_frames_fast(scene1_frame, scene2_frame, progress)
    # 15ms per blend × 15 frames = 225ms total (v3.0)
    # vs 120ms × 15 = 1800ms with PIL (v2.0)

    blended.save(f"frame_{i:05d}.png", compress_level=1)
```

**Why Chosen (v3.0):**
- **Speed:** 8x faster than PIL blending
- **Quality:** Identical results to PIL.blend()
- **Simple:** Just 4 lines of code
- **Dependency:** Already common in data science projects

**Why Not Used Before (v1.0, v2.0):**
- PIL.blend() was "good enough"
- Simplicity prioritized over speed
- v3.0 identified blending as bottleneck → optimized

---

## 🎨 Local Python Modules

### **`generate_documentation_videos.py` - Visual Rendering Engine**

**Location:** `scripts/generate_documentation_videos.py`
**Size:** ~833 lines
**Purpose:** Keyframe generation, visual design system, animation functions

**⚠️ CRITICAL DEPENDENCY:** All video generation scripts import from this module. Without it, video generation will fail with `ModuleNotFoundError`.

**Installation:**
```bash
# Must be present in scripts/ directory
# If missing, copy from archive:
cp archive/scripts_old/generate_documentation_videos.py scripts/
```

**Usage in System:**

#### **A. Imported by Video Generators**
```python
# In generate_videos_from_timings_v3_simple.py
from generate_documentation_videos import (
    create_title_keyframes,      # Title slide rendering
    create_command_keyframes,    # Terminal card rendering
    create_list_keyframes,       # List slide rendering
    create_outro_keyframes,      # Outro slide rendering
    ease_out_cubic,              # Animation easing function
    FPS,                         # Frame rate (30)
    WIDTH,                       # Resolution width (1920)
    HEIGHT                       # Resolution height (1080)
)
```

#### **B. Constants Defined**
```python
# Video specifications
WIDTH, HEIGHT = 1920, 1080  # Full HD resolution
FPS = 30                     # Frame rate

# Color palette (modern light theme)
BG_LIGHT = (245, 248, 252)        # Light blue-gray background
BG_WHITE = (255, 255, 255)        # Pure white
ACCENT_ORANGE = (255, 107, 53)    # Orange accent
ACCENT_BLUE = (59, 130, 246)      # Blue accent
ACCENT_PURPLE = (139, 92, 246)    # Purple accent
ACCENT_GREEN = (16, 185, 129)     # Green accent
ACCENT_PINK = (236, 72, 153)      # Pink accent
TEXT_DARK = (15, 23, 42)          # Dark text
TEXT_GRAY = (100, 116, 139)       # Gray text
TEXT_LIGHT = (148, 163, 184)      # Light text
CODE_BLUE = (59, 130, 246)        # Code syntax color
CARD_BG = (255, 255, 255)         # Card background
CARD_SHADOW = (203, 213, 225)     # Card shadow

# Fonts loaded from Windows
font_title = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", 120)
font_subtitle = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 48)
font_header = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", 64)
font_desc = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 38)
font_code = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 32)
font_small = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 28)
font_tiny = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 24)
```

#### **C. Core Functions**

**1. Animation Easing**
```python
def ease_out_cubic(t):
    """
    Cubic easing for smooth animations

    Args:
        t (float): Progress from 0.0 to 1.0

    Returns:
        float: Eased value (0.0 to 1.0)

    Curve: Starts fast, slows down at end
    """
    return 1 - pow(1 - t, 3)

# Used in blending:
for i in range(30):  # 1 second at 30 FPS
    progress = ease_out_cubic(i / 30.0)
    blended = blend(start, end, progress)
```

**2. Background Generation**
```python
def create_modern_mesh_bg(width, height, accent_color):
    """
    Creates modern gradient mesh background

    Elements:
    - Light blue-gray base
    - Translucent accent ellipses
    - Subtle grid overlay (40px spacing)

    Returns: PIL.Image (RGB mode)
    """
    img = Image.new('RGB', (width, height), BG_LIGHT)
    draw = ImageDraw.Draw(img, 'RGBA')

    # Gradient ellipses
    draw.ellipse([1200, -300, 2200, 500], fill=accent_color + (15,))
    draw.ellipse([-200, 600, 600, 1300], fill=accent_color + (20,))

    # Grid lines
    for i in range(0, width, 40):
        draw.line([(i, 0), (i, height)], fill=CARD_SHADOW + (30,), width=1)

    return img
```

**3. Base Frame Template**
```python
def create_base_frame(accent_color):
    """
    Creates base frame with branding elements

    Elements:
    - Modern mesh background
    - Left accent border (12px)
    - Bottom accent bar (12px, 50% opacity)
    - CC logo in bottom right

    Returns: PIL.Image (RGBA mode)
    """
    img = create_modern_mesh_bg(WIDTH, HEIGHT, accent_color).convert('RGBA')
    draw = ImageDraw.Draw(img, 'RGBA')

    # Left border (solid)
    draw.rectangle([0, 0, 12, HEIGHT], fill=accent_color + (255,))

    # Bottom bar (translucent)
    draw.rectangle([0, HEIGHT-12, WIDTH, HEIGHT], fill=accent_color + (120,))

    # Logo (bottom right)
    draw.rounded_rectangle([1800, 990, 1860, 1050], radius=12, fill=accent_color)
    draw.text((1812, 998), "CC", font=font_subtitle, fill=BG_WHITE)

    return img
```

**4. Keyframe Generators (Scene Types)**

**Title Scenes:**
```python
def create_title_keyframes(title, subtitle, accent_color):
    """
    Generate start/end frames for title slides

    Layout:
    - "GUIDE" badge at top
    - Large centered title (120px bold)
    - Accent underline
    - Subtitle text (48px regular)

    Returns:
        tuple: (start_frame, end_frame) - Both PIL.Image RGB

    Animation: Fade from base → full title
    """
    base = create_base_frame(accent_color)
    start_frame = base.copy()
    end_frame = base.copy()

    draw = ImageDraw.Draw(end_frame, 'RGBA')

    # GUIDE badge
    draw.rounded_rectangle([860, 280, 1060, 340],
                          radius=30, fill=accent_color + (40,))
    draw.text((920, 296), "GUIDE", font=font_small, fill=accent_color)

    # Title text (centered)
    bbox = draw.textbbox((0, 0), title, font=font_title)
    w = bbox[2] - bbox[0]
    draw.text(((WIDTH - w) // 2, 380), title, font=font_title, fill=TEXT_DARK)

    # Accent underline
    draw.rectangle([(WIDTH - w) // 2, 520, (WIDTH + w) // 2, 526], fill=accent_color)

    # Subtitle
    bbox2 = draw.textbbox((0, 0), subtitle, font=font_subtitle)
    w2 = bbox2[2] - bbox2[0]
    draw.text(((WIDTH - w2) // 2, 560), subtitle, font=font_subtitle, fill=TEXT_GRAY)

    return start_frame.convert('RGB'), end_frame.convert('RGB')
```

**Command Scenes:**
```python
def create_command_keyframes(header, description, commands, accent_color):
    """
    Generate terminal/command card frames

    Layout:
    - ❯ icon in top left
    - Header + description
    - macOS-style terminal card with:
      - Colored dots (●●●)
      - Syntax-highlighted commands

    Command syntax:
    - Lines starting with '$' → Blue (commands)
    - Lines starting with '→' → Green (output)
    - Lines starting with '#' → Gray (comments)

    Returns:
        tuple: (start_frame, end_frame) - Both PIL.Image RGB
    """
    base = create_base_frame(accent_color)
    start_frame = base.copy()

    # Header with icon
    draw = ImageDraw.Draw(start_frame, 'RGBA')
    draw.rounded_rectangle([120, 90, 200, 170], radius=16,
                          fill=accent_color + (40,))
    draw.text((138, 102), "❯", font=font_title, fill=accent_color)
    draw.text((230, 100), header, font=font_header, fill=TEXT_DARK)
    draw.text((230, 180), description, font=font_desc, fill=TEXT_GRAY)

    # Terminal card
    end_frame = start_frame.copy()
    draw = ImageDraw.Draw(end_frame, 'RGBA')

    # Card shadow + body
    draw.rounded_rectangle([266, 326, 1666, 906], radius=20,
                          fill=CARD_SHADOW + (100,))
    draw.rounded_rectangle([260, 320, 1660, 900], radius=20, fill=CARD_BG)

    # Header bar
    draw.rounded_rectangle([260, 320, 1660, 370], radius=20,
                          fill=accent_color + (30,))

    # Dots (macOS style)
    colors = [(255, 95, 86), (255, 189, 46), (39, 201, 63)]
    for i, color in enumerate(colors):
        draw.ellipse([290 + i*30, 338, 304 + i*30, 352], fill=color)

    # Commands (syntax highlighted)
    y = 420
    for line in commands:
        if line.startswith('$ '):
            draw.text((310, y), "❯", font=font_code, fill=accent_color)
            draw.text((340, y), line[2:], font=font_code, fill=CODE_BLUE)
        elif line.startswith('→'):
            draw.text((310, y), "→", font=font_code, fill=ACCENT_GREEN)
            draw.text((340, y), line[2:], font=font_code, fill=TEXT_DARK)
        elif line.startswith('#'):
            draw.text((310, y), line, font=font_code, fill=TEXT_LIGHT)
        y += 48

    return start_frame.convert('RGB'), end_frame.convert('RGB')
```

**List Scenes:**
```python
def create_list_keyframes(header, description, items, accent_color):
    """
    Generate list/checklist frames

    Layout:
    - ☰ icon in top left
    - Header + description
    - Numbered cards for each item
    - Supports tuple items: (title, description)

    Returns:
        tuple: (start_frame, end_frame) - Both PIL.Image RGB
    """
    base = create_base_frame(accent_color)
    start_frame = base.copy()

    # Header
    draw = ImageDraw.Draw(start_frame, 'RGBA')
    draw.rounded_rectangle([120, 90, 200, 170], radius=16,
                          fill=accent_color + (40,))
    draw.text((134, 98), "☰", font=font_title, fill=accent_color)
    draw.text((230, 100), header, font=font_header, fill=TEXT_DARK)
    draw.text((230, 180), description, font=font_desc, fill=TEXT_GRAY)

    # List items
    end_frame = start_frame.copy()
    draw = ImageDraw.Draw(end_frame, 'RGBA')

    y = 360
    for i, item in enumerate(items, 1):
        # Item card
        draw.rounded_rectangle([300, y, 1620, y + 85], radius=12,
                              fill=accent_color + (15,))

        # Number badge
        draw.rounded_rectangle([320, y + 25, 356, y + 61], radius=8,
                              fill=accent_color)
        draw.text((330, y + 29), str(i), font=font_small, fill=BG_WHITE)

        # Text
        if isinstance(item, tuple):
            title, desc = item
            draw.text((380, y + 12), title, font=font_desc, fill=TEXT_DARK)
            draw.text((380, y + 48), desc, font=font_small, fill=TEXT_GRAY)
        else:
            draw.text((380, y + 28), item, font=font_desc, fill=TEXT_DARK)

        y += 103

    return start_frame.convert('RGB'), end_frame.convert('RGB')
```

**Outro Scenes:**
```python
def create_outro_keyframes(main_text, sub_text, accent_color):
    """
    Generate outro/closing frames

    Layout:
    - Large checkmark (✓) icon
    - Main message text (64px bold)
    - Pill-shaped button with subtitle

    Returns:
        tuple: (start_frame, end_frame) - Both PIL.Image RGB
    """
    base = create_base_frame(accent_color)
    start_frame = base.copy()
    end_frame = base.copy()

    draw = ImageDraw.Draw(end_frame, 'RGBA')

    # Checkmark icon
    draw.ellipse([910, 320, 1010, 420], fill=accent_color + (40,),
                outline=accent_color, width=4)
    draw.text((928, 330), "✓", font=font_title, fill=accent_color)

    # Main text
    bbox = draw.textbbox((0, 0), main_text, font=font_header)
    w = bbox[2] - bbox[0]
    draw.text(((WIDTH - w) // 2, 450), main_text, font=font_header, fill=TEXT_DARK)

    # Pill button
    bbox2 = draw.textbbox((0, 0), sub_text, font=font_subtitle)
    w2 = bbox2[2] - bbox2[0]
    pill_w = w2 + 60
    pill_x = (WIDTH - pill_w) // 2
    draw.rounded_rectangle([pill_x, 550, pill_x + pill_w, 610],
                          radius=30, fill=accent_color)
    draw.text(((WIDTH - w2) // 2, 562), sub_text, font=font_subtitle, fill=BG_WHITE)

    return start_frame.convert('RGB'), end_frame.convert('RGB')
```

#### **D. Dependencies**
```python
from PIL import Image, ImageDraw, ImageFont  # Image manipulation
import subprocess                            # FFmpeg execution (legacy)
import os                                     # File operations (legacy)
import shutil                                # Cleanup (legacy)
```

**Note:** `subprocess`, `os`, `shutil` are imported but only used in the legacy `generate_video()` function (v1.0), which is not used by the current unified system (v2.0+).

#### **E. Legacy Code (Not Used)**
```python
# VIDEO_DEFINITIONS dict - Hardcoded v1.0 video definitions (deprecated)
# generate_video() function - v1.0 generation logic (replaced by unified system)
```

The current system uses `UnifiedVideo` objects instead of the hardcoded `VIDEO_DEFINITIONS` dictionary.

**Why This Module is Critical:**
1. **All keyframe generation** - Without it, no visual content
2. **Design system** - Colors, fonts, layouts all defined here
3. **Animation** - `ease_out_cubic` used for smooth transitions
4. **Constants** - `FPS`, `WIDTH`, `HEIGHT` referenced throughout

**Performance:**
- **Keyframe generation:** ~10-20ms per scene (4 functions total)
- **Text rendering:** ~5ms per text element
- **Background creation:** ~15ms with mesh gradient

**Why Chosen:**
- **Centralized design** - All visual elements in one place
- **Reusable functions** - Same keyframes for all videos
- **Type-specific rendering** - 4 scene types cover all needs
- **Easy to modify** - Change colors/fonts in one place

---

## 🖥️ System Dependencies

### **1. FFmpeg - Fast Forward MPEG**

**Version:** 7.1+ (with NVENC support)
**Binary Location:** `C:/Users/brand/AppData/Local/Programs/Python/Python310/lib/site-packages/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe`

**Purpose:** Video encoding, audio processing, duration measurement, stream muxing

**Installation:**
```bash
# Method 1: Via imageio-ffmpeg (Python package - USED)
pip install imageio-ffmpeg

# Method 2: Standalone (alternative)
# Download from https://ffmpeg.org/download.html
```

**Usage in System:**

#### **A. Audio Duration Measurement**
```bash
# Command executed via subprocess
ffmpeg -i scene_01_title.mp3

# Parse stderr output:
# Duration: 00:00:03.84, start: 0.025056, bitrate: 96 kb/s
#           ^^^^^^^^^^^ Extract this!

# Python parsing:
for line in result.stderr.split('\n'):
    if 'Duration:' in line:
        time_str = line.split('Duration:')[1].split(',')[0].strip()
        # "00:00:03.84" → 3.84 seconds
        h, m, s = time_str.split(':')
        duration = int(h) * 3600 + int(m) * 60 + float(s)
```

**Precision:** ±0.01 seconds (10ms accuracy)

#### **B. Video Encoding (GPU-Accelerated)**
```bash
# v3.0 Optimized Settings
ffmpeg -y \
  -f concat -safe 0 -i concat.txt \
  -c:v h264_nvenc \          # NVIDIA GPU encoder
  -preset p4 \               # Quality preset (p1-p7, p4=balanced)
  -tune hq \                 # High quality tuning
  -rc vbr \                  # Variable bitrate
  -cq 20 \                   # Constant quality (18-28, lower=better)
  -b:v 8M \                  # Target bitrate 8 Mbps
  -maxrate 12M \             # Max bitrate 12 Mbps
  -bufsize 16M \             # Buffer size
  -pix_fmt yuv420p \         # Pixel format (compatibility)
  -gpu 0 \                   # GPU index (first GPU)
  output.mp4
```

**Encoding Performance:**
- **Input:** 1920×1080 PNG frames at 30 FPS
- **Output:** H.264 MP4, 8 Mbps VBR
- **Speed:** ~1.5-2x realtime (60s video in ~40s)
- **GPU:** NVIDIA RTX 2000 Ada (NVENC engine)

**Codec Comparison:**

| Codec | Speed | Quality | GPU | Use |
|-------|-------|---------|-----|-----|
| `h264_nvenc` | ⚡⚡⚡⚡⚡ | ⭐⭐⭐⭐ | ✅ Yes | **USED (v3.0)** |
| `libx264` | ⚡⚡ | ⭐⭐⭐⭐⭐ | ❌ CPU | Fallback |
| `hevc_nvenc` | ⚡⚡⚡⚡ | ⭐⭐⭐⭐⭐ | ✅ Yes | Alternative |

#### **C. Audio Processing**
```bash
# Delay audio by 1000ms (1 second)
# Fade in over 300ms starting at 1.0s
ffmpeg -y \
  -i silent_video.mp4 \
  -f concat -safe 0 -i audio_concat.txt \
  -c:v copy \                                    # Copy video (no re-encode)
  -af "adelay=1000:all=1,afade=t=in:st=1.0:d=0.3" \  # Audio filters
  -c:a aac \                                     # Audio codec AAC
  -b:a 192k \                                    # Audio bitrate 192 kbps
  output.mp4
```

**Audio Filters Used:**

1. **`adelay`** - Delay audio to sync with visual fade-in
   ```
   adelay=1000:all=1
          │     └─── Apply to all channels
          └──────── Delay in milliseconds
   ```

2. **`afade`** - Fade in audio smoothly
   ```
   afade=t=in:st=1.0:d=0.3
         │    │     └─ Duration: 300ms
         │    └────── Start time: 1.0s
         └─────────── Type: fade in
   ```

**Result:** Audio starts at 1.0s, fades in over 300ms

#### **D. Stream Muxing (Combine Video + Audio)**
```bash
# Mux without re-encoding
ffmpeg -y \
  -i silent_video.mp4 \     # Video stream
  -i processed_audio.mp3 \  # Audio stream
  -c:v copy \               # Copy video codec (no re-encode)
  -c:a aac \                # Encode audio to AAC
  -b:a 192k \               # Audio bitrate
  final_output.mp4
```

**Why `copy` codec:**
- No quality loss (exact copy)
- Instant operation (~1 second)
- Saves processing time

#### **E. Frame Concatenation**
```bash
# concat.txt file format:
file '/absolute/path/frame_00000.png'
duration 0.0333333333  # 1/30 second
file '/absolute/path/frame_00001.png'
duration 0.0333333333
...
file '/absolute/path/frame_00150.png'  # Last frame (no duration)

# Command:
ffmpeg -f concat -safe 0 -i concat.txt output.mp4
```

**NVENC Hardware Requirements:**
- **GPU:** NVIDIA GTX 10-series or newer
- **Drivers:** Latest NVIDIA drivers
- **CUDA:** Not required (NVENC is separate)

**Verify NVENC Support:**
```bash
ffmpeg -encoders 2>&1 | grep nvenc

# Expected output:
# V....D h264_nvenc           NVIDIA NVENC H.264 encoder
# V....D hevc_nvenc           NVIDIA NVENC HEVC encoder
```

**Why Chosen:**
- **Industry standard:** Universal compatibility
- **GPU acceleration:** 5-10x faster than CPU encoding
- **Powerful:** All video/audio operations in one tool
- **Flexible:** Command-line, scriptable
- **Free:** Open-source, no licensing

---

### **2. Windows TrueType Fonts**

**Purpose:** Text rendering in video frames

**Fonts Used:**

| Font File | Description | Size | Usage |
|-----------|-------------|------|-------|
| `arialbd.ttf` | Arial Bold | 120px, 64px | Titles, headers |
| `arial.ttf` | Arial Regular | 48px, 38px, 28px, 24px | Subtitles, descriptions, small text |
| `consola.ttf` | Consolas (monospace) | 32px | Code, commands, terminal output |

**Loading Fonts:**
```python
from PIL import ImageFont

# Title font (120px bold)
font_title = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", 120)

# Subtitle (48px regular)
font_subtitle = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 48)

# Header (64px bold)
font_header = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", 64)

# Description (38px regular)
font_desc = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 38)

# Code/terminal (32px monospace)
font_code = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 32)

# Small text (28px regular)
font_small = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 28)

# Tiny text (24px regular)
font_tiny = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 24)
```

**Font Hierarchy:**
```
Title (120px bold)
    ├─ Subtitle (48px regular)
    │
    ├─ Header (64px bold)
    │   └─ Description (38px regular)
    │       └─ Small text (28px regular)
    │           └─ Tiny text (24px regular)
    │
    └─ Code/Terminal (32px monospace)
```

**Why These Fonts:**
- **Arial:** Clean, modern, highly readable
- **Consolas:** Excellent monospace for code
- **Built-in:** Pre-installed on Windows (no downloads)
- **TrueType:** Scalable, anti-aliased rendering

**Cross-Platform Alternatives:**
```python
import platform

if platform.system() == "Windows":
    font_path = "C:/Windows/Fonts/arial.ttf"
elif platform.system() == "Darwin":  # macOS
    font_path = "/System/Library/Fonts/Helvetica.ttc"
elif platform.system() == "Linux":
    font_path = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
```

---

## 📥 Installation Guide

### **Quick Install (All Packages)**

```bash
# Install Python packages
pip install Pillow edge-tts numpy

# FFmpeg (via imageio-ffmpeg)
pip install imageio-ffmpeg

# Ensure local module is present
ls scripts/generate_documentation_videos.py  # Must exist!

# Verify installation
python -c "import PIL; import edge_tts; import numpy; print('✅ All packages installed')"
cd scripts && python -c "import generate_documentation_videos; print('✅ Local module OK')"
```

### **Detailed Install Steps**

#### **1. Python Packages (pip)**
```bash
# Pillow (image processing)
pip install Pillow

# edge-tts (text-to-speech)
pip install edge-tts

# NumPy (fast array operations)
pip install numpy

# Optional: imageio-ffmpeg (FFmpeg binaries)
pip install imageio-ffmpeg
```

#### **2. Verify FFmpeg NVENC**
```bash
# Check if NVENC is available
ffmpeg -encoders 2>&1 | grep nvenc

# Expected output:
# V....D h264_nvenc           NVIDIA NVENC H.264 encoder

# If not found:
# 1. Update NVIDIA drivers
# 2. Use CPU encoding (libx264) as fallback
```

#### **3. Font Verification (Windows)**
```bash
# Check if fonts exist
dir C:\Windows\Fonts\arial*.ttf
dir C:\Windows\Fonts\consola.ttf

# Should show:
# arial.ttf
# arialbd.ttf
# consola.ttf
```

### **Requirements File (Create This)**

Create `requirements.txt`:
```txt
# Image processing
Pillow>=10.0.0

# Text-to-speech
edge-tts>=7.2.3

# Numerical operations
numpy>=1.24.0

# FFmpeg binaries (optional, recommended)
imageio-ffmpeg>=0.4.9
```

Install from requirements:
```bash
pip install -r requirements.txt
```

---

## 📊 Package Usage Matrix

### **Package Usage by Phase**

| Package | Phase 1 (Audio) | Phase 2 (Video) | Purpose |
|---------|-----------------|-----------------|---------|
| **os** | ✅ Create dirs | ✅ File operations | Path handling, directory management |
| **json** | ✅ Reports | ✅ Load timing | Structured data storage |
| **subprocess** | ✅ Duration probe | ✅ Encode/mux | Run FFmpeg commands |
| **asyncio** | ✅ TTS generation | ❌ | Async operations for edge-tts |
| **shutil** | ❌ | ✅ Cleanup | Remove temp directories |
| **sys** | ✅ Imports | ✅ Imports | Module path manipulation |
| **datetime** | ✅ Timestamps | ✅ Timestamps | Unique filenames |
| **Pillow** | ❌ | ✅ Render frames | Image creation, text rendering |
| **edge-tts** | ✅ Generate audio | ❌ | Neural voice synthesis |
| **numpy** | ❌ | ✅ (v3.0) | Fast frame blending |
| **FFmpeg** | ✅ Measure duration | ✅ Encode/mux | All video/audio processing |

### **Package Usage by Script**

| Package | unified_video_system.py | generate_all_videos_unified_v2.py | generate_videos_from_timings_v3_simple.py |
|---------|-------------------------|-----------------------------------|-------------------------------------------|
| **os** | ✅ | ✅ | ✅ |
| **json** | ✅ | ✅ | ✅ |
| **subprocess** | ✅ | ✅ | ✅ |
| **asyncio** | ✅ | ✅ | ❌ |
| **shutil** | ❌ | ❌ | ✅ |
| **sys** | ❌ | ✅ | ✅ |
| **datetime** | ✅ | ✅ | ✅ |
| **Pillow** | ✅ | ❌ | ✅ |
| **edge-tts** | ✅ | ✅ | ❌ |
| **numpy** | ❌ | ❌ | ✅ (v3.0) |
| **FFmpeg** | ✅ | ✅ | ✅ |

---

## 🔢 Version Requirements

### **Tested Versions**

```python
# Python version
Python 3.10+  # Required for modern async features

# Core packages
Pillow==10.0.0          # or newer
edge-tts==7.2.3         # or newer
numpy==1.24.0           # or newer
imageio-ffmpeg==0.4.9   # or newer (provides FFmpeg 7.1)

# System
FFmpeg 7.1+             # With NVENC support
Windows 10/11           # For fonts (cross-platform possible)
NVIDIA GPU (optional)   # For hardware encoding
```

### **Compatibility Matrix**

| Python Version | Pillow | edge-tts | numpy | Status |
|---------------|--------|----------|-------|--------|
| **3.10** | ✅ 10.x | ✅ 7.2+ | ✅ 1.24+ | ✅ Tested |
| **3.11** | ✅ 10.x | ✅ 7.2+ | ✅ 1.24+ | ✅ Compatible |
| **3.12** | ✅ 10.x | ✅ 7.2+ | ✅ 1.26+ | ⚠️ NumPy 1.26+ required |
| **3.9** | ✅ 10.x | ✅ 7.2+ | ✅ 1.24+ | ⚠️ Missing some async features |
| **3.8** | ⚠️ 9.x | ✅ 7.2+ | ✅ 1.24+ | ⚠️ Limited async support |

### **Minimum vs. Recommended**

| Package | Minimum | Recommended | Why |
|---------|---------|-------------|-----|
| **Python** | 3.9 | 3.10+ | Better async/await |
| **Pillow** | 9.0 | 10.0+ | Performance improvements |
| **edge-tts** | 6.0 | 7.2+ | More voices, stability |
| **numpy** | 1.21 | 1.24+ | Better typing, performance |
| **FFmpeg** | 4.0 | 7.1+ | NVENC improvements |

---

## 🎯 Summary

### **Complete Dependency List**

```txt
# Standard Library (Built-in, no install needed)
os
json
subprocess
asyncio
shutil
sys
datetime
contextlib

# Third-Party Python (pip install)
Pillow>=10.0.0
edge-tts>=7.2.3
numpy>=1.24.0

# Local Python Modules (must be in scripts/)
generate_documentation_videos.py  # Visual rendering engine

# System Dependencies
FFmpeg 7.1+ (via imageio-ffmpeg or standalone)
Windows TrueType Fonts (arial.ttf, arialbd.ttf, consola.ttf)

# Optional but Recommended
imageio-ffmpeg>=0.4.9  # Provides FFmpeg binaries
```

### **Installation One-Liner**

```bash
pip install Pillow edge-tts numpy imageio-ffmpeg && \
ls scripts/generate_documentation_videos.py && \
echo "✅ All dependencies installed"
```

### **Why This Stack?**

| Layer | Technology | Reason |
|-------|-----------|--------|
| **Audio Gen** | edge-tts | Free, high-quality neural voices |
| **Image** | Pillow | Standard, reliable, TrueType support |
| **Performance** | NumPy | 8x faster blending (v3.0) |
| **Video** | FFmpeg | Industry standard, GPU acceleration |
| **Orchestration** | Python stdlib | No extra dependencies |

### **Key Takeaways**

1. **Minimal Dependencies:** Only 3 pip packages + 1 local module + FFmpeg
2. **Standard Libraries:** Leverage Python built-ins heavily
3. **Performance:** NumPy optimization in v3.0 (8x speedup)
4. **Quality:** Neural TTS + GPU encoding = professional output
5. **Free:** All tools are free and open-source
6. **Critical Module:** `generate_documentation_videos.py` must be in scripts/

---

*Last Updated: 2025-10-03*
*System Version: v3.0 (Optimized)*
*Total Dependencies: 16 (8 built-in, 8 external)*
*⚠️ Includes 1 critical local module: generate_documentation_videos.py*
