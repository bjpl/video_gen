# Configuration Fixes - Quick Reference

**Quick checklist for fixing critical configuration issues in video_gen**

---

## CRITICAL Fixes (Do First)

### 1. Add python-dotenv to requirements.txt

```bash
# Edit requirements.txt, add after PyYAML:
python-dotenv>=1.0.0
```

### 2. Fix FFmpeg Path (video_gen/shared/config.py)

```python
# BEFORE (line 36-40):
self.ffmpeg_path = os.getenv(
    "FFMPEG_PATH",
    "C:/Users/brand/AppData/Local/Programs/Python/Python310/lib/site-packages/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe"
)

# AFTER:
import imageio_ffmpeg  # Add to imports at top

self.ffmpeg_path = os.getenv(
    "FFMPEG_PATH",
    imageio_ffmpeg.get_ffmpeg_exe()  # Cross-platform!
)
```

### 3. Fix FFmpeg Path (video_gen/video_generator/unified.py)

```python
# BEFORE (line 55):
FFMPEG_PATH = "C:/Users/brand/AppData/Local/Programs/Python/Python310/lib/site-packages/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe"

# AFTER:
import imageio_ffmpeg  # Add to imports at top
FFMPEG_PATH = os.getenv("FFMPEG_PATH", imageio_ffmpeg.get_ffmpeg_exe())
```

### 4. Remove googletrans (requirements.txt)

```bash
# Comment out or remove this line:
# googletrans==4.0.0-rc1  # CONFLICTS with httpx - use Claude API instead
```

---

## Update .env.example

Replace entire file with:

```bash
# ============================================================================
# Video Generation System - Environment Configuration
# ============================================================================

# ----------------------------------------------------------------------------
# AI Services
# ----------------------------------------------------------------------------

# Claude API for narration and translation (recommended)
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here

# OpenAI API (alternative)
# OPENAI_API_KEY=

# ----------------------------------------------------------------------------
# YouTube Integration (optional)
# ----------------------------------------------------------------------------
# YOUTUBE_API_KEY=

# ----------------------------------------------------------------------------
# Web UI
# ----------------------------------------------------------------------------
API_HOST=0.0.0.0
API_PORT=8000

# ----------------------------------------------------------------------------
# Defaults
# ----------------------------------------------------------------------------
TRANSLATION_METHOD=claude
DEFAULT_ACCENT_COLOR=blue
DEFAULT_VOICE=male

# ----------------------------------------------------------------------------
# Paths (optional - auto-detected if not set)
# ----------------------------------------------------------------------------
# VIDEO_GEN_OUTPUT_DIR=
# VIDEO_GEN_TEMP_DIR=
# FFMPEG_PATH=

# ----------------------------------------------------------------------------
# Performance
# ----------------------------------------------------------------------------
VIDEO_GEN_MAX_WORKERS=4
LOG_LEVEL=INFO
```

---

## Test After Changes

```bash
# 1. Reinstall dependencies
pip install -r requirements.txt

# 2. Verify FFmpeg detection works
python -c "from video_gen.shared.config import config; print(config.ffmpeg_path)"

# 3. Check for conflicts
pip check

# 4. Test basic functionality
python scripts/create_video_auto.py --help
```

---

## Optional: Update Web UI Dependencies

If you use the web UI (app/), update these versions:

```bash
# requirements.txt
fastapi>=0.115.0,<0.117.0      # was: >=0.109.0
uvicorn[standard]>=0.35.0      # was: >=0.27.0
pydantic>=2.7.4,<3.0.0         # was: implicitly older
```

Then reinstall:
```bash
pip install -r requirements.txt --upgrade
```

---

## Quick Validation Commands

```bash
# Check installed versions
pip list | grep -E "python-dotenv|fastapi|pydantic|anthropic|googletrans"

# Verify no googletrans installed (should show nothing or be commented)
pip show googletrans

# Test imports
python -c "from dotenv import load_dotenv; print('✓ dotenv works')"
python -c "import imageio_ffmpeg; print('✓ FFmpeg:', imageio_ffmpeg.get_ffmpeg_exe())"

# Full system check
python -c "from video_gen.shared.config import config; print('✓ Config loaded'); print('  FFmpeg:', config.ffmpeg_path); print('  Output:', config.output_dir)"
```

---

## Files Modified Summary

1. ✅ `requirements.txt` - Add python-dotenv, remove googletrans
2. ✅ `video_gen/shared/config.py` - Fix FFmpeg path
3. ✅ `video_gen/video_generator/unified.py` - Fix FFmpeg path
4. ✅ `.env.example` - Add all variables

**Total Changes:** 4 files, ~10 lines changed

**Time Required:** 10-15 minutes

---

## If Something Breaks

### Import Error: No module named 'dotenv'
```bash
pip install python-dotenv
```

### Import Error: No module named 'imageio_ffmpeg'
```bash
pip install imageio-ffmpeg
```

### FFmpeg not found
```bash
# Verify installation
python -c "import imageio_ffmpeg; print(imageio_ffmpeg.get_ffmpeg_exe())"

# If fails, manually set in .env:
echo "FFMPEG_PATH=/path/to/ffmpeg" >> .env
```

### Dependency conflicts after update
```bash
# Rollback if needed
pip install fastapi==0.109.2 uvicorn==0.27.1

# Or use virtual environment
python -m venv fresh_env
source fresh_env/bin/activate  # or fresh_env\Scripts\activate on Windows
pip install -r requirements.txt
```

---

**Last Updated:** 2025-10-05
