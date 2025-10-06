# Configuration Audit Report - video_gen Project

**Date:** 2025-10-05
**Platform:** Windows 10, Python 3.10.11
**Project Location:** C:\Users\brand\Development\Project_Workspace\active-development\video_gen

---

## Executive Summary

The video_gen project has a generally well-structured configuration system with some critical issues requiring immediate attention:

- **CRITICAL:** Missing `python-dotenv` in requirements.txt (used but not declared)
- **CRITICAL:** Hardcoded Windows-specific FFmpeg path in production code
- **HIGH:** Multiple dependency conflicts affecting web UI stability
- **MEDIUM:** Duplicate configuration systems causing confusion
- **MEDIUM:** Excessive sys.path manipulation across 20+ files

---

## 1. Missing Dependencies

### CRITICAL: python-dotenv Not Declared

**Issue:** The package `python-dotenv` is used in multiple files but NOT listed in requirements.txt

**Files Using dotenv:**
```
video_gen/shared/config.py:8:    from dotenv import load_dotenv
app/main.py:30-32:              from dotenv import load_dotenv
                                load_dotenv()
                                load_dotenv(Path(__file__).parent / ".env")
```

**Current Status:**
- Installed: `python-dotenv==1.0.1` (via dependency, not direct)
- In requirements.txt: ❌ NOT LISTED

**Impact:**
- Users following installation instructions will get ImportError
- CI/CD pipelines will fail
- Docker builds will break

**Fix Required:**
```diff
# requirements.txt
+ # Environment configuration
+ python-dotenv>=1.0.0

  # Web UI dependencies (FastAPI + HTMX + Alpine.js)
  fastapi>=0.109.0
```

### MEDIUM: Optional Dependencies Not Clearly Marked

**Issue:** Some dependencies are listed as "optional" in comments but will be installed by default

```python
# requirements.txt lines 28-44
youtube-transcript-api>=0.6.0        # Should be optional
google-api-python-client>=2.100.0    # Marked optional but installed
googletrans==4.0.0-rc1               # Conflicts with other packages
```

**Recommendation:**
Create an optional dependencies file or use pip extras:

```python
# requirements.txt (core only)
Pillow>=10.0.0
edge-tts>=7.2.3
numpy>=1.24.0
# ... core deps only

# requirements-optional.txt
youtube-transcript-api>=0.6.0
google-api-python-client>=2.100.0
# Note: googletrans conflicts with httpx, use Claude API instead
```

---

## 2. Dependency Conflicts

### HIGH: Multiple Version Conflicts Detected

**Conflicts Found:**
```
chainlit 2.8.1 requires:
  - fastapi<0.117,>=0.116.1  (have: 0.109.2) ❌
  - pydantic<3,>=2.7.2       (have: 2.6.1)  ❌
  - uvicorn>=0.35.0          (have: 0.27.1) ❌

gradio 5.47.0 requires:
  - fastapi<1.0,>=0.115.2    (have: 0.109.2) ❌
  - starlette<1.0,>=0.40.0   (have: 0.36.3) ❌

googletrans 4.0.0rc1 requires:
  - httpx==0.13.3            (have: 0.28.1) ❌ MAJOR CONFLICT

langchain packages require:
  - pydantic>=2.7.4          (have: 2.6.1)  ❌
```

**Root Cause:**
- Project specifies older versions for stability
- External packages (chainlit, gradio) not directly used by video_gen
- googletrans pinned to ancient httpx version (0.13.3 from 2020)

**Impact on video_gen:**
- Web UI may have compatibility issues
- Translation service using googletrans will conflict
- Other packages using httpx will break

**Recommended Fix:**

1. **Drop googletrans** (already noted in app/requirements.txt):
```python
# requirements.txt
- googletrans==4.0.0-rc1
+ # googletrans removed due to httpx conflicts
+ # Use Claude API (anthropic) for high-quality translation
```

2. **Update core web UI dependencies** (if using app/):
```python
# requirements.txt
- fastapi>=0.109.0
+ fastapi>=0.115.0,<0.117.0

- uvicorn[standard]>=0.27.0
+ uvicorn[standard]>=0.35.0

- pydantic>=2.5.3
+ pydantic>=2.7.4,<3.0.0
```

3. **Separate app dependencies**:
```bash
# Keep main requirements.txt for core video generation
# Move web UI to requirements-web.txt
```

### MEDIUM: Outdated Packages

**Packages with newer versions available:**
```
agate: 1.9.1 -> 1.13.0
aiohttp: 3.9.3 -> 3.12.15
anthropic: 0.34.0 -> 0.69.0 (INSTALLED but requirements says >=0.34.0)
fastapi: 0.109.2 -> 0.115+ (held back intentionally)
```

**Note:** anthropic is already at 0.69.0 (good), just update minimum:
```diff
- anthropic>=0.34.0
+ anthropic>=0.69.0
```

---

## 3. Hardcoded Paths (CRITICAL)

### Windows-Specific FFmpeg Path in Production Code

**File:** `video_gen/video_generator/unified.py:55`
```python
# ❌ HARDCODED - Will break on other machines!
FFMPEG_PATH = "C:/Users/brand/AppData/Local/Programs/Python/Python310/lib/site-packages/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe"
```

**File:** `video_gen/shared/config.py:37-40`
```python
# ⚠️ BETTER but still hardcoded default
self.ffmpeg_path = os.getenv(
    "FFMPEG_PATH",
    "C:/Users/brand/AppData/Local/Programs/Python/Python310/lib/site-packages/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe"
)
```

**Impact:**
- ❌ Breaks on Linux/Mac
- ❌ Breaks on different Windows user accounts
- ❌ Breaks with different Python versions
- ❌ Not portable to Docker/CI

**Proper Solution:**

```python
# video_gen/shared/config.py
import imageio_ffmpeg

self.ffmpeg_path = os.getenv(
    "FFMPEG_PATH",
    imageio_ffmpeg.get_ffmpeg_exe()  # ✅ Cross-platform!
)
```

**Why this works:**
- imageio_ffmpeg is already in requirements.txt
- Automatically detects platform (Windows/Linux/Mac)
- Returns correct binary path for current system
- Verified working: `C:\Users\brand\AppData\Local\Programs\Python\Python310\lib\site-packages\imageio_ffmpeg\binaries\ffmpeg-win-x86_64-v7.1.exe`

### Windows-Specific Font Paths

**File:** `video_gen/shared/config.py:66-70`
```python
# ⚠️ Windows only - Will fail on Linux/Mac
self.fonts = {
    "title": "C:/Windows/Fonts/arialbd.ttf",
    "subtitle": "C:/Windows/Fonts/arial.ttf",
    "code": "C:/Windows/Fonts/consola.ttf",
}
```

**Recommended Fix:**
```python
import platform

def get_default_fonts():
    """Get platform-appropriate default fonts."""
    system = platform.system()

    if system == "Windows":
        return {
            "title": "C:/Windows/Fonts/arialbd.ttf",
            "subtitle": "C:/Windows/Fonts/arial.ttf",
            "code": "C:/Windows/Fonts/consola.ttf",
        }
    elif system == "Darwin":  # macOS
        return {
            "title": "/System/Library/Fonts/Helvetica.ttc",
            "subtitle": "/System/Library/Fonts/Helvetica.ttc",
            "code": "/System/Library/Fonts/Courier.dfont",
        }
    else:  # Linux
        return {
            "title": "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "subtitle": "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "code": "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        }

# In Config.__init__:
self.fonts = get_default_fonts()

# Allow override from environment
if custom_fonts := os.getenv("VIDEO_GEN_FONTS_JSON"):
    import json
    self.fonts.update(json.loads(custom_fonts))
```

---

## 4. Configuration Architecture Issues

### Duplicate Configuration Systems

**Problem:** Two separate Config classes doing similar things

1. **video_gen/config.py** (147 lines)
   - Modern dataclass-based approach
   - Uses pathlib.Path
   - Lazy initialization via get_config()
   - NOT imported by actual code

2. **video_gen/shared/config.py** (108 lines)
   - Singleton pattern
   - Hardcoded paths
   - Actually used by the codebase
   - Has Windows-specific issues

**Current Usage:**
```python
# This is what's actually imported everywhere:
from video_gen.shared.config import config

# This is unused:
from video_gen.config import get_config
```

**Recommendation:**
1. Merge into single configuration system
2. Use the better design from video_gen/config.py
3. Add cross-platform path detection from shared/config.py
4. Keep singleton pattern for convenience

### Missing .env.example Entries

**Current .env.example (19 lines):**
```bash
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
API_HOST=0.0.0.0
API_PORT=8000
TRANSLATION_METHOD=claude
DEFAULT_ACCENT_COLOR=blue
DEFAULT_VOICE=male
```

**Missing Important Variables:**
```bash
# Missing from .env.example:
FFMPEG_PATH=                    # Custom FFmpeg path (optional)
OPENAI_API_KEY=                 # OpenAI API (referenced in config.py)
VIDEO_GEN_OUTPUT_DIR=           # Custom output directory
VIDEO_GEN_TEMP_DIR=             # Custom temp directory
VIDEO_GEN_MAX_WORKERS=4         # Concurrent workers
LOG_LEVEL=INFO                  # Logging level
YOUTUBE_API_KEY=                # YouTube API (if using search)
VIDEO_GEN_FONTS_JSON=           # Custom font paths (JSON)
```

**Enhanced .env.example:**
```bash
# ============================================================================
# Video Generation System - Environment Configuration
# ============================================================================
# Copy this file to .env and customize for your environment

# ----------------------------------------------------------------------------
# AI Services (at least one recommended)
# ----------------------------------------------------------------------------

# Claude API for high-quality narration and translation (recommended)
# Get your key at: https://console.anthropic.com/
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here

# OpenAI API (alternative for narration)
# OPENAI_API_KEY=sk-...

# ----------------------------------------------------------------------------
# YouTube Integration (optional)
# ----------------------------------------------------------------------------

# YouTube Data API v3 key for video search
# Get at: https://console.cloud.google.com/
# YOUTUBE_API_KEY=

# ----------------------------------------------------------------------------
# Web UI Configuration
# ----------------------------------------------------------------------------

# FastAPI server settings
API_HOST=0.0.0.0
API_PORT=8000

# ----------------------------------------------------------------------------
# Video Generation Defaults
# ----------------------------------------------------------------------------

# Translation method: "claude" (high quality) or "google" (free, deprecated)
TRANSLATION_METHOD=claude

# Default visual style
DEFAULT_ACCENT_COLOR=blue  # Options: blue, purple, orange, green, pink, cyan
DEFAULT_VOICE=male         # Options: male, male_warm, female, female_friendly

# ----------------------------------------------------------------------------
# Paths & Directories (usually auto-detected, override if needed)
# ----------------------------------------------------------------------------

# Custom output directory (default: ./output)
# VIDEO_GEN_OUTPUT_DIR=/path/to/outputs

# Custom temp directory (default: ./temp)
# VIDEO_GEN_TEMP_DIR=/path/to/temp

# Custom FFmpeg binary path (default: auto-detected from imageio-ffmpeg)
# FFMPEG_PATH=/usr/bin/ffmpeg

# Custom fonts (JSON format, platform defaults used if not set)
# VIDEO_GEN_FONTS_JSON={"title": "/path/to/font.ttf", "subtitle": "...", "code": "..."}

# ----------------------------------------------------------------------------
# Performance & Logging
# ----------------------------------------------------------------------------

# Maximum concurrent workers for parallel processing (default: 4)
VIDEO_GEN_MAX_WORKERS=4

# Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_LEVEL=INFO

# ----------------------------------------------------------------------------
# Advanced Options
# ----------------------------------------------------------------------------

# Video resolution (default: 1920x1080)
# VIDEO_WIDTH=1920
# VIDEO_HEIGHT=1080

# Video framerate (default: 30)
# VIDEO_FPS=30
```

---

## 5. sys.path Manipulation Issues

### Excessive Path Manipulation (20+ files)

**Files Manipulating sys.path:**
```
video_gen/video_generator/unified.py:35
app/input_adapters/wizard.py:31
app/main.py:24,27
app/main_backup.py:21
app/services/video_service.py:22
app/utils.py:17
scripts/create_from_template.py:31
scripts/create_video_auto.py:39
... and 12+ more scripts
```

**Problems:**
- Fragile imports that break when run from different directories
- Hard to debug import errors
- Not compatible with proper packaging
- Inconsistent patterns (append vs insert, absolute vs relative)

**Root Cause:**
Project is not installed as a package, so scripts can't import video_gen normally.

**Recommended Fix:**

1. **Add setup.py or pyproject.toml:**
```python
# pyproject.toml
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "video_gen"
version = "2.0.0"
description = "Professional video generation system"
requires-python = ">=3.10"
dependencies = [
    "Pillow>=10.0.0",
    "edge-tts>=7.2.3",
    "numpy>=1.24.0",
    "imageio-ffmpeg>=0.4.9",
    "moviepy>=2.1.1",
    "PyYAML>=6.0",
    "requests>=2.31.0",
    "anthropic>=0.69.0",
    "python-dotenv>=1.0.0",
]

[project.optional-dependencies]
web = [
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.35.0",
    "jinja2>=3.1.3",
    "python-multipart>=0.0.6",
]
youtube = [
    "youtube-transcript-api>=0.6.0",
]
dev = [
    "pytest>=8.0.0",
    "pytest-asyncio>=0.23.0",
    "httpx>=0.26.0",
]

[project.scripts]
video-gen = "scripts.create_video_auto:main"
```

2. **Install in development mode:**
```bash
pip install -e .                    # Core
pip install -e ".[web,youtube,dev]" # All features
```

3. **Remove all sys.path manipulation:**
```python
# ❌ OLD (in every script):
sys.path.append('.')
sys.path.insert(0, str(project_root))

# ✅ NEW (nothing needed):
from video_gen.pipeline import get_pipeline
from scripts.translation_service import TranslationService
```

---

## 6. Environment-Specific Issues

### Python Version Dependency

**Current:** Python 3.10.11 (good)
**Requirements:** No explicit version specified

**Add to README.md:**
```markdown
## Requirements

- Python 3.10 or higher (tested on 3.10.11)
- FFmpeg (automatically installed via imageio-ffmpeg)
- Windows/Linux/macOS supported
```

**Add to pyproject.toml:**
```toml
requires-python = ">=3.10"
```

### Platform Detection

**Current:** No platform-specific handling except hardcoded Windows paths

**Recommended:**
Add platform detection utility:

```python
# video_gen/shared/platform_utils.py
import platform
from pathlib import Path
from typing import Dict

def get_platform_config() -> Dict[str, any]:
    """Get platform-specific configuration."""
    system = platform.system()

    config = {
        "system": system,
        "is_windows": system == "Windows",
        "is_macos": system == "Darwin",
        "is_linux": system == "Linux",
    }

    # Platform-specific paths
    if config["is_windows"]:
        config["temp_dir"] = Path(os.getenv("TEMP", "C:/Temp"))
        config["fonts_dir"] = Path("C:/Windows/Fonts")
    elif config["is_macos"]:
        config["temp_dir"] = Path("/tmp")
        config["fonts_dir"] = Path("/System/Library/Fonts")
    else:  # Linux
        config["temp_dir"] = Path("/tmp")
        config["fonts_dir"] = Path("/usr/share/fonts")

    return config
```

---

## 7. Version Pinning Strategy

### Current Strategy: Mixed

**Categories Found:**
1. **Exact pinning:** `googletrans==4.0.0-rc1`
2. **Minimum version:** `Pillow>=10.0.0`
3. **Range:** (none found)
4. **Unpinned:** (none found)

**Issues:**
- No maximum versions could lead to breaking changes
- Exact pins (googletrans) cause conflicts
- No lockfile for reproducible installs

**Recommended Strategy:**

1. **requirements.txt:** Minimum versions for compatibility
```python
Pillow>=10.0.0,<12.0.0
edge-tts>=7.2.3,<8.0.0
numpy>=1.24.0,<2.0.0
```

2. **requirements-lock.txt:** Exact versions for production
```bash
# Generate with:
pip freeze > requirements-lock.txt
```

3. **Use dependabot or renovate** for automated updates

---

## 8. Configuration Completeness

### .gitignore Analysis

**Current .gitignore:** Good coverage

✅ Ignores output files (audio/, videos/, *.mp4, *.mp3)
✅ Ignores Python artifacts (__pycache__, *.pyc)
✅ Ignores environment files (.env)
✅ Ignores IDE files (.vscode/, .idea/)

**Potential Addition:**
```gitignore
# Add these:
.translation_cache/   # From translation_service.py
output/state/         # State files from config
output/logs/          # Log files from config
*.coverage            # Coverage reports
htmlcov/              # Coverage HTML
.pytest_cache/        # Pytest cache
```

### Missing Documentation

**Files to Create:**

1. **CONFIGURATION.md** - Complete configuration reference
2. **DEPLOYMENT.md** - Production deployment guide
3. **TROUBLESHOOTING.md** - Common configuration issues

---

## Summary of Required Fixes

### CRITICAL (Must Fix Immediately)

1. ✅ **Add python-dotenv to requirements.txt**
   ```diff
   + python-dotenv>=1.0.0
   ```

2. ✅ **Fix FFmpeg path detection**
   ```python
   import imageio_ffmpeg
   self.ffmpeg_path = os.getenv("FFMPEG_PATH", imageio_ffmpeg.get_ffmpeg_exe())
   ```

3. ✅ **Remove or fix googletrans dependency**
   ```diff
   - googletrans==4.0.0-rc1
   + # googletrans removed due to conflicts - use Claude API
   ```

### HIGH Priority (Fix Soon)

4. ✅ **Update .env.example** with all variables
5. ✅ **Make fonts cross-platform**
6. ✅ **Resolve FastAPI/Pydantic version conflicts**
7. ✅ **Add setup.py or pyproject.toml**

### MEDIUM Priority (Cleanup)

8. ✅ **Merge duplicate Config classes**
9. ✅ **Remove sys.path manipulation**
10. ✅ **Update outdated packages**
11. ✅ **Add version pins (upper bounds)**
12. ✅ **Update .gitignore**

### LOW Priority (Nice to Have)

13. Create requirements-lock.txt
14. Add platform detection utilities
15. Document configuration in CONFIGURATION.md
16. Set up automated dependency updates

---

## Implementation Plan

### Phase 1: Critical Fixes (30 minutes)

```bash
# 1. Update requirements.txt
# 2. Fix FFmpeg path in video_gen/shared/config.py
# 3. Update .env.example
# 4. Test on Windows
```

### Phase 2: Dependency Cleanup (1 hour)

```bash
# 1. Remove googletrans
# 2. Update FastAPI/Pydantic versions
# 3. Test web UI
# 4. Update app/requirements.txt
```

### Phase 3: Architecture Improvements (2 hours)

```bash
# 1. Create pyproject.toml
# 2. Merge Config classes
# 3. Add platform detection
# 4. Remove sys.path hacks
# 5. Test installation: pip install -e .
```

### Phase 4: Documentation & Cleanup (1 hour)

```bash
# 1. Update .gitignore
# 2. Create CONFIGURATION.md
# 3. Update README.md with requirements
# 4. Generate requirements-lock.txt
```

---

## Testing Checklist

After implementing fixes:

- [ ] Fresh Python 3.10+ environment
- [ ] `pip install -r requirements.txt` works without errors
- [ ] All imports work without sys.path manipulation
- [ ] FFmpeg detection works: `python -c "from video_gen.shared.config import config; print(config.ffmpeg_path)"`
- [ ] Web UI starts: `uvicorn app.main:app`
- [ ] Video generation works: `python scripts/create_video_auto.py --help`
- [ ] No dependency conflicts: `pip check`
- [ ] Cross-platform test (if possible): Run on Linux/Mac VM

---

## Files Requiring Changes

### Immediate Changes Needed:

1. `requirements.txt` - Add python-dotenv, remove googletrans, update versions
2. `video_gen/shared/config.py` - Fix FFmpeg and font paths
3. `.env.example` - Add all environment variables
4. `video_gen/video_generator/unified.py` - Remove hardcoded FFmpeg path

### Recommended Changes:

5. `pyproject.toml` - NEW: Package metadata and dependencies
6. `video_gen/shared/platform_utils.py` - NEW: Platform detection
7. `.gitignore` - Add cache directories
8. `docs/CONFIGURATION.md` - NEW: Configuration documentation

### Files to Remove/Consolidate:

9. `video_gen/config.py` - Merge into shared/config.py or vice versa
10. All `sys.path.append/insert` statements - Remove after package install

---

**End of Configuration Audit Report**

Generated: 2025-10-05
Auditor: Claude Code Configuration Analysis Agent
Project: video_gen v2.0.0
