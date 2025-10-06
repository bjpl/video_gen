# Critical Configuration Patches

**Ready-to-apply code changes for critical configuration issues**

---

## Patch 1: requirements.txt

**File:** `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\requirements.txt`

**Change:** Add python-dotenv after line 20 (after PyYAML)

```diff
 # YAML parsing (input files)
 PyYAML>=6.0

+# Environment configuration
+python-dotenv>=1.0.0
+
 # HTTP requests (document fetching)
 requests>=2.31.0
```

**And remove/comment googletrans (line 44):**

```diff
 # Alternative translation (free fallback)
-googletrans==4.0.0-rc1
+# googletrans==4.0.0-rc1  # Removed: Conflicts with httpx. Use Claude API instead.
```

---

## Patch 2: video_gen/shared/config.py

**File:** `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\video_gen\shared\config.py`

**Change 1:** Add imageio_ffmpeg import (after line 7)

```diff
 import os
 from pathlib import Path
 from typing import Dict, Any, Optional
 from dotenv import load_dotenv
+import imageio_ffmpeg
```

**Change 2:** Fix FFmpeg path detection (lines 36-40)

```diff
         # FFmpeg configuration
-        self.ffmpeg_path = os.getenv(
-            "FFMPEG_PATH",
-            "C:/Users/brand/AppData/Local/Programs/Python/Python310/lib/site-packages/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe"
-        )
+        self.ffmpeg_path = os.getenv(
+            "FFMPEG_PATH",
+            imageio_ffmpeg.get_ffmpeg_exe()  # Cross-platform auto-detection
+        )
```

**Change 3:** Make fonts cross-platform (lines 65-70)

```diff
+        # Platform-specific font paths
+        import platform
+        system = platform.system()
+
-        # Font paths (Windows)
-        self.fonts = {
-            "title": "C:/Windows/Fonts/arialbd.ttf",
-            "subtitle": "C:/Windows/Fonts/arial.ttf",
-            "code": "C:/Windows/Fonts/consola.ttf",
-        }
+        if system == "Windows":
+            self.fonts = {
+                "title": "C:/Windows/Fonts/arialbd.ttf",
+                "subtitle": "C:/Windows/Fonts/arial.ttf",
+                "code": "C:/Windows/Fonts/consola.ttf",
+            }
+        elif system == "Darwin":  # macOS
+            self.fonts = {
+                "title": "/System/Library/Fonts/Helvetica.ttc",
+                "subtitle": "/System/Library/Fonts/Helvetica.ttc",
+                "code": "/System/Library/Fonts/Courier.dfont",
+            }
+        else:  # Linux
+            self.fonts = {
+                "title": "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
+                "subtitle": "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
+                "code": "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
+            }
```

---

## Patch 3: video_gen/video_generator/unified.py

**File:** `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\video_gen\video_generator\unified.py`

**Change 1:** Add imageio_ffmpeg import (after line 24)

```diff
 import subprocess
 import shutil
 import numpy as np
+import imageio_ffmpeg
 from PIL import Image
 from pathlib import Path
```

**Change 2:** Fix FFmpeg path (line 55)

```diff
 # Constants
 TRANSITION_DURATION = 0.5
 ANIM_DURATION = 1.0
-FFMPEG_PATH = "C:/Users/brand/AppData/Local/Programs/Python/Python310/lib/site-packages/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe"
+FFMPEG_PATH = os.getenv("FFMPEG_PATH", imageio_ffmpeg.get_ffmpeg_exe())
```

**Note:** You'll also need to add `import os` at the top if it's not already there (it should be at line 21).

---

## Patch 4: .env.example (Complete Replacement)

**File:** `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\.env.example`

**Replace entire file with:**

```bash
# ============================================================================
# Video Generation System - Environment Configuration
# ============================================================================
# Copy this file to .env and fill in your values

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

# Translation method: "claude" (high quality) or "google" (deprecated)
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

## Patch 5: Update .gitignore

**File:** `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\.gitignore`

**Add after line 56 (.env):**

```diff
 !examples/**/*.mp3
 .env
+
+# Translation cache
+.translation_cache/
+
+# State and logs
+output/state/
+output/logs/
+
+# Testing artifacts
+.coverage
+htmlcov/
+.pytest_cache/
```

---

## Application Order

Apply patches in this order:

1. ✅ Patch 1: requirements.txt
2. ✅ Patch 2: video_gen/shared/config.py
3. ✅ Patch 3: video_gen/video_generator/unified.py
4. ✅ Patch 4: .env.example
5. ✅ Patch 5: .gitignore

Then run:

```bash
# Reinstall dependencies
pip install -r requirements.txt

# Verify changes
python -c "from video_gen.shared.config import config; print('✓ Config OK'); print('FFmpeg:', config.ffmpeg_path)"

# Check for conflicts
pip check
```

---

## Rollback Instructions

If anything breaks, you can rollback:

```bash
# Rollback all changes
git checkout requirements.txt
git checkout video_gen/shared/config.py
git checkout video_gen/video_generator/unified.py
git checkout .env.example
git checkout .gitignore

# Reinstall original dependencies
pip install -r requirements.txt
```

---

## Expected Results After Patches

### Before Patches:
```
❌ python-dotenv missing from requirements
❌ Hardcoded Windows path in 2 files
❌ googletrans conflicts with httpx
❌ Will fail on Linux/Mac
❌ pip check shows 15+ conflicts
```

### After Patches:
```
✅ python-dotenv in requirements.txt
✅ FFmpeg auto-detected cross-platform
✅ googletrans removed (no conflicts)
✅ Works on Windows/Linux/Mac
✅ pip check clean (or only external package conflicts)
✅ Fonts work on all platforms
```

---

## Testing Checklist

After applying all patches:

- [ ] `pip install -r requirements.txt` completes without errors
- [ ] `python -c "from dotenv import load_dotenv"` works
- [ ] `python -c "from video_gen.shared.config import config; print(config.ffmpeg_path)"` shows correct path
- [ ] FFmpeg path does NOT contain "brand" or hardcoded user path
- [ ] `pip check` shows no googletrans conflicts
- [ ] `pip show googletrans` shows nothing or is commented in requirements
- [ ] Video generation test: `python scripts/create_video_auto.py --help`

---

**Created:** 2025-10-05
**Status:** Ready to Apply
**Risk Level:** Low (only configuration changes, no logic changes)
**Estimated Time:** 15 minutes
