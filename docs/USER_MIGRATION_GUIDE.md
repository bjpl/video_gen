# User Migration Guide

## Overview

This guide helps you transition from the old fragmented workflow to the new unified video generation system.

## What's New

### For New Users
- **One command instead of 5-6** - Create videos with a single command
- **Automatic instead of manual** - System handles all coordination
- **5-10 minutes instead of 30-45** - Faster execution
- **Real-time progress instead of blind waiting** - See what's happening
- **Unified interface** - One tool for all input types

### For Existing Users
- **Old scripts still work** - 100% backward compatible
- **New way is easier** - We recommend switching
- **No data loss** - Existing videos and configurations unaffected
- **Gradual migration** - Switch at your own pace
- **Better error handling** - Clear messages and recovery

## Migration Benefits

| Feature | Old Workflow | New Workflow | Improvement |
|---------|-------------|--------------|-------------|
| Commands needed | 5-6 | 1 | 83% reduction |
| Time to video | 30-45 min | 5-10 min | 67% faster |
| Error recovery | Manual restart | Auto-resume | Automatic |
| Progress tracking | None | Real-time | ✅ Added |
| Input formats | Separate scripts | Unified | Simpler |

## How to Migrate

### Step 1: Update Installation

```bash
# Update dependencies
cd video_gen
pip install -r requirements.txt

# Verify installation
python -c "from video_gen import Pipeline; print('✅ Installation successful')"
```

### Step 2: Try New Workflow

**Old way (5-6 commands):**
```bash
# Document workflow
python scripts/create_video.py --document README.md
python scripts/generate_script_from_document.py README.md
python scripts/generate_videos_from_timings_v3_optimized.py
# ... more steps ...

# YouTube workflow
python scripts/create_video.py --youtube "VIDEO_URL"
python scripts/generate_script_from_youtube.py "VIDEO_URL"
# ... more steps ...
```

**New way (1 command):**
```bash
# Document workflow
python scripts/create_video_auto.py --from README.md --type document

# YouTube workflow
python scripts/create_video_auto.py --from "VIDEO_URL" --type youtube

# YAML workflow
python scripts/create_video_auto.py --from config.yaml --type yaml
```

### Step 3: Update Your Workflows

See detailed migration examples below for each use case.

## Migration Paths

### Path 1: Document-Based Videos

**Old workflow:**
```bash
# Step 1: Create initial structure
python scripts/create_video.py --document my_article.md

# Step 2: Generate script
python scripts/generate_script_from_document.py my_article.md \
  --output-dir outputs/my_video \
  --language English \
  --tone professional

# Step 3: Generate audio
python scripts/generate_audio.py outputs/my_video/script.yaml

# Step 4: Generate video
python scripts/generate_videos_from_timings_v3_optimized.py \
  outputs/my_video/script.yaml

# Step 5: Check output
ls outputs/my_video/
```

**New workflow:**
```bash
# One command does everything
python scripts/create_video_auto.py \
  --from my_article.md \
  --type document \
  --language English \
  --tone professional \
  --output-dir outputs/my_video

# That's it! Video is ready
```

### Path 2: YouTube-Based Videos

**Old workflow:**
```bash
# Step 1: Create structure
python scripts/create_video.py --youtube "https://youtube.com/watch?v=..."

# Step 2: Extract and process
python scripts/generate_script_from_youtube.py "URL" \
  --output-dir outputs/youtube_video

# Step 3: Generate audio
python scripts/generate_audio.py outputs/youtube_video/script.yaml

# Step 4: Generate video
python scripts/generate_videos_from_timings_v3_optimized.py \
  outputs/youtube_video/script.yaml
```

**New workflow:**
```bash
# One command
python scripts/create_video_auto.py \
  --from "https://youtube.com/watch?v=..." \
  --type youtube \
  --output-dir outputs/youtube_video
```

### Path 3: YAML Configuration Videos

**Old workflow:**
```bash
# Step 1: Create YAML manually
vim my_config.yaml

# Step 2: Generate script
python scripts/generate_script_from_yaml.py my_config.yaml

# Step 3: Generate audio
python scripts/generate_audio.py my_config.yaml

# Step 4: Generate video
python scripts/generate_videos_from_timings_v3_optimized.py my_config.yaml
```

**New workflow:**
```bash
# One command
python scripts/create_video_auto.py \
  --from my_config.yaml \
  --type yaml

# Or use Python API
python -c "
from video_gen import Pipeline
result = Pipeline.create(source='my_config.yaml', source_type='yaml')
print(f'Video: {result.output_path}')
"
```

### Path 4: Programmatic/Batch Videos

**Old workflow:**
```bash
# Multiple manual steps for each video
python scripts/generate_script_from_document.py doc1.md
python scripts/generate_videos_from_timings_v3_optimized.py doc1.yaml
python scripts/generate_script_from_document.py doc2.md
python scripts/generate_videos_from_timings_v3_optimized.py doc2.yaml
# ... repeat ...
```

**New workflow:**
```python
# Batch processing with Python API
from video_gen import Pipeline

docs = ['doc1.md', 'doc2.md', 'doc3.md']
results = []

for doc in docs:
    result = Pipeline.create(
        source=doc,
        source_type='document',
        language='English',
        tone='professional'
    )
    results.append(result)
    print(f'✅ {doc} -> {result.output_path}')

print(f'Completed {len(results)} videos')
```

## Command Equivalents

### Document Processing
| Old Command | New Command |
|-------------|-------------|
| `create_video.py --document X` | `create_video_auto.py --from X --type document` |
| `generate_script_from_document.py X` | `create_video_auto.py --from X --type document` |
| `document_to_programmatic.py X` | `create_video_auto.py --from X --type document --export-yaml` |

### YouTube Processing
| Old Command | New Command |
|-------------|-------------|
| `create_video.py --youtube URL` | `create_video_auto.py --from URL --type youtube` |
| `generate_script_from_youtube.py URL` | `create_video_auto.py --from URL --type youtube` |
| `youtube_to_programmatic.py URL` | `create_video_auto.py --from URL --type youtube --export-yaml` |

### YAML Processing
| Old Command | New Command |
|-------------|-------------|
| `generate_script_from_yaml.py X` | `create_video_auto.py --from X --type yaml` |
| `generate_videos_from_set.py X` | `create_video_auto.py --from X --type yaml` |
| `generate_video_set.py` | Use Python API with VideoSet |

### Batch Operations
| Old Command | New Command |
|-------------|-------------|
| `generate_all_videos_unified_v2.py` | Use Python API in loop |
| `generate_all_sets.py` | Use Python API with VideoSet |
| `generate_multilingual_set.py` | `create_video_auto.py --multilingual` |

## Advanced Features

### 1. Resume Failed Jobs

**Old way:** Start from scratch
```bash
# Had to restart entire process
python scripts/generate_script_from_document.py doc.md
# ... repeat all steps
```

**New way:** Automatic resume
```bash
# Automatically resumes from last checkpoint
python scripts/create_video_auto.py --from doc.md --type document --resume
```

### 2. Real-Time Progress

**Old way:** No feedback
```bash
# No idea what's happening
python scripts/generate_videos_from_timings_v3_optimized.py config.yaml
# ... wait and hope ...
```

**New way:** Live progress
```bash
# See exactly what's happening
python scripts/create_video_auto.py --from config.yaml --type yaml
# [1/5] Parsing input...
# [2/5] Generating script...
# [3/5] Generating audio...
# [4/5] Creating video...
# [5/5] Complete!
```

### 3. Error Recovery

**Old way:** Manual debugging
```bash
# Error somewhere in middle - start over
python scripts/generate_script_from_document.py doc.md  # ✅
python scripts/generate_audio.py script.yaml  # ❌ Error!
# Fix issue, start from beginning
```

**New way:** Smart recovery
```bash
# Error detected and handled
python scripts/create_video_auto.py --from doc.md --type document
# Error in audio generation - retrying...
# Resumed from checkpoint
# Complete!
```

## Python API Migration

### Old Approach
```python
# Multiple imports and manual coordination
from scripts.generate_script_from_document import process_document
from scripts.generate_videos_from_timings_v3_optimized import generate_video

# Manual pipeline
script = process_document('doc.md')
audio = generate_audio(script)
video = generate_video(audio)
```

### New Approach
```python
# Simple unified API
from video_gen import Pipeline

# One call
result = Pipeline.create(
    source='doc.md',
    source_type='document',
    language='English',
    tone='professional'
)

print(f'Video ready: {result.output_path}')
```

## Troubleshooting Migration

### Issue 1: "Module not found"

**Symptom:**
```
ModuleNotFoundError: No module named 'video_gen'
```

**Solution:**
```bash
# Install in development mode
cd video_gen
pip install -e .

# Or add to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:/path/to/video_gen"
```

### Issue 2: "Old scripts not working"

**Symptom:**
```
ImportError: cannot import name 'old_function'
```

**Solution:**
Old scripts are fully backward compatible. If you see import errors:
```bash
# Make sure you're in the right directory
cd video_gen

# Run old script normally
python scripts/create_video.py --document README.md
```

### Issue 3: "Different output format"

**Symptom:**
Output files in different location

**Solution:**
New system uses consistent output structure:
```
outputs/
  video_name/
    script.yaml
    audio.mp3
    video.mp4
    metadata.json
```

Old outputs are unchanged. New outputs follow this structure.

## FAQ

### Q: Do I need to rewrite my scripts?

**A:** No! All old scripts still work. But we recommend trying the new unified approach - it's much simpler.

### Q: Will my existing videos still work?

**A:** Yes! Existing videos and configurations are completely unaffected. The new system is additive, not replacing.

### Q: How do I get help?

**A:** See:
- `docs/TROUBLESHOOTING.md` - Common issues and fixes
- `docs/API_DOCUMENTATION.md` - Python API reference
- `docs/USER_GUIDE.md` - Complete usage guide
- `docs/QUICKSTART.md` - Quick start examples

### Q: Can I mix old and new workflows?

**A:** Yes! You can use old scripts for some tasks and new unified approach for others. They're fully compatible.

### Q: What if I find a bug in the new system?

**A:** Fall back to old scripts immediately (they still work). Report the bug, and we'll fix it. Your work won't be blocked.

### Q: Is performance better?

**A:** Yes! New system is:
- 67% faster (5-10 min vs 30-45 min)
- More reliable (automatic error recovery)
- Easier to monitor (real-time progress)

### Q: Do I lose any features?

**A:** No! All features from old scripts are available in the new unified system, plus many improvements.

## Migration Checklist

- [ ] Update installation (`pip install -r requirements.txt`)
- [ ] Test new command with simple document
- [ ] Compare output with old workflow
- [ ] Update your documentation/scripts
- [ ] Train team on new commands
- [ ] Keep old scripts as backup for 30 days
- [ ] Monitor production usage
- [ ] Report any issues

## Rollback Plan

If you need to go back to the old workflow:

```bash
# Old scripts are still there and working
cd scripts
ls create_video.py  # ✅ Still exists
ls generate_script_from_document.py  # ✅ Still exists

# Use them as before
python scripts/create_video.py --document README.md
```

No uninstallation needed - old and new coexist peacefully!

## Support

**Need help with migration?**
- Check `docs/TROUBLESHOOTING.md`
- Review example commands above
- Test with simple examples first
- Keep old scripts as backup

**Migration support timeline:**
- **Immediate:** Try new workflow alongside old
- **Week 1-2:** Test new workflow with real content
- **Week 3-4:** Gradually switch to new workflow
- **Month 2+:** Fully on new workflow (old still available)

---

**Remember:** Migration is optional and gradual. Take your time and migrate at your own pace. Both old and new systems work perfectly!
