# Troubleshooting Guide

## Quick Reference

### Common Issues

| Issue | Quick Fix | Details |
|-------|-----------|---------|
| Module not found | `pip install -e .` | [Link](#module-not-found-errors) |
| API key missing | Set environment variable | [Link](#api-key-issues) |
| Audio generation fails | Check OpenAI quota | [Link](#audio-generation-issues) |
| Video generation fails | Check video files exist | [Link](#video-generation-issues) |
| Progress hangs | Check error logs | [Link](#pipeline-hangs) |

---

## Installation Issues

### Module Not Found Errors

**Symptom:**
```
ModuleNotFoundError: No module named 'video_gen'
```

**Solutions:**

1. **Install in development mode:**
```bash
cd video_gen
pip install -e .
```

2. **Or add to PYTHONPATH:**
```bash
# Linux/Mac
export PYTHONPATH="${PYTHONPATH}:/path/to/video_gen"

# Windows
set PYTHONPATH=%PYTHONPATH%;C:\path\to\video_gen
```

3. **Verify installation:**
```bash
python -c "from video_gen import Pipeline; print('✅ Installed correctly')"
```

### Dependency Issues

**Symptom:**
```
ImportError: cannot import name 'X' from 'Y'
```

**Solutions:**

1. **Update all dependencies:**
```bash
pip install -r requirements.txt --upgrade
```

2. **Check Python version:**
```bash
python --version  # Should be 3.8+
```

3. **Reinstall specific package:**
```bash
pip uninstall problematic-package
pip install problematic-package
```

### Permission Errors

**Symptom:**
```
PermissionError: [Errno 13] Permission denied
```

**Solutions:**

1. **Run with user permissions:**
```bash
pip install --user -r requirements.txt
```

2. **Check file permissions:**
```bash
ls -la video_gen/
chmod +x scripts/*.py  # If needed
```

---

## Configuration Issues

### API Key Issues

**Symptom:**
```
Error: OpenAI API key not configured
```

**Solutions:**

1. **Set environment variable:**
```bash
# Linux/Mac
export OPENAI_API_KEY="sk-..."

# Windows
set OPENAI_API_KEY=sk-...

# Or in .env file
echo "OPENAI_API_KEY=sk-..." > .env
```

2. **Verify API key:**
```bash
python -c "import os; print('Key set:', bool(os.getenv('OPENAI_API_KEY')))"
```

3. **Check .env file location:**
```bash
# Should be in project root
ls -la .env
cat .env  # Verify contents
```

### Configuration File Issues

**Symptom:**
```
Error: Configuration file not found
```

**Solutions:**

1. **Check file path:**
```bash
ls -la config.yaml
# Or wherever your config is
```

2. **Use absolute path:**
```bash
python scripts/create_video_auto.py --from /full/path/to/config.yaml --type yaml
```

3. **Validate YAML syntax:**
```bash
python -c "import yaml; yaml.safe_load(open('config.yaml'))"
```

---

## Input Processing Issues

### Document Processing Fails

**Symptom:**
```
Error: Failed to parse document
```

**Solutions:**

1. **Check file encoding:**
```bash
file document.md  # Should be UTF-8
iconv -f ISO-8859-1 -t UTF-8 document.md > document_utf8.md
```

2. **Verify file exists:**
```bash
ls -la document.md
cat document.md  # Check contents
```

3. **Try with simple test:**
```bash
echo "# Test Document\n\nThis is a test." > test.md
python scripts/create_video_auto.py --from test.md --type document
```

### YouTube Processing Fails

**Symptom:**
```
Error: Failed to extract YouTube video
```

**Solutions:**

1. **Check video URL format:**
```bash
# Valid formats:
https://www.youtube.com/watch?v=VIDEO_ID
https://youtu.be/VIDEO_ID
```

2. **Verify video is public:**
- Open URL in browser
- Ensure not private/unlisted

3. **Check youtube-dl installation:**
```bash
pip install --upgrade youtube-dl
youtube-dl --version
```

### YAML Processing Fails

**Symptom:**
```
Error: Invalid YAML format
```

**Solutions:**

1. **Validate YAML syntax:**
```bash
python -c "import yaml; yaml.safe_load(open('config.yaml'))"
```

2. **Check indentation:**
```yaml
# CORRECT
videos:
  - name: "Video 1"
    scenes:
      - narration: "Scene 1"

# WRONG (tabs not allowed)
videos:
	- name: "Video 1"
```

3. **Use online validator:**
Visit: https://www.yamllint.com/

---

## Audio Generation Issues

### OpenAI API Quota Exceeded

**Symptom:**
```
Error: You exceeded your current quota
```

**Solutions:**

1. **Check quota:**
- Visit: https://platform.openai.com/account/usage
- Verify billing and limits

2. **Wait and retry:**
```bash
python scripts/create_video_auto.py --from document.md --type document --resume
```

3. **Use different API key:**
```bash
export OPENAI_API_KEY="sk-different-key"
```

### Audio Generation Hangs

**Symptom:**
Progress stops at "Generating audio..."

**Solutions:**

1. **Check API connection:**
```bash
curl https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY"
```

2. **Increase timeout:**
```python
# In config.py
AUDIO_TIMEOUT = 120  # Increase from 60
```

3. **Check network:**
```bash
ping api.openai.com
```

### Audio Quality Issues

**Symptom:**
Audio sounds distorted or wrong

**Solutions:**

1. **Check voice settings:**
```yaml
# In YAML config
voice: "alloy"  # Try: alloy, echo, fable, onyx, nova, shimmer
speed: 1.0      # Range: 0.25 - 4.0
```

2. **Verify audio file:**
```bash
ffprobe output/audio.mp3
```

3. **Test with simple text:**
```bash
echo "Test audio" | python scripts/generate_audio.py
```

---

## Video Generation Issues

### Video Files Missing

**Symptom:**
```
Error: Video file not found
```

**Solutions:**

1. **Check video paths:**
```bash
ls -la outputs/*/video.mp4
```

2. **Verify video URLs:**
```yaml
# In YAML config
scenes:
  - video_url: "file:///absolute/path/to/video.mp4"
```

3. **Download missing videos:**
```bash
youtube-dl "VIDEO_URL" -o "videos/%(title)s.%(ext)s"
```

### FFmpeg Not Found

**Symptom:**
```
Error: ffmpeg not found
```

**Solutions:**

1. **Install FFmpeg:**
```bash
# Ubuntu/Debian
sudo apt-get install ffmpeg

# Mac
brew install ffmpeg

# Windows
# Download from: https://ffmpeg.org/download.html
```

2. **Verify installation:**
```bash
ffmpeg -version
which ffmpeg
```

3. **Add to PATH:**
```bash
export PATH="/path/to/ffmpeg/bin:$PATH"
```

### Video Generation Fails

**Symptom:**
```
Error: Failed to generate video
```

**Solutions:**

1. **Check FFmpeg command:**
```bash
# Test FFmpeg manually
ffmpeg -i input.mp4 -i audio.mp3 -c:v copy -c:a aac output.mp4
```

2. **Verify input files:**
```bash
ffprobe input.mp4  # Check video
ffprobe audio.mp3  # Check audio
```

3. **Check disk space:**
```bash
df -h .
```

---

## Pipeline Issues

### Pipeline Hangs

**Symptom:**
Progress stops and nothing happens

**Solutions:**

1. **Check logs:**
```bash
tail -f video_gen.log
```

2. **Enable debug mode:**
```bash
export VIDEO_GEN_DEBUG=1
python scripts/create_video_auto.py --from doc.md --type document
```

3. **Check process:**
```bash
ps aux | grep python
top  # Check CPU/memory
```

### Resume Doesn't Work

**Symptom:**
```
Error: Cannot resume from checkpoint
```

**Solutions:**

1. **Check state file:**
```bash
ls -la .video_gen_state/
cat .video_gen_state/state.json
```

2. **Verify state format:**
```bash
python -c "import json; json.load(open('.video_gen_state/state.json'))"
```

3. **Start fresh:**
```bash
rm -rf .video_gen_state/
python scripts/create_video_auto.py --from doc.md --type document
```

### Events Not Firing

**Symptom:**
No progress updates shown

**Solutions:**

1. **Check event handler:**
```python
from video_gen import Pipeline

def on_progress(event):
    print(f"Progress: {event}")

result = Pipeline.create(
    source="doc.md",
    source_type="document",
    on_progress=on_progress
)
```

2. **Enable verbose logging:**
```bash
python scripts/create_video_auto.py --from doc.md --type document --verbose
```

---

## Performance Issues

### Slow Execution

**Symptom:**
Takes much longer than expected

**Solutions:**

1. **Check API latency:**
```bash
time curl https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY"
```

2. **Monitor resource usage:**
```bash
top
htop  # If available
```

3. **Check network speed:**
```bash
speedtest-cli
```

### High Memory Usage

**Symptom:**
Process uses excessive memory

**Solutions:**

1. **Reduce batch size:**
```python
# Process fewer scenes at once
BATCH_SIZE = 5  # Instead of 10
```

2. **Clear cache:**
```bash
rm -rf __pycache__/
rm -rf .pytest_cache/
```

3. **Monitor memory:**
```bash
# While running
watch -n 1 'ps aux | grep python'
```

---

## Error Messages Reference

### Common Error Messages

#### "Invalid input format"

**Cause:** Input file format not recognized
**Fix:** Specify correct `--type` parameter

```bash
# Correct
python scripts/create_video_auto.py --from doc.md --type document

# Not
python scripts/create_video_auto.py --from doc.md  # Missing type
```

#### "Stage validation failed"

**Cause:** Input doesn't meet requirements
**Fix:** Check validation errors in output

```bash
# See what's wrong
python scripts/create_video_auto.py --from doc.md --type document --verbose
```

#### "Output directory not writable"

**Cause:** No write permission to output directory
**Fix:** Change permissions or use different directory

```bash
chmod +w outputs/
# Or
python scripts/create_video_auto.py --from doc.md --type document --output-dir /tmp/videos
```

#### "Timeout waiting for response"

**Cause:** API call took too long
**Fix:** Increase timeout or check network

```python
# In config.py
API_TIMEOUT = 300  # Increase from 120
```

---

## Debug Mode

### Enable Debug Logging

```bash
# Method 1: Environment variable
export VIDEO_GEN_DEBUG=1

# Method 2: Command line
python scripts/create_video_auto.py --from doc.md --type document --debug

# Method 3: In code
import logging
logging.basicConfig(level=logging.DEBUG)
```

### View Debug Output

```bash
# Save to file
python scripts/create_video_auto.py --from doc.md --type document --debug > debug.log 2>&1

# View in real-time
tail -f debug.log
```

### Debug Specific Components

```python
import logging

# Debug only pipeline
logging.getLogger('video_gen.pipeline').setLevel(logging.DEBUG)

# Debug only audio generation
logging.getLogger('video_gen.audio_generator').setLevel(logging.DEBUG)
```

---

## Getting Help

### Before Asking for Help

1. **Check this guide** - Search for your error message
2. **Enable debug mode** - Get detailed error information
3. **Test with simple example** - Isolate the problem
4. **Check logs** - Review error messages carefully

### Information to Provide

When asking for help, include:

1. **Error message:**
```bash
python scripts/create_video_auto.py --from doc.md --type document 2>&1 | tee error.log
```

2. **System info:**
```bash
python --version
pip list | grep -E "(openai|fastapi|pydantic)"
ffmpeg -version
```

3. **Configuration:**
```bash
# Redact sensitive info
cat config.yaml | grep -v "api_key"
```

4. **Minimal reproduction:**
```bash
# Smallest command that causes the issue
python scripts/create_video_auto.py --from test.md --type document
```

### Support Resources

- **Documentation:** `docs/` directory
- **API Reference:** `docs/API_DOCUMENTATION.md`
- **User Guide:** `docs/USER_GUIDE.md`
- **Migration Guide:** `docs/USER_MIGRATION_GUIDE.md`

---

## Known Issues

### Issue 1: TestClient API Version

**Description:** Web UI integration tests fail with httpx version mismatch

**Workaround:** Tests pass in isolation, web UI works correctly

**Status:** Non-critical, manual testing performed

**Fix:** Update httpx dependency when new version available

### Issue 2: YouTube Download Rate Limiting

**Description:** YouTube may rate-limit download requests

**Workaround:** Add delays between downloads or use different IP

**Status:** Expected behavior from YouTube

**Fix:** Implement exponential backoff (planned)

---

## Quick Diagnostics

### Check System Health

```bash
# Run diagnostics
python scripts/check_system.py

# Or manually:
python --version              # Should be 3.8+
pip list | grep openai        # Should be installed
ffmpeg -version               # Should be installed
echo $OPENAI_API_KEY | wc -c  # Should be >0
ls -la outputs/               # Should exist and be writable
```

### Test Each Component

```bash
# Test input adapter
python -c "from video_gen.input_adapters import AdapterFactory; print('✅ Adapters OK')"

# Test pipeline
python -c "from video_gen.pipeline import PipelineOrchestrator; print('✅ Pipeline OK')"

# Test audio generator
python -c "from video_gen.audio_generator import UnifiedAudioGenerator; print('✅ Audio OK')"

# Test video generator
python -c "from video_gen.video_generator import UnifiedVideoGenerator; print('✅ Video OK')"
```

---

## Emergency Rollback

If the new system has issues, immediately use old scripts:

```bash
# Old workflow still works
cd scripts
python create_video.py --document README.md
python generate_script_from_document.py README.md
python generate_videos_from_timings_v3_optimized.py output.yaml
```

All old scripts remain functional as backup!

---

**Remember:** Most issues are configuration-related. Check API keys, file paths, and permissions first!
