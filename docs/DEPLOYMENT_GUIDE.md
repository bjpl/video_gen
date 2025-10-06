# Deployment Guide - Auto-Orchestrator Video Generation System

## Overview

This guide covers deploying the auto-orchestrator system from initial setup to production use.

## System Requirements

### Hardware Requirements
- **CPU**: Multi-core processor (4+ cores recommended)
- **RAM**: 4GB minimum, 8GB+ recommended
- **Storage**: 2GB+ free space for dependencies and generated files
- **Network**: Internet connection for TTS and optional AI features

### Software Requirements
- **Python**: 3.8 or higher
- **FFmpeg**: Required for video encoding
- **Git**: For version control (optional)

## Installation Steps

### 1. Clone Repository (if applicable)

```bash
cd C:/Users/brand/Development/Project_Workspace/active-development/
git clone <repository-url> video_gen
cd video_gen
```

### 2. Install Python Dependencies

```bash
# Full installation (recommended)
pip install -r requirements.txt

# Minimal installation (without YouTube features)
pip install Pillow edge-tts numpy imageio-ffmpeg PyYAML requests
```

### 3. Verify FFmpeg Installation

FFmpeg is automatically installed via `imageio-ffmpeg`. Verify:

```bash
python -c "import imageio_ffmpeg; print(imageio_ffmpeg.get_ffmpeg_exe())"
```

### 4. Configure API Keys (Optional)

For AI-powered features (enhanced narration, translation):

**Windows:**
```batch
setx ANTHROPIC_API_KEY "your_key_here"
```

**Linux/Mac:**
```bash
export ANTHROPIC_API_KEY="your_key_here"
# Add to ~/.bashrc or ~/.zshrc for persistence
```

### 5. Verify Installation

```bash
# Check auto-orchestrator
python scripts/create_video_auto.py --help

# Run syntax check
python -m py_compile scripts/create_video_auto.py

# Run tests
pytest tests/test_auto_orchestrator.py -v
```

## Directory Structure

The system expects the following structure:

```
video_gen/
├── scripts/           # All Python scripts
│   ├── create_video_auto.py
│   ├── generate_script_from_document.py
│   └── ...
├── inputs/            # Input files (documents, YAML)
├── drafts/            # Generated YAML scripts
├── audio/             # Generated audio files
├── videos/            # Generated video files
├── tests/             # Test files
├── docs/              # Documentation
└── requirements.txt   # Dependencies
```

## First-Time Setup

### 1. Create Test Document

```bash
# Create a simple test file
echo "# Test Video

## Introduction
This is a test video.

## Key Point
Here's the main concept.

## Conclusion
Thanks for watching!" > inputs/test.md
```

### 2. Generate Your First Video

```bash
python scripts/create_video_auto.py --from inputs/test.md --type document
```

### 3. Verify Output

Check the following directories:
- `drafts/` - Generated YAML file
- `audio/` - Generated audio with timing
- `videos/` - Final video output

## Configuration Options

### Voice Options
- `male` - Standard male voice
- `male_warm` - Warm, friendly male voice
- `female` - Standard female voice
- `female_friendly` - Warm, friendly female voice

### Color Schemes
- `blue` - Professional blue theme
- `orange` - Energetic orange theme
- `purple` - Creative purple theme
- `green` - Natural green theme
- `pink` - Playful pink theme
- `cyan` - Tech-focused cyan theme

### Usage Examples

```bash
# Basic document conversion
python scripts/create_video_auto.py --from README.md --type document

# Custom voice and color
python scripts/create_video_auto.py --from README.md --type document \
    --voice female_friendly --color purple

# Longer video with AI narration
python scripts/create_video_auto.py --from guide.md --type document \
    --duration 180 --use-ai

# From existing YAML
python scripts/create_video_auto.py --from inputs/my_video.yaml --type yaml

# Interactive wizard
python scripts/create_video_auto.py --type wizard
```

## Troubleshooting

### Common Issues

#### 1. ImportError: No module named 'X'

**Solution:**
```bash
pip install -r requirements.txt
```

#### 2. FFmpeg not found

**Solution:**
```bash
pip install --upgrade imageio-ffmpeg
```

#### 3. Permission denied on Windows

**Solution:**
Run Command Prompt as Administrator or use:
```bash
python -m pip install --user -r requirements.txt
```

#### 4. Audio generation fails

**Cause:** Network issues with edge-tts service

**Solution:**
- Check internet connection
- Try again (service may be temporarily unavailable)
- Use VPN if blocked in your region

#### 5. YAML parsing errors

**Solution:**
Check YAML syntax:
```bash
python -c "import yaml; yaml.safe_load(open('inputs/file.yaml'))"
```

### Debug Mode

Run individual stages manually:

```bash
# Stage 1: Parse document
python scripts/generate_script_from_document.py inputs/test.md

# Stage 2: Generate script from YAML
python scripts/generate_script_from_yaml.py drafts/generated.yaml

# Stage 3: Generate audio
python scripts/generate_all_videos_unified_v2.py

# Stage 4: Generate video
python scripts/generate_videos_from_timings_v3_simple.py
```

## Production Deployment

### 1. Server Setup (Linux)

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install python3 python3-pip

# Install Python packages
pip3 install -r requirements.txt

# Set up service user
sudo useradd -m -s /bin/bash videogen
sudo chown -R videogen:videogen /opt/video_gen
```

### 2. Environment Variables

Create `/etc/environment.d/video_gen.conf`:

```bash
ANTHROPIC_API_KEY=your_key_here
VIDEO_OUTPUT_DIR=/var/video_gen/output
```

### 3. Systemd Service (Optional)

Create `/etc/systemd/system/video_gen.service`:

```ini
[Unit]
Description=Video Generation Service
After=network.target

[Service]
Type=simple
User=videogen
WorkingDirectory=/opt/video_gen
Environment="PYTHONUNBUFFERED=1"
ExecStart=/usr/bin/python3 scripts/web_server.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable video_gen
sudo systemctl start video_gen
```

### 4. Web UI Deployment

For web-based access:

```bash
# Install web dependencies
pip install fastapi uvicorn jinja2 python-multipart

# Run web server
python scripts/web_server.py --host 0.0.0.0 --port 8000
```

Access at: `http://your-server:8000`

### 5. Security Considerations

- **API Keys**: Store in environment variables, never in code
- **File Uploads**: Validate all file types and sizes
- **Network**: Use firewall to restrict access
- **Updates**: Keep dependencies updated regularly

```bash
# Check for security updates
pip list --outdated

# Update packages
pip install --upgrade -r requirements.txt
```

### 6. Monitoring

Monitor system health:

```bash
# Disk space
df -h /var/video_gen

# Process status
ps aux | grep python

# System resources
top -p $(pgrep -f create_video_auto)
```

## Backup and Recovery

### Backup Strategy

```bash
# Backup generated content
tar -czf backup_$(date +%Y%m%d).tar.gz \
    drafts/ audio/ videos/ inputs/

# Backup to remote
rsync -avz video_gen/ backup-server:/backups/video_gen/
```

### Recovery

```bash
# Restore from backup
tar -xzf backup_20250104.tar.gz

# Verify integrity
python scripts/create_video_auto.py --help
pytest tests/ -v
```

## Performance Optimization

### 1. Parallel Processing

For batch processing:

```bash
# Process multiple documents
for file in inputs/*.md; do
    python scripts/create_video_auto.py --from "$file" --type document --auto &
done
wait
```

### 2. Resource Limits

Configure Python memory limits:

```bash
# Limit memory usage
ulimit -v 4194304  # 4GB limit
python scripts/create_video_auto.py --from large_doc.md --type document
```

### 3. Cleanup Old Files

```bash
# Remove files older than 30 days
find videos/ -name "*.mp4" -mtime +30 -delete
find audio/ -type d -mtime +30 -exec rm -rf {} +
```

## Maintenance

### Regular Tasks

**Daily:**
- Check disk space
- Review error logs
- Verify service status

**Weekly:**
- Update dependencies
- Test backup restoration
- Review performance metrics

**Monthly:**
- Security audit
- Clean old files
- Update documentation

## Support and Resources

### Documentation
- [Quick Start Guide](../QUICK_START.md)
- [API Documentation](API_DESIGN.md)
- [Troubleshooting Guide](TROUBLESHOOTING_IMPORT_ERROR.md)

### Getting Help
1. Check error messages and logs
2. Review documentation
3. Run tests: `pytest tests/ -v`
4. Check GitHub issues (if applicable)

### Version Information

Current version: 3.0.0

**Changelog:**
- v3.0.0: Auto-orchestrator with unified pipeline
- v2.0.0: Multilingual support (28+ languages)
- v1.0.0: Initial release

## Next Steps

After successful deployment:

1. **Test thoroughly** - Run test suite
2. **Create sample videos** - Test all input types
3. **Monitor performance** - Check resource usage
4. **Train users** - Share quick start guide
5. **Plan maintenance** - Schedule regular updates

## Appendix

### A. Command Reference

```bash
# Help
python scripts/create_video_auto.py --help

# Document input
python scripts/create_video_auto.py --from FILE --type document

# YouTube input
python scripts/create_video_auto.py --from QUERY --type youtube

# YAML input
python scripts/create_video_auto.py --from FILE --type yaml

# Wizard mode
python scripts/create_video_auto.py --type wizard

# Options
--voice {male|female|male_warm|female_friendly}
--color {blue|orange|purple|green|pink|cyan}
--duration SECONDS
--use-ai
--output-dir DIR
--auto
```

### B. Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `ANTHROPIC_API_KEY` | Claude AI API key | No (for AI features) |
| `YOUTUBE_API_KEY` | YouTube Data API key | No (for YouTube search) |
| `VIDEO_OUTPUT_DIR` | Custom output directory | No |

### C. File Formats

**Supported Input:**
- Markdown (.md)
- Plain text (.txt)
- YAML (.yaml, .yml)
- YouTube URLs/queries

**Generated Output:**
- YAML scripts (.yaml)
- Audio files (.mp3)
- Video files (.mp4)
- Timing reports (.json)
