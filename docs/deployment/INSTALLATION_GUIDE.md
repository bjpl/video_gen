# Installation Guide - Video Generation System

Complete installation instructions for all platforms and deployment scenarios.

## Table of Contents

- [System Requirements](#system-requirements)
- [Quick Installation](#quick-installation)
- [Platform-Specific Installation](#platform-specific-installation)
- [Docker Installation](#docker-installation)
- [Development Setup](#development-setup)
- [Troubleshooting](#troubleshooting)
- [Verification](#verification)

---

## System Requirements

### Minimum Requirements

- **Operating System**: Linux, macOS, Windows 10/11, or WSL2
- **Python**: 3.10 or higher
- **Memory**: 4 GB RAM
- **Storage**: 2 GB free space (10+ GB recommended for video outputs)
- **Internet**: Required for initial setup and TTS voice downloads

### Recommended Requirements

- **Python**: 3.12+
- **Memory**: 8 GB RAM or higher
- **GPU**: NVIDIA GPU with NVENC support (5-10x faster encoding)
- **Storage**: SSD with 20+ GB free space
- **CPU**: 4+ cores for parallel processing

### Dependencies

**Core Dependencies (Auto-installed):**
- FFmpeg (with NVENC support for GPU acceleration)
- Pillow >= 11.3.0
- edge-tts >= 7.2.3
- numpy >= 1.24.0
- moviepy >= 2.1.1
- PyYAML >= 6.0.3
- anthropic >= 0.71.0 (optional, for AI features)

**Optional Dependencies:**
- Docker (for containerized deployment)
- NVIDIA Docker (for GPU support in containers)

---

## Quick Installation

### 1. Clone Repository

```bash
git clone https://github.com/bjpl/video_gen.git
cd video_gen
```

### 2. Install Python Dependencies

```bash
# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Verify Installation

```bash
# Check Python modules
python -c "import PIL, edge_tts, numpy, yaml; print('✅ Core packages OK')"

# Check FFmpeg
ffmpeg -version

# Test video generation
python scripts/create_video.py --help
```

### 4. Optional: Configure AI Features

```bash
# Set Anthropic API key for AI-enhanced narration
export ANTHROPIC_API_KEY="sk-ant-api03-YOUR_KEY_HERE"

# Verify
python -c "import anthropic; print('✅ AI features available')"
```

**Success!** You're ready to create videos.

---

## Platform-Specific Installation

### Linux (Ubuntu/Debian)

```bash
# Update package lists
sudo apt-get update

# Install Python and FFmpeg
sudo apt-get install -y python3 python3-pip python3-venv ffmpeg

# Clone and install
git clone https://github.com/bjpl/video_gen.git
cd video_gen
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# For NVIDIA GPU support
# sudo apt-get install nvidia-cuda-toolkit
```

### macOS

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python and FFmpeg
brew install python@3.12 ffmpeg

# Clone and install
git clone https://github.com/bjpl/video_gen.git
cd video_gen
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Windows

#### Option A: Native Windows

```powershell
# Install Python from python.org (3.10+)
# Download and install FFmpeg from https://www.gyan.dev/ffmpeg/builds/

# Add FFmpeg to PATH (System Properties > Environment Variables)

# Clone and install
git clone https://github.com/bjpl/video_gen.git
cd video_gen
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

#### Option B: WSL2 (Recommended)

```bash
# Install WSL2 and Ubuntu from Microsoft Store

# In Ubuntu terminal:
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv ffmpeg
git clone https://github.com/bjpl/video_gen.git
cd video_gen
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Docker Installation

### Prerequisites

- Docker 20.10+ installed
- Docker Compose 2.0+ installed
- (Optional) NVIDIA Docker for GPU support

### Standard Deployment

```bash
# Clone repository
git clone https://github.com/bjpl/video_gen.git
cd video_gen

# Copy environment configuration
cp .env.example .env
# Edit .env with your settings (optional)

# Build and start
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f video-gen

# Access web UI at http://localhost:8000
```

### GPU-Accelerated Deployment

```bash
# Install NVIDIA Docker
distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
curl -s -L https://nvidia.github.io/nvidia-docker/gpgkey | sudo apt-key add -
curl -s -L https://nvidia.github.io/nvidia-docker/$distribution/nvidia-docker.list | sudo tee /etc/apt/sources.list.d/nvidia-docker.list
sudo apt-get update && sudo apt-get install -y nvidia-docker2
sudo systemctl restart docker

# Edit docker-compose.yml and uncomment GPU section
# Then start with GPU support
docker-compose up -d
```

### Docker CLI Mode

```bash
# Build image
docker build -t video-gen:latest .

# Run CLI commands
docker run --rm video-gen python scripts/create_video.py --help

# Run with volume mounts
docker run --rm \
  -v $(pwd)/inputs:/app/inputs:ro \
  -v $(pwd)/outputs:/app/outputs \
  video-gen python scripts/create_video.py --document /app/inputs/README.md

# Run web UI
docker run -d -p 8000:8000 \
  -v $(pwd)/outputs:/app/outputs \
  --name video-gen-app \
  video-gen
```

---

## Development Setup

### For Contributors and Advanced Users

```bash
# Clone with development branches
git clone https://github.com/bjpl/video_gen.git
cd video_gen
git checkout develop  # Or feature branch

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install with development dependencies
pip install -r requirements.txt
pip install pytest pytest-cov pytest-asyncio black flake8 mypy

# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Run tests
pytest tests/ -v

# Run with coverage
pytest --cov=video_gen --cov=app --cov-report=html

# Format code
black video_gen/ app/ scripts/

# Type checking
mypy video_gen/
```

### IDE Setup

#### VS Code

```json
// .vscode/settings.json
{
  "python.defaultInterpreterPath": "${workspaceFolder}/venv/bin/python",
  "python.testing.pytestEnabled": true,
  "python.testing.pytestArgs": ["tests"],
  "python.formatting.provider": "black",
  "python.linting.enabled": true,
  "python.linting.flake8Enabled": true,
  "editor.formatOnSave": true
}
```

#### PyCharm

1. Open project in PyCharm
2. Configure Python interpreter: Settings > Project > Python Interpreter > Add > Virtual Environment
3. Select existing venv or create new
4. Mark directories:
   - `video_gen/` as Sources Root
   - `tests/` as Test Sources Root
5. Configure pytest: Settings > Tools > Python Integrated Tools > Testing > pytest

---

## Troubleshooting

### Common Issues

#### "ModuleNotFoundError: No module named 'PIL'"

```bash
# Virtual environment not activated
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Or reinstall Pillow
pip install --upgrade Pillow>=11.3.0
```

#### "FFmpeg not found"

```bash
# Check FFmpeg installation
ffmpeg -version

# If not found:
# Ubuntu/Debian: sudo apt-get install ffmpeg
# macOS: brew install ffmpeg
# Windows: Download from https://www.gyan.dev/ffmpeg/builds/
#          Add to PATH in System Environment Variables
```

#### "No NVENC encoder found"

```bash
# Check GPU support
ffmpeg -encoders 2>&1 | grep nvenc

# If empty, you have no GPU support (CPU encoding will work but slower)
# To enable: Install NVIDIA drivers and CUDA toolkit
# Ubuntu: sudo apt-get install nvidia-cuda-toolkit
```

#### "edge-tts voice download fails"

```bash
# Requires internet connection
# Check connectivity
ping google.com

# If behind proxy, set:
export HTTP_PROXY=http://proxy:port
export HTTPS_PROXY=http://proxy:port

# Test voice download
python -c "import asyncio; from edge_tts import Communicate; asyncio.run(Communicate('test').save('test.mp3')); print('✅ TTS working')"
```

#### "Anthropic API error"

```bash
# Check API key is set
echo $ANTHROPIC_API_KEY

# Verify key format (should start with sk-ant-api03-)
# Get new key at: https://console.anthropic.com/

# Test API
python -c "from anthropic import Anthropic; client = Anthropic(); print('✅ API key valid')"

# System will fall back to template narration if API fails
```

#### "Permission denied" errors

```bash
# Linux/macOS: Fix permissions
chmod +x scripts/*.py
sudo chown -R $USER:$USER video_gen/

# Windows: Run as Administrator or adjust folder permissions
```

#### "Out of memory" during video generation

```bash
# Reduce video resolution in config
# Or increase system RAM
# Or process scenes individually instead of parallel

# Edit config or use environment variable:
export PARALLEL_PROCESSING=false
```

### Docker Issues

#### "Cannot connect to Docker daemon"

```bash
# Start Docker service
sudo systemctl start docker  # Linux
# Or start Docker Desktop (Windows/Mac)

# Add user to docker group (Linux)
sudo usermod -aG docker $USER
# Log out and back in
```

#### "Port 8000 already in use"

```bash
# Find process using port
lsof -i :8000  # Linux/macOS
netstat -ano | findstr :8000  # Windows

# Kill process or use different port
docker-compose down
# Edit docker-compose.yml or .env to change PORT
docker-compose up -d
```

---

## Verification

### System Check Script

```bash
# Create verification script
cat > verify_install.sh << 'EOF'
#!/bin/bash
echo "=== Video Gen Installation Verification ==="
echo ""

# Python version
echo -n "Python version: "
python3 --version || echo "❌ Python not found"

# Virtual environment
if [ -d "venv" ]; then
    echo "✅ Virtual environment found"
else
    echo "⚠️  Virtual environment not found (optional)"
fi

# Core packages
echo -n "Core packages: "
python3 -c "import PIL, edge_tts, numpy, yaml, moviepy" 2>/dev/null && echo "✅" || echo "❌"

# AI package
echo -n "AI features: "
python3 -c "import anthropic" 2>/dev/null && echo "✅" || echo "⚠️  Optional"

# FFmpeg
echo -n "FFmpeg: "
ffmpeg -version >/dev/null 2>&1 && echo "✅" || echo "❌"

# NVENC support
echo -n "GPU encoding: "
ffmpeg -encoders 2>&1 | grep -q nvenc && echo "✅ NVENC available" || echo "⚠️  CPU encoding only"

# API key
echo -n "AI API key: "
[ -n "$ANTHROPIC_API_KEY" ] && echo "✅ Set" || echo "⚠️  Not set (optional)"

echo ""
echo "=== Verification Complete ==="
EOF

chmod +x verify_install.sh
./verify_install.sh
```

### Test Generation

```bash
# Quick test with example file
python scripts/create_video.py --yaml inputs/example_simple.yaml

# If successful, you should see:
# ✅ Script generated
# ✅ Audio generated
# ✅ Video rendered
# Output: videos/unified_v3_fast/example_simple_*.mp4
```

---

## Next Steps

After successful installation:

1. **Read Quick Start Guide**: `docs/guides/GETTING_STARTED.md`
2. **Try Examples**: `python scripts/create_video.py --yaml inputs/example_simple.yaml`
3. **Configure AI Features**: Set `ANTHROPIC_API_KEY` for enhanced narration
4. **Explore Documentation**: See `docs/guides/START_HERE.md`
5. **Run Tests**: `pytest tests/ -v` to verify all components

---

## Support

- **Documentation**: Full docs in `docs/` directory
- **Issues**: Report bugs at https://github.com/bjpl/video_gen/issues
- **Examples**: See `inputs/` directory for YAML templates
- **Community**: GitHub Discussions

---

**Installation complete!** You're ready to generate professional videos.

*Last Updated: November 27, 2025*
