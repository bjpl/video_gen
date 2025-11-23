# 🚀 Getting Started with Video Gen

**From Zero to Your First Professional Video in 10 Minutes**

---

## ⚡ Quick Start Checklist

### **Step 1: Installation** (2 minutes)

```bash
# Clone repository
git clone https://github.com/bjpl/video_gen.git
cd video_gen

# Install dependencies
pip install -r requirements.txt
```

**✅ Installed:** Pillow, edge-tts, numpy, PyYAML, anthropic, and more

---

### **Step 2: Optional - API Key Setup** (1 minute)

**For AI-enhanced narration (recommended but optional):**

```bash
# Get API key: https://console.anthropic.com/account/keys

# Set environment variable
export ANTHROPIC_API_KEY="sk-ant-api03-YOUR_KEY_HERE"

# Verify
echo $ANTHROPIC_API_KEY
```

**Skip this step?** No problem! Template-based narration works great and is free.

---

### **Step 3: Choose Your Input Method** (5-15 minutes)

**Pick the method that matches your content source:**

#### **Option A: From Existing Documentation** (Fastest - 5 min)

```bash
# Parse your README or guide
python scripts/create_video.py --document README.md

# With AI narration (if API key set)
python scripts/create_video.py --document README.md --use-ai
```

---

#### **Option B: From YouTube Video** (Quick - 5 min)

```bash
# Create summary from YouTube tutorial
python scripts/create_video.py --youtube-url "https://youtube.com/watch?v=VIDEO_ID"

# With AI narration
python scripts/create_video.py --youtube-url "URL" --use-ai
```

---

#### **Option C: Interactive Wizard** (Guided - 10-15 min)

```bash
# Launch guided creation
python scripts/create_video.py --wizard

# With AI narration
python scripts/create_video.py --wizard --use-ai
```

**This asks you questions and generates everything!**

---

### **Step 4: Review Generated Script** (2-5 minutes)

```bash
# Check the generated narration
cat scripts/drafts/*_SCRIPT_*.md

# Example output:
# ## Scene 1: Title (3-8s)
# **Narration:**
# "My Video Title. Learn essential concepts quickly"
#
# **Word Count:** 7 words
# **Estimated:** 3.1s

# Happy with it? Continue to next step
# Want to edit? Modify the script, then continue
```

---

### **Step 5: Generate Audio** (30-90 seconds)

```bash
cd scripts

# Generate neural TTS audio + timing reports
python generate_all_videos_unified_v2.py

# You'll see:
# ✓ Generating audio for scene_01...
# ✓ Duration: 3.84s
# ✓ Timing report saved
```

**What just happened:**
- ✅ Professional neural TTS audio generated
- ✅ Exact durations measured
- ✅ Timing reports created (critical for perfect sync!)

---

### **Step 6: Generate Video** (2-5 minutes)

```bash
# Still in scripts/ directory
python generate_videos_from_timings_v3_simple.py

# You'll see:
# [1/1] Rendering keyframes...
# ✓ Encoding video with GPU...
# ✓ Complete: 12.3 MB, 45.2s
```

**What just happened:**
- ✅ Visual frames rendered (6 scene types)
- ✅ GPU-accelerated encoding (fast!)
- ✅ Perfect audio/visual synchronization
- ✅ Final video created!

---

### **Step 7: Watch Your Video!** (30 seconds)

```bash
# Windows
start ../videos/unified_v3_fast/*_with_audio_*.mp4

# Mac
open ../videos/unified_v3_fast/*_with_audio_*.mp4

# Linux
xdg-open ../videos/unified_v3_fast/*_with_audio_*.mp4
```

**🎉 You did it!** Professional video ready to share.

---

## 📊 What You Just Created

```
📹 my_video_45s_v2.0_with_audio_20251004_012345.mp4

Properties:
├─ Resolution: 1920x1080 (Full HD)
├─ Duration: 45 seconds (example)
├─ Video: H.264 (GPU NVENC)
├─ Audio: Neural TTS (Edge-TTS)
├─ Narration: Professional (template or AI)
├─ Sync: Perfect (±0.1s)
└─ Ready to: Share, upload, present!
```

---

## 🎓 Next Steps

### **Learn More:**

1. **Read input methods guide:**
   ```bash
   cat docs/THREE_INPUT_METHODS_GUIDE.md
   ```

2. **Try AI narration:**
   ```bash
   cat AI_NARRATION_QUICKSTART.md
   ```

3. **Explore scene types:**
   ```bash
   cat docs/NEW_SCENE_TYPES_GUIDE.md
   ```

4. **Learn voice mixing:**
   ```bash
   cat docs/VOICE_GUIDE_COMPLETE.md
   ```

### **Create More Videos:**

```bash
# Try all the examples
python scripts/create_video.py --yaml inputs/example_simple.yaml
python scripts/create_video.py --yaml inputs/example_new_scene_types.yaml
python scripts/create_video.py --yaml inputs/example_four_voices.yaml
```

### **Batch Processing (10-15 videos):**

```bash
# Parse multiple documents
for doc in my_docs/*.md; do
    python scripts/create_video.py --document "$doc"
done

# Generate all at once
cd scripts
python generate_all_videos_unified_v2.py
python generate_videos_from_timings_v3_optimized.py  # Parallel mode
```

---

## 🆘 Troubleshooting

### **"Import error: generate_documentation_videos"**

```bash
# Make sure you're in the right directory
cd video_gen/scripts
python create_video.py --help
```

### **"AI narration not working"**

```bash
# Check API key is set
echo $ANTHROPIC_API_KEY

# Install anthropic package
pip install anthropic

# System will fall back to templates if API fails (still works!)
```

### **"No NVENC encoder found"**

```bash
# Check GPU support
ffmpeg -encoders 2>&1 | grep nvenc

# If not found, system uses CPU encoding (slower but works)
```

### **"Audio generation failed"**

```bash
# Edge-TTS requires internet
# Check connection, then retry
```

---

## 🎯 Feature Overview

### **Complete Feature Matrix:**

| Feature | Count/Details | Status |
|---------|---------------|--------|
| **Input Methods** | 3 (docs, YouTube, wizard) | ✅ Working |
| **Scene Types** | 6 (title, command, list, outro, code_comparison, quote) | ✅ All tested |
| **Voices** | 4 (Andrew, Brandon, Aria, Ava) | ✅ Mix per scene |
| **Narration** | 2 modes (template/AI) | ✅ Choose per video |
| **Dependencies** | 20 total | ✅ All documented |
| **Documentation** | 12 guides (~30K words) | ✅ Comprehensive |
| **Examples** | 4 templates | ✅ Working |

---

## 💡 Pro Tips

### **1. Start Simple:**

Use template-based narration first:
```bash
python scripts/create_video.py --wizard
# No --use-ai flag = free, instant
```

Review the output. If narration quality is good → stick with it!

### **2. Use AI for Flagship Content:**

For important videos, add `--use-ai`:
```bash
python scripts/create_video.py --wizard --use-ai
# Better narration for ~$0.05
```

### **3. Hybrid Approach:**

```bash
# Generate 10 videos with templates (free)
for doc in docs/*.md; do
    python scripts/create_video.py --document "$doc"
done

# Regenerate 2-3 important ones with AI
python scripts/create_video.py --document docs/intro.md --use-ai
python scripts/create_video.py --document docs/flagship.md --use-ai

# Cost: $0.10-0.15 for the important ones
```

### **4. Mix Voices for Long Videos:**

```yaml
scenes:
  - voice: male              # Andrew - formal
  - voice: female            # Aria - technical
  - voice: male_warm         # Brandon - engaging
  - voice: female_friendly   # Ava - friendly
# Variety maintains engagement!
```

---

## 📚 Full Documentation Index

**Essential (Read First):**
1. This file (GETTING_STARTED.md)
2. AI_NARRATION_QUICKSTART.md
3. docs/THREE_INPUT_METHODS_GUIDE.md

**Reference:**
4. docs/NEW_SCENE_TYPES_GUIDE.md
5. docs/VOICE_GUIDE_COMPLETE.md
6. docs/COMPLETE_USER_WORKFLOW.md

**Technical:**
7. docs/PACKAGE_DOCUMENTATION.md
8. docs/WORKFLOW_VISUAL_OUTLINE.md
9. docs/AI_NARRATION_GUIDE.md

**Advanced:**
10. docs/SYSTEM_OVERVIEW_VISUAL.md
11. docs/TEMPLATE_SYSTEM_EXPLAINED.md
12. docs/INPUT_SYSTEM_DESIGN.md

---

## ✅ Verification

**Is everything working?**

```bash
# Check Python packages
python -c "import PIL, edge_tts, numpy, yaml; print('✅ Core packages OK')"

# Check optional packages
python -c "import anthropic; print('✅ AI narration available')"
# Or: ⚠️ AI package not installed (template mode only)

# Check FFmpeg
ffmpeg -version

# Check local modules
python -c "import sys; sys.path.append('scripts'); import generate_documentation_videos; print('✅ Modules OK')"

# All checks pass? You're ready! 🎉
```

---

## 🎬 Your First Video - Step by Step

### **Complete Example:**

```bash
# 1. Create simple YAML
cat > inputs/my_first_video.yaml << 'EOF'
video:
  title: "My First Video"
  accent_color: blue

scenes:
  - type: title
    title: "Hello World"
    subtitle: "My First Generated Video"
    key_message: "This is easier than I thought"

  - type: list
    header: "What I Learned"
    items:
      - "Installation was easy"
      - "Templates work great"
      - "Videos look professional"

  - type: outro
    main_text: "Ready for More!"
    sub_text: "See Documentation"
EOF

# 2. Generate script (with AI if you have API key)
python scripts/create_video.py --yaml inputs/my_first_video.yaml --use-ai

# 3. Review
cat scripts/drafts/*SCRIPT*.md

# 4. Generate
cd scripts
python generate_all_videos_unified_v2.py
python generate_videos_from_timings_v3_simple.py

# 5. Watch!
start ../videos/unified_v3_fast/*my_first_video*.mp4

# Done! 🎉
```

---

## 🎯 Success Criteria

**You're successful when:**

✅ You understand the 3 input methods
✅ You can create YAML input files
✅ You know the 6 scene types
✅ You've generated your first video
✅ Audio and video are perfectly synced
✅ You understand template vs AI narration

**Stuck? Read:** `docs/THREE_INPUT_METHODS_GUIDE.md`

---

**Welcome to professional video generation!**

*From idea to video in minutes.*

*Last Updated: 2025-10-03*
