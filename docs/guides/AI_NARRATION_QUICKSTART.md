# 🤖 AI Narration - Quick Start

**Enhanced Narration with Claude API - Setup in 2 Minutes**

---

## ⚡ Quick Setup

```bash
# 1. Install anthropic package
pip install anthropic

# 2. Get your API key
# Visit: https://console.anthropic.com/account/keys
# Create new key, copy it

# 3. Set environment variable
export ANTHROPIC_API_KEY="sk-ant-api03-YOUR_KEY_HERE"

# 4. Use AI narration
python scripts/create_video.py --yaml inputs/example_simple.yaml --use-ai
```

**That's it!** AI-enhanced narration is now active.

---

## 🎯 When to Use AI vs Templates

### **Use Templates (Free, Default):**

✅ Batch processing (10-15 videos)
✅ Technical documentation
✅ API references
✅ Command cheat sheets
✅ Quick iteration

**Command:**
```bash
python scripts/create_video.py --yaml inputs/my_video.yaml
# No --use-ai flag = templates (free, instant)
```

---

### **Use AI (Better Quality, Small Cost):**

✅ Marketing videos
✅ Course introductions
✅ Storytelling content
✅ Flagship tutorials
✅ Public-facing content

**Command:**
```bash
python scripts/create_video.py --yaml inputs/my_video.yaml --use-ai
# With --use-ai flag = Claude API (~$0.03-0.08 per video)
```

---

## 📊 Quality Difference

### **Template Narration:**
> "Getting started with Python decorators. Run these commands to get started. This gives you cleaner code and reusable patterns."

**Functional, clear, professional** ⭐⭐⭐⭐

### **AI Narration:**
> "Python decorators transform how you write code by adding functionality without modifying the original function. These simple commands demonstrate the elegant syntax that makes your code more maintainable and reusable."

**Natural, engaging, contextual** ⭐⭐⭐⭐⭐

---

## 💰 Cost

**Per video:** ~$0.03-0.08
**Per scene:** ~$0.005-0.015

**Example costs:**
- 1 video (6 scenes): ~$0.04
- 5 videos: ~$0.20
- 15 videos: ~$0.60

**Worth it for flagship content!**

---

## 🔧 Usage Examples

### **Method 1: Via create_video.py**

```bash
# Documents with AI
python scripts/create_video.py --document README.md --use-ai

# YouTube with AI
python scripts/create_video.py --youtube-url "URL" --use-ai

# Wizard with AI
python scripts/create_video.py --wizard --use-ai
```

### **Method 2: Direct script generator**

```bash
# Generate with AI
python scripts/generate_script_from_yaml.py inputs/my_video.yaml --use-ai

# Generate without AI (template)
python scripts/generate_script_from_yaml.py inputs/my_video.yaml
```

---

## ✅ Verification

### **Check if AI is working:**

```bash
# Set API key
export ANTHROPIC_API_KEY="sk-ant-api03-..."

# Try with simple example
cd scripts
python generate_script_from_yaml.py ../inputs/example_simple.yaml --use-ai

# Should see:
# ✅ AI narration enabled (Claude API)
# (then generates with enhanced narration)

# If you see:
# ⚠️ ANTHROPIC_API_KEY not found
# → API key not set correctly
```

---

## 🎯 Best Practice

### **Hybrid Approach (Recommended):**

```bash
# 1. Generate all videos with templates (free, fast)
for yaml in inputs/*.yaml; do
    python scripts/generate_script_from_yaml.py "$yaml"
done

# 2. Review narration
cat drafts/*_SCRIPT_*.md

# 3. Identify 2-3 videos that need better narration

# 4. Regenerate those with AI
python scripts/generate_script_from_yaml.py inputs/course_intro.yaml --use-ai
python scripts/generate_script_from_yaml.py inputs/marketing_demo.yaml --use-ai

# Cost: ~$0.10 for the important ones
# Time: 2 seconds per scene (still fast!)
```

---

## 🔒 Privacy Note

**Template mode:** All local, no data sent anywhere ✅

**AI mode:** Topics and key points sent to Anthropic API
- Anthropic doesn't use data for training
- Check privacy policy: https://www.anthropic.com/legal/privacy

**For sensitive/proprietary content:** Use template mode

---

## 📚 Full Documentation

See `docs/AI_NARRATION_GUIDE.md` for complete details including:
- Cost analysis
- Quality comparisons
- Fallback behavior
- AI prompts used per scene type
- Privacy considerations

---

*AI Narration Quick Start - 2025-10-03*
*Status: ✅ Ready to use with --use-ai flag*
*Cost: ~$0.03-0.08 per video*
*Quality: Significantly more natural*
