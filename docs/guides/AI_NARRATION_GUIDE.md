# 🤖 AI-Powered Narration Guide

**Enhanced Narration Generation with Claude API**

---

## 🎯 Two Narration Modes

### **Mode 1: Template-Based** (Default, Free)

**How it works:**
```python
# Simple string formatting
narration = f"{topic}. Run these {count} commands. This gives you {benefits}."
```

**Pros:**
- ✅ Instant generation (milliseconds)
- ✅ Completely free
- ✅ No API key needed
- ✅ Works offline (after TTS)
- ✅ Predictable results
- ✅ Privacy-friendly

**Example output:**
> "Getting started with FastAPI. Run these 2 commands to get started. This gives you Easy installation, Ready in seconds."

**Quality:** ⭐⭐⭐⭐ Professional, functional

---

### **Mode 2: AI-Enhanced** (Optional, Costs Money)

**How it works:**
```python
# Claude API generates natural narration
response = claude.messages.create(
    model="claude-3-5-sonnet-20241022",
    messages=[{
        "content": "Create professional narration for: {topic}..."
    }]
)
```

**Pros:**
- ✅ More natural language
- ✅ Context-aware phrasing
- ✅ Varied vocabulary
- ✅ Better flow and engagement

**Cons:**
- ❌ Requires API key (ANTHROPIC_API_KEY)
- ❌ Costs ~$0.01-0.05 per video
- ❌ Slower (~2 seconds per scene)
- ❌ Needs internet connection
- ❌ Sends data to Anthropic API

**Example output:**
> "Let's get started with FastAPI - one of the fastest Python web frameworks. Install both FastAPI and Uvicorn with these simple commands, and you'll be ready to build high-performance APIs in seconds."

**Quality:** ⭐⭐⭐⭐⭐ Excellent, highly natural

---

## 🚀 How to Use AI Narration

### **Setup (One-Time):**

```bash
# 1. Install anthropic package
pip install anthropic

# 2. Get API key from Anthropic
# Visit: https://console.anthropic.com/account/keys

# 3. Set environment variable
export ANTHROPIC_API_KEY="sk-ant-api03-..."  # Linux/Mac
# OR
set ANTHROPIC_API_KEY=sk-ant-api03-...  # Windows CMD
# OR
$env:ANTHROPIC_API_KEY="sk-ant-api03-..."  # Windows PowerShell
```

### **Usage:**

```bash
# Generate with AI narration
python scripts/generate_script_from_yaml.py inputs/my_video.yaml --use-ai

# Or via master command
python scripts/create_video.py --yaml inputs/my_video.yaml --use-ai

# Or in wizard
python scripts/create_video.py --wizard
# (Add --use-ai flag when launching)
```

---

## 📊 Comparison: Template vs AI

### **Quality Comparison:**

**Input YAML:**
```yaml
- type: command
  header: "Quick Start"
  topic: "Getting started with Python decorators"
  commands:
    - "@decorator"
    - "def my_function():"
    - "    pass"
  key_points:
    - Cleaner code
    - Reusable patterns
    - Enhanced functionality
```

**Template Output:**
> "Getting started with Python decorators. Run these 3 commands to get started. This gives you Cleaner code, Reusable patterns."

**AI Output (Example):**
> "Python decorators unlock powerful code reusability. These three lines demonstrate the basic syntax that lets you enhance function behavior without modifying the original code. You'll immediately see cleaner, more maintainable patterns."

**Difference:**
- Template: Functional, structured, predictable
- AI: Natural, flowing, contextual

---

## 💰 Cost Analysis

### **Template-Based: $0.00**

- Unlimited videos
- Unlimited scenes
- Zero cost forever

### **AI-Enhanced: ~$0.03-0.08 per video**

**Breakdown:**
```
Cost per API call: ~$0.003-0.008 (depends on complexity)
Average scenes per video: 5-6
Cost per video: 5-6 × $0.005 = $0.025-0.030

For 15 videos: ~$0.45-1.20
For 100 videos: ~$3-8
```

**Claude 3.5 Sonnet Pricing:**
- Input: $3 / 1M tokens (~300 tokens per scene = $0.001)
- Output: $15 / 1M tokens (~150 tokens per scene = $0.002)
- Total per scene: ~$0.003-0.008

**Reasonable for quality improvement!**

---

## 🔧 When to Use Which Mode

### **Use Template-Based (Default) When:**

✅ Creating many videos (batch processing)
✅ Budget is zero
✅ Content is highly structured (technical tutorials)
✅ Consistency is more important than variety
✅ Quick iteration needed
✅ Privacy is a concern

**Best for:**
- API documentation
- Command references
- Technical tutorials
- Batch video generation

---

### **Use AI-Enhanced When:**

✅ Creating flagship content
✅ Need engaging narration
✅ Marketing/promotional videos
✅ Narrative-style content
✅ Want maximum quality
✅ Budget allows ($0.03-0.08 per video)

**Best for:**
- Course introductions
- Marketing videos
- Explanation videos
- Storytelling content
- Public-facing tutorials

---

## 🎬 Practical Examples

### **Example 1: Batch Technical Docs (Template)**

```bash
# Generate 15 API documentation videos
# Cost: $0.00
# Time: Fast

for doc in api_docs/*.md; do
    python scripts/create_video.py --document "$doc"
done

python scripts/generate_all_videos_unified_v2.py
python scripts/generate_videos_from_timings_v3_optimized.py
```

**Why template:** Batch processing, structured content, free

---

### **Example 2: Course Introduction (AI-Enhanced)**

```bash
# Generate flagship course intro video
# Cost: ~$0.05
# Time: +2 seconds per scene

python scripts/create_video.py --wizard --use-ai

# AI generates more engaging narration:
# "Welcome to this comprehensive course on Python development.
#  Over the next series, you'll master everything from basic
#  syntax to advanced design patterns..."
```

**Why AI:** Marketing/engagement matters, worth the cost

---

### **Example 3: Hybrid Approach**

```bash
# Generate with templates first (free)
python scripts/generate_script_from_yaml.py inputs/my_video.yaml

# Review the output
cat drafts/my_video_SCRIPT_*.md

# If narration needs improvement, regenerate specific videos with AI
python scripts/generate_script_from_yaml.py inputs/course_intro.yaml --use-ai
```

**Why hybrid:** Iterate fast with templates, polish key videos with AI

---

## 🛡️ Fallback Behavior

**The system is smart about failures:**

```python
if use_ai:
    try:
        # Try Claude API
        narration = generate_with_ai(...)
    except Exception:
        # Fallback to template automatically
        print("⚠️  AI failed, using template")
        narration = generate_template(...)
```

**You always get narration, even if:**
- ❌ No API key set
- ❌ API is down
- ❌ Rate limit hit
- ❌ Network issues

**System gracefully falls back to templates!**

---

## 📋 AI Prompts Used (For Each Scene Type)

### **Title Scene:**
```
Create professional video narration for a title scene.

Title: {title}
Subtitle: {subtitle}
Key message: {key_message}

Create a brief, engaging introduction (1-2 sentences, ~10 words).
Style: Professional, welcoming, clear.
Target pace: 135 WPM
```

### **Command Scene:**
```
Create professional video narration for a command/tutorial scene.

Topic: {topic}
Commands shown: {count} commands
Key points: {points}

Create engaging narration (2-3 sentences, 15-20 words).
Style: Educational, clear, encouraging.
Mention running the commands and the benefits.
```

### **Code Comparison:**
```
Create professional video narration for a code refactoring scene.

Header: {header}
Improvement: {improvement}
Key points: {points}

Create narration explaining the improvement (2 sentences, 12-18 words).
Style: Technical but accessible, focus on benefits.
```

**Prompts are carefully crafted for:**
- Appropriate length (fits timing)
- Professional tone
- Educational style
- Natural phrasing

---

## ✅ Quick Command Reference

```bash
# Template-based (free, fast)
python generate_script_from_yaml.py inputs/my_video.yaml

# AI-enhanced (better quality, costs money)
python generate_script_from_yaml.py inputs/my_video.yaml --use-ai

# Via master command
python create_video.py --yaml inputs/my_video.yaml --use-ai
python create_video.py --wizard --use-ai
python create_video.py --document README.md --use-ai
```

---

## 🎯 Recommendation

### **Start with Template-Based:**

1. Create your first videos with templates (free)
2. Review the narration quality
3. If satisfied → stick with templates!
4. If you want more natural phrasing → add `--use-ai`

### **Cost-Effective Strategy:**

```bash
# Batch process with templates (free)
python generate_script_from_yaml.py inputs/video_*.yaml

# Review generated scripts
cat drafts/*_SCRIPT_*.md

# If 1-2 videos need better narration, regenerate those with AI
python generate_script_from_yaml.py inputs/flagship_video.yaml --use-ai

# Cost: $0.00 for most, $0.05 for the important ones
```

---

## 🔒 Privacy & Security

### **Template-Based:**
- ✅ All processing local
- ✅ No data sent externally
- ✅ No API keys needed

### **AI-Enhanced:**
- ⚠️ Topics/key points sent to Anthropic API
- ⚠️ Requires API key
- ✅ Anthropic has strong privacy policies
- ✅ Data not used for training (per Anthropic terms)

**For sensitive content:** Use template-based mode

---

## 📈 Expected Quality Improvement

**Template narration (current):**
- Professional: ⭐⭐⭐⭐
- Natural: ⭐⭐⭐
- Engaging: ⭐⭐⭐
- Consistency: ⭐⭐⭐⭐⭐

**AI narration (with Claude):**
- Professional: ⭐⭐⭐⭐⭐
- Natural: ⭐⭐⭐⭐⭐
- Engaging: ⭐⭐⭐⭐⭐
- Consistency: ⭐⭐⭐⭐

**Is the improvement worth $0.03-0.08 per video?**

For most technical tutorials: **Probably not** (templates are fine)
For marketing/flagship content: **Probably yes** (engagement matters)

---

*AI Narration Guide - 2025-10-03*
*Status: ✅ Implemented and available*
*Default: Template-based (free)*
*Optional: AI-enhanced with --use-ai flag*
