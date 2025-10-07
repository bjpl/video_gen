# How to Run the Bilingual Internet Guide Script

## 🎯 What This Script Does

Creates **10 videos** from Internet Guide Vol 1:
- 5 videos in English
- 5 videos in Spanish (auto-translated)
- Uses 3 voices (male, female, male_warm)
- ~90 seconds each

## 🚀 Quick Run

```bash
cd /c/Users/brand/Development/Project_Workspace/active-development/video_gen
python scripts/generate_internet_guide_bilingual.py
```

## ⚙️ Configuration Options

### Option 1: Template Narration (FREE - Recommended to start)

**No API key needed!**

The script is configured to use template narration by default.

### Option 2: AI Narration (Optional - Better quality)

If you want AI-enhanced narration:

1. Set your API key:
```bash
export ANTHROPIC_API_KEY="sk-ant-api03-..."
```

2. Edit the script, change:
```python
"use_ai_narration": False  # Change to True
```

## 📂 Output

After running, check:
```
output/internet_guide_vol1_en/  # 5 English videos
output/internet_guide_vol1_es/  # 5 Spanish videos
```

Each directory contains:
- video_01.mp4 through video_05.mp4
- Audio files
- Timing reports
- Metadata

## ⏱️ Expected Time

- Template narration: ~15-20 minutes total
- AI narration: ~20-25 minutes total

## 🎙️ Voice Assignment

- Video 1: Male voice (Andrew)
- Video 2: Female voice (Aria)
- Video 3: Male warm voice (Brandon)
- Video 4: Male voice (Andrew) - rotates back
- Video 5: Female voice (Aria) - rotates back

Spanish videos use native Spanish voices automatically.

## ✅ You're Ready!

Just run the script - it works with or without AI API key.
