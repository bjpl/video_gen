# ✅ YES! You Can Use Raw Markdown/GitHub/YouTube

**Quick answer to: "Can I just use a markdown/GitHub without special formatting?"**

---

## 🎯 Short Answer: YES!

**You can parse raw content directly - NO manual formatting needed!**

---

## 🚀 Three Ways to Parse Raw Content

### **1. Local Markdown File**

```python
from scripts.document_to_programmatic import parse_document_to_set

# Just point to your markdown - that's it!
parse_document_to_set('README.md')

# System automatically:
# ✓ Parses markdown structure
# ✓ Creates appropriate scenes
# ✓ Generates narration
# ✓ Exports to YAML
# ✓ Ready to generate video!
```

**Then:**
```bash
cd scripts
python generate_video_set.py ../sets/readme
python generate_videos_from_set.py ../output/readme
```

---

### **2. GitHub README (No Download Needed!)**

```python
from scripts.document_to_programmatic import github_readme_to_video

# Just the GitHub URL - system handles everything!
builder = github_readme_to_video('https://github.com/django/django')
builder.export_to_yaml('sets/django_video')

# System automatically:
# ✓ Fetches README from GitHub
# ✓ Parses structure
# ✓ Creates scenes
# ✓ Generates narration
# ✓ Ready to go!
```

---

### **3. YouTube Video Transcript**

```python
from scripts.youtube_to_programmatic import parse_youtube_to_set

# Just the YouTube URL!
parse_youtube_to_set(
    'https://youtube.com/watch?v=VIDEO_ID',
    target_duration=60  # Condense to 60 seconds
)

# System automatically:
# ✓ Fetches transcript
# ✓ Extracts key points
# ✓ Creates summary scenes
# ✓ Generates narration
# ✓ Ready to render!
```

---

## 💡 What Gets Auto-Parsed

### **From Markdown:**

**Input (raw README.md):**
```markdown
# My Project

## Installation

```bash
npm install my-project
npm start
```

## Features

- Fast performance
- Easy to use
- Well documented
```

**Auto-Generated Scenes:**
```python
# Scene 1: Title
"My Project" / "Documentation Overview"

# Scene 2: Command scene
Header: "Installation"
Commands: ["npm install my-project", "npm start"]

# Scene 3: List scene
Header: "Features"
Items: ["Fast performance", "Easy to use", "Well documented"]

# Scene 4: Outro
"Learn More" / "See full documentation"
```

**No manual work required!**

---

### **From YouTube:**

**Input:** YouTube URL

**Auto-Generated:**
- Title scene (from video title if available)
- Multiple list scenes (key points from transcript)
- Outro scene

**Transcript automatically:**
- ✓ Fetched from YouTube
- ✓ Split into sections
- ✓ Key points extracted
- ✓ Condensed to target duration

---

## 🔧 Command Line Usage

### **Parse Markdown:**

```bash
# Local file
python document_to_programmatic.py README.md

# GitHub URL
python document_to_programmatic.py https://github.com/user/repo/blob/main/README.md

# With styling
python document_to_programmatic.py README.md --accent-color purple --voice female
```

### **Parse YouTube:**

```bash
# YouTube URL
python youtube_to_programmatic.py https://youtube.com/watch?v=VIDEO_ID

# Condense 30-min video to 60-sec summary
python youtube_to_programmatic.py https://youtube.com/watch?v=ID --duration 60
```

---

## 🎯 Complete Workflows

### **Workflow 1: GitHub README → Video (Fastest)**

```bash
# ONE command!
cd scripts
python document_to_programmatic.py https://github.com/fastapi/fastapi

# Then generate
python generate_video_set.py ../sets/fastapi
python generate_videos_from_set.py ../output/fastapi

# Done! Video from GitHub README in ~5 minutes
```

---

### **Workflow 2: Multiple READMEs → Series (Programmatic)**

```python
from scripts.document_to_programmatic import github_readme_to_video
from scripts.python_set_builder import VideoSetBuilder

# Create set
builder = VideoSetBuilder("github_series", "GitHub Series")

# Parse multiple repos
repos = [
    'https://github.com/django/django',
    'https://github.com/fastapi/fastapi',
    'https://github.com/pallets/flask'
]

for repo_url in repos:
    # Auto-parse each README
    temp = github_readme_to_video(repo_url)
    builder.videos.extend(temp.videos)

# Export
builder.export_to_yaml('sets/github_series')

# Generate
# python generate_video_set.py ../sets/github_series
# python generate_videos_from_set.py ../output/github_series
```

**Result:** Series of videos auto-generated from GitHub READMEs!

---

### **Workflow 3: YouTube Playlist → Series**

```python
from scripts.youtube_to_programmatic import parse_youtube_to_builder
from scripts.python_set_builder import VideoSetBuilder

builder = VideoSetBuilder("youtube_series", "YouTube Tutorial Series")

# YouTube video IDs
videos = [
    'https://youtube.com/watch?v=VIDEO_ID_1',
    'https://youtube.com/watch?v=VIDEO_ID_2',
    'https://youtube.com/watch?v=VIDEO_ID_3'
]

for i, url in enumerate(videos, 1):
    # Parse each YouTube video
    temp = parse_youtube_to_builder(url, target_duration=60)

    # Customize
    video = temp.videos[0]
    video.video_id = f"tutorial_{i:02d}"
    video.title = f"Tutorial {i}"

    builder.videos.append(video)

builder.export_to_yaml('sets/youtube_series')
```

**Result:** Series auto-generated from YouTube playlist!

---

## ✨ Key Points

### **✅ You Can Parse:**
- Local markdown files (README.md, docs/*.md)
- GitHub URLs (raw content fetched automatically)
- YouTube URLs (transcripts fetched automatically)
- Plain text files
- Any content the parsers support

### **✅ NO Special Formatting Needed:**
- Works with standard markdown
- Works with GitHub-flavored markdown
- Works with regular READMEs
- No preprocessing required

### **✅ Then Customize (Optional):**
- Use as-is (fully automatic)
- Enhance with custom scenes
- Override narration where needed
- Combine multiple sources

---

## 🎬 Real Example: FastAPI GitHub → Video

```python
# Complete workflow in 3 lines!
from scripts.document_to_programmatic import github_readme_to_video

builder = github_readme_to_video('https://github.com/fastapi/fastapi')
builder.export_to_yaml('sets/fastapi_demo')
```

```bash
cd scripts
python generate_video_set.py ../sets/fastapi_demo
python generate_videos_from_set.py ../output/fastapi_demo

# Done! Video created from FastAPI's README
```

**Time:** ~5 minutes total
**Manual work:** 3 lines of code!

---

## 📖 See Also

- **`CONTENT_CONTROL_GUIDE.md`** - All 5 levels of control explained
- **`PROGRAMMATIC_GUIDE.md`** - Complete Python API reference
- **`scripts/document_to_programmatic.py`** - Document parser bridge
- **`scripts/youtube_to_programmatic.py`** - YouTube parser bridge
- **`scripts/example_document_programmatic.py`** - Working examples

---

## ✅ Summary

**Question:** "Can I just use a markdown/GitHub without special formatting?"

**Answer:** **YES! Absolutely!**

```python
# Markdown
from scripts.document_to_programmatic import parse_document_to_set
parse_document_to_set('README.md')

# GitHub
from scripts.document_to_programmatic import github_readme_to_video
github_readme_to_video('https://github.com/user/repo').export_to_yaml('sets/demo')

# YouTube
from scripts.youtube_to_programmatic import parse_youtube_to_set
parse_youtube_to_set('https://youtube.com/watch?v=ID')
```

**System handles all the parsing automatically!**

**No special formatting, no manual structuring, no preprocessing needed!** 🎉
