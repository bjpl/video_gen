# ✅ Programmatic Video Generation - Complete Guide

**Everything you need to know about programmatic video creation**

---

## 🎯 Quick Answer to Your Questions

### **"Can I just use a markdown/GitHub without special formatting?"**

**✅ YES!** One line of code:

```python
from scripts.document_to_programmatic import github_readme_to_video
github_readme_to_video('https://github.com/user/repo').export_to_yaml('sets/demo')
```

### **"How do I guide the content generation?"**

**You have 5 options:**

1. **Full auto** - Parse markdown/YouTube → done
2. **Parse + enhance** - Auto-parse, add custom touches
3. **Structure + auto-narrate** - You define structure, system writes narration
4. **Full custom** - You write every word
5. **Load from files/DB** - Content managed externally

**All work programmatically!**

---

## 🚀 Three Ways to Use Programmatic Generation

### **Method 1: Parse Existing Content**

**NO manual content creation needed!**

```python
# Local markdown
from scripts.document_to_programmatic import parse_document_to_set
parse_document_to_set('README.md')

# GitHub README
from scripts.document_to_programmatic import github_readme_to_video
builder = github_readme_to_video('https://github.com/fastapi/fastapi')
builder.export_to_yaml('sets/fastapi')

# YouTube video
from scripts.youtube_to_programmatic import parse_youtube_to_set
parse_youtube_to_set('https://youtube.com/watch?v=VIDEO_ID')

# Then generate
# cd scripts
# python generate_video_set.py ../sets/{name}
# python generate_videos_from_set.py ../output/{name}
```

**Perfect for:**
- Existing documentation
- GitHub READMEs
- YouTube tutorials
- Quick video generation

---

### **Method 2: Build from Scratch**

**Full programmatic control!**

```python
from scripts.python_set_builder import VideoSetBuilder

builder = VideoSetBuilder("my_videos", "My Videos")

builder.add_video(
    video_id="intro",
    title="Introduction",
    scenes=[
        builder.create_title_scene("Hello", "World"),
        builder.create_command_scene("Setup", "Install", ["$ pip install"]),
        builder.create_list_scene("Features", "Key Points", [("Fast", "10x")]),
        builder.create_outro_scene("Done", "Easy")
    ]
)

builder.export_to_yaml('sets/my_videos')

# Then generate
# cd scripts
# python generate_video_set.py ../sets/my_videos
# python generate_videos_from_set.py ../output/my_videos
```

**Perfect for:**
- Custom content
- Complex logic
- Dynamic generation
- Exact control needed

---

### **Method 3: Hybrid (Best of Both!)**

**Parse base content, enhance programmatically!**

```python
from scripts.document_to_programmatic import parse_document_to_builder

# Step 1: Parse README (auto)
builder = parse_document_to_builder('README.md')

# Step 2: Customize intro (custom)
builder.videos[0].scenes[0] = builder.create_title_scene(
    "Enhanced Tutorial",
    "Auto-Parsed + Custom",
    narration="Welcome! This video combines automatic parsing with custom enhancements for the best experience."
)

# Step 3: Add bonus content (programmatic)
builder.add_video(
    video_id='advanced_tips',
    title='Advanced Tips',
    scenes=[
        builder.create_list_scene(
            "Pro Tips",
            "Level Up",
            [("Tip 1", "Use virtual envs"), ("Tip 2", "Write tests")]
        )
    ]
)

builder.export_to_yaml('sets/hybrid')
```

**Perfect for:**
- Existing docs as foundation
- Custom enhancements
- Best quality/effort ratio

---

## 📋 Complete Command Reference

### **Parse Content:**

```bash
# Markdown
python document_to_programmatic.py README.md

# GitHub
python document_to_programmatic.py https://github.com/user/repo/blob/main/README.md

# YouTube
python youtube_to_programmatic.py https://youtube.com/watch?v=VIDEO_ID

# With options
python document_to_programmatic.py README.md --accent-color purple --voice female
python youtube_to_programmatic.py https://youtube.com/watch?v=ID --duration 90
```

### **Generate Videos:**

```bash
cd scripts

# Generate audio/timing
python generate_video_set.py ../sets/my_set
python generate_all_sets.py  # All sets

# Render videos
python generate_videos_from_set.py ../output/my_set
python generate_videos_from_set.py --all  # All sets
```

---

## 🎨 Narration Control

### **Auto-Generate (Minimal Effort):**

```python
builder.create_title_scene("Python", "Tutorial")
# Auto: "Python. Tutorial."

builder.create_command_scene("Install", "Setup", ["$ pip install"])
# Auto: "Install. Setup. Run this command to get started."
```

### **Guide Auto-Generation (Better Quality):**

```python
builder.create_command_scene(
    "Installation",
    "Setup Python",
    ["$ pip install numpy pandas"],
    topic="Setting up Python for data science",  # ← Guides narration
    key_points=[                                  # ← Included in narration
        "Install essential packages",
        "Quick two-step process"
    ]
)
# Auto: "Setting up Python for data science. Run this command to get started.
#        This installs essential packages in a quick two-step process."
```

### **Custom Narration (Full Control):**

```python
builder.create_title_scene(
    "Advanced Python",
    "Expert Level",
    narration="Welcome to advanced Python. This tutorial assumes mastery of the basics and dives deep into metaclasses, decorators, and async programming."
)
```

---

## 💡 Real-World Examples

### **Example 1: FastAPI GitHub → Video (30 seconds)**

```python
from scripts.document_to_programmatic import github_readme_to_video

# One line!
github_readme_to_video('https://github.com/fastapi/fastapi').export_to_yaml('sets/fastapi')
```

```bash
cd scripts
python generate_video_set.py ../sets/fastapi
python generate_videos_from_set.py ../output/fastapi

# Done! Video from FastAPI README in ~5 minutes total
```

---

### **Example 2: 10 YouTube Tutorials → Series**

```python
from scripts.youtube_to_programmatic import parse_youtube_to_builder
from scripts.python_set_builder import VideoSetBuilder

builder = VideoSetBuilder("youtube_course", "YouTube Course")

# Parse 10 YouTube tutorials
youtube_urls = [
    'https://youtube.com/watch?v=VIDEO_1',
    'https://youtube.com/watch?v=VIDEO_2',
    # ... 8 more
]

for i, url in enumerate(youtube_urls, 1):
    temp = parse_youtube_to_builder(url, target_duration=60)
    video = temp.videos[0]
    video.video_id = f"lesson_{i:02d}"
    video.title = f"Lesson {i}"
    builder.videos.append(video)

builder.export_to_yaml('sets/youtube_course')

# Result: 10-video series auto-generated from YouTube!
```

---

### **Example 3: Database → Videos with Custom Narration**

```python
import sqlite3
from scripts.python_set_builder import VideoSetBuilder

conn = sqlite3.connect('content.db')
cursor = conn.execute('SELECT id, title, custom_narration, commands FROM videos')

builder = VideoSetBuilder("db_content", "Database Content")

for video_id, title, narration, commands_json in cursor:
    import json
    commands = json.loads(commands_json)

    builder.add_video(
        video_id=f"video_{video_id}",
        title=title,
        scenes=[
            builder.create_title_scene(
                title,
                "Tutorial",
                narration=narration  # Custom from database
            ),
            builder.create_command_scene(
                "Commands",
                "Examples",
                commands  # From database
                # Narration auto-generated
            ),
            builder.create_outro_scene("Done", "Next lesson")
        ]
    )

builder.export_to_yaml('sets/db_content')
```

---

## 📊 What's Automatically Handled

### **Document Parsing:**
- ✅ Markdown structure (headers, lists, code blocks)
- ✅ GitHub README (fetched automatically)
- ✅ Code blocks → command scenes
- ✅ Lists → list scenes
- ✅ Sections → appropriate scene types

### **YouTube Parsing:**
- ✅ Transcript fetching
- ✅ Key point extraction
- ✅ Summary generation
- ✅ Scene structuring
- ✅ Duration targeting

### **Narration Generation:**
- ✅ Title scenes
- ✅ Command explanations
- ✅ List introductions
- ✅ Outro messages
- ✅ Transitions

**You only provide custom content where YOU want control!**

---

## 🎯 Choosing Your Approach

### **Use Parsing (Method 1) when:**
- ✅ You have markdown/README/YouTube
- ✅ Want fastest route to video
- ✅ Content structure is good
- ✅ Auto-narration acceptable

### **Use Scratch Building (Method 2) when:**
- ✅ Need exact structure
- ✅ Custom narration required
- ✅ Complex conditional logic
- ✅ No existing content

### **Use Hybrid (Method 3) when:**
- ✅ Have base content (docs)
- ✅ Want to enhance it
- ✅ Best quality/effort balance
- ✅ Combining sources

---

## 📚 Documentation

| Guide | Purpose | When to Read |
|-------|---------|--------------|
| **[PARSE_RAW_CONTENT.md](PARSE_RAW_CONTENT.md)** | Parse markdown/GitHub/YouTube | Want to parse existing content |
| **[CONTENT_CONTROL_GUIDE.md](CONTENT_CONTROL_GUIDE.md)** | All 5 levels of control | Want to understand all options |
| **[PROGRAMMATIC_GUIDE.md](PROGRAMMATIC_GUIDE.md)** | Complete Python API | Building from scratch |
| **[START_HERE.md](START_HERE.md)** | This file | Getting started |

---

## ✨ Summary

**You asked:** "Can I use markdown/GitHub without special formatting?"

**Answer:** **YES! Multiple ways:**

1. **Parse directly:**
   ```python
   parse_document_to_set('README.md')  # One line!
   ```

2. **Parse + customize:**
   ```python
   builder = parse_document_to_builder('README.md')
   builder.add_video(...)  # Add more
   ```

3. **Build from scratch:**
   ```python
   builder = VideoSetBuilder(...)
   builder.add_video(...)  # Full control
   ```

**You control content generation through:**
- ✅ Parsing (auto)
- ✅ Structure (you provide, system narrates)
- ✅ Custom narration (you write)
- ✅ External content (DB, files, API)
- ✅ Mix of all above

**The system is FLEXIBLE - use as much or as little control as you need!** 🎬

---

*Complete programmatic system with parsing bridges*
*Location: `C:\Users\brand\Development\Project_Workspace\active-development\video_gen`*
*Status: ✅ FULLY OPERATIONAL*
