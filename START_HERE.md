# 🎬 START HERE - Programmatic Video Generation

**Your video generation system now supports programmatic Python workflows!**

**Location:** `C:\Users\brand\Development\Project_Workspace\active-development\video_gen`

---

## ✅ Status: READY TO USE

All integration tests passing ✅

---

## 🚀 NEW: Modern Pipeline v2.0 (Production Ready!)

### **Three Ways to Generate Videos:**

#### 1. Auto-Orchestrator (Simple CLI)
```bash
cd scripts

# From your documentation
python create_video_auto.py --from ../README.md --type document

# From YouTube
python create_video_auto.py --from "python tutorial" --type youtube

# Interactive wizard
python create_video_auto.py --type wizard

# With options
python create_video_auto.py --from ../README.md --type document \
    --voice male --color blue --duration 120 --use-ai --verbose
```

#### 2. Template-Based Generation
```bash
cd scripts

# Use built-in template
python create_from_template.py --template tutorial

# List available templates
python create_from_template.py --list

# From custom template script
python create_from_template.py --script my_template.py
```

#### 3. Programmatic Builder (Python Code)
```python
from scripts.python_set_builder import VideoSetBuilder, SceneConfig

builder = VideoSetBuilder("my_videos", "My Video Series")
builder.add_video(
    video_id="intro",
    title="Introduction",
    scenes=[...]
)
builder.export_to_yaml("sets/my_videos")
```

**Features:**
- ✅ Modern pipeline architecture with 6 stages
- ✅ Template system with scene types
- ✅ State management & error recovery
- ✅ Progress tracking & event system
- ✅ Multilingual support built-in

---

## 🚀 Try It Right Now

### **Quick Test (30 seconds):**

```bash
cd scripts

# Test with provided examples
python generate_video_set.py ../sets/tutorial_series_example

# Check what was created
ls ../output/tutorial_series_example/audio/
ls ../output/tutorial_series_example/reports/

# Render videos (takes 2-3 minutes)
python generate_videos_from_set.py ../output/tutorial_series_example

# Watch your videos!
ls ../output/tutorial_series_example/videos/
```

---

## 🐍 Create Your First Programmatic Video

### **Option A: Parse Existing Content (Fastest!)**

```python
# From markdown
from scripts.document_to_programmatic import parse_document_to_set
parse_document_to_set('README.md')  # That's it!

# From GitHub
from scripts.document_to_programmatic import github_readme_to_video
github_readme_to_video('https://github.com/user/repo').export_to_yaml('sets/demo')

# From YouTube
from scripts.youtube_to_programmatic import parse_youtube_to_set
parse_youtube_to_set('https://youtube.com/watch?v=VIDEO_ID')

# Then generate:
# cd scripts
# python generate_video_set.py ../sets/{set_name}
# python generate_videos_from_set.py ../output/{set_name}
```

**See:** [PARSE_RAW_CONTENT.md](PARSE_RAW_CONTENT.md) for complete parsing guide.

---

### **Option B: Build from Scratch**

Create `my_first_video.py`:

```python
from scripts.python_set_builder import VideoSetBuilder

# Create builder
builder = VideoSetBuilder(
    set_id="my_first_video",
    set_name="My First Programmatic Video"
)

# Add a simple video
builder.add_video(
    video_id="hello_world",
    title="Hello World",
    scenes=[
        builder.create_title_scene("Hello", "World"),
        builder.create_command_scene(
            "Quick Example",
            "Your First Command",
            ["$ echo 'Hello, World!'"]
        ),
        builder.create_outro_scene("Done!", "That was easy")
    ]
)

# Export
builder.export_to_yaml("sets/my_first_video")
print("✓ Video definition created!")
```

### **Step 2: Run It**

```bash
python my_first_video.py
```

### **Step 3: Generate**

```bash
cd scripts
python generate_video_set.py ../sets/my_first_video
python generate_videos_from_set.py ../output/my_first_video
```

### **Step 4: Watch!**

```bash
# Your video is here:
ls ../output/my_first_video/videos/
```

---

## 📚 Documentation

### **Quick References:**

| Doc | Purpose | Time |
|-----|---------|------|
| **[PARSE_RAW_CONTENT.md](PARSE_RAW_CONTENT.md)** 🆕 | Parse markdown/GitHub/YouTube | 5 min |
| **[EDUCATIONAL_SCENES_QUICKREF.md](EDUCATIONAL_SCENES_QUICKREF.md)** 🆕 | Educational scene types | 5 min |
| **[MULTILINGUAL_QUICKREF.md](MULTILINGUAL_QUICKREF.md)** 🆕 | Multilingual generation | 5 min |
| **[CONTENT_CONTROL_GUIDE.md](CONTENT_CONTROL_GUIDE.md)** 🆕 | Content control options | 8 min |
| **[PROGRAMMATIC_GUIDE.md](PROGRAMMATIC_GUIDE.md)** | Complete Python API | 10 min |
| **[status/INTEGRATION_COMPLETE.md](status/INTEGRATION_COMPLETE.md)** | What was added | 5 min |
| **[README.md](README.md)** | Project overview | 10 min |

### **Complete Guides:**

| Doc | Purpose |
|-----|---------|
| [EDUCATIONAL_SCENES_GUIDE.md](EDUCATIONAL_SCENES_GUIDE.md) | Complete educational reference |
| [MULTILINGUAL_GUIDE.md](MULTILINGUAL_GUIDE.md) | Complete multilingual reference |
| [docs/THREE_INPUT_METHODS_GUIDE.md](docs/THREE_INPUT_METHODS_GUIDE.md) | All 4 input methods |
| [AI_NARRATION_QUICKSTART.md](AI_NARRATION_QUICKSTART.md) | AI narration setup |
| [GETTING_STARTED.md](GETTING_STARTED.md) | Original getting started |

---

## 🎯 What You Can Do Now

### **Before:**
- ✅ Parse documents → video
- ✅ YouTube URL → video
- ✅ Interactive wizard → video

### **NOW:**
- ✅ Parse documents → video
- ✅ YouTube URL → video
- ✅ Interactive wizard → video
- ✅ **Python code → video** 🆕
- ✅ **Python code → video sets** 🆕
- ✅ **Generate from database** 🆕
- ✅ **Generate from API** 🆕
- ✅ **Batch automation** 🆕
- ✅ **CI/CD integration** 🆕

---

## 💡 Common Use Cases

### **Use Case 1: GitHub README → Video (Fastest!)**

```python
# ONE line!
from scripts.document_to_programmatic import github_readme_to_video
github_readme_to_video('https://github.com/django/django').export_to_yaml('sets/django')
```

```bash
cd scripts
python generate_video_set.py ../sets/django
python generate_videos_from_set.py ../output/django
```

---

### **Use Case 2: Multiple READMEs → Series**

```python
from scripts.document_to_programmatic import github_readme_to_video
from scripts.python_set_builder import VideoSetBuilder

builder = VideoSetBuilder("frameworks", "Web Frameworks")

# Parse 3 GitHub READMEs automatically
for repo in ['django/django', 'fastapi/fastapi', 'pallets/flask']:
    temp = github_readme_to_video(f'https://github.com/{repo}')
    builder.videos.extend(temp.videos)

builder.export_to_yaml('sets/frameworks')

# Result: 3 videos from READMEs!
```

---

### **Use Case 3: Tutorial Series from Scratch**

```python
from scripts.python_set_builder import TutorialSeriesBuilder

builder = TutorialSeriesBuilder("python_course", "Python Course")

for lesson in ["Variables", "Functions", "Classes"]:
    builder.add_video(
        video_id=lesson.lower(),
        title=lesson,
        scenes=[...]
    )

builder.export_to_yaml("sets/python_course")
```

---

### **Use Case 4: Product Catalog from Database**

```python
import sqlite3
from scripts.python_set_builder import MarketingSeriesBuilder

conn = sqlite3.connect('products.db')
cursor = conn.execute('SELECT id, name FROM products')

builder = MarketingSeriesBuilder("catalog", "Product Catalog")

for product_id, name in cursor:
    builder.add_video(
        video_id=f"product_{product_id}",
        title=name,
        scenes=[...]
    )

builder.export_to_yaml("sets/catalog")
```

### **Use Case 3: API-Driven Content**

```python
import requests
from scripts.python_set_builder import VideoSetBuilder

response = requests.get('https://api.example.com/content')

builder = VideoSetBuilder("api_content", "API Content")

for item in response.json():
    builder.add_video(
        video_id=item['slug'],
        title=item['title'],
        scenes=[...]
    )

builder.export_to_yaml("sets/api_content")
```

---

## 🔧 Key Commands

```bash
# Generate set(s)
python generate_video_set.py ../sets/my_set
python generate_all_sets.py                    # All sets

# Render video(s)
python generate_videos_from_set.py ../output/my_set
python generate_videos_from_set.py --all       # All sets

# List sets
python generate_all_sets.py --list
```

---

## 📁 Project Structure

```
video_gen/
├── scripts/
│   ├── python_set_builder.py          ← NEW! Programmatic API
│   ├── generate_video_set.py          ← NEW! Set generator
│   ├── generate_all_sets.py           ← NEW! Batch generator
│   ├── generate_videos_from_set.py    ← NEW! Video renderer
│   └── ... (existing scripts)
│
├── sets/                              ← NEW! Video definitions
│   ├── tutorial_series_example/       ← Try this!
│   └── product_demo_series/           ← Try this!
│
├── output/                            ← NEW! Generated content
│   └── {set_name}/
│       ├── audio/
│       ├── videos/
│       └── reports/
│
├── PROGRAMMATIC_GUIDE.md              ← NEW! API docs
├── INTEGRATION_COMPLETE.md            ← NEW! Setup summary
└── README.md                          ← UPDATED!
```

---

## ✨ What Was Added

✅ **5 new scripts** - Programmatic generation tools
✅ **2 directories** - sets/ and output/
✅ **2 example sets** - 7 example videos total
✅ **3 new docs** - Complete API reference
✅ **2 updated docs** - README + input methods guide

**Total additions:** ~2000 lines of code + documentation

---

## 🎓 Next Steps

### **1. Test Examples (5 min)**
```bash
cd scripts
python generate_video_set.py ../sets/tutorial_series_example
python generate_videos_from_set.py ../output/tutorial_series_example
```

### **2. Read API Guide (10 min)**
```bash
cat PROGRAMMATIC_GUIDE.md
```

### **3. Create Your Own (15 min)**
```python
# Write your Python code
from scripts.python_set_builder import VideoSetBuilder
builder = VideoSetBuilder("my_videos", "My Videos")
builder.add_video(...)
builder.export_to_yaml("sets/my_videos")
```

```bash
# Generate
cd scripts
python generate_video_set.py ../sets/my_videos
python generate_videos_from_set.py ../output/my_videos
```

---

## 🎬 Summary

**Your video generation system now has:**

✅ **4 input methods** (was 3)
✅ **Video set architecture** (new!)
✅ **Programmatic Python API** (new!)
✅ **Batch automation** (new!)
✅ **Dynamic content support** (new!)
✅ **Complete documentation** (updated!)

**Everything is:**
- ✅ Tested and verified
- ✅ Fully integrated
- ✅ Backwards compatible
- ✅ Production ready

---

**🚀 Start creating videos programmatically today!**

See `PROGRAMMATIC_GUIDE.md` for complete API reference.

---

*Setup completed: 2025-10-04*
*Location: `C:\Users\brand\Development\Project_Workspace\active-development\video_gen`*
*Status: ✅ ALL SYSTEMS GO!*
