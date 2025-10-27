# Programmatic Video Generation Guide

**Create videos and video sets with Python code**

---

## 📊 Visual Decision Tree: Choose Your Approach

```
┌─────────────────────────────────────────────────────┐
│          WHAT CONTENT DO YOU HAVE?                  │
└─────────────────────────────────────────────────────┘
                         │
         ┌───────────────┴───────────────┐
         ▼                               ▼
    ┌─────────┐                     ┌─────────┐
    │ Existing│                     │   No    │
    │ Content │                     │ Content │
    └─────────┘                     └─────────┘
         │                               │
         ▼                               ▼
    ┌─────────────────────┐         ┌─────────────────────┐
    │ OPTION A:           │         │ OPTION B:           │
    │ Parse Raw Content   │         │ Build from Scratch  │
    │                     │         │                     │
    │ ✅ README.md        │         │ ✅ Database data    │
    │ ✅ GitHub repo      │         │ ✅ API response     │
    │ ✅ YouTube video    │         │ ✅ Custom structure │
    │                     │         │ ✅ Templates        │
    │ 📦 Zero setup       │         │ 🎨 Full control     │
    │ ⚡ 1-line code      │         │ 🔧 Programmatic     │
    └─────────────────────┘         └─────────────────────┘
```

---

## 🎯 Two Approaches

### 📋 **Comparison: Parse vs Build**

| Feature | 🔍 Parse Raw Content | 🛠️ Build from Scratch |
|---------|---------------------|----------------------|
| **Setup Time** | ⚡ Instant | ⏱️ Minutes |
| **Code Lines** | 1-3 lines | 10-50 lines |
| **Content Source** | Files/URLs | Your data |
| **Control Level** | ⭐⭐⭐ Medium | ⭐⭐⭐⭐⭐ Full |
| **Best For** | Docs → Videos | Data → Videos |
| **Learning Curve** | Easy | Moderate |

### 🔄 **Visual Workflow Comparison**

```
┌─────────────────────────────────────────────────────────────────┐
│                    PARSE APPROACH                               │
└─────────────────────────────────────────────────────────────────┘

📄 README.md  →  🤖 Parser  →  📋 YAML  →  🎬 Video
   (1 sec)        (instant)      (auto)      (5 min)

┌─────────────────────────────────────────────────────────────────┐
│                    BUILD APPROACH                               │
└─────────────────────────────────────────────────────────────────┘

💾 Your Data  →  📝 Builder  →  📋 YAML  →  🎬 Video
   (you have)     (you write)    (export)    (5 min)
```

---

## 🚀 Quick Start

### **Option A: Parse Raw Content (Easiest!)**

```
┌────────────────────────────────────────────────────────────┐
│  STEP-BY-STEP: Parse Markdown → Video                     │
└────────────────────────────────────────────────────────────┘

Step 1: Write ONE line of Python
┌─────────────────────────────────────────────────────┐
│ from scripts.document_to_programmatic import \      │
│     parse_document_to_set                           │
│ parse_document_to_set('README.md')                  │
└─────────────────────────────────────────────────────┘
                           ↓
Step 2: System Auto-Generates Everything
┌─────────────────────────────────────────────────────┐
│ ✅ Parses markdown structure                        │
│ ✅ Creates title/command/list scenes                │
│ ✅ Generates professional narration                 │
│ ✅ Exports to sets/readme/                          │
└─────────────────────────────────────────────────────┘
                           ↓
Step 3: Generate Video (standard commands)
┌─────────────────────────────────────────────────────┐
│ cd scripts                                          │
│ python generate_video_set.py ../sets/readme        │
│ python generate_videos_from_set.py ../output/readme│
└─────────────────────────────────────────────────────┘
                           ↓
                    🎬 Video Ready!
```

#### 💡 **Context: When to Use Parse Approach**

| ✅ **Use When** | ❌ **Don't Use When** |
|----------------|----------------------|
| You have existing markdown/README | Content is in database |
| Content structure is good | Need highly custom layout |
| Want video in 5 minutes | Need specific narration style |
| GitHub repo documentation | Generating from API data |

#### 📝 **Annotated Code Example:**

```python
# 1️⃣ FROM MARKDOWN FILE
from scripts.document_to_programmatic import parse_document_to_set

parse_document_to_set('README.md')
# ↑ What this does:
#   - Reads README.md
#   - Parses H1/H2/code blocks/lists
#   - Creates appropriate scene types
#   - Auto-generates narration
#   - Exports to sets/readme/
# ↑ Why we do this:
#   - Zero manual work
#   - Consistent structure
#   - Professional narration

# 2️⃣ FROM GITHUB REPO
from scripts.document_to_programmatic import github_readme_to_video

github_readme_to_video('https://github.com/user/repo') \
    .export_to_yaml('sets/demo')
# ↑ What this does:
#   - Fetches README from GitHub API
#   - Parses content
#   - Returns VideoSetBuilder (can customize!)
#   - Exports to sets/demo/
# ↑ Why we do this:
#   - No manual download needed
#   - Always gets latest README
#   - Can enhance before exporting

# 3️⃣ FROM YOUTUBE VIDEO
from scripts.youtube_to_programmatic import parse_youtube_to_set

parse_youtube_to_set('https://youtube.com/watch?v=VIDEO_ID')
# ↑ What this does:
#   - Fetches video transcript
#   - Extracts key points
#   - Condenses to 60-90 seconds
#   - Creates summary video
# ↑ Why we do this:
#   - Turn long videos into shorts
#   - Auto-summarization
#   - Repurpose content
```

**See:** [PARSE_RAW_CONTENT.md](PARSE_RAW_CONTENT.md) for complete parsing guide.

---

### **Option B: Build from Scratch**

```
┌────────────────────────────────────────────────────────────┐
│  STEP-BY-STEP: Build Custom Video from Data               │
└────────────────────────────────────────────────────────────┘

Step 1: Create Builder
┌─────────────────────────────────────────────────────┐
│ builder = VideoSetBuilder(                          │
│     set_id="my_videos",      # Unique identifier   │
│     set_name="My Collection" # Display name        │
│ )                                                   │
└─────────────────────────────────────────────────────┘
                           ↓
Step 2: Add Video(s) Programmatically
┌─────────────────────────────────────────────────────┐
│ builder.add_video(                                  │
│     video_id="intro",                               │
│     title="Introduction",                           │
│     scenes=[                                        │
│         builder.create_title_scene(...),            │
│         builder.create_outro_scene(...)             │
│     ]                                               │
│ )                                                   │
└─────────────────────────────────────────────────────┘
                           ↓
Step 3: Export to YAML
┌─────────────────────────────────────────────────────┐
│ builder.export_to_yaml("sets/my_videos")           │
│ # Creates: sets/my_videos/*.yaml                    │
└─────────────────────────────────────────────────────┘
                           ↓
Step 4: Generate Video (same as parse approach)
┌─────────────────────────────────────────────────────┐
│ cd scripts                                          │
│ python generate_video_set.py ../sets/my_videos     │
│ python generate_videos_from_set.py \                │
│        ../output/my_videos                          │
└─────────────────────────────────────────────────────┘
                           ↓
                    🎬 Video Ready!
```

#### 💡 **Context: When to Use Build Approach**

| ✅ **Use When** | ❌ **Don't Use When** |
|----------------|----------------------|
| Content in database/API | Have markdown files |
| Need custom structure | Simple doc → video |
| Generating many variations | One-off video needed |
| Template-based content | Content already structured |

#### 📝 **Annotated Code Example:**

```python
from scripts.python_set_builder import VideoSetBuilder

# 1️⃣ CREATE BUILDER
builder = VideoSetBuilder(
    set_id="my_videos",      # ← Used for file/folder names
    set_name="My Collection" # ← Used in video metadata
)
# ↑ What this does: Initializes empty video set
# ↑ Why we do this: Container for all videos

# 2️⃣ ADD VIDEO
builder.add_video(
    video_id="intro",       # ← Unique ID for this video
    title="Introduction",   # ← Display title
    scenes=[                # ← List of scenes
        builder.create_title_scene(
            "Hello",        # ← Main title text
            "World"         # ← Subtitle text
        ),
        # ↑ What this does: Creates title card
        # ↑ Why we do this: Professional intro

        builder.create_outro_scene(
            "Done",         # ← Main outro text
            "Easy!"         # ← Sub text
        )
        # ↑ What this does: Creates closing card
        # ↑ Why we do this: Clear ending
    ]
)

# 3️⃣ EXPORT
builder.export_to_yaml("sets/my_videos")
# ↑ What this does: Writes YAML files to disk
# ↑ Why we do this: Standard format for generator

# ↓ VARIATION: Export returns path for chaining
set_path = builder.export_to_yaml("sets/my_videos")
print(f"Exported to: {set_path}")
```

---

## 📊 Quick Reference: When to Use What

| Your Input | Best Method | Code |
|------------|-------------|------|
| **Local README.md** | Parse document | `parse_document_to_set('README.md')` |
| **GitHub URL** | Parse GitHub | `github_readme_to_video('url').export_to_yaml('sets/x')` |
| **YouTube URL** | Parse YouTube | `parse_youtube_to_set('url')` |
| **Database data** | Build from scratch | `VideoSetBuilder(...)` |
| **API response** | Build from scratch | `VideoSetBuilder(...)` |
| **Custom structure** | Build from scratch | `VideoSetBuilder(...)` |

---

## 📚 Content Parsing API

### **parse_document_to_set()**

Parse local markdown or GitHub README into a complete video set.

```python
from scripts.document_to_programmatic import parse_document_to_set

# Local file
parse_document_to_set('README.md')

# GitHub URL
parse_document_to_set(
    'https://github.com/user/repo/blob/main/README.md',
    set_id='custom_name',  # Optional
    defaults={'accent_color': 'blue'}  # Optional
)
```

**Returns:** Path to exported set directory

---

### **github_readme_to_video()**

Parse GitHub repository README.

```python
from scripts.document_to_programmatic import github_readme_to_video

# Just the repo URL
builder = github_readme_to_video('https://github.com/fastapi/fastapi')

# Or full README URL
builder = github_readme_to_video('https://github.com/user/repo/blob/main/README.md')

# Customize
builder.add_video(...)  # Add more videos
builder.export_to_yaml('sets/fastapi')
```

**Returns:** VideoSetBuilder (can customize before exporting)

---

### **parse_youtube_to_set()**

Parse YouTube video transcript into summary video.

```python
from scripts.youtube_to_programmatic import parse_youtube_to_set

# YouTube URL
parse_youtube_to_set(
    'https://youtube.com/watch?v=VIDEO_ID',
    target_duration=60,  # Condense to 60 seconds
    defaults={'accent_color': 'purple', 'voice': 'female'}
)
```

**Returns:** Path to exported set directory

---

## 📚 Builder API Reference

### **VideoSetBuilder**

```python
VideoSetBuilder(
    set_id="my_set",              # Required: unique ID
    set_name="My Videos",         # Required: display name
    defaults={                    # Optional: defaults
        'accent_color': 'blue',   # orange|blue|purple|green|pink
        'voice': 'male'           # male|male_warm|female|female_friendly
    }
)
```

### **Add Videos**

```python
builder.add_video(
    video_id="video1",
    title="My Video",
    scenes=[...]
)
```

### **Scene Helpers**

```python
# Title scene
builder.create_title_scene("Title", "Subtitle")

# Command/code scene
builder.create_command_scene(
    "Header",
    "Description",
    ["$ command1", "$ command2"]
)

# List scene
builder.create_list_scene(
    "Header",
    "Description",
    [("Item 1", "Description 1"), ("Item 2", "Description 2")]
)

# Outro scene
builder.create_outro_scene("Main Text", "Sub Text")
```

---

## 🔀 Combining Approaches

### **Parse Document + Add Custom Content:**

```python
from scripts.document_to_programmatic import parse_document_to_builder

# Parse README (auto-generates base content)
builder = parse_document_to_builder('README.md')

# Add custom videos programmatically
builder.add_video(
    video_id='bonus',
    title='Bonus Content',
    scenes=[...]
)

builder.export_to_yaml('sets/enhanced_readme')
```

### **Parse Multiple Sources:**

```python
from scripts.document_to_programmatic import github_readme_to_video
from scripts.youtube_to_programmatic import parse_youtube_to_builder
from scripts.python_set_builder import VideoSetBuilder

# Create main builder
builder = VideoSetBuilder("multi_source", "Multi-Source Content")

# Add from GitHub
github_builder = github_readme_to_video('https://github.com/user/repo')
builder.videos.extend(github_builder.videos)

# Add from YouTube
youtube_builder = parse_youtube_to_builder('https://youtube.com/watch?v=ID')
builder.videos.extend(youtube_builder.videos)

# Add custom content
builder.add_video(video_id='custom', title='Custom', scenes=[...])

builder.export_to_yaml('sets/multi_source')
```

---

## 💡 Complete Example

```python
from scripts.python_set_builder import VideoSetBuilder

# Create tutorial series
builder = VideoSetBuilder(
    set_id="python_basics",
    set_name="Python Basics Tutorial",
    defaults={
        'accent_color': 'blue',
        'voice': 'male',
        'target_duration': 60
    },
    naming={
        'prefix': 'lesson',
        'use_numbers': True,
        'separator': '-'
    }
)

# Add lessons programmatically
topics = ["Variables", "Functions", "Classes"]

for i, topic in enumerate(topics, 1):
    builder.add_video(
        video_id=f"{i:02d}_{topic.lower()}",
        title=f"Lesson {i}: {topic}",
        scenes=[
            builder.create_title_scene(
                f"Lesson {i}",
                topic
            ),
            builder.create_command_scene(
                f"{topic} Example",
                "Basic Usage",
                [
                    f"# {topic} in Python",
                    "# Example code here"
                ]
            ),
            builder.create_outro_scene(
                f"You learned {topic}!",
                f"Next: Lesson {i+1}"
            )
        ]
    )

# Export
builder.export_to_yaml("sets/python_basics")

print(f"Created {len(topics)} lesson videos!")
```

---

## 🎨 Pre-configured Builders

### **Tutorial Series**

```python
from scripts.python_set_builder import TutorialSeriesBuilder

builder = TutorialSeriesBuilder("my_course", "My Course")
# Pre-configured: blue, male voice, numbered lessons
```

### **Marketing Videos**

```python
from scripts.python_set_builder import MarketingSeriesBuilder

builder = MarketingSeriesBuilder("demos", "Product Demos")
# Pre-configured: purple, friendly voice, short videos
```

---

## 📁 File Structure

```
video_gen/
├── sets/                    # Video set definitions
│   ├── my_videos/
│   │   ├── set_config.yaml
│   │   └── *.yaml
│   └── ...
│
├── output/                  # Generated content
│   ├── my_videos/
│   │   ├── audio/
│   │   ├── videos/
│   │   ├── scripts/
│   │   └── reports/
│   └── ...
│
└── scripts/
    ├── python_set_builder.py          # Programmatic builder
    ├── generate_video_set.py          # Generate set audio
    ├── generate_all_sets.py           # Generate all sets
    └── generate_videos_from_set.py    # Render videos
```

---

## 🔄 Complete Workflow

### **1. Create set programmatically**

```bash
cd video_gen
python -c "
from scripts.python_set_builder import VideoSetBuilder

builder = VideoSetBuilder('demo', 'Demo Videos')
builder.add_video(...)
builder.export_to_yaml('sets/demo')
"
```

### **2. Generate audio + timing**

```bash
cd scripts
python generate_video_set.py ../sets/demo
```

### **3. Render videos**

```bash
python generate_videos_from_set.py ../output/demo
```

### **4. Find your videos**

```bash
ls ../output/demo/videos/
```

---

## 🎯 Use Cases

### **Generate from Database**

```python
import sqlite3
from scripts.python_set_builder import VideoSetBuilder

conn = sqlite3.connect('data.db')
cursor = conn.execute('SELECT id, name, description FROM items')

builder = VideoSetBuilder("db_videos", "Database Videos")

for item_id, name, description in cursor:
    builder.add_video(
        video_id=f"item_{item_id}",
        title=name,
        scenes=[
            builder.create_title_scene(name, description),
            builder.create_outro_scene("Learn More", f"item/{item_id}")
        ]
    )

builder.export_to_yaml("sets/db_videos")
```

### **Generate from API**

```python
import requests
from scripts.python_set_builder import VideoSetBuilder

response = requests.get('https://api.example.com/products')
products = response.json()

builder = VideoSetBuilder("products", "Product Catalog")

for product in products:
    builder.add_video(
        video_id=product['slug'],
        title=product['name'],
        scenes=[
            builder.create_title_scene(product['name'], product['tagline']),
            builder.create_list_scene(
                "Features",
                "What You Get",
                [(f['name'], f['desc']) for f in product['features']]
            ),
            builder.create_outro_scene("Try It", product['url'])
        ]
    )

builder.export_to_yaml("sets/products")
```

---

## 📊 Commands Reference

```bash
# Generate single set
cd scripts
python generate_video_set.py ../sets/my_set

# Generate multiple sets
python generate_video_set.py ../sets/set1 ../sets/set2

# Generate ALL sets
python generate_all_sets.py

# List all sets
python generate_all_sets.py --list

# Render videos for set
python generate_videos_from_set.py ../output/my_set

# Render ALL videos
python generate_videos_from_set.py --all
```

---

## 🎓 Examples

See working examples in:
- `sets/tutorial_series_example/` - 4-video tutorial series
- `sets/product_demo_series/` - 3-video marketing series

Try them:
```bash
cd scripts
python generate_video_set.py ../sets/tutorial_series_example
python generate_videos_from_set.py ../output/tutorial_series_example
```

---

## 💡 Tips

✅ **Use pre-configured builders** for quick setup
✅ **Generate in loops** for batch content
✅ **Export to YAML** then use standard pipeline
✅ **Mix methods** - start with wizard, add programmatically
✅ **Track in git** - sets/ folder, ignore output/

---

## 🔧 Troubleshooting Guide

### 📊 **Common Issues Decision Tree**

```
┌──────────────────────────────────────────────────────────┐
│              TROUBLESHOOTING FLOWCHART                   │
└──────────────────────────────────────────────────────────┘

        Video generation fails?
                │
        ┌───────┴───────┐
        ▼               ▼
    Parse error?    Generation error?
        │               │
        ▼               ▼
    Check input     Check YAML
        │               │
        ▼               ▼
    ┌─────────┐     ┌─────────┐
    │ Is file │     │ Valid   │
    │ valid?  │     │ format? │
    └─────────┘     └─────────┘
```

### 🐛 **Common Problems & Solutions**

#### **Problem 1: Parse fails on README**

```
❌ Error: "Failed to parse document"

✅ Solution:
1. Check file exists:
   ls README.md

2. Check encoding (must be UTF-8):
   file README.md

3. Check markdown syntax:
   # Must have H1
   ## Must have H2
   ``` code blocks must close ```

4. Try with simple test:
   echo "# Test\n## Section\nContent" > test.md
   parse_document_to_set('test.md')
```

#### **Problem 2: GitHub URL doesn't work**

```
❌ Error: "Failed to fetch from GitHub"

✅ Solutions:
1. Check URL format:
   ✅ https://github.com/user/repo
   ✅ https://github.com/user/repo/blob/main/README.md
   ❌ github.com/user/repo (missing https://)

2. Check repo is public:
   - Open URL in browser
   - Should not require login

3. Try with known working repo:
   github_readme_to_video('https://github.com/fastapi/fastapi')
```

#### **Problem 3: Videos have no narration**

```
❌ Issue: Video generates but silent

✅ Solutions:
1. Check scene has narration:
   builder.create_title_scene(
       "Title",
       "Subtitle",
       narration="Must provide narration!"  # ← Add this!
   )

2. Or use auto-narration (don't provide narration param):
   builder.create_title_scene("Title", "Subtitle")
   # System auto-generates narration

3. Check TTS setup:
   - Azure key configured?
   - Voice name valid?
```

#### **Problem 4: Export path not found**

```
❌ Error: "Directory not found: sets/my_set"

✅ Solutions:
1. Use absolute paths:
   import os
   set_path = os.path.abspath('sets/my_set')
   builder.export_to_yaml(set_path)

2. Or ensure directory exists:
   os.makedirs('sets/my_set', exist_ok=True)
   builder.export_to_yaml('sets/my_set')

3. Check working directory:
   import os
   print(os.getcwd())  # Should be video_gen/
```

### 📝 **Validation Checklist**

```
BEFORE GENERATING:
□ File/URL is accessible
□ Markdown has H1, H2 headers
□ Code blocks properly closed (```)
□ Export directory exists
□ YAML files generated in sets/

AFTER PARSING:
□ Check sets/{name}/set_config.yaml exists
□ Check sets/{name}/*.yaml video files exist
□ Validate YAML structure:
  cd scripts
  python -c "import yaml; yaml.safe_load(open('../sets/name/file.yaml'))"

BEFORE VIDEO GENERATION:
□ TTS credentials configured
□ Dependencies installed (pip install -r requirements.txt)
□ Sufficient disk space (1GB+ per video set)
```

### 🎯 **Quick Debugging Commands**

```bash
# Test parsing
python -c "
from scripts.document_to_programmatic import parse_document_to_set
parse_document_to_set('README.md')
print('✅ Parsing works!')
"

# Validate YAML
python -c "
import yaml, glob
for f in glob.glob('sets/*/set_config.yaml'):
    yaml.safe_load(open(f))
    print(f'✅ {f} valid')
"

# Test builder
python -c "
from scripts.python_set_builder import VideoSetBuilder
b = VideoSetBuilder('test', 'Test')
b.add_video('v1', 'Video 1', scenes=[
    b.create_title_scene('Hello', 'World')
])
path = b.export_to_yaml('sets/test')
print(f'✅ Exported to {path}')
"
```

---

**🎬 Start creating videos programmatically!**
