# Programmatic Video Generation Guide

**Create videos and video sets with Python code**

---

## 🎯 Two Approaches

1. **Parse raw content** (markdown, GitHub, YouTube) → auto-generate
2. **Build from scratch** - full programmatic control

**Both work! Choose based on your needs.**

---

## 🚀 Quick Start

### **Option A: Parse Raw Content (Easiest!)**

```python
# From markdown
from scripts.document_to_programmatic import parse_document_to_set
parse_document_to_set('README.md')  # Done!

# From GitHub
from scripts.document_to_programmatic import github_readme_to_video
github_readme_to_video('https://github.com/user/repo').export_to_yaml('sets/demo')

# From YouTube
from scripts.youtube_to_programmatic import parse_youtube_to_set
parse_youtube_to_set('https://youtube.com/watch?v=VIDEO_ID')
```

**See:** [PARSE_RAW_CONTENT.md](PARSE_RAW_CONTENT.md) for complete parsing guide.

---

### **Option B: Build from Scratch**

```python
from scripts.python_set_builder import VideoSetBuilder

# Create builder
builder = VideoSetBuilder(
    set_id="my_videos",
    set_name="My Video Collection"
)

# Add a video
builder.add_video(
    video_id="intro",
    title="Introduction",
    scenes=[
        builder.create_title_scene("Hello", "World"),
        builder.create_outro_scene("Done", "Easy!")
    ]
)

# Export to YAML
builder.export_to_yaml("sets/my_videos")

# Then generate:
# cd scripts
# python generate_video_set.py ../sets/my_videos
# python generate_videos_from_set.py ../output/my_videos
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

**🎬 Start creating videos programmatically!**
