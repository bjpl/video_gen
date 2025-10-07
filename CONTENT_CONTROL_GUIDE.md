# Content Control Guide - Programmatic Generation

**Complete guide to controlling content when using programmatic video generation**

---

## 🎯 Key Question: How Do I Control the Content?

**Short Answer:** You have **5 levels of control**, from fully automatic to 100% custom!

```
┌──────────────────────────────────────────────────────────┐
│          CONTENT CONTROL DECISION TREE                   │
└──────────────────────────────────────────────────────────┘

    How much control do you need?
                │
        ┌───────┴────────┬──────────┬──────────┐
        ▼                ▼          ▼          ▼
    ┌───────┐      ┌─────────┐  ┌────────┐  ┌─────┐
    │ None  │      │  Some   │  │  More  │  │ Full│
    │(Auto) │      │(Enhance)│  │(Guide) │  │100% │
    └───────┘      └─────────┘  └────────┘  └─────┘
        │                │          │          │
        ▼                ▼          ▼          ▼
    Level 1          Level 2    Level 3    Level 4
    Parse →          Parse +    Structure  Custom
    Auto             Custom     + Auto     Narration
```

---

## 📊 Five Levels of Content Control

### 🎯 **Visual Comparison: Control vs Effort**

```
CONTROL LEVEL               EFFORT              USE CASE
═══════════════════════════════════════════════════════════

Level 1: Parse Auto         ⭐ Lowest           📄 Docs exist
┌────────────────┐         ┌────────────┐      ✅ Structure OK
│ Zero work      │  ═══→   │ 1 line code│      ✅ Fast needed
│ Full auto      │         │            │      ❌ Custom brand
└────────────────┘         └────────────┘

Level 2: Parse + Enhance    ⭐⭐ Low            📄 Docs + extras
┌────────────────┐         ┌────────────┐      ✅ 80% auto
│ Parse first    │  ═══→   │ Add custom │      ✅ Some tweaks
│ Then customize │         │            │      ✅ Multi-source
└────────────────┘         └────────────┘

Level 3: Structure + Auto   ⭐⭐⭐ Medium        🔧 Have data
┌────────────────┐         ┌────────────┐      ✅ Define layout
│ Define scenes  │  ═══→   │ Auto-narr  │      ✅ Trust AI
│ Auto narration │         │            │      ✅ Consistency
└────────────────┘         └────────────┘

Level 4: Full Custom        ⭐⭐⭐⭐ High        🎨 Brand voice
┌────────────────┐         ┌────────────┐      ✅ Exact words
│ Every word     │  ═══→   │ 100% yours │      ✅ Marketing
│ Total control  │         │            │      ✅ Legal/precise
└────────────────┘         └────────────┘

Level 5: External Content   ⭐⭐ Low            💾 CMS/Database
┌────────────────┐         ┌────────────┐      ✅ Content mgmt
│ Load from DB   │  ═══→   │ Generate   │      ✅ Dynamic
│ Or API/files   │         │            │      ✅ Team-managed
└────────────────┘         └────────────┘
```

### 📋 **Detailed Comparison Table**

| Level | Method | Effort | Control | Speed | Use When |
|-------|--------|--------|---------|-------|----------|
| **1** | Parse document → auto | ⭐ Lowest | ⭐⭐ Basic | ⚡ Instant | Have existing docs |
| **2** | Parse + customize | ⭐⭐ Low | ⭐⭐⭐ Medium | ⚡ Fast | Enhance existing docs |
| **3** | Structure → auto-narrate | ⭐⭐⭐ Medium | ⭐⭐⭐⭐ High | 🏃 Quick | Provide structure |
| **4** | Structure + custom narration | ⭐⭐⭐⭐ High | ⭐⭐⭐⭐⭐ Full | 🐌 Slower | Exact wording needed |
| **5** | Load from content files | ⭐⭐ Low | ⭐⭐⭐⭐⭐ Full | ⚡ Fast | Content in DB/files |

---

## Level 1: Parse Document → Auto-Generate Everything

**🎯 Easiest - Zero manual content creation**

### **From Local Markdown:**

```python
from scripts.document_to_programmatic import parse_document_to_set

# ONE line - that's it!
set_path = parse_document_to_set('README.md')

# Generated:
# - Parses README structure
# - Creates scenes automatically
# - Auto-generates narration
# - Exports to YAML
```

### **From GitHub README:**

```python
from scripts.document_to_programmatic import github_readme_to_video

# Parse GitHub README directly (no download needed!)
builder = github_readme_to_video(
    'https://github.com/fastapi/fastapi'  # Just the repo URL!
)

builder.export_to_yaml('sets/fastapi_demo')
```

### **From YouTube Video:**

```python
from scripts.youtube_to_programmatic import parse_youtube_to_set

# Parse YouTube transcript automatically
set_path = parse_youtube_to_set(
    'https://youtube.com/watch?v=VIDEO_ID',
    target_duration=90  # Target summary length
)

# Generated:
# - Fetches transcript
# - Extracts key points
# - Creates scenes
# - Auto-generates narration
```

**What you provide:** Just a URL or file path
**What you get:** Complete video ready to generate

---

## Level 2: Parse → Customize

**🎯 Start automatic, then enhance**

### **Parse Document + Add Custom Content:**

```python
from scripts.document_to_programmatic import parse_document_to_builder

# Step 1: Parse README automatically
builder = parse_document_to_builder('README.md')

# Step 2: Enhance with custom intro
builder.videos[0].scenes.insert(0,
    builder.create_title_scene(
        "Enhanced Tutorial",
        "Auto-Parsed + Custom Touches",
        narration="Welcome! This video automatically parsed the README, then we added custom narration for a personal touch."
    )
)

# Step 3: Add bonus content
builder.add_video(
    video_id='bonus_tips',
    title='Bonus Tips',
    scenes=[
        builder.create_list_scene(
            "Pro Tips",
            "Extra Content",
            [
                ("Tip 1", "Use version control"),
                ("Tip 2", "Write tests"),
                ("Tip 3", "Document your code")
            ]
        )
    ]
)

# Export
builder.export_to_yaml('sets/enhanced_readme')
```

### **Parse Multiple Sources → One Set:**

```python
from scripts.document_to_programmatic import parse_document_to_builder
from scripts.youtube_to_programmatic import parse_youtube_to_builder
from scripts.python_set_builder import VideoSetBuilder

# Create main builder
builder = VideoSetBuilder(
    set_id='complete_tutorial',
    set_name='Complete Tutorial - All Sources'
)

# Add from README
readme_builder = parse_document_to_builder('README.md')
builder.videos.extend(readme_builder.videos)

# Add from YouTube
youtube_builder = parse_youtube_to_builder('https://youtube.com/watch?v=ID')
builder.videos.extend(youtube_builder.videos)

# Add custom content
builder.add_video(
    video_id='summary',
    title='Summary & Next Steps',
    scenes=[...]  # Your custom content
)

builder.export_to_yaml('sets/complete_tutorial')
```

---

## Level 3: Provide Structure → Auto-Narrate

**🎯 You define structure, system writes narration**

```python
from scripts.python_set_builder import VideoSetBuilder

builder = VideoSetBuilder("structured", "Structured Content")

builder.add_video(
    video_id="tutorial",
    title="Python Tutorial",
    scenes=[
        # Just provide visual content - narration auto-generated!
        builder.create_title_scene(
            "Python Tutorial",
            "Complete Guide"
            # Auto: "Python tutorial. Complete guide."
        ),

        builder.create_command_scene(
            "Installation",
            "Set Up Python",
            ["$ python --version", "$ pip install numpy"]
            # Auto: "Installation. Set up Python. Run these 2 commands..."
        ),

        builder.create_list_scene(
            "Features",
            "Why Python",
            [("Easy", "Simple syntax"), ("Powerful", "Rich libs")]
            # Auto: "Features. Why Python. Key features include easy and powerful."
        )
    ]
)
```

**You provide:** Scene type + visual content
**System generates:** Professional narration automatically

---

## Level 4: Full Custom Narration

**🎯 Complete control over every word**

```python
builder.add_video(
    video_id="custom",
    title="Custom Narration",
    scenes=[
        builder.create_title_scene(
            "Advanced Python",
            "Expert Level",
            narration="Welcome to advanced Python. This deep dive assumes you're comfortable with the basics and ready to tackle complex concepts like metaclasses, decorators, and asynchronous programming."
        ),

        builder.create_command_scene(
            "Decorator Pattern",
            "Function Wrappers",
            [
                "@timer",
                "def slow_function():",
                "    time.sleep(1)",
                "    return 'Done'"
            ],
            narration="Decorators wrap functions to add behavior. The at-sign timer decorator measures execution time. Define your function normally. The decorator automatically times it. This pattern is powerful for logging, caching, and profiling."
        ),

        builder.create_list_scene(
            "Advanced Patterns",
            "Master These",
            [
                ("Decorators", "Function wrappers"),
                ("Generators", "Lazy evaluation"),
                ("Context Managers", "Resource handling")
            ],
            narration="Three essential advanced patterns. Decorators for function wrappers and cross-cutting concerns. Generators for memory-efficient lazy evaluation. Context managers for guaranteed resource cleanup. Master these and you're in the top ten percent of Python developers."
        ),

        builder.create_outro_scene(
            "You're an Expert!",
            "advanced-python.dev",
            narration="Congratulations! You've mastered advanced Python patterns. Visit advanced dash python dot dev for real-world projects and continued learning.",
            voice="male_warm"  # Warmer voice for celebration
        )
    ]
)
```

**You provide:** Every word of narration
**System uses:** Your exact text

---

## Level 5: Load Content from Files/Database

**🎯 Content managed externally**

### **From JSON File:**

```python
import json
from scripts.python_set_builder import VideoSetBuilder

# Load content
with open('video_content.json') as f:
    content = json.load(f)

builder = VideoSetBuilder("json_content", "Content from JSON")

for video_data in content['videos']:
    builder.add_video(
        video_id=video_data['id'],
        title=video_data['title'],
        scenes=[
            builder.create_title_scene(
                video_data['title'],
                video_data['subtitle'],
                narration=video_data['narration']['intro']
            ),
            builder.create_command_scene(
                video_data['section']['header'],
                video_data['section']['description'],
                video_data['section']['commands'],
                narration=video_data['narration']['main']
            ),
            builder.create_outro_scene(
                video_data['outro']['main'],
                video_data['outro']['sub'],
                narration=video_data['narration']['outro']
            )
        ]
    )

builder.export_to_yaml('sets/json_content')
```

**`video_content.json`:**
```json
{
  "videos": [
    {
      "id": "lesson_01",
      "title": "Variables",
      "subtitle": "Storing Data",
      "section": {
        "header": "Creating Variables",
        "description": "Basic Syntax",
        "commands": ["x = 10", "print(x)"]
      },
      "narration": {
        "intro": "Variables in Python. Learn how to store data.",
        "main": "Create a variable with assignment. Print to see the value.",
        "outro": "You now understand variables. Next: functions."
      },
      "outro": {
        "main": "Great!",
        "sub": "Next: Functions"
      }
    }
  ]
}
```

### **From Database:**

```python
import sqlite3
from scripts.python_set_builder import VideoSetBuilder

conn = sqlite3.connect('content.db')

# Table: videos (id, title, intro_narration, main_narration, outro_narration, commands_json)
cursor = conn.execute('SELECT * FROM videos')

builder = VideoSetBuilder("db_videos", "Database Videos")

for row in cursor:
    video_id, title, intro_narr, main_narr, outro_narr, commands_json = row

    import json
    commands = json.loads(commands_json)

    builder.add_video(
        video_id=video_id,
        title=title,
        scenes=[
            builder.create_title_scene(
                title,
                "Tutorial",
                narration=intro_narr  # From database!
            ),
            builder.create_command_scene(
                "Commands",
                "How To",
                commands,  # From database!
                narration=main_narr  # From database!
            ),
            builder.create_outro_scene(
                "Learn More",
                "docs.example.com",
                narration=outro_narr  # From database!
            )
        ]
    )

builder.export_to_yaml('sets/db_videos')
```

---

## 🔀 Hybrid Approaches (Best Practice!)

### **Approach 1: Parse + Guide Narration**

```python
from scripts.document_to_programmatic import parse_document_to_builder

# Parse document
builder = parse_document_to_builder('README.md')

# Get the auto-generated video
video = builder.videos[0]

# Add context to guide better narration
for scene in video.scenes:
    if scene.scene_type == 'command':
        # Add topic/key_points for richer auto-narration
        scene.visual_content['topic'] = "Quick setup process"
        scene.visual_content['key_points'] = [
            "Takes under 2 minutes",
            "No configuration needed",
            "Works on all platforms"
        ]

builder.export_to_yaml('sets/guided_readme')
```

### **Approach 2: Parse Multiple + Custom Narration**

```python
from scripts.document_to_programmatic import parse_document_to_builder
from scripts.python_set_builder import VideoSetBuilder

# Create main set
builder = VideoSetBuilder("docs_collection", "Documentation Collection")

# Parse multiple docs (auto-narration)
for doc_file in ['README.md', 'INSTALLATION.md', 'USAGE.md']:
    temp = parse_document_to_builder(doc_file)
    builder.videos.extend(temp.videos)

# Add custom intro video (custom narration)
builder.videos.insert(0,
    builder.VideoConfig(
        video_id='00_welcome',
        title='Welcome',
        scenes=[
            builder.create_title_scene(
                "Documentation Series",
                "Complete Guide",
                narration="Welcome to the complete documentation series. We've converted all documentation into easy-to-follow video tutorials. Let's get started."
            )
        ]
    )
)

# Add custom outro (custom narration)
builder.add_video(
    video_id='99_conclusion',
    title='Conclusion',
    scenes=[
        builder.create_outro_scene(
            "You're Ready!",
            "Start Building",
            narration="You've completed the documentation series. You have everything you need to start building amazing projects. Good luck!"
        )
    ]
)

builder.export_to_yaml('sets/docs_collection')
```

---

## 🚀 Complete Real-World Examples

### **Example 1: GitHub README → Video (Zero Manual Work)**

```python
from scripts.document_to_programmatic import github_readme_to_video

# Literally ONE line of code!
builder = github_readme_to_video('https://github.com/django/django')
builder.export_to_yaml('sets/django_demo')

# That's it! Everything auto-generated from the README:
# - Structure parsed
# - Scenes created
# - Narration generated
# - Ready to render
```

**Then generate:**
```bash
cd scripts
python generate_video_set.py ../sets/django_demo
python generate_videos_from_set.py ../output/django_demo
```

---

### **Example 2: YouTube Tutorial → Summary Video**

```python
from scripts.youtube_to_programmatic import parse_youtube_to_set

# Parse 30-minute YouTube tutorial → 60-second summary
set_path = parse_youtube_to_set(
    'https://youtube.com/watch?v=VIDEO_ID',
    target_duration=60,  # Condense to 60 seconds
    defaults={
        'accent_color': 'purple',
        'voice': 'female'
    }
)

# Auto-generated:
# - Transcript fetched
# - Key points extracted
# - Narration condensed
# - Scenes structured
```

---

### **Example 3: Multiple READMEs → Tutorial Series**

```python
from scripts.document_to_programmatic import parse_document_to_builder
from scripts.python_set_builder import VideoSetBuilder

# Create set
builder = VideoSetBuilder(
    set_id='framework_comparison',
    set_name='Framework Comparison Series'
)

# Parse multiple GitHub READMEs
frameworks = [
    ('https://github.com/django/django', 'Django'),
    ('https://github.com/fastapi/fastapi', 'FastAPI'),
    ('https://github.com/pallets/flask', 'Flask')
]

for github_url, name in frameworks:
    # Parse each README
    temp = github_readme_to_video(github_url)

    # Customize
    video = temp.videos[0]
    video.video_id = name.lower()
    video.title = f"{name} Overview"

    # Add to main set
    builder.videos.append(video)

# Export
builder.export_to_yaml('sets/framework_comparison')

# Result: 3 videos, auto-generated from GitHub READMEs!
```

---

### **Example 4: Database Content with Custom Narration**

```python
import sqlite3
from scripts.python_set_builder import VideoSetBuilder

# Database structure:
# CREATE TABLE tutorials (
#     id INT,
#     topic TEXT,
#     intro_text TEXT,
#     code_examples TEXT,
#     key_takeaways TEXT
# )

conn = sqlite3.connect('tutorials.db')
cursor = conn.execute('SELECT * FROM tutorials ORDER BY id')

builder = VideoSetBuilder("db_tutorials", "Tutorial Database")

for tutorial_id, topic, intro, code, takeaways in cursor:
    import json
    code_list = json.loads(code)
    takeaways_list = json.loads(takeaways)

    builder.add_video(
        video_id=f"tutorial_{tutorial_id:02d}",
        title=topic,
        scenes=[
            builder.create_title_scene(
                topic,
                f"Lesson {tutorial_id}",
                narration=intro  # Custom from DB
            ),
            builder.create_command_scene(
                "Example Code",
                "See It In Action",
                code_list  # From DB
                # No narration → auto-generated from code
            ),
            builder.create_list_scene(
                "Key Takeaways",
                "Remember These",
                takeaways_list  # From DB
                # No narration → auto-generated from items
            ),
            builder.create_outro_scene(
                f"Completed {topic}!",
                f"Next: Lesson {tutorial_id + 1}"
                # No narration → auto-generated
            )
        ]
    )

builder.export_to_yaml('sets/db_tutorials')
```

---

## 💡 Content Control Patterns

### **Pattern 1: Auto Everything**

```python
# Markdown → Video (zero manual work)
from scripts.document_to_programmatic import parse_document_to_set

parse_document_to_set('README.md')
```

### **Pattern 2: Auto Structure + Custom Key Scenes**

```python
# Parse document
builder = parse_document_to_builder('README.md')

# Replace intro with custom
builder.videos[0].scenes[0] = builder.create_title_scene(
    "Custom Intro",
    "Personal Touch",
    narration="Your custom intro narration here..."
)

# Replace outro with custom
builder.videos[0].scenes[-1] = builder.create_outro_scene(
    "Custom Outro",
    "Call to Action",
    narration="Your custom outro narration here..."
)

# Middle scenes stay auto-generated!
```

### **Pattern 3: Manual Structure + Auto Narration**

```python
builder = VideoSetBuilder("manual_structure", "Manual Structure")

# You define structure
topics = ["Intro", "Setup", "Usage", "Advanced"]

for topic in topics:
    builder.add_video(
        video_id=topic.lower(),
        title=topic,
        scenes=[
            builder.create_title_scene(topic, f"{topic} Section"),
            builder.create_command_scene(f"{topic} Commands", "Examples", ["# ..."]),
            builder.create_outro_scene("Next", f"Next: {topic}")
        ]
        # All scenes auto-generate narration from structure!
    )
```

### **Pattern 4: Template-Based with Variables**

```python
def create_api_video(builder, endpoint, method, description, example_response):
    """Template with custom narration using variables"""

    builder.add_video(
        video_id=f"api_{endpoint.replace('/', '_')}",
        title=f"{method} {endpoint}",
        scenes=[
            builder.create_title_scene(
                f"{method} {endpoint}",
                "API Endpoint",
                narration=f"{method} request to {endpoint}. {description}"
            ),
            builder.create_command_scene(
                "Example Request",
                f"{method} {endpoint}",
                [
                    f"curl -X {method} https://api.example.com{endpoint}",
                    f"→ {example_response}"
                ],
                narration=f"Send a {method} request to the {endpoint} endpoint. {description}. The response includes {example_response}."
            )
        ]
    )

# Use template with data
builder = VideoSetBuilder("api_docs", "API Documentation")

endpoints = [
    ('/users', 'GET', 'Fetch all users', 'user list'),
    ('/users/123', 'GET', 'Fetch specific user', 'user details'),
    ('/users', 'POST', 'Create new user', 'created user')
]

for endpoint, method, desc, response in endpoints:
    create_api_video(builder, endpoint, method, desc, response)
```

---

## 📚 Command Line Quick Reference

### **Parse Document:**

```bash
# Local file
python document_to_programmatic.py README.md

# GitHub URL
python document_to_programmatic.py https://github.com/user/repo/blob/main/README.md

# With options
python document_to_programmatic.py README.md --accent-color purple --voice female
```

### **Parse YouTube:**

```bash
# YouTube URL
python youtube_to_programmatic.py https://youtube.com/watch?v=VIDEO_ID

# With options
python youtube_to_programmatic.py https://youtube.com/watch?v=ID \\
    --accent-color green \\
    --voice female \\
    --duration 90
```

### **Then Generate:**

```bash
cd scripts
python generate_video_set.py ../sets/{set_name}
python generate_videos_from_set.py ../output/{set_name}
```

---

## 🎯 Decision Guide

### **Choose Level Based on Your Needs:**

**Use Level 1 (Parse document) when:**
- ✅ You have existing markdown/README
- ✅ Want zero manual work
- ✅ Content structure is good as-is
- ✅ Quick video needed

**Use Level 2 (Parse + customize) when:**
- ✅ Have existing docs as base
- ✅ Want to enhance with custom touches
- ✅ Combining multiple sources
- ✅ 80% auto, 20% custom

**Use Level 3 (Structure + auto-narrate) when:**
- ✅ You know the structure
- ✅ Trust auto-narration quality
- ✅ Want consistency
- ✅ Generating many videos

**Use Level 4 (Full custom) when:**
- ✅ Need exact wording
- ✅ Brand voice important
- ✅ Complex explanations
- ✅ Marketing/sales content

**Use Level 5 (External content) when:**
- ✅ Content in CMS/database
- ✅ API-driven content
- ✅ Team manages content separately
- ✅ Content reuse across platforms

---

## 💡 Pro Tips

### **Tip 1: Start Auto, Refine Later**

```python
# 1. Quick parse
builder = parse_document_to_builder('README.md')
builder.export_to_yaml('sets/readme_v1')

# 2. Generate and review
# (Generate video, watch it)

# 3. If needed, customize
builder = parse_document_to_builder('README.md')
# Add custom narration to key scenes
builder.videos[0].scenes[0].narration = "Custom intro..."
builder.export_to_yaml('sets/readme_v2')
```

### **Tip 2: Mix Parsed + Custom**

```python
# Parse README (auto)
builder = parse_document_to_builder('README.md')

# Add programmatic content (custom)
builder.add_video(
    video_id='advanced_tips',
    title='Advanced Tips',
    scenes=[...]  # Your custom content
)

# Best of both worlds!
```

### **Tip 3: Use Narration Templates**

```python
NARRATION_TEMPLATES = {
    'intro': lambda title: f"{title}. Your complete guide to getting started.",
    'outro': lambda topic: f"You've completed {topic}. Continue to the next lesson."
}

builder.add_video(
    video_id='lesson',
    title='Lesson 1',
    scenes=[
        builder.create_title_scene(
            "Lesson 1",
            "Variables",
            narration=NARRATION_TEMPLATES['intro']("Variables")
        ),
        # ... middle scenes ...
        builder.create_outro_scene(
            "Great!",
            "Next",
            narration=NARRATION_TEMPLATES['outro']("variables")
        )
    ]
)
```

---

## 📊 Summary

**YES! You can absolutely use raw markdown/GitHub READMEs programmatically:**

### **Simplest (Full Auto):**
```python
from scripts.document_to_programmatic import parse_document_to_set
parse_document_to_set('README.md')  # Done!
```

### **With Customization:**
```python
builder = parse_document_to_builder('README.md')
builder.add_video(...)  # Add more
builder.videos[0].scenes[0].narration = "Custom..."  # Customize
builder.export_to_yaml('sets/my_set')
```

### **YouTube Too:**
```python
from scripts.youtube_to_programmatic import parse_youtube_to_set
parse_youtube_to_set('https://youtube.com/watch?v=ID')  # Done!
```

---

**🎬 You can parse ANY content source programmatically!**

- ✅ Local markdown files
- ✅ GitHub READMEs
- ✅ YouTube transcripts
- ✅ Plain text files
- ✅ Multiple sources combined
- ✅ With or without customization

**The system handles ALL the parsing - you just provide the source!**
