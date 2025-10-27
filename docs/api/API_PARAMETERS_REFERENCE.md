# Complete API Parameters Reference

**Comprehensive documentation of all programmatic API parameters**

---

## 📊 Visual API Structure Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Video Generation API                         │
│                                                                      │
│  Input: VideoConfig or VideoSet                                     │
│    ↓                                                                │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ VideoConfig (Single Video)                                    │  │
│  │ ├── video_id (required)                                       │  │
│  │ ├── title (required)                                          │  │
│  │ ├── description (required)                                    │  │
│  │ ├── scenes[] (required) ──────────────┐                       │  │
│  │ ├── accent_color (optional)           │                       │  │
│  │ └── voices[] (optional)               │                       │  │
│  └───────────────────────────────────────┼───────────────────────┘  │
│                                          │                          │
│  ┌───────────────────────────────────────▼──────────────────────┐  │
│  │ SceneConfig (Individual Scene)                                │  │
│  │ ├── scene_id (required)                                       │  │
│  │ ├── scene_type (required) ─────┐                              │  │
│  │ ├── narration (required)       │                              │  │
│  │ ├── visual_content (required) ─┼─────┐                        │  │
│  │ ├── voice (optional)           │     │                        │  │
│  │ ├── min_duration (optional)    │     │                        │  │
│  │ └── max_duration (optional)    │     │                        │  │
│  └────────────────────────────────┼─────┼────────────────────────┘  │
│                                   │     │                           │
│         12 Scene Types ◄──────────┘     └──► Type-specific content  │
│         ├── title                              (see below)          │
│         ├── command                                                 │
│         ├── list                                                    │
│         ├── outro                                                   │
│         ├── code_comparison                                         │
│         ├── quote                                                   │
│         ├── learning_objectives                                     │
│         ├── quiz                                                    │
│         ├── exercise                                                │
│         ├── problem                                                 │
│         ├── solution                                                │
│         └── checkpoint                                              │
│                                                                      │
│  Output: Generated video with audio + visuals                       │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Parameter Hierarchy Diagram

```
InputConfig (Pipeline Entry)
    │
    ├─► input_type: "programmatic"
    ├─► source: VideoConfig | VideoSet
    ├─► languages: ["en", "es", ...]  ← Multilingual expansion
    └─► accent_color, voice (optional overrides)
         │
         └─► Pipeline Processing
              │
              ├─► 1 video × N languages → N outputs
              └─► M videos × N languages → M×N outputs
```

---

## 📦 Core Models

### VideoSet

**Purpose:** Collection of multiple related videos (for batch processing and multilingual workflows)

**Required Parameters:**

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `set_id` | `str` | Unique set identifier | `"python_tutorial"` |
| `name` | `str` | Set display name | `"Python Tutorial Series"` |

**Optional Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `description` | `str` | `""` | Set description |
| `videos` | `List[VideoConfig]` | `[]` | List of videos in set |
| `metadata` | `Dict[str, Any]` | `{}` | Metadata (languages, etc.) |

**Special Properties:**

- `languages` (property) - Returns list of languages from metadata
- `to_dict()` (method) - Serialize to dictionary

**Example - Single Language Set:**
```python
from video_gen.shared.models import VideoSet, VideoConfig

video_set = VideoSet(
    set_id="tutorial_series",
    name="Python Tutorial Series",
    description="Complete Python basics course",
    videos=[
        VideoConfig(...),  # Video 1
        VideoConfig(...),  # Video 2
        VideoConfig(...)   # Video 3
    ],
    metadata={"languages": ["en"]}
)
```

**Example - Multilingual Set:**
```python
video_set = VideoSet(
    set_id="tutorial_multilingual",
    name="Python Tutorial (Multi-language)",
    description="Tutorial in English, Spanish, French",
    videos=[
        VideoConfig(video_id="tutorial_en", ...),  # English version
        VideoConfig(video_id="tutorial_es", ...),  # Spanish version
        VideoConfig(video_id="tutorial_fr", ...)   # French version
    ],
    metadata={
        "languages": ["en", "es", "fr"],
        "source_language": "en"
    }
)
```

---

### VideoConfig

**Purpose:** Configuration for a complete video

**Required Parameters:**

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `video_id` | `str` | Unique video identifier | `"intro_video"` |
| `title` | `str` | Video title | `"Introduction to Python"` |
| `description` | `str` | Video description | `"Learn Python basics"` |
| `scenes` | `List[SceneConfig]` | List of scene configurations | `[scene1, scene2]` |

**Optional Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `accent_color` | `str` | `"blue"` | Color theme: blue, orange, purple, green, pink, cyan |
| `version` | `str` | `"v2.0"` | Video format version |
| `voices` | `List[str]` | `["male"]` | Voice rotation list: male, male_warm, female, female_friendly |

**Runtime Fields (Auto-populated):**
- `total_duration` - Calculated from scenes
- `audio_dir` - Generated audio directory
- `video_file` - Output video path
- `final_file` - Final processed video
- `generation_timestamp` - When generated

**Example:**
```python
from video_gen.shared.models import VideoConfig, SceneConfig

video = VideoConfig(
    video_id="tutorial_01",
    title="Python Tutorial Part 1",
    description="Variables and data types",
    scenes=[...],  # List of SceneConfig
    accent_color="blue",  # Optional
    voices=["male", "female"]  # Optional - rotates voices
)
```

---

### SceneConfig

**Purpose:** Configuration for a single scene in a video

**Required Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `scene_id` | `str` | Unique scene identifier |
| `scene_type` | `str` | One of 12 types (see below) |
| `narration` | `str` | What the voice says |
| `visual_content` | `Dict[str, Any]` | Scene-specific content (see below) |

**Optional Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `voice` | `str` | `"male"` | Voice for this scene |
| `min_duration` | `float` | `3.0` | Minimum scene duration (seconds) |
| `max_duration` | `float` | `15.0` | Maximum scene duration (seconds) |

**Runtime Fields (Auto-populated):**
- `actual_audio_duration` - Measured TTS duration
- `final_duration` - Final scene duration
- `audio_file` - Generated audio path
- `warnings` - Any generation warnings

---

## 🎨 Scene Types & visual_content Requirements

### 🎬 Scene Type Visual Gallery

**Quick visual reference for all 12 scene types:**

```
┌─────────────────────┬─────────────────────┬─────────────────────┐
│    TITLE SCENE      │   COMMAND SCENE     │    LIST SCENE       │
│ ┌─────────────────┐ │ ┌─────────────────┐ │ ┌─────────────────┐ │
│ │                 │ │ │  Installation   │ │ │  Key Features   │ │
│ │   PYTHON        │ │ │  ════════════   │ │ │  ────────────   │ │
│ │   TUTORIAL      │ │ │                 │ │ │                 │ │
│ │                 │ │ │ $ pip install X │ │ │ 1. Feature one  │ │
│ │ Learn Basics    │ │ │ $ npm run dev   │ │ │ 2. Feature two  │ │
│ │                 │ │ │ $ make build    │ │ │ 3. Feature thr  │ │
│ └─────────────────┘ │ └─────────────────┘ │ └─────────────────┘ │
│   Center aligned    │  Terminal style     │  Numbered bullets   │
├─────────────────────┼─────────────────────┼─────────────────────┤
│   QUIZ SCENE        │  CODE COMPARISON    │  LEARNING OBJECTIVES│
│ ┌─────────────────┐ │ ┌────────┬────────┐ │ ┌─────────────────┐ │
│ │ What is 2+2?    │ │ │ Before │ After  │ │ │ 🎯 Lesson Goals │ │
│ │                 │ │ │ ────── │ ────── │ │ │                 │ │
│ │ A) 3            │ │ │ code1  │ code1  │ │ │ ▸ Understand X  │ │
│ │ B) 4   ✓        │ │ │ code2  │ better │ │ │ ▸ Use Y         │ │
│ │ C) 5            │ │ │ code3  │ code2  │ │ │ ▸ Create Z      │ │
│ │ D) 6            │ │ │        │        │ │ │                 │ │
│ └─────────────────┘ │ └────────┴────────┘ │ └─────────────────┘ │
│  Multiple choice    │  Side-by-side       │  Bulleted goals     │
├─────────────────────┼─────────────────────┼─────────────────────┤
│  EXERCISE SCENE     │  PROBLEM SCENE      │  SOLUTION SCENE     │
│ ┌─────────────────┐ │ ┌─────────────────┐ │ ┌─────────────────┐ │
│ │ ✏️ Practice      │ │ │ ⚠️ Challenge     │ │ │ ✓ Solution      │ │
│ │                 │ │ │                 │ │ │                 │ │
│ │ Create 3 vars:  │ │ │ Reverse string  │ │ │ def reverse():  │ │
│ │ name, age, city │ │ │ without using   │ │ │   return s[::-1]│ │
│ │                 │ │ │ built-in funcs  │ │ │                 │ │
│ │ 💡 Hint: Use    │ │ │                 │ │ │ We use slicing  │ │
│ │    descriptive  │ │ │ Difficulty: MED │ │ │ with step -1    │ │
│ └─────────────────┘ │ └─────────────────┘ │ └─────────────────┘ │
│  Task + hints       │  Challenge prompt   │  Code + explanation │
├─────────────────────┼─────────────────────┼─────────────────────┤
│  CHECKPOINT SCENE   │    QUOTE SCENE      │    OUTRO SCENE      │
│ ┌────────┬────────┐ │ ┌─────────────────┐ │ ┌─────────────────┐ │
│ │ Learned│ Next   │ │ │                 │ │ │                 │ │
│ │ ────── │ ────── │ │ │   "Code is      │ │ │       ✓         │ │
│ │ ✓ Vars │ → OOP  │ │ │    like humor"  │ │ │                 │ │
│ │ ✓ Funcs│ → Files│ │ │                 │ │ │  Thanks for     │ │
│ │ ✓ Loops│ → Tests│ │ │   - Anonymous   │ │ │   Watching!     │ │
│ └────────┴────────┘ │ └─────────────────┘ │ │                 │ │
│  Two-column review  │  Centered quote     │  Call to action     │
└─────────────────────┴─────────────────────┴─────────────────────┘
```

---

### 📋 Scene Type Comparison Matrix

| Scene Type | Best For | Visual Style | Content Density | Animation |
|------------|----------|--------------|-----------------|-----------|
| **title** | Intro, section headers | Large centered text | Low | Fade in |
| **command** | Code, terminal commands | Dark terminal | Medium | Line-by-line |
| **list** | Features, steps | Numbered bullets | Medium | Sequential |
| **outro** | End screens, CTA | Centered + icon | Low | Checkmark |
| **code_comparison** | Before/after code | Split screen | High | Side fade |
| **quote** | Inspiration, wisdom | Large centered | Low | Fade in |
| **learning_objectives** | Lesson goals | Bulleted list | Medium | Sequential |
| **quiz** | Knowledge checks | Multiple choice | Medium | Reveal answer |
| **exercise** | Practice tasks | Task + hints | Medium | Fade in |
| **problem** | Coding challenges | Problem statement | Medium | Difficulty color |
| **solution** | Problem solutions | Code + explanation | High | Two-phase |
| **checkpoint** | Progress review | Two-column | Medium | Column fade |

---

### 1. Title Scene (`scene_type="title"`)

**Layout Diagram:**
```
┌────────────────────────────────────────────────────┐
│                                                    │
│                                                    │
│                                                    │
│               ┌──────────────────┐                 │
│               │                  │                 │
│               │   PYTHON         │  ← Large title  │
│               │   TUTORIAL       │    (100px font) │
│               │                  │                 │
│               └──────────────────┘                 │
│                                                    │
│                  Learn the Basics  ← Subtitle      │
│                                      (50px font)   │
│                                                    │
│                                                    │
│                                                    │
└────────────────────────────────────────────────────┘
       1920×1080px, gradient background
```

**visual_content Required:**
```python
{
    "title": str,      # Main title text
    "subtitle": str    # Subtitle text
}
```

**📝 Pro Tips:**
- ✅ Keep title under 30 characters for best readability
- ✅ Subtitle complements title, not duplicates it
- ✅ Use title case for professional look
- ⚠️ Avoid ALL CAPS unless intentional emphasis

**💡 Best Practices:**
- Title should be concise, impactful statement
- Subtitle provides context or preview
- Works great for: Intros, section dividers, chapter headers

**❌ Common Mistakes:**
```python
# Too long - will truncate or overflow
"title": "Complete Beginner's Guide to Advanced Python Programming Techniques"

# Too similar to subtitle
"title": "Python Tutorial"
"subtitle": "A Tutorial on Python"  # ❌ Redundant!
```

**✅ Good Examples:**
```python
# Professional course intro
{"title": "Python Mastery", "subtitle": "From Zero to Hero"}

# Section header
{"title": "Variables & Types", "subtitle": "Lesson 1"}

# Topic intro
{"title": "API Development", "subtitle": "Build RESTful Services"}
```

**Example:**
```python
SceneConfig(
    scene_id="intro",
    scene_type="title",
    narration="Welcome to our tutorial on Python programming",
    visual_content={
        "title": "Python Tutorial",
        "subtitle": "Learn the Basics"
    }
)
```

---

### 2. Command Scene (`scene_type="command"`)

**Layout Diagram:**
```
┌────────────────────────────────────────────────────┐
│  Installation                        ← Header      │
│  ═══════════════════════════════════               │
│                                                    │
│  Setup                                ← Label      │
│  ┌──────────────────────────────────────────────┐ │
│  │ $ pip install fastapi               ← Line 1 │ │
│  │ $ pip install uvicorn               ← Line 2 │ │
│  │ $ uvicorn main:app --reload         ← Line 3 │ │
│  └──────────────────────────────────────────────┘ │
│                                                    │
│         Dark terminal background (35, 35, 35)     │
│         Monospace font, syntax highlighting       │
└────────────────────────────────────────────────────┘
```

**visual_content Required:**
```python
{
    "header": str,           # Section header
    "label": str,            # Command label (e.g., "Setup")
    "commands": List[str]    # List of command strings (max 8)
}
```

**📝 Pro Tips:**
- ✅ Max 8 commands per scene for readability
- ✅ Use actual executable commands
- ✅ Include $ or > prompt symbols for clarity
- 💡 Break long commands across scenes if needed

**💡 Best Practices:**
- Each command should be copy-paste ready
- Show real-world usage patterns
- Include comments with # for complex commands
- Works great for: Installation, setup, deployment

**✨ Advanced Features:**
- Automatic syntax highlighting for common shells
- Line numbering for multi-step processes
- Terminal-style dark background for contrast

**✅ Good Examples:**
```python
# Installation sequence
{
    "header": "Getting Started",
    "label": "Install Dependencies",
    "commands": [
        "pip install -r requirements.txt",
        "python manage.py migrate",
        "python manage.py createsuperuser"
    ]
}

# Docker workflow
{
    "header": "Docker Deployment",
    "label": "Build and Run",
    "commands": [
        "docker build -t myapp .",
        "docker run -p 8000:8000 myapp"
    ]
}

# Git workflow
{
    "header": "Version Control",
    "label": "Commit Changes",
    "commands": [
        "git add .",
        "git commit -m 'Add feature'",
        "git push origin main"
    ]
}
```

**Example:**
```python
SceneConfig(
    scene_id="install",
    scene_type="command",
    narration="First, install the required packages",
    visual_content={
        "header": "Installation",
        "label": "Setup",
        "commands": [
            "pip install fastapi",
            "pip install uvicorn"
        ]
    }
)
```

---

### 3. List Scene (`scene_type="list"`)

**visual_content Required:**
```python
{
    "header": str,                    # List header
    "description": str,               # List description
    "items": List[str] or List[dict]  # List items (str or {text, desc})
}
```

**Example:**
```python
SceneConfig(
    scene_id="features",
    scene_type="list",
    narration="Here are the key features of FastAPI",
    visual_content={
        "header": "Key Features",
        "description": "What makes FastAPI great",
        "items": [
            "Fast performance",
            "Easy to learn",
            "Type hints",
            "Automatic docs",
            "Async support"
        ]
    }
)
```

**Or with descriptions:**
```python
visual_content={
    "items": [
        {"text": "Fast", "desc": "High performance"},
        {"text": "Easy", "desc": "Simple syntax"}
    ]
}
```

---

### 4. Outro Scene (`scene_type="outro"`)

**visual_content Required:**
```python
{
    "main_text": str,  # Thank you message
    "sub_text": str    # Call to action
}
```

**Example:**
```python
SceneConfig(
    scene_id="end",
    scene_type="outro",
    narration="Thanks for watching! Check out the documentation for more",
    visual_content={
        "main_text": "Thanks for Watching!",
        "sub_text": "See Full Documentation"
    }
)
```

---

### 5. Code Comparison (`scene_type="code_comparison"`)

**visual_content Required:**
```python
{
    "before_code": List[str],  # Original code lines
    "after_code": List[str],   # Refactored code lines
    "before_label": str,       # Left label (default: "Before")
    "after_label": str         # Right label (default: "After")
}
```

**Example:**
```python
SceneConfig(
    scene_id="refactor",
    scene_type="code_comparison",
    narration="Here's how we can refactor this code for better readability",
    visual_content={
        "before_code": [
            "def process(data):",
            "    result = []",
            "    for item in data:",
            "        result.append(item * 2)",
            "    return result"
        ],
        "after_code": [
            "def process(data):",
            "    return [item * 2 for item in data]"
        ],
        "before_label": "Original",
        "after_label": "Optimized"
    }
)
```

---

### 6. Quote Scene (`scene_type="quote"`)

**visual_content Required:**
```python
{
    "quote_text": str,      # The quote
    "attribution": str      # Who said it (optional)
}
```

**Example:**
```python
SceneConfig(
    scene_id="wisdom",
    scene_type="quote",
    narration="As the saying goes, code is like humor",
    visual_content={
        "quote_text": "Code is like humor. When you have to explain it, it's bad.",
        "attribution": "Cory House"
    }
)
```

---

### 7. Learning Objectives (`scene_type="learning_objectives"`)

**visual_content Required:**
```python
{
    "title": str,              # Lesson title
    "objectives": List[str]    # Learning goals (max 5)
}
```

**Example:**
```python
SceneConfig(
    scene_id="objectives",
    scene_type="learning_objectives",
    narration="By the end of this lesson, you will understand these key concepts",
    visual_content={
        "title": "Lesson Goals",
        "objectives": [
            "Understand variables",
            "Use basic data types",
            "Write simple functions"
        ]
    }
)
```

---

### 8. Quiz Scene (`scene_type="quiz"`)

**visual_content Required:**
```python
{
    "question": str,           # Quiz question
    "options": List[str],      # Answer choices (max 4)
    "correct_index": int       # Index of correct answer (0-3)
}
```

**Example:**
```python
SceneConfig(
    scene_id="quiz1",
    scene_type="quiz",
    narration="Let's test your knowledge with a quick question",
    visual_content={
        "question": "What is the output of print(2 + 2)?",
        "options": ["22", "4", "Error", "None"],
        "correct_index": 1  # "4" is correct
    }
)
```

---

### 9. Exercise Scene (`scene_type="exercise"`)

**visual_content Required:**
```python
{
    "title": str,           # Exercise title
    "instructions": str,    # What to do
    "hints": List[str]      # Helpful hints (max 3)
}
```

**Example:**
```python
SceneConfig(
    scene_id="practice",
    scene_type="exercise",
    narration="Now it's your turn to practice",
    visual_content={
        "title": "Practice: Variables",
        "instructions": "Create three variables: name, age, and city",
        "hints": [
            "Use descriptive variable names",
            "age should be an integer"
        ]
    }
)
```

---

### 10. Problem Scene (`scene_type="problem"`)

**visual_content Required:**
```python
{
    "title": str,           # Problem title
    "problem_text": str,    # Problem description
    "difficulty": str       # "easy", "medium", or "hard"
}
```

**Example:**
```python
SceneConfig(
    scene_id="challenge",
    scene_type="problem",
    narration="Here's a coding challenge for you",
    visual_content={
        "title": "Reverse a String",
        "problem_text": "Write a function that reverses a string without using built-in reverse methods",
        "difficulty": "medium"  # Changes color: easy=green, medium=orange, hard=red
    }
)
```

---

### 11. Solution Scene (`scene_type="solution"`)

**visual_content Required:**
```python
{
    "code": List[str],       # Solution code lines
    "explanation": str       # Explanation text
}
```

**Example:**
```python
SceneConfig(
    scene_id="solution",
    scene_type="solution",
    narration="Here's one way to solve this problem",
    visual_content={
        "code": [
            "def reverse_string(s):",
            "    return s[::-1]"
        ],
        "explanation": "We use Python's slice notation with a step of -1 to reverse the string"
    }
)
```

---

### 12. Checkpoint Scene (`scene_type="checkpoint"`)

**visual_content Required:**
```python
{
    "learned_topics": List[str],  # What was covered (max 6)
    "next_topics": List[str]      # What's coming next (max 6)
}
```

**Example:**
```python
SceneConfig(
    scene_id="checkpoint",
    scene_type="checkpoint",
    narration="Let's review what we've learned and preview what's next",
    visual_content={
        "learned_topics": [
            "Variables",
            "Data types",
            "Functions"
        ],
        "next_topics": [
            "Classes",
            "Modules",
            "File I/O"
        ]
    }
)
```

---

## 🎨 Visual Content Structure Summary

**Quick Reference Table:**

| Scene Type | Required Keys | Optional Keys | Max Items |
|------------|--------------|---------------|-----------|
| `title` | title, subtitle | - | - |
| `command` | header, label, commands | - | 8 commands |
| `list` | header, description, items | - | 5 items |
| `outro` | main_text, sub_text | - | - |
| `code_comparison` | before_code, after_code | before_label, after_label | 10 lines each |
| `quote` | quote_text | attribution | - |
| `learning_objectives` | title, objectives | - | 5 objectives |
| `quiz` | question, options, correct_index | - | 4 options |
| `exercise` | title, instructions, hints | - | 3 hints |
| `problem` | title, problem_text, difficulty | - | - |
| `solution` | code, explanation | - | 12 code lines |
| `checkpoint` | learned_topics, next_topics | - | 6 per column |

---

## 🔊 Voice Options

### Voice Characteristics Comparison

```
┌─────────────────┬──────────────┬──────────────┬──────────────┬──────────────┐
│ Characteristic  │   "male"     │ "male_warm"  │  "female"    │"female_      │
│                 │  (Andrew)    │  (Brandon)   │   (Aria)     │ friendly"    │
│                 │              │              │              │   (Ava)      │
├─────────────────┼──────────────┼──────────────┼──────────────┼──────────────┤
│ Tone            │ Professional │ Engaging     │ Professional │ Friendly     │
│ Pace            │ Medium       │ Relaxed      │ Crisp        │ Warm         │
│ Best For        │ Technical    │ Tutorials    │ Business     │ Educational  │
│ Authority Level │ High         │ Medium       │ High         │ Medium       │
│ Approachability │ Medium       │ High         │ Medium       │ High         │
│ Energy          │ Steady       │ Enthusiastic │ Clear        │ Pleasant     │
└─────────────────┴──────────────┴──────────────┴──────────────┴──────────────┘
```

**Available Voices:**

| Voice ID | Description | Gender | Tone | Use Cases |
|----------|-------------|--------|------|-----------|
| `"male"` | Andrew - Professional | Male | Confident, clear | Corporate, technical docs, formal content |
| `"male_warm"` | Brandon - Engaging | Male | Warm, friendly | Tutorials, guides, casual explainers |
| `"female"` | Aria - Clear | Female | Professional, crisp | Business, presentations, announcements |
| `"female_friendly"` | Ava - Pleasant | Female | Friendly, approachable | Educational, onboarding, how-tos |

**💡 Voice Selection Guide:**

```
Content Type                    Recommended Voice(s)
────────────────────────────────────────────────────
Technical Documentation    →    "male" or "female"
Tutorial / Course          →    "male_warm" or "female_friendly"
Product Demo               →    "male" or "female"
Educational Kids Content   →    "female_friendly"
Corporate Training         →    "female" or "male"
Casual How-To              →    "male_warm"
Formal Presentation        →    "male" or "female"
Storytelling               →    "male_warm" or "female_friendly"
```

**Voice Rotation Patterns:**

```python
# Pattern 1: Single voice for consistency
VideoConfig(..., voices=["male"])
# All scenes: male → male → male → male

# Pattern 2: Alternating for variety (recommended)
VideoConfig(..., voices=["male", "female"])
# Scenes: male → female → male → female → ...

# Pattern 3: Two similar tones
VideoConfig(..., voices=["male", "male_warm"])
# Scenes: male → male_warm → male → male_warm → ...

# Pattern 4: Full rotation for maximum variety
VideoConfig(..., voices=["male", "male_warm", "female", "female_friendly"])
# Scenes: male → male_warm → female → female_friendly → male → ...
```

**📝 Pro Tips:**
- ✅ Use rotation to distinguish between speakers/topics
- ✅ Keep 1 voice for short videos (< 5 scenes)
- ✅ Use 2 voices for dialog-style or contrasting sections
- 💡 Match voice energy to content tone

**Per-scene override:**
```python
SceneConfig(..., voice="female")  # Overrides video default for this scene
```

**✨ Advanced: Contextual Voice Usage**
```python
video = VideoConfig(
    voices=["male", "female"],  # Default rotation
    scenes=[
        SceneConfig(..., voice="male"),          # Intro - authoritative
        SceneConfig(...),                        # Auto: female (rotation)
        SceneConfig(...),                        # Auto: male (rotation)
        SceneConfig(..., voice="female_friendly") # Exercise - friendly tone
    ]
)
```

---

## 🎨 Color Options

### Color Psychology & Visual Guide

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Color Palette Preview                          │
│                                                                       │
│  BLUE     ████████  (59, 130, 246)   Professional • Trustworthy     │
│  ORANGE   ████████  (255, 107, 53)   Energetic • Creative           │
│  PURPLE   ████████  (168, 85, 247)   Premium • Sophisticated        │
│  GREEN    ████████  (16, 185, 129)   Success • Growth               │
│  PINK     ████████  (236, 72, 153)   Playful • Modern               │
│  CYAN     ████████  (6, 182, 212)    Tech • Innovation              │
└──────────────────────────────────────────────────────────────────────┘
```

**Available Colors:**

| Color | RGB | Psychology | Best For | Avoid For |
|-------|-----|------------|----------|-----------|
| `"blue"` | (59, 130, 246) | Professional, trustworthy, calm | Corporate, finance, healthcare, education | Food, entertainment |
| `"orange"` | (255, 107, 53) | Energetic, creative, enthusiastic | Creative, marketing, youth content | Serious, professional |
| `"purple"` | (168, 85, 247) | Premium, sophisticated, luxury | High-end products, creative, spiritual | Budget content |
| `"green"` | (16, 185, 129) | Success, growth, nature | Environmental, health, finance | Warning content |
| `"pink"` | (236, 72, 153) | Playful, modern, friendly | Youth, creative, lifestyle | Corporate, technical |
| `"cyan"` | (6, 182, 212) | Tech, innovation, clarity | Technology, science, modern | Traditional, classic |

**💡 Color Selection Decision Tree:**

```
What's your content focus?
│
├─ Business/Corporate?      → BLUE (trustworthy)
├─ Creative/Marketing?      → ORANGE (energetic)
├─ Premium/Luxury?          → PURPLE (sophisticated)
├─ Environmental/Health?    → GREEN (growth)
├─ Youth/Lifestyle?         → PINK (playful)
└─ Technology/Innovation?   → CYAN (modern)
```

**📝 Pro Tips:**
- ✅ Stick to one color per video for brand consistency
- ✅ Match color to audience expectations (tech → cyan/blue)
- ✅ Consider cultural color meanings for global audiences
- ⚠️ Avoid red/yellow (reserved for warnings/errors in UI)

**✨ Color Combinations for Video Sets:**
```python
# Series with consistent theme (all blue)
VideoSet(videos=[
    VideoConfig(..., accent_color="blue"),   # Part 1
    VideoConfig(..., accent_color="blue"),   # Part 2
    VideoConfig(..., accent_color="blue")    # Part 3
])

# Series with progressive theme
VideoSet(videos=[
    VideoConfig(..., accent_color="green"),  # Beginner - growth
    VideoConfig(..., accent_color="orange"), # Intermediate - energy
    VideoConfig(..., accent_color="purple")  # Advanced - premium
])

# Topic-based coloring
VideoSet(videos=[
    VideoConfig(..., accent_color="blue"),   # Intro/Theory
    VideoConfig(..., accent_color="cyan"),   # Code/Technical
    VideoConfig(..., accent_color="green")   # Results/Success
])
```

**Usage:**
```python
# Using color name (recommended)
VideoConfig(..., accent_color="purple")

# Using RGB tuple (advanced)
VideoConfig(..., accent_color=(168, 85, 247))

# Override via InputConfig
InputConfig(
    source=video,
    accent_color=(59, 130, 246)  # Overrides video's color
)
```

**🎨 Visual Impact Examples:**

```
Title Scene with Different Colors:
┌────────────┬────────────┬────────────┐
│   BLUE     │  ORANGE    │  PURPLE    │
│            │            │            │
│  Python    │  Python    │  Python    │
│  Tutorial  │  Tutorial  │  Tutorial  │
│            │            │            │
│ Trustworthy│ Energetic  │ Premium    │
└────────────┴────────────┴────────────┘
```

---

## ⏱️ Duration Control

**Scene Duration Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `min_duration` | `float` | `3.0` | Minimum seconds for scene |
| `max_duration` | `float` | `15.0` | Maximum seconds for scene |

**How it works:**
1. System generates audio from narration
2. Measures actual audio duration
3. Adjusts within min/max bounds
4. Adds padding if audio too short
5. Speeds up slightly if audio too long

**Example:**
```python
SceneConfig(
    ...,
    min_duration=5.0,   # At least 5 seconds
    max_duration=10.0,  # At most 10 seconds
    narration="Short text"  # If audio is 2s, scene will be 5s (min)
)
```

---

## 📋 Complete Working Example

```python
from video_gen.shared.models import VideoConfig, SceneConfig

video = VideoConfig(
    video_id="complete_example",
    title="Complete API Example",
    description="Shows all parameters and scene types",
    accent_color="blue",
    voices=["male", "female"],  # Rotates between voices
    scenes=[
        # 1. Title scene
        SceneConfig(
            scene_id="intro",
            scene_type="title",
            narration="Welcome to the complete API example",
            visual_content={
                "title": "Complete Example",
                "subtitle": "All Parameters Demonstrated"
            },
            voice="male",
            min_duration=4.0,
            max_duration=6.0
        ),

        # 2. Command scene
        SceneConfig(
            scene_id="install",
            scene_type="command",
            narration="Install the required packages using pip",
            visual_content={
                "header": "Installation",
                "label": "Setup Commands",
                "commands": [
                    "pip install fastapi",
                    "pip install uvicorn"
                ]
            }
        ),

        # 3. List scene
        SceneConfig(
            scene_id="features",
            scene_type="list",
            narration="Here are the main features of the system",
            visual_content={
                "header": "Key Features",
                "description": "What this provides",
                "items": [
                    "Programmatic API",
                    "12 scene types",
                    "4 voices",
                    "Multilingual support"
                ]
            }
        ),

        # 4. Code comparison
        SceneConfig(
            scene_id="refactor",
            scene_type="code_comparison",
            narration="Here's how we can improve the code",
            visual_content={
                "before_code": ["def old():", "    pass"],
                "after_code": ["def new():", "    return True"],
                "before_label": "Original",
                "after_label": "Improved"
            }
        ),

        # 5. Quiz
        SceneConfig(
            scene_id="quiz",
            scene_type="quiz",
            narration="Quick knowledge check",
            visual_content={
                "question": "What is 2 + 2?",
                "options": ["3", "4", "5", "6"],
                "correct_index": 1
            }
        ),

        # 6. Outro
        SceneConfig(
            scene_id="end",
            scene_type="outro",
            narration="Thanks for watching this complete example",
            visual_content={
                "main_text": "Thanks for Watching!",
                "sub_text": "See Full Documentation"
            }
        )
    ]
)

# Use with pipeline
from video_gen.pipeline import get_pipeline
from video_gen.shared.models import InputConfig

pipeline = get_pipeline()
result = await pipeline.execute(InputConfig(
    input_type="programmatic",
    source=video,
    accent_color=(59, 130, 246),  # Can override
    voice="male"  # Can override
))
```

---

## 🚀 InputConfig (Pipeline Entry Point)

**For using programmatic API with pipeline:**

```python
from video_gen.shared.models import InputConfig

config = InputConfig(
    input_type="programmatic",  # Required: "programmatic" for Python API
    source=video_config,        # Required: VideoConfig or VideoSet object
    accent_color=(59, 130, 246),  # Optional: RGB tuple or color name
    voice="male",               # Optional: Default voice
    languages=["en", "es", "fr"],  # Optional: Generate in multiple languages
    video_count=1,              # Optional: For splitting
    split_by_h2=False           # Optional: For document splitting
)
```

**All Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `input_type` | `str` | ✅ Yes | - | Use `"programmatic"` for Python API |
| `source` | `VideoConfig` or `VideoSet` | ✅ Yes | - | Your video configuration |
| `accent_color` | `tuple` or `str` | No | `"blue"` | RGB tuple or color name |
| `voice` | `str` | No | `"male"` | Default voice |
| `languages` | `List[str]` | No | `["en"]` | **Languages to generate** (multilingual) |
| `output_dir` | `Path` | No | `None` | Custom output directory |
| `auto_generate` | `bool` | No | `True` | Auto-proceed with generation |
| `skip_review` | `bool` | No | `False` | Skip review step |
| `resume_from` | `str` | No | `None` | Resume from specific stage |
| `video_count` | `int` | No | `1` | Number of videos (document splitting) |
| `split_by_h2` | `bool` | No | `False` | Split by H2 headings (documents) |

---

## 🎯 Common Patterns

### Pattern 1: Single Video with Mixed Scenes
```python
video = VideoConfig(
    video_id="tutorial",
    title="Tutorial",
    description="Learn something",
    scenes=[
        SceneConfig(scene_type="title", ...),
        SceneConfig(scene_type="command", ...),
        SceneConfig(scene_type="quiz", ...),
        SceneConfig(scene_type="outro", ...)
    ]
)
```

### Pattern 2: Multiple Videos in Set
```python
from video_gen.shared.models import VideoSet

video_set = VideoSet(
    set_id="series",
    name="Tutorial Series",
    description="Complete tutorial",
    videos=[
        VideoConfig(...),  # Video 1
        VideoConfig(...),  # Video 2
        VideoConfig(...)   # Video 3
    ]
)
```

### Pattern 3: Voice Rotation
```python
video = VideoConfig(
    ...,
    voices=["male", "female"],  # Alternates: scene 1=male, scene 2=female, scene 3=male...
    scenes=[scene1, scene2, scene3, scene4]
)
```

### Pattern 4: Programmatic Loop Generation
```python
scenes = []
for i, topic in enumerate(["Vars", "Funcs", "Classes"]):
    scenes.append(SceneConfig(
        scene_id=f"topic_{i}",
        scene_type="title",
        narration=f"Now let's learn about {topic}",
        visual_content={"title": topic, "subtitle": f"Topic {i+1}"}
    ))

video = VideoConfig(..., scenes=scenes)
```

---

## ⚠️ Common Mistakes

### Mistake 1: Missing visual_content keys
```python
# ❌ WRONG - missing required "title" key
SceneConfig(
    scene_type="title",
    visual_content={"subtitle": "Test"}  # Missing "title"!
)

# ✅ CORRECT
SceneConfig(
    scene_type="title",
    visual_content={"title": "Main", "subtitle": "Test"}
)
```

### Mistake 2: Wrong scene_type value
```python
# ❌ WRONG - invalid scene type
SceneConfig(scene_type="header", ...)  # No such type!

# ✅ CORRECT - use one of 12 valid types
SceneConfig(scene_type="title", ...)
```

### Mistake 3: Forgetting description
```python
# ❌ WRONG - description is required
VideoConfig(
    video_id="test",
    title="Test"
    # Missing description!
)

# ✅ CORRECT
VideoConfig(
    video_id="test",
    title="Test",
    description="Test video"
)
```

---

## 📚 Related Documentation

- **PROGRAMMATIC_GUIDE.md** - High-level guide with examples
- **RENDERER_API.md** - Renderer function reference
- **PARSE_RAW_CONTENT.md** - Parsing markdown/GitHub/YouTube
- **docs/PRODUCTION_READINESS.md** - API status (80% tested)

---

---

## 🌍 Multilingual Workflows (Programmatic)

### 🔄 Multilingual Expansion Flow Diagram

```
┌────────────────────────────────────────────────────────────────────┐
│              Multilingual Video Generation Pipeline                │
│                                                                    │
│  Input: VideoConfig + languages=["en", "es", "fr"]                │
│    │                                                               │
│    ▼                                                               │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │ Original Video (English)                                      │ │
│  │ ├── Scene 1: "Welcome to Python"                             │ │
│  │ ├── Scene 2: "Variables store data"                          │ │
│  │ └── Scene 3: "Functions are reusable"                        │ │
│  └──────────────────────────────────────────────────────────────┘ │
│         │                                                          │
│         ├──────────┬──────────┬──────────┐                        │
│         ▼          ▼          ▼          ▼                        │
│    ┌────────┐ ┌────────┐ ┌────────┐                              │
│    │   EN   │ │   ES   │ │   FR   │  ← Translation Layer         │
│    └────────┘ └────────┘ └────────┘                              │
│         │          │          │                                   │
│         ▼          ▼          ▼                                   │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐                             │
│  │tutorial_│ │tutorial_│ │tutorial_│  ← Generated Videos          │
│  │   en/   │ │   es/   │ │   fr/   │                             │
│  │         │ │         │ │         │                             │
│  │ Scene1  │ │ Scene1  │ │ Scene1  │  ← Same visuals,            │
│  │ Scene2  │ │ Scene2  │ │ Scene2  │    translated narration     │
│  │ Scene3  │ │ Scene3  │ │ Scene3  │                             │
│  └─────────┘ └─────────┘ └─────────┘                             │
│                                                                    │
│  Output: 3 complete videos with localized audio                   │
└────────────────────────────────────────────────────────────────────┘
```

### 📊 Multilingual Expansion Matrix

```
Input Scenarios:
┌──────────────────────┬─────────────┬─────────────┬──────────────┐
│ Input Type           │ Videos (M)  │ Languages(N)│ Output Count │
├──────────────────────┼─────────────┼─────────────┼──────────────┤
│ Single VideoConfig   │      1      │      3      │   1 × 3 = 3  │
│ VideoSet (3 videos)  │      3      │      3      │   3 × 3 = 9  │
│ VideoSet (5 videos)  │      5      │      4      │   5 × 4 = 20 │
│ Single VideoConfig   │      1      │      1      │   1 × 1 = 1  │
└──────────────────────┴─────────────┴─────────────┴──────────────┘

Formula: Total Videos = M (videos) × N (languages)
```

### 🌐 Translation Workflow Visualization

```
Original (English)                    Translations
─────────────────                    ──────────────
narration: "Welcome"     ┌─────►  "Bienvenido" (ES)
   │                     │
   ├─────────────────────┼─────►  "Bienvenue" (FR)
   │                     │
   └─────────────────────┴─────►  "Willkommen" (DE)

visual_content stays same:
{
  "title": "Python Tutorial"  ──►  Same for all languages
  "subtitle": "Learn Basics"  ──►  (not translated by default)
}
```

**💡 Translation Best Practices:**
- ✅ Narration is auto-translated
- ✅ Visual text (titles, subtitles) stays in source language
- ✅ For fully localized visuals, create separate VideoConfigs
- ⚠️ Translation quality depends on source clarity

### Single Video → Multiple Languages

```python
from video_gen.shared.models import VideoConfig, InputConfig
from video_gen.pipeline import get_pipeline

# Create English video
video = VideoConfig(
    video_id="tutorial",
    title="Python Tutorial",
    description="Learn Python",
    scenes=[...]  # English scenes
)

# Generate in 3 languages
pipeline = get_pipeline()
result = await pipeline.execute(InputConfig(
    input_type="programmatic",
    source=video,
    languages=["en", "es", "fr"]  # 🌍 Auto-translates to Spanish, French
))

# Output: 3 videos (tutorial_en/, tutorial_es/, tutorial_fr/)
```

### Video Set → Multilingual

```python
# Create set of 3 videos
video_set = VideoSet(
    set_id="course",
    name="Python Course",
    videos=[
        VideoConfig(video_id="lesson_01", ...),
        VideoConfig(video_id="lesson_02", ...),
        VideoConfig(video_id="lesson_03", ...)
    ]
)

# Generate in 4 languages
result = await pipeline.execute(InputConfig(
    input_type="programmatic",
    source=video_set,
    languages=["en", "es", "fr", "de"]
))

# Output: 12 videos (3 lessons × 4 languages)
```

**languages parameter:** `List[str]` - Language codes (en, es, fr, de, pt, it, ja, zh, etc.)

---

## 📊 Single vs Set Workflow Comparison

### 🤔 Decision Tree: VideoConfig vs VideoSet

```
What are you creating?
│
├─ Single topic/video?
│  │
│  ├─ One language only?
│  │  └─► Use: VideoConfig
│  │      Output: 1 video
│  │
│  └─ Multiple languages?
│     └─► Use: VideoConfig + languages=["en", "es", ...]
│         Output: N videos (1 per language)
│
└─ Multiple videos/series?
   │
   ├─ Same language for all?
   │  └─► Use: VideoSet with M videos
   │      Output: M videos
   │
   └─ Multiple languages for all?
      └─► Use: VideoSet + languages=["en", "es", ...]
          Output: M × N videos (M videos × N languages)
```

### 📈 Comparison Matrix

| Aspect | Single Video | Video Set |
|--------|-------------|-----------|
| **Use** | `VideoConfig` | `VideoSet` |
| **Best For** | Standalone content | Series, courses, batches |
| **Structure** | Single video_id | set_id + multiple videos |
| **Output** | 1 directory | Multiple directories organized |
| **Multilingual** | 1 video × N languages | M videos × N languages |
| **Use Cases** | Tutorial, demo, explainer | Course, series, batch processing |
| **Complexity** | Simple | Moderate |
| **Organization** | Flat | Hierarchical |

### 📊 Output Structure Visualization

```
Single VideoConfig:
└── tutorial/
    ├── tutorial_final.mp4
    ├── audio/
    └── frames/

Single VideoConfig + languages=["en", "es", "fr"]:
├── tutorial_en/
│   ├── tutorial_en_final.mp4
│   └── audio/
├── tutorial_es/
│   ├── tutorial_es_final.mp4
│   └── audio/
└── tutorial_fr/
    ├── tutorial_fr_final.mp4
    └── audio/

VideoSet (3 videos):
└── course_series/
    ├── lesson_01/
    │   ├── lesson_01_final.mp4
    │   └── audio/
    ├── lesson_02/
    │   ├── lesson_02_final.mp4
    │   └── audio/
    └── lesson_03/
        ├── lesson_03_final.mp4
        └── audio/

VideoSet + languages=["en", "es"] (3 videos × 2 languages = 6 outputs):
└── course_series/
    ├── lesson_01_en/
    ├── lesson_01_es/
    ├── lesson_02_en/
    ├── lesson_02_es/
    ├── lesson_03_en/
    └── lesson_03_es/
```

### 💡 Real-World Scenarios

**Scenario 1: Single Tutorial Video**
```python
# Use: Single VideoConfig
video = VideoConfig(
    video_id="python_intro",
    title="Python Introduction",
    scenes=[...]
)
# Output: 1 video
```

**Scenario 2: Tutorial in 3 Languages**
```python
# Use: VideoConfig + languages
video = VideoConfig(
    video_id="python_intro",
    title="Python Introduction",
    scenes=[...]
)
InputConfig(source=video, languages=["en", "es", "fr"])
# Output: 3 videos (en, es, fr)
```

**Scenario 3: 5-Part Course Series**
```python
# Use: VideoSet
course = VideoSet(
    set_id="python_course",
    name="Complete Python Course",
    videos=[
        VideoConfig(video_id="lesson_01", ...),
        VideoConfig(video_id="lesson_02", ...),
        VideoConfig(video_id="lesson_03", ...),
        VideoConfig(video_id="lesson_04", ...),
        VideoConfig(video_id="lesson_05", ...)
    ]
)
# Output: 5 videos
```

**Scenario 4: 5-Part Course in 4 Languages**
```python
# Use: VideoSet + languages
course = VideoSet(
    set_id="python_course",
    videos=[...5 videos...]
)
InputConfig(source=course, languages=["en", "es", "fr", "de"])
# Output: 20 videos (5 lessons × 4 languages)
```

---

**This reference now documents:**
- ✅ All VideoConfig parameters
- ✅ All SceneConfig parameters
- ✅ All 12 scene types with visual_content
- ✅ VideoSet parameters ✨ NEW
- ✅ Multilingual workflows ✨ NEW
- ✅ Single vs Set comparison ✨ NEW
- ✅ InputConfig.languages parameter ✨ NEW

Use with PROGRAMMATIC_GUIDE.md for complete programmatic API coverage.

*Last Updated: 2025-10-06*

---

## 🤖 AI Narration vs Template Narration

### Comparison

| Aspect | Template Narration | AI Narration |
|--------|-------------------|--------------|
| **Quality** | Professional, functional | Natural, engaging |
| **Speed** | Instant | ~3-5 seconds per scene |
| **Cost** | FREE | ~$0.01-0.05 per video |
| **API Key** | Not required | Requires ANTHROPIC_API_KEY |
| **Consistency** | Predictable | More varied, natural |
| **Best For** | Batch processing, testing | Final production, high-quality content |

### Usage

**Template Narration (Default):**
```python
result = await pipeline.execute(InputConfig(
    input_type="programmatic",
    source=video
    # use_ai_narration defaults to False
))
```

**AI-Enhanced Narration:**
```python
result = await pipeline.execute(InputConfig(
    input_type="programmatic",
    source=video,
    use_ai_narration=True  # ✨ Enables AI narration
))
```

**Requirements for AI Narration:**
1. Set environment variable: `ANTHROPIC_API_KEY="sk-ant-api03-..."`
2. Or add to .env file
3. Set `use_ai_narration=True` in InputConfig

**Fallback Behavior:**
- If `use_ai_narration=True` but no API key → Falls back to template with warning
- Template narration is high quality - don't feel you must use AI

### When to Use Each

**Use Template Narration When:**
- ✅ Generating many videos (faster, free)
- ✅ Testing and development
- ✅ Batch automation
- ✅ Template quality meets your needs (it's good!)

**Use AI Narration When:**
- ✨ Final production videos
- ✨ Marketing/sales content
- ✨ You want maximum natural speech
- ✨ Willing to pay ~$0.03 per video

**💡 Pro Tip:** Try template first! If it meets your needs, stick with it. Only use AI if you specifically need more natural narration.

