# Complete API Parameters Reference

**Comprehensive documentation of all programmatic API parameters**

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

### 1. Title Scene (`scene_type="title"`)

**visual_content Required:**
```python
{
    "title": str,      # Main title text
    "subtitle": str    # Subtitle text
}
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

**visual_content Required:**
```python
{
    "header": str,           # Section header
    "label": str,            # Command label (e.g., "Setup")
    "commands": List[str]    # List of command strings
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

**Available Voices:**

| Voice ID | Description | Gender | Tone |
|----------|-------------|--------|------|
| `"male"` | Andrew - Professional | Male | Confident, clear |
| `"male_warm"` | Brandon - Engaging | Male | Warm, friendly |
| `"female"` | Aria - Clear | Female | Professional, crisp |
| `"female_friendly"` | Ava - Pleasant | Female | Friendly, approachable |

**Voice Rotation:**
```python
# Single voice for all scenes
VideoConfig(..., voices=["male"])

# Rotate between two voices
VideoConfig(..., voices=["male", "female"])

# Use all four voices
VideoConfig(..., voices=["male", "male_warm", "female", "female_friendly"])
```

**Per-scene override:**
```python
SceneConfig(..., voice="female")  # Overrides video default
```

---

## 🎨 Color Options

**Available Colors:**

| Color | RGB | Use Case |
|-------|-----|----------|
| `"blue"` | (59, 130, 246) | Professional, trustworthy |
| `"orange"` | (255, 107, 53) | Energetic, creative |
| `"purple"` | (168, 85, 247) | Premium, sophisticated |
| `"green"` | (16, 185, 129) | Success, growth |
| `"pink"` | (236, 72, 153) | Playful, modern |
| `"cyan"` | (6, 182, 212) | Tech, innovation |

**Usage:**
```python
VideoConfig(..., accent_color="purple")
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

| Aspect | Single Video | Video Set |
|--------|-------------|-----------|
| **Use** | `VideoConfig` | `VideoSet` |
| **Best For** | Standalone content | Series, courses, batches |
| **Output** | 1 directory | Multiple videos organized |
| **Multilingual** | 1 video × N languages | M videos × N languages |
| **Example** | Tutorial | 5-part course |

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
