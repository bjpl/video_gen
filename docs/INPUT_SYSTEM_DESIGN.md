# 📥 Input System Design - Three Input Methods

**Purpose:** Allow users to create videos from any source material

---

## 🎯 Three Input Methods

```
┌────────────────────────────────────────────────────────────────┐
│                    INPUT SOURCES                               │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Method 1: DOCUMENTS               Method 2: YOUTUBE           │
│  ├─ README.md                      ├─ Video transcription     │
│  ├─ Documentation                  ├─ Search by topic         │
│  ├─ Blog posts                     ├─ Extract key points      │
│  └─ Text files                     └─ Auto-structure          │
│                                                                │
│  Method 3: INTERACTIVE WIZARD                                 │
│  ├─ Guided Q&A                                                │
│  ├─ Topic selection                                           │
│  ├─ Content building                                          │
│  └─ Review before export                                      │
│                                                                │
├────────────────────────────────────────────────────────────────┤
│                    ALL CONVERGE TO                             │
│                                                                │
│              Structured YAML → Script Generator                │
└────────────────────────────────────────────────────────────────┘
```

---

## 🔧 Method 1: Document Parser

### **Purpose:**
Convert existing documentation (README, guides, blog posts) into video scripts

### **Input Examples:**

#### **A. GitHub README**
```markdown
# Project Name

## Installation

Install with npm:
```bash
npm install project-name
```

## Quick Start

1. Initialize the project
2. Run the development server
3. Open browser to localhost:3000

## Features

- Fast performance
- Easy to use
- Well documented
```

#### **B. Documentation Page**
```markdown
# File Operations Guide

## Reading Files

The Read tool allows you to view file contents...

## Editing Files

Use the Edit tool to make precise changes...

## Writing Files

The Write tool creates new files...
```

### **Parser Design:**

```python
class DocumentParser:
    """Parse markdown/text documents into video structure"""

    def parse_document(self, file_path):
        """
        Main parsing function

        Strategy:
        1. Extract headings (H1, H2, H3) → Scene structure
        2. Extract code blocks → Commands
        3. Extract lists → List items
        4. Extract paragraphs → Narration source
        """

    def extract_structure(self, markdown_text):
        """
        Analyze document structure

        Returns:
        {
            'title': 'Document Title',
            'sections': [
                {
                    'heading': 'Section Name',
                    'level': 2,  # H2
                    'content': 'paragraph text...',
                    'code_blocks': [...],
                    'lists': [...]
                }
            ]
        }
        """

    def convert_to_scenes(self, structure):
        """
        Convert doc structure to video scenes

        Rules:
        - H1 → Title scene
        - H2 with code blocks → Command scene
        - H2 with lists → List scene
        - Last section → Outro scene
        """

    def generate_narration_from_section(self, section):
        """
        Extract key points from section text
        Generate professional narration

        Techniques:
        - Summarize paragraphs
        - Extract action verbs
        - Identify benefits
        - Create conversational flow
        """
```

### **Usage:**

```bash
python generate_script_from_document.py README.md
python generate_script_from_document.py docs/guide.md
python generate_script_from_document.py https://github.com/user/repo/README.md
```

---

## 🎥 Method 2: YouTube Transcription Fetcher

### **Purpose:**
Create videos based on YouTube video content with intelligent search

### **Features Needed:**

#### **A. Search Mechanism**
```python
class YouTubeTranscriptionFetcher:
    """Fetch and process YouTube transcriptions"""

    def search_videos(self, query, filters):
        """
        Search YouTube with smart filters

        Args:
            query: Search terms
            filters: {
                'duration': 'short' | 'medium' | 'long',
                'category': 'education' | 'tech' | 'tutorial',
                'date': 'week' | 'month' | 'year',
                'language': 'en',
                'min_views': 1000
            }

        Returns:
            List of matching videos with metadata
        """

    def get_transcript(self, video_id):
        """
        Fetch video transcript

        Uses:
        - Official YouTube API (if available)
        - youtube-transcript-api package (fallback)

        Returns:
            {
                'title': 'Video Title',
                'duration': 600,
                'transcript': [...],
                'segments': [...]
            }
        """

    def extract_key_segments(self, transcript, target_duration=60):
        """
        Intelligent segment extraction

        Strategy:
        - Identify topic changes
        - Extract main points
        - Filter filler words
        - Group related content
        - Fit to target duration
        """
```

#### **B. Interactive Search UI**
```
================================================================================
YOUTUBE TRANSCRIPT SEARCH
================================================================================

Search for: python async programming tutorial
Filters:
  - Duration: medium (4-20 min)
  - Category: education
  - Language: English
  - Min views: 10,000

Searching...

Found 15 results:
--------------------------------------------------------------------------------
[1] Async Python Complete Guide (12:34)
    By: TechWithTim | 125K views | 2 weeks ago
    ⭐⭐⭐⭐⭐ High quality transcript available

[2] Mastering Asyncio in Python (15:22)
    By: ArjanCodes | 89K views | 1 month ago
    ⭐⭐⭐⭐ Good transcript available

[3] Python Async/Await Tutorial (08:45)
    By: Corey Schafer | 234K views | 6 months ago
    ⭐⭐⭐⭐⭐ High quality transcript available

Select video (1-15): 1

Fetching transcript for "Async Python Complete Guide"...
✓ Retrieved 342 transcript segments

Analyzing content...
✓ Identified 5 main topics
✓ Extracted 12 key points
✓ Found 8 code examples

Generate video script? (y/n): y

Creating video structure...
✓ Scene 1: Title (from video title)
✓ Scene 2: Introduction (from first 2 min)
✓ Scene 3: Async basics (timestamp 2:15-5:30)
✓ Scene 4: Await syntax (timestamp 5:30-8:45)
✓ Scene 5: Practical example (timestamp 8:45-11:20)
✓ Scene 6: Outro (summary)

Script saved: drafts/async_python_guide_SCRIPT_*.md
Review and edit, then continue with audio generation!
```

### **Usage:**

```bash
# Interactive search
python generate_script_from_youtube.py --search "python async tutorial"

# Direct video ID
python generate_script_from_youtube.py --video-id "dQw4w9WgXcQ"

# With filters
python generate_script_from_youtube.py \
  --search "machine learning basics" \
  --duration medium \
  --min-views 50000
```

---

## 🧙 Method 3: Interactive Wizard

### **Purpose:**
Guided step-by-step creation for users starting from just ideas

### **Wizard Flow:**

```
================================================================================
VIDEO CREATION WIZARD
================================================================================

This wizard will guide you through creating a professional video script.
Answer a few questions and we'll generate the narration for you!

Press Ctrl+C at any time to cancel.
================================================================================

STEP 1: VIDEO BASICS
────────────────────────────────────────────────────────────────────

What's your video about?
> Tutorial on Python decorators

Great! What's a good title? (or press Enter for: "Python Decorators Tutorial")
> Python Decorators Explained

Perfect! Choose an accent color:
  1. 🟠 Orange (energetic)
  2. 🔵 Blue (professional)
  3. 🟣 Purple (creative)
  4. 🟢 Green (growth)
  5. 🌸 Pink (friendly)
  6. 🔷 Cyan (modern)

Select (1-6): 3

Choose default voice:
  1. Male (Andrew - confident, professional)
  2. Female (Aria - clear, crisp)

Select (1-2): 1

Target duration (30, 60, 90, 120 seconds): 60

✓ Video: "Python Decorators Explained" | Purple | Male voice | ~60s

================================================================================

STEP 2: CONTENT STRUCTURE
────────────────────────────────────────────────────────────────────

How many main topics/sections do you want to cover? (2-6 recommended): 3

Section 1: What topic?
> What decorators are

Section 2: What topic?
> Basic syntax

Section 3: What topic?
> Practical examples

✓ Structure: Intro → 3 sections → Outro = 5 scenes total

================================================================================

STEP 3: SCENE DETAILS
────────────────────────────────────────────────────────────────────

━━━ SCENE 1: Title ━━━

Subtitle for your title screen? (or press Enter for auto-generated)
> Master Python's Powerful Feature

Key message for the introduction?
> Learn to write cleaner, more elegant code

✓ Scene 1 configured


━━━ SCENE 2: What decorators are ━━━

What scene type works best?
  1. Command/Terminal (show code examples)
  2. List (bullet points)
  3. Custom narration (you write it)

Select (1-3): 1

What are the key points about "What decorators are"? (one per line, empty line to finish)
> Functions that modify other functions
> Add behavior without changing code
> Use @ syntax
>

Do you have code examples to show? (y/n): y

Enter commands/code (one per line, empty line to finish):
> @decorator
> def my_function():
>     pass
>

✓ Scene 2 configured


━━━ SCENE 3: Basic syntax ━━━

What scene type works best?
  1. Command/Terminal (show code examples)
  2. List (bullet points)
  3. Custom narration (you write it)

Select (1-3): 1

Key points about "Basic syntax"?
> Define decorator function
> Use @decorator_name
> Return wrapper function
>

Code examples:
> def my_decorator(func):
>     def wrapper():
>         print("Before")
>         func()
>         print("After")
>     return wrapper
>

✓ Scene 3 configured


━━━ SCENE 4: Practical examples ━━━

Scene type?
  1. Command/Terminal
  2. List
  3. Custom narration

Select: 2

List items for "Practical examples" (title: description, or just title):
> Logging: Track function calls
> Timing: Measure performance
> Caching: Store results
>

✓ Scene 4 configured


━━━ SCENE 5: Outro ━━━

Closing message?
> Master Decorators Today

Link to documentation?
> DECORATORS_GUIDE.md

✓ Scene 5 configured

================================================================================

STEP 4: REVIEW & GENERATE
────────────────────────────────────────────────────────────────────

Video: Python Decorators Explained
Scenes: 5
Estimated Duration: 58.2s
Topics Covered:
  1. What decorators are
  2. Basic syntax
  3. Practical examples

Generate script now? (y/n): y

Generating professional narration from your inputs...

✓ Scene 1: "Python Decorators Explained. Learn to write cleaner, more elegant code."
✓ Scene 2: "Functions that modify other functions. Decorators add behavior..."
✓ Scene 3: "Understanding basic decorator syntax. Define decorator function..."
✓ Scene 4: "Practical applications of decorators. Key examples include logging..."
✓ Scene 5: "Master Decorators Today. See DECORATORS_GUIDE.md for complete guides."

================================================================================
SCRIPT GENERATION COMPLETE
================================================================================

Files created:
  📝 drafts/python_decorators_SCRIPT_20251004_002245.md
  🐍 drafts/python_decorators_CODE_20251004_002245.py
  📋 drafts/python_decorators_INPUT_20251004_002245.yaml

Next steps:
  1. Review: cat drafts/python_decorators_SCRIPT_*.md
  2. Edit if needed: nano drafts/python_decorators_SCRIPT_*.md
  3. Continue: python generate_all_videos_unified_v2.py

Press Enter to exit...
```

---

## 🏗️ Implementation Architecture

### **Unified Input System:**

```
┌─────────────────────────────────────────────────────────────────┐
│                    INPUT DISPATCHER                             │
│                                                                 │
│  $ python create_video.py [--method METHOD] [INPUT]            │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  --method document README.md                                   │
│  --method youtube "python tutorial"                            │
│  --method wizard                                               │
│  --method yaml inputs/my_video.yaml (existing)                 │
│                                                                 │
└────────────────┬────────────────────────────────────────────────┘
                 │
    ┌────────────┴────────────┬─────────────────┬──────────────┐
    │                         │                 │              │
    ▼                         ▼                 ▼              ▼
┌─────────┐           ┌──────────┐      ┌────────┐     ┌──────────┐
│Document │           │ YouTube  │      │Wizard  │     │  YAML    │
│ Parser  │           │ Fetcher  │      │        │     │  Parser  │
└────┬────┘           └─────┬────┘      └───┬────┘     └─────┬────┘
     │                      │               │                │
     └──────────────────────┴───────────────┴────────────────┘
                            │
                            ▼
                  ┌─────────────────┐
                  │ Intermediate    │
                  │ Representation  │
                  │ (Unified Format)│
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ Narration       │
                  │ Generator       │
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ Output:         │
                  │ - YAML          │
                  │ - Markdown      │
                  │ - Python Code   │
                  └─────────────────┘
```

---

## 📄 Method 1 Design: Document Parser

### **File:** `generate_script_from_document.py`

### **Key Features:**

1. **Markdown Parsing**
   - Headings → Scene structure
   - Code blocks → Command content
   - Lists → List items
   - Paragraphs → Narration source

2. **Intelligent Structuring**
   - Determine scene types from content
   - Extract commands vs explanatory text
   - Identify key points
   - Summarize for narration

3. **Multi-Format Support**
   - Markdown (.md)
   - Plain text (.txt)
   - reStructuredText (.rst)
   - HTML (simple parsing)

### **Example Usage:**

```bash
# Local file
python generate_script_from_document.py docs/README.md

# GitHub URL
python generate_script_from_document.py \
  https://raw.githubusercontent.com/user/repo/main/README.md

# With options
python generate_script_from_document.py README.md \
  --max-scenes 6 \
  --target-duration 90 \
  --accent-color purple \
  --voice female
```

### **Parsing Strategy:**

```python
def parse_markdown_structure(md_text):
    """
    Parse markdown into hierarchical structure

    Example input:
    # Main Title

    ## Section 1
    This is explanatory text.

    ```bash
    command here
    ```

    ## Section 2
    - Point 1
    - Point 2

    Output:
    {
        'title': 'Main Title',
        'sections': [
            {
                'heading': 'Section 1',
                'type': 'command',  # Has code block
                'text': 'This is explanatory text.',
                'code_blocks': ['command here']
            },
            {
                'heading': 'Section 2',
                'type': 'list',  # Has bullet list
                'items': ['Point 1', 'Point 2']
            }
        ]
    }
    """
```

---

## 📺 Method 2 Design: YouTube Transcription

### **File:** `generate_script_from_youtube.py`

### **Dependencies:**

```bash
pip install youtube-transcript-api google-api-python-client
```

### **Key Features:**

#### **A. Smart Search**
```python
class YouTubeSearcher:
    """Intelligent YouTube search with filters"""

    def search(self, query, filters):
        """
        Search with intelligent filtering

        Categories for software/learning:
        - Programming tutorials
        - Software engineering
        - Tech explanations
        - Course content
        - Conference talks

        Quality filters:
        - Transcript availability
        - View count threshold
        - Recent videos preferred
        - Educational content priority
        """
```

#### **B. Transcript Processing**
```python
class TranscriptProcessor:
    """Process YouTube transcripts into video structure"""

    def chunk_by_topics(self, transcript):
        """
        Identify topic changes in transcript

        Techniques:
        - Detect topic shifts (speaker cues)
        - Group related segments
        - Identify introduction/conclusion
        - Extract code examples mentioned
        """

    def extract_key_points(self, transcript_chunk):
        """
        Extract main points from transcript segment

        Strategy:
        - Identify declarative statements
        - Filter filler words ("um", "uh", "like")
        - Extract action items
        - Identify benefits/features
        """

    def generate_commands_from_transcript(self, text):
        """
        Extract mentioned commands/code

        Patterns:
        - "you would type..."
        - "run the command..."
        - "execute this..."
        - Code mentioned verbally
        """
```

#### **C. Interactive Segment Selection**
```
Transcript loaded: "Async Python Complete Guide" (12:34)

Automatically identified segments:
────────────────────────────────────────────────────────────────
[1] 0:00-1:30   Introduction to async programming
[2] 1:30-3:45   Why use async/await
[3] 3:45-6:20   Basic async syntax
[4] 6:20-8:15   Practical example - web scraping
[5] 8:15-10:30  Common mistakes and solutions
[6] 10:30-12:34 Summary and next steps

Select segments to include in your video (comma-separated, or 'all'): 1,3,4,6

Selected segments total: 7:20
Target your video duration: 60

System will:
  ✓ Condense 7:20 of content to ~60s
  ✓ Extract key points
  ✓ Generate concise narration
  ✓ Create visual structure

Generate script? (y/n): y
```

### **Usage:**

```bash
# Method A: Interactive search
python generate_script_from_youtube.py --search "python decorators"

# Method B: Direct video
python generate_script_from_youtube.py --url "https://youtube.com/watch?v=VIDEO_ID"

# Method C: Video ID
python generate_script_from_youtube.py --video-id "dQw4w9WgXcQ"

# With options
python generate_script_from_youtube.py \
  --search "fastapi tutorial" \
  --duration 60 \
  --extract-commands \
  --accent-color blue
```

---

## 🧙‍♂️ Method 3 Design: Interactive Wizard

### **File:** `generate_script_wizard.py`

### **Wizard Sections:**

#### **Section 1: Video Basics** (1-2 min)
```python
def wizard_basics():
    """
    Gather basic video information

    Questions:
    1. What's your video about? (topic)
    2. Video title? (auto-suggested from topic)
    3. Accent color? (visual selector)
    4. Voice preference? (male/female)
    5. Target duration? (30/60/90/120s presets)
    """
```

#### **Section 2: Content Type** (30 sec)
```python
def wizard_content_type():
    """
    Determine content type

    Options:
    1. Tutorial (step-by-step how-to)
    2. Overview (feature showcase)
    3. Troubleshooting (problem-solution)
    4. Comparison (A vs B)
    5. Best Practices (tips & techniques)
    6. Custom (free-form)

    Each type has different scene templates
    """
```

#### **Section 3: Structure Builder** (2-5 min)
```python
def wizard_build_structure(content_type):
    """
    Build scene structure based on content type

    For Tutorial:
    - Title scene
    - Prerequisites (optional)
    - Step 1 (command scene)
    - Step 2 (command scene)
    - Step 3 (command scene)
    - Summary (list of what learned)
    - Outro

    For each scene:
    - Ask for topic/heading
    - Ask for key points (bullet format)
    - Ask for commands (if applicable)
    - Auto-suggest narration
    """
```

#### **Section 4: Scene Details** (3-10 min)
```python
def wizard_scene_details(scene, scene_type):
    """
    Gather details for each scene

    Command scenes:
    - Header text
    - Topic/purpose
    - Commands to show
    - Key takeaways

    List scenes:
    - Header text
    - List items (title + description)
    - Main message

    Auto-generate narration from inputs
    """
```

#### **Section 5: Review & Confirm** (1-2 min)
```python
def wizard_review(video_structure):
    """
    Show preview and allow edits

    Display:
    - Video title and duration
    - All scenes with narration
    - Estimated timing

    Options:
    - Generate script (proceed)
    - Edit scene (go back)
    - Cancel (exit)
    - Save draft (for later)
    """
```

### **Wizard Templates by Content Type:**

#### **Template 1: Tutorial**
```
Scene 1: Title
Scene 2: Prerequisites (list)
Scene 3: Step 1 (command)
Scene 4: Step 2 (command)
Scene 5: Step 3 (command)
Scene 6: Summary (list)
Scene 7: Outro
```

#### **Template 2: Feature Overview**
```
Scene 1: Title
Scene 2: Introduction (command)
Scene 3: Key Features (list)
Scene 4: Quick Start (command)
Scene 5: Outro
```

#### **Template 3: Troubleshooting**
```
Scene 1: Title
Scene 2: Common Issues (list)
Scene 3: Solution 1 (command)
Scene 4: Solution 2 (command)
Scene 5: Prevention Tips (list)
Scene 6: Outro
```

### **Usage:**

```bash
# Launch wizard
python generate_script_wizard.py

# Launch with preset
python generate_script_wizard.py --type tutorial

# Resume saved draft
python generate_script_wizard.py --resume drafts/my_video_draft.json
```

---

## 🔄 Unified Interface

### **Master Command:**

```bash
python create_video.py [OPTIONS]
```

**Options:**
```
Input Methods:
  --document FILE         Parse document (README, guide, etc.)
  --youtube SEARCH       Search YouTube and select transcript
  --youtube-id VIDEO_ID  Direct YouTube video ID
  --wizard               Launch interactive wizard
  --yaml FILE            Use YAML input (existing method)

Common Options:
  --title TEXT           Video title (override)
  --accent-color COLOR   orange, blue, purple, green, pink, cyan
  --voice VOICE          male or female
  --duration SECONDS     Target duration
  --output-dir DIR       Where to save outputs

Examples:
  python create_video.py --document README.md
  python create_video.py --youtube "python async tutorial"
  python create_video.py --wizard
  python create_video.py --yaml inputs/my_video.yaml
```

---

## 📊 Input Method Comparison

| Method | Best For | Effort | Control | Speed |
|--------|----------|--------|---------|-------|
| **Document** | Converting existing docs | Low | Medium | Fast ⚡⚡⚡ |
| **YouTube** | Leveraging video content | Low | Medium | Fast ⚡⚡⚡ |
| **Wizard** | Starting from scratch | Medium | High | Medium ⚡⚡ |
| **YAML** | Full control, batch processing | High | Full | Varies ⚡-⚡⚡⚡ |

---

## 🎯 User Personas

### **Persona 1: Documentation Maintainer**
**Has:** Existing README, guides
**Needs:** Quick video versions
**Uses:** Document parser
**Flow:** README → Parse → Review → Generate

### **Persona 2: Content Curator**
**Has:** YouTube videos on similar topics
**Needs:** Condensed summary videos
**Uses:** YouTube transcription
**Flow:** Search → Select → Extract → Generate

### **Persona 3: Course Creator**
**Has:** Topics to teach
**Needs:** Tutorial series
**Uses:** Interactive wizard
**Flow:** Wizard Q&A → Review → Generate → Repeat for series

### **Persona 4: Power User**
**Has:** Specific requirements
**Needs:** Full control
**Uses:** Direct YAML
**Flow:** Write YAML → Generate → Done

---

## 📋 Next Steps to Implement

### **Priority 1: Document Parser** (Most Useful)
- Parse markdown structure
- Extract code blocks
- Generate scene structure
- Create narration from content

### **Priority 2: Interactive Wizard** (Best UX)
- Design question flow
- Create templates for common content types
- Build review interface
- Save/resume functionality

### **Priority 3: YouTube Integration** (Advanced)
- API integration
- Transcript fetching
- Smart segmentation
- Content extraction

---

*Design Document: 2025-10-03*
*Status: Ready for implementation*
*All three methods will output to unified YAML → Script Generator pipeline*
