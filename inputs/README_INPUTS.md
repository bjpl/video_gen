# 📥 Video Input Files

**Purpose:** User-friendly input formats for video creation

---

## 🎯 What This Solves

### **The Problem:**

**Current workflow** requires users to write narration directly in Python code:

```python
narration="Edit, write, and read files with intelligent manipulation..."
```

**This is hard because:**
- ❌ Users must write professional narration themselves
- ❌ Must know Python syntax
- ❌ Must understand UnifiedVideo structure
- ❌ Must calculate pacing (135 WPM)
- ❌ High barrier to entry

### **The Solution:**

**New workflow** accepts natural inputs:

```yaml
topic: "File operations overview"
key_points:
  - Edit files
  - Write files
  - Read files
```

**System generates professional narration automatically!**

---

## 📝 How to Create Videos (User-Friendly Way)

### **Step 1: Write YAML Input (5-15 minutes)**

Create a file in `inputs/` directory:

```bash
nano inputs/my_video.yaml
```

Use the templates provided below.

### **Step 2: Generate Script (30 seconds)**

```bash
python scripts/generate_script_from_yaml.py inputs/my_video.yaml
```

**Output:**
```
✅ Markdown script saved: drafts/my_video_SCRIPT_20251003_150122.md
✅ Python code saved: drafts/my_video_CODE_20251003_150122.py

Review the script and make edits if needed!
```

### **Step 3: Review Generated Script (5 minutes)**

```bash
cat scripts/drafts/my_video_SCRIPT_*.md
```

**Edit if needed:**
```bash
nano scripts/drafts/my_video_SCRIPT_*.md
```

### **Step 4: Import to Main File (10 seconds)**

Copy the VIDEO object from `*_CODE_*.py` to `generate_all_videos_unified_v2.py`:

```bash
# Or use import helper (future tool)
python import_script.py drafts/my_video_CODE_*.py
```

### **Step 5: Generate Audio + Video (standard workflow)**

```bash
python generate_all_videos_unified_v2.py
python generate_videos_from_timings_v3_simple.py
```

---

## 📋 YAML Input Format Reference

### **Minimal Example:**

```yaml
video:
  id: "my_video"
  title: "My Video Title"
  accent_color: blue

scenes:
  - type: title
    title: "Main Title"
    subtitle: "Subtitle Here"

  - type: outro
    main_text: "Thank You"
    sub_text: "See README.md"
```

**System generates all narration automatically!**

### **Full Example:**

```yaml
video:
  id: "feature_guide"              # Video ID (required)
  title: "Feature Guide"           # Display title (required)
  description: "Feature overview"  # Short description
  accent_color: blue               # orange, blue, purple, green, pink, cyan
  voice: male                      # male or female (default for all scenes)
  version: "v2.0"                  # Version tag
  target_duration: 60              # Optional: target length in seconds

scenes:
  - type: title                    # Scene type (required)
    id: scene_01_intro             # Scene ID (optional, auto-generated)
    title: "Feature Guide"         # Title text
    subtitle: "Complete Overview"  # Subtitle text
    key_message: "Learn everything you need"  # Used for narration generation
    narration: "Custom narration..."  # Optional: override auto-generated
    voice: male                    # Optional: override default voice
    min_duration: 3.0              # Optional: default 3.0
    max_duration: 8.0              # Optional: default 15.0

  - type: command
    header: "Commands"
    description: "Essential Commands"
    topic: "Getting started with basic commands"  # Used for narration
    commands:
      - "$ command one"
      - "$ command two"
      - "→ output"
    key_points:                    # Used for narration generation
      - Easy to remember
      - Fast execution
      - Powerful results

  - type: list
    header: "Features"
    description: "Key Capabilities"
    topic: "The main features you should know"
    items:
      - title: "Feature 1"
        description: "What it does"
      - title: "Feature 2"
        description: "Why it matters"
      # Or simple list:
      - "Simple item text"

  - type: outro
    main_text: "Get Started Today"
    sub_text: "documentation.md"
    key_message: "Everything you need is ready"
```

---

## 🎨 Scene Types

### **1. Title Scenes**

**Visual:** Large centered title with subtitle

**YAML:**
```yaml
- type: title
  title: "Main Title Text"
  subtitle: "Subtitle Text"
  key_message: "What this video is about"  # For narration
```

**Auto-generated narration:**
> "Main Title Text. What this video is about."

---

### **2. Command Scenes**

**Visual:** Terminal card with syntax-highlighted commands

**YAML:**
```yaml
- type: command
  header: "Header Text"
  description: "Description Text"
  topic: "What these commands do"  # For narration
  commands:
    - "$ command here"
    - "→ output here"
  key_points:
    - Point 1
    - Point 2
```

**Auto-generated narration:**
> "What these commands do. Run these commands to get started. This gives you Point 1, Point 2."

---

### **3. List Scenes**

**Visual:** Numbered cards with items

**YAML:**
```yaml
- type: list
  header: "Header Text"
  description: "Description"
  topic: "Overview of these items"  # For narration
  items:
    - title: "Item 1"
      description: "Details"
    - title: "Item 2"
      description: "Details"
```

**Auto-generated narration:**
> "Overview of these items. Key features include Item 1, and Item 2."

---

### **4. Outro Scenes**

**Visual:** Checkmark with call-to-action

**YAML:**
```yaml
- type: outro
  main_text: "Main Message"
  sub_text: "documentation.md"
  key_message: "Final thoughts"  # For narration
```

**Auto-generated narration:**
> "Main Message. Final thoughts. See documentation.md for complete guides."

---

## 🔄 Complete Workflow Examples

### **Example 1: From Scratch (Natural Way)**

**You create:** `inputs/search_guide.yaml`

```yaml
video:
  id: "search_guide"
  title: "Search Features"
  accent_color: green

scenes:
  - type: title
    title: "Search Features"
    subtitle: "Find Anything Instantly"
    key_message: "Master powerful search capabilities"

  - type: command
    header: "File Search"
    topic: "Finding files by name or pattern"
    commands:
      - "$ claude glob '**/*.py'"
      - "$ claude glob 'src/**/*.ts'"
    key_points:
      - Pattern matching
      - Recursive search

  - type: command
    header: "Content Search"
    topic: "Finding code by content"
    commands:
      - "$ claude grep 'function'"
      - "$ claude grep 'TODO' --type py"
    key_points:
      - Fast regex search
      - Type filtering

  - type: outro
    main_text: "Search Like a Pro"
    sub_text: "See SEARCH_GUIDE.md"
```

**Run:**
```bash
python generate_script_from_yaml.py inputs/search_guide.yaml
# Review: drafts/search_guide_SCRIPT_*.md
# Edit if needed, then continue...
```

---

### **Example 2: From Existing Documentation**

**You have:** `docs/features/file_operations.md`

```markdown
# File Operations

Claude Code provides powerful file manipulation.

## Reading Files
Use the Read tool to view file contents.

## Editing Files
Edit tool makes precise changes.

## Writing Files
Write tool creates new files.
```

**Create input:**
```yaml
video:
  id: "file_ops_from_docs"
  title: "File Operations"
  accent_color: orange

scenes:
  - type: title
    title: "File Operations"
    subtitle: "Powerful File Manipulation"
    key_message: "Work with files efficiently"

  # Auto-generate from doc headings
  - type: command
    header: "Reading Files"
    topic: "View file contents with the Read tool"
    commands:
      - "$ claude read app.py"
      - "→ Shows file contents"

  - type: command
    header: "Editing Files"
    topic: "Make precise changes with the Edit tool"
    commands:
      - "$ claude edit app.py"

  - type: command
    header: "Writing Files"
    topic: "Create new files with the Write tool"
    commands:
      - "$ claude write new_file.py"
```

---

## 🎓 Learning Path

### **Beginner: Use Simple Templates**

Start with minimal YAML - let system generate everything:

```yaml
video:
  id: "my_first_video"
  title: "My First Video"
  accent_color: blue

scenes:
  - type: title
    title: "Hello World"
    subtitle: "My First Video"

  - type: outro
    main_text: "Thanks for Watching"
    sub_text: "See docs"
```

### **Intermediate: Add Structure**

Provide topics and key points for better narration:

```yaml
  - type: command
    header: "Commands"
    topic: "Basic usage commands"
    commands: [...]
    key_points:
      - Easy to learn
      - Powerful features
```

### **Advanced: Full Control**

Override everything - write custom narration, exact timing:

```yaml
  - type: command
    narration: "Your exact narration text here with perfect pacing..."
    min_duration: 8.5
    max_duration: 9.0
    voice: female
```

---

## 📚 More Examples

See `inputs/` directory for:
- `example_simple.yaml` - Minimal input, auto-generated narration
- `example_advanced.yaml` - Mix of auto and custom narration
- `template_blank.yaml` - Empty template to copy

---

## 🔧 Troubleshooting

### **"How do I know if narration will be good?"**

Run the script generator first - it outputs estimated narration. Review before committing to audio/video generation.

### **"Can I edit the generated narration?"**

Yes! Edit the markdown script file or the Python code directly.

### **"What if I want to write all narration myself?"**

Provide `narration:` field in YAML for every scene. System won't auto-generate.

### **"How do I convert existing docs?"**

Copy structure from docs, simplify to YAML format. Or use `narration:` field with doc text.

---

*Created: 2025-10-03*
*Purpose: Make video creation accessible to everyone*
*Reduces barrier from "programmer + writer" to "anyone with ideas"*
