# 🎨 Template System - Complete Explanation

**Three Types of Templates in the System**

---

## 🔍 Current Template Situation

There are **THREE SEPARATE template systems** that need to be unified:

```
┌──────────────────────────────────────────────────────────────────┐
│                    THREE TEMPLATE SYSTEMS                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  TYPE 1: VISUAL TEMPLATES     (PNG files - NOT INTEGRATED)      │
│  ├─ Location: slide_templates/                                  │
│  ├─ Format: 10 PNG design templates                             │
│  ├─ Purpose: Visual design inspiration                          │
│  └─ Status: ❌ Not used in current workflow                      │
│                                                                  │
│  TYPE 2: CONTENT TYPE TEMPLATES  (Wizard structure)             │
│  ├─ Location: generate_script_wizard.py                         │
│  ├─ Format: Python dictionaries                                 │
│  ├─ Purpose: Scene structure for different content types        │
│  └─ Status: ✅ Used in wizard                                    │
│                                                                  │
│  TYPE 3: SCENE RENDERING TEMPLATES  (Actual visuals)            │
│  ├─ Location: generate_documentation_videos.py                  │
│  ├─ Format: Python rendering functions                          │
│  ├─ Purpose: Generate actual video frames                       │
│  └─ Status: ✅ Used in video generation                          │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 📊 Template Type 1: Visual Slide Templates (NOT INTEGRATED)

### **What They Are:**

```
slide_templates/
├─ 01_hero_title.png          (Hero card with icon)
├─ 02_two_column.png          (Split layout)
├─ 03_three_cards.png         (3-column grid)
├─ 04_feature_spotlight.png   (Visual + features)
├─ 05_stats_dashboard.png     (4 stat cards)
├─ 06_timeline.png            (Horizontal timeline)
├─ 07_comparison.png          (Split comparison)
├─ 08_icon_list.png           (Large icon rows)
├─ 09_minimal_centered.png    (Centered minimal)
└─ 10_grid_gallery.png        (2x3 gallery)
```

**Purpose:** Design inspiration, manual use in presentations

**Status:** ❌ **NOT used in automated video workflow**

**Why:** These are static PNG files meant for:
- PowerPoint/Keynote presentations
- Design inspiration
- Manual customization in Figma/Canva

**Could they be integrated?** Yes, but would need:
- Conversion to programmatic rendering
- Text overlay capability
- Animation support

---

## ⚙️ Template Type 2: Content Type Templates (ACTIVELY USED)

### **What They Are:**

Scene structure patterns for different content types.

**Location:** `generate_script_wizard.py` (lines 68-106)

```python
self.templates = {
    'tutorial': {
        'description': 'Step-by-step how-to guide',
        'scene_pattern': ['title', 'command', 'command', 'command', 'list', 'outro'],
        'suggestions': {
            'title_subtitle': 'Step-by-Step Guide',
            'outro_main': 'Start Building Today'
        }
    },

    'overview': {
        'description': 'Feature showcase and overview',
        'scene_pattern': ['title', 'list', 'command', 'list', 'outro'],
        'suggestions': {
            'title_subtitle': 'Complete Overview',
            'outro_main': 'Try These Features'
        }
    },

    'troubleshooting': {
        'description': 'Problem-solution guide',
        'scene_pattern': ['title', 'list', 'command', 'command', 'list', 'outro'],
        'suggestions': {
            'title_subtitle': 'Common Issues & Solutions',
            'outro_main': 'Solve Problems Fast'
        }
    },

    'comparison': {
        'description': 'Compare options or approaches',
        'scene_pattern': ['title', 'list', 'list', 'command', 'outro'],
        'suggestions': {
            'title_subtitle': 'Making the Right Choice',
            'outro_main': 'Choose Wisely'
        }
    },

    'best_practices': {
        'description': 'Tips, techniques, and recommendations',
        'scene_pattern': ['title', 'list', 'list', 'command', 'outro'],
        'suggestions': {
            'title_subtitle': 'Expert Tips & Techniques',
            'outro_main': 'Code Like a Pro'
        }
    }
}
```

**How They Work:**

```
User selects: "Tutorial"
    ↓
Wizard uses template:
    scene_pattern = ['title', 'command', 'command', 'command', 'list', 'outro']
    ↓
Asks questions for each scene type
    ↓
Generates YAML with that structure
```

**Status:** ✅ **ACTIVELY USED** in wizard

---

## 🎨 Template Type 3: Scene Rendering Templates (CORE SYSTEM)

### **What They Are:**

Python functions that actually render visual frames.

**Location:** `generate_documentation_videos.py` (lines 65-253)

```python
# Four scene rendering functions:

def create_title_keyframes(title, subtitle, accent_color):
    """
    Renders title screens
    Visual: GUIDE badge + large centered title + underline + subtitle
    """

def create_command_keyframes(header, description, commands, accent_color):
    """
    Renders terminal/command screens
    Visual: Icon + header + macOS-style terminal card with syntax highlighting
    """

def create_list_keyframes(header, description, items, accent_color):
    """
    Renders list screens
    Visual: Icon + header + numbered cards with items
    """

def create_outro_keyframes(main_text, sub_text, accent_color):
    """
    Renders outro screens
    Visual: Checkmark + main message + pill-shaped CTA button
    """
```

**How They Work:**

```
Video generator calls:
    create_title_keyframes("My Title", "Subtitle", ACCENT_BLUE)
    ↓
Function uses Pillow to draw:
    ├─ Background with gradient mesh
    ├─ "GUIDE" badge at top
    ├─ Large centered title text
    ├─ Accent underline
    └─ Subtitle text
    ↓
Returns: (start_frame, end_frame) PIL Images
    ↓
Used for animation blending
```

**Status:** ✅ **CORE SYSTEM** - actively renders all visuals

---

## 🔄 How Templates Work Together (Current)

```
CONTENT TYPE TEMPLATE               SCENE RENDERING TEMPLATE
(Structure)                         (Visual)
     │                                   │
     │                                   │
Wizard selects "tutorial"           Video generator needs to
     ↓                              render scene type "command"
scene_pattern:                           ↓
['title', 'command', ...]           Calls:
     │                              create_command_keyframes(...)
     │                                   ↓
     └─────────────┬─────────────────────┘
                   │
                   ▼
            YAML with scenes:
            - type: title     ───> create_title_keyframes()
            - type: command   ───> create_command_keyframes()
            - type: list      ───> create_list_keyframes()
            - type: outro     ───> create_outro_keyframes()
```

**The visual PNG templates (Type 1) are NOT connected to this flow.**

---

## 🎯 Template Management Strategy

### **Option A: Current System (What We Have)**

```
Content Type Templates (Wizard)
    ↓
Generate scene structure
    ↓
Scene Rendering Templates (Python functions)
    ↓
Actual video frames

Visual PNG templates = Separate (manual use)
```

**Pros:**
- ✅ Works well
- ✅ Consistent visuals
- ✅ Easy to extend

**Cons:**
- ❌ PNG templates not integrated
- ❌ Can't easily add new visual styles
- ❌ Templates scattered across files

---

### **Option B: Unified Template System (Proposed)**

```
┌─────────────────────────────────────────────────────────────┐
│            UNIFIED TEMPLATE REPOSITORY                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  templates/                                                 │
│  ├─ content_types/          (Scene structure patterns)      │
│  │  ├─ tutorial.yaml                                        │
│  │  ├─ overview.yaml                                        │
│  │  ├─ troubleshooting.yaml                                 │
│  │  └─ custom.yaml                                          │
│  │                                                           │
│  ├─ scene_styles/           (Visual rendering)              │
│  │  ├─ modern_light/        (Current style)                 │
│  │  │  ├─ title.py                                          │
│  │  │  ├─ command.py                                        │
│  │  │  ├─ list.py                                           │
│  │  │  └─ outro.py                                          │
│  │  │                                                        │
│  │  ├─ dark_theme/          (Future: dark mode)             │
│  │  ├─ minimal/             (Future: minimal style)         │
│  │  └─ corporate/           (Future: corporate branding)    │
│  │                                                           │
│  └─ narration/              (Narration generation)          │
│     ├─ tutorial_prompts.yaml                                │
│     ├─ overview_prompts.yaml                                │
│     └─ custom_prompts.yaml                                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Benefits:**
- ✅ All templates in one place
- ✅ Easy to add new styles
- ✅ User can choose visual theme
- ✅ Maintainable and extensible

---

## 💡 Recommended Approach (Pragmatic)

### **Keep Current System + Document It Clearly**

**Why:** Current system works well, don't over-engineer

**What to clarify:**

```
TWO ACTIVE TEMPLATE SYSTEMS:
────────────────────────────────────────────────────────────────

1. CONTENT TYPE TEMPLATES (Structure)
   Location: generate_script_wizard.py
   Purpose: Define scene flow for different content types
   Used by: Wizard
   Examples: tutorial, overview, troubleshooting

2. SCENE RENDERING TEMPLATES (Visual)
   Location: generate_documentation_videos.py
   Purpose: Render actual video frames
   Used by: Video generator
   Types: title, command, list, outro

SEPARATE (Not integrated):
────────────────────────────────────────────────────────────────

3. VISUAL DESIGN TEMPLATES (Inspiration)
   Location: slide_templates/*.png
   Purpose: Design inspiration for presentations
   Used by: Manual PowerPoint/Figma work
   Not connected to automated workflow
```

---

## 🛠️ Template Usage Guide

### **For Users Creating Videos:**

#### **1. Content Type Templates (Wizard)**

**When:** Using wizard to create video

**How:**
```bash
python create_video.py --wizard

# Step 2 asks:
# "What type of video?"
#   1. Tutorial (step-by-step)
#   2. Overview (feature showcase)
#   3. Troubleshooting (problem-solution)
#   4. Comparison (A vs B)
#   5. Best Practices (tips)

# Select one, wizard applies that template's scene structure
```

**Result:** Video structured appropriately for content type

---

#### **2. Scene Type Templates (Always Active)**

**When:** Every video generation

**Scene Types Available:**

| Type | Visual Layout | Use For |
|------|---------------|---------|
| **title** | Large centered title + subtitle | Opening, chapter breaks |
| **command** | Terminal card with commands | Code examples, CLI usage |
| **list** | Numbered cards with items | Features, steps, tips |
| **outro** | Checkmark + CTA button | Closing, call-to-action |

**How to use in YAML:**
```yaml
scenes:
  - type: title       # Uses create_title_keyframes()
    title: "..."
    subtitle: "..."

  - type: command     # Uses create_command_keyframes()
    header: "..."
    commands: [...]

  - type: list        # Uses create_list_keyframes()
    header: "..."
    items: [...]

  - type: outro       # Uses create_outro_keyframes()
    main_text: "..."
```

**Result:** Each scene renders with appropriate visual style

---

### **For Advanced Users (Adding New Templates):**

#### **Add New Content Type Template:**

**Edit:** `generate_script_wizard.py`

```python
self.templates = {
    # Existing...

    'quick_reference': {  # ← NEW
        'description': 'Command cheat sheet',
        'scene_pattern': ['title', 'command', 'command', 'command', 'outro'],
        'suggestions': {
            'title_subtitle': 'Command Reference',
            'outro_main': 'Bookmark This'
        }
    }
}
```

**Result:** Wizard now offers "Quick Reference" as option 6

---

#### **Add New Scene Type (Visual):**

**Edit:** `generate_documentation_videos.py`

```python
def create_code_example_keyframes(title, code, explanation, accent_color):
    """
    New scene type: Full-screen code with explanation
    """
    base = create_base_frame(accent_color)
    start_frame = base.copy()
    end_frame = base.copy()

    draw = ImageDraw.Draw(end_frame, 'RGBA')

    # Render code in large font
    # Add syntax highlighting
    # Add explanation below

    return start_frame.convert('RGB'), end_frame.convert('RGB')
```

**Then use in YAML:**
```yaml
- type: code_example  # ← NEW TYPE
  title: "Example Code"
  code: "print('hello')"
  explanation: "This prints hello"
```

**Update video generator to handle new type:**
```python
elif scene.scene_type == 'code_example':
    start, end = create_code_example_keyframes(...)
```

---

## 📋 Current Active Templates

### **Content Type Templates (5):**

| Template | Scene Count | Structure | Best For |
|----------|-------------|-----------|----------|
| **tutorial** | 6 | title + 3 commands + list + outro | Step-by-step guides |
| **overview** | 5 | title + list + command + list + outro | Feature showcases |
| **troubleshooting** | 6 | title + list + 2 commands + list + outro | Problem-solving |
| **comparison** | 5 | title + 2 lists + command + outro | A vs B comparisons |
| **best_practices** | 5 | title + 2 lists + command + outro | Tips & techniques |

### **Scene Rendering Templates (4):**

| Template | Visual Elements | Use Cases |
|----------|----------------|-----------|
| **title** | GUIDE badge, large title, underline, subtitle | Opening slides |
| **command** | Terminal card, syntax highlighting, macOS dots | CLI commands, code |
| **list** | Numbered cards, title+description | Features, tips, steps |
| **outro** | Checkmark icon, CTA button | Closing, resources |

---

## 🎯 Template Workflow (How They Connect)

### **User Journey with Templates:**

```
STEP 1: User chooses content type
────────────────────────────────────────────────────────────
Wizard: "What type of video?"
User selects: "Tutorial"

Content Type Template Applied:
scene_pattern = ['title', 'command', 'command', 'command', 'list', 'outro']


STEP 2: Wizard asks questions per scene
────────────────────────────────────────────────────────────
For each scene in pattern:
├─ title → asks for title, subtitle
├─ command → asks for topic, commands, key points
├─ command → asks for topic, commands, key points
├─ command → asks for topic, commands, key points
├─ list → asks for items
└─ outro → asks for closing message


STEP 3: YAML generated
────────────────────────────────────────────────────────────
scenes:
  - type: title
  - type: command
  - type: command
  - type: command
  - type: list
  - type: outro


STEP 4: Script generator creates narration
────────────────────────────────────────────────────────────
Reads YAML scene types, generates professional narration


STEP 5: Video generator renders frames
────────────────────────────────────────────────────────────
For each scene type, calls corresponding render function:
├─ type: title → create_title_keyframes()
├─ type: command → create_command_keyframes()
├─ type: list → create_list_keyframes()
└─ type: outro → create_outro_keyframes()


STEP 6: Final video with consistent visual style
────────────────────────────────────────────────────────────
All scenes use same rendering functions = consistent look
```

---

## 🔧 Template Management (Current Best Practice)

### **Where Templates Are Defined:**

| Template Type | File | Lines | Edit To |
|--------------|------|-------|---------|
| **Content Types** | `generate_script_wizard.py` | 68-106 | Add new content patterns |
| **Scene Visuals** | `generate_documentation_videos.py` | 65-253 | Modify visual appearance |
| **Narration Logic** | `generate_script_from_yaml.py` | 26-95 | Change auto-narration |

### **To Add New Content Type:**

**1. Edit wizard templates:**
```python
# In generate_script_wizard.py, add to self.templates:
'api_reference': {
    'description': 'API endpoint documentation',
    'scene_pattern': ['title', 'list', 'command', 'command', 'list', 'outro'],
    'suggestions': {
        'title_subtitle': 'API Reference Guide',
        'outro_main': 'Start Integrating'
    }
}
```

**2. User can now select "API Reference" in wizard**

**That's it!** Uses existing scene rendering templates.

---

### **To Customize Visual Appearance:**

**Edit:** `generate_documentation_videos.py`

```python
# Change colors
BG_LIGHT = (245, 248, 252)  # Light background
ACCENT_BLUE = (59, 130, 246)  # Accent color

# Change fonts
font_title = ImageFont.truetype("arial.ttf", 120)  # Title size
font_code = ImageFont.truetype("consolas.ttf", 32)  # Code size

# Modify rendering functions
def create_title_keyframes(...):
    # Change badge position, title size, layout, etc.
```

**Result:** All videos use new visual style

---

## 📦 Proposed: Template Library System

### **Create Centralized Template Library:**

```
templates/
├─ content_types.yaml          (All content type patterns)
├─ scene_visuals.yaml          (Visual style configurations)
├─ narration_templates.yaml    (Narration generation rules)
│
├─ styles/
│  ├─ modern_light/            (Current style)
│  │  ├─ colors.yaml
│  │  ├─ fonts.yaml
│  │  └─ layouts.yaml
│  │
│  ├─ dark_mode/               (Future)
│  └─ minimal/                 (Future)
│
└─ README_TEMPLATES.md         (Template documentation)
```

### **Example: content_types.yaml**

```yaml
tutorial:
  description: "Step-by-step how-to guide"
  scene_pattern:
    - title
    - command
    - command
    - command
    - list
    - outro
  suggestions:
    title_subtitle: "Step-by-Step Guide"
    outro_main: "Start Building Today"
  narration_style:
    tone: instructional
    pace: moderate
    emphasis: action_verbs

overview:
  description: "Feature showcase and overview"
  scene_pattern:
    - title
    - list
    - command
    - list
    - outro
  suggestions:
    title_subtitle: "Complete Overview"
    outro_main: "Try These Features"
  narration_style:
    tone: promotional
    pace: energetic
    emphasis: benefits

# Easy to add more...
api_reference:
  description: "API endpoint documentation"
  scene_pattern:
    - title
    - list
    - command
    - command
    - list
    - outro
```

### **Example: styles/modern_light/colors.yaml**

```yaml
background:
  primary: [245, 248, 252]   # BG_LIGHT
  card: [255, 255, 255]      # BG_WHITE

accents:
  orange: [255, 107, 53]
  blue: [59, 130, 246]
  purple: [139, 92, 246]
  green: [16, 185, 129]
  pink: [236, 72, 153]

text:
  dark: [15, 23, 42]
  gray: [100, 116, 139]
  light: [148, 163, 184]

theme_name: "Modern Light"
description: "Clean, professional light theme"
```

---

## 🚀 Recommendation: Keep Current + Add Template Manager

### **Current System Works Well:**

✅ Content type templates in wizard (easy to add)
✅ Scene rendering in one file (consistent visuals)
✅ Clear separation of concerns

### **Add Template Manager (Future Enhancement):**

```bash
# List available templates
python manage_templates.py --list

# Add new content type
python manage_templates.py --add-content-type \
  --name "api_reference" \
  --pattern "title,list,command,command,outro"

# Change visual style
python manage_templates.py --set-style dark_mode

# Export current templates to YAML
python manage_templates.py --export
```

---

## 📊 Template Usage Statistics

### **Current System:**

| Template Type | Count | Used In | Extensible? |
|--------------|-------|---------|-------------|
| **Content Types** | 5 | Wizard | ✅ Easy (add to dict) |
| **Scene Renderers** | 4 | Video gen | ⚠️ Medium (need Python) |
| **Visual PNGs** | 10 | Manual use | ❌ Not integrated |

### **Proposed Unified:**

| Template Type | Count | Used In | Extensible? |
|--------------|-------|---------|-------------|
| **Content Types** | 5+ | Wizard | ✅ Very easy (YAML) |
| **Visual Styles** | 1+ | Video gen | ✅ Easy (YAML config) |
| **Scene Types** | 4+ | Video gen | ✅ Medium (Python + YAML) |

---

## 🎯 Quick Answer to Your Question

### **How are templates handled NOW?**

**Two active systems:**

1. **Content Type Templates** (in wizard)
   - 5 predefined patterns (tutorial, overview, etc.)
   - Hardcoded in `generate_script_wizard.py`
   - Define scene structure
   - ✅ Easy to add new ones (just edit Python dict)

2. **Scene Rendering Templates** (in video gen)
   - 4 rendering functions (title, command, list, outro)
   - Coded in `generate_documentation_videos.py`
   - Define visual appearance
   - ⚠️ Moderate effort to add (need Python/Pillow)

**One inactive system:**

3. **Visual Slide Templates** (PNG files)
   - 10 pre-rendered designs
   - In `slide_templates/` directory
   - For manual presentations (PowerPoint, etc.)
   - ❌ Not connected to automated workflow

---

## 💡 Should You Change Anything?

### **For Now: NO**

**Current system is:**
- ✅ Working well
- ✅ Easy to use
- ✅ Sufficient for needs

**Only change if:**
- You want dark mode visual style
- Need 10+ new content type patterns
- Want users to customize visual themes

### **Future Enhancement: Unified Template Library**

**When you need:**
- Multiple visual themes (light, dark, minimal)
- User-selectable styles
- Brand customization per video
- External template sharing

**Then:** Implement centralized template management system

---

*Template System Explained - 2025-10-03*
*Current: Two active template systems (content + visual)*
*Recommendation: Keep current, document clearly*
*Future: Unified template library when needed*
