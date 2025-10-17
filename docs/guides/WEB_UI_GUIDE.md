# 🌐 Web UI Complete Guide

**Professional Video Generation Through an Intuitive Web Interface**

**Last Updated:** October 11, 2025
**UI/API Feature Parity:** 90% (up from 60%)
**Status:** Production-Ready

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [UI Components](#ui-components)
4. [Scene Builder](#scene-builder)
5. [Multilingual Generation](#multilingual-generation)
6. [AI Narration](#ai-narration)
7. [Advanced Features](#advanced-features)
8. [Workflows](#workflows)
9. [Troubleshooting](#troubleshooting)

---

## Overview

### What is the Web UI?

The Video Gen Web UI provides a **zero-code interface** for professional video generation, offering 90% feature parity with the programmatic API. Built with **HTMX + Alpine.js**, it's fast, lightweight, and requires no build step.

### Key Features

✅ **12 Scene Types** - All scene types accessible with full parameter control
✅ **Duration Controls** - Min/max duration settings on every scene
✅ **Multilingual** - Generate videos in 28+ languages simultaneously
✅ **Voice Rotation** - Multi-voice support with clear rotation patterns
✅ **AI Enhancement** - Claude AI script improvement with transparent costs
✅ **Scene Preview** - Validate content before generation
✅ **Real-time Progress** - Server-Sent Events for live updates
✅ **4 Input Methods** - Document, YouTube, Builder, Programmatic API

### UI Pages

| Page | URL | Purpose | Best For |
|------|-----|---------|----------|
| **Quick Start** | `/create` | Fast video generation | Single videos from docs/YouTube |
| **Scene Builder** | `/builder` | Scene-by-scene control | Custom educational content |
| **Multilingual** | `/multilingual` | Multi-language videos | Global content distribution |
| **Progress** | `/progress` | Task monitoring | Tracking generation status |

---

## Quick Start

### 1. Start the Server

```bash
cd app
python main.py
# Or: uvicorn main:app --reload --port 8000
```

### 2. Open Browser

```
http://localhost:8000
```

### 3. Choose Your Workflow

**Option A: Quick Start (Fastest)**
1. Navigate to `/create`
2. Enter title or paste document/YouTube URL
3. Configure voice, color, language
4. Click "Generate Video"

**Option B: Scene Builder (Most Control)**
1. Navigate to `/builder`
2. Add scenes one-by-one with full parameter control
3. Configure global settings
4. Generate custom video

**Option C: Multilingual (Global Reach)**
1. Navigate to `/multilingual`
2. Select source language
3. Choose 1-27 target languages
4. Configure voices per language
5. Generate video set

---

## UI Components

### Quick Start Interface (`/create`)

**New in Phase 1+2:**
- ✨ **Scene Preview** - See parsed scenes before generation
- ✨ **Voice Rotation Explainer** - Visual guide to multi-voice patterns
- ✨ **AI Narration Clarity** - Cost disclosure and API key requirements

**Components:**

#### 1. Input Method Selection

```
┌──────────────────────────────────────┐
│ 📄 Manual Title Entry                │
│ Enter a title and let AI generate    │
│ scenes automatically                 │
└──────────────────────────────────────┘

┌──────────────────────────────────────┐
│ 📚 Document Parsing                  │
│ Upload README.md or paste Markdown   │
│ Auto-generates scenes from headers   │
└──────────────────────────────────────┘

┌──────────────────────────────────────┐
│ 🎥 YouTube Transcription             │
│ Paste YouTube URL to extract        │
│ transcript and generate scenes       │
└──────────────────────────────────────┘

┌──────────────────────────────────────┐
│ 📁 YAML Configuration                │
│ Upload pre-configured YAML file      │
│ for advanced customization           │
└──────────────────────────────────────┘
```

#### 2. Voice Configuration

**Single Voice:**
```html
Andrew (Male) - Professional, confident
Brandon (Male Warm) - Warm, friendly
Aria (Female) - Professional, crisp
Ava (Female Friendly) - Friendly, approachable
```

**Multi-Voice Rotation (NEW!):**
- **1 Track:** Same voice throughout
- **2 Tracks:** Alternates - Track 1 → Track 2 → Track 1...
- **3+ Tracks:** Full rotation through all voices

**Use Cases:**
- Conversations (2 voices)
- Interviews (2 voices)
- Multi-speaker tutorials (3-4 voices)

#### 3. AI Narration Toggle (UPDATED Phase 2)

**Old Label:** "AI-Enhanced Narration"
**New Label:** "Claude AI Script Enhancement 🌟"

**What Changed:**
- Clear cost disclosure: ~$0.03/video
- Time estimate: +3-5s per scene
- API key requirement notice (shows when enabled)
- BETA badge for transparency

**When to Use:**
- ✅ High-stakes content (sales, education, brand)
- ✅ Natural conversational tone needed
- ❌ Budget-constrained (use template narration)
- ❌ Technical documentation (template works great)

#### 4. Scene Preview (NEW Phase 2)

**Feature:** Validate parsed content before generation

**How to Use:**
1. Enter document or YouTube URL
2. Click "👁️ Preview Scenes" button
3. Review scene breakdown:
   - Scene type badges (color-coded)
   - Scene titles and content
   - Voice assignments
   - Duration estimates
4. Click "Generate" when satisfied

**Color Coding:**
- 🔵 Title - Blue
- 🟢 Section - Green
- 🟣 List - Purple
- ⚫ Code - Gray
- 🟠 Conclusion - Orange
- 🟡 Info - Yellow

---

## Scene Builder

### Overview

The **Scene Builder** (`/builder`) provides **scene-by-scene control** with access to all 12 scene types and their specific parameters.

### New in Phase 1 (October 11, 2025)

✅ **12/12 Scene Types** - All scene types now have complete forms
✅ **Duration Controls** - Min/max duration on every scene
✅ **6 New Scene Forms** - code_comparison, quote, learning_objectives (enhanced), problem (with difficulty), solution (code+explanation), exercise (with hints), checkpoint (two-column)

### Scene Types Available

#### **General Purpose (6 types)**

1. **Title** - Main title slides with subtitle
2. **Command** - Terminal commands with labels
3. **List** - Bulleted or numbered lists
4. **Outro** - Closing screens with call-to-action
5. **Code Comparison** (NEW Phase 1) - Before/after code
6. **Quote** (NEW Phase 1) - Quotes with attribution

#### **Educational (6 types)**

7. **Learning Objectives** (ENHANCED Phase 1) - Lesson goals
8. **Problem** (ENHANCED Phase 1) - Challenges with difficulty levels
9. **Solution** (ENHANCED Phase 1) - Solutions with code+explanation
10. **Exercise** (ENHANCED Phase 1) - Practice tasks with hints
11. **Checkpoint** (ENHANCED Phase 1) - Progress review (learned vs next)
12. **Quiz** - Multiple choice questions

### Scene-Specific Parameters

#### Code Comparison Form (NEW)

```html
┌─────────────────────────────────────┐
│ Before Label: [Before          ▼] │
│ After Label:  [After           ▼] │
│                                     │
│ Original Code:                      │
│ ┌─────────────────────────────────┐ │
│ │ def old_func():                 │ │
│ │     return "legacy"             │ │
│ └─────────────────────────────────┘ │
│                                     │
│ Refactored Code:                    │
│ ┌─────────────────────────────────┐ │
│ │ def new_func() -> str:          │ │
│ │     return "modern"             │ │
│ └─────────────────────────────────┘ │
└─────────────────────────────────────┘
```

**API Mapping:**
```python
{
    "before_code": ["def old_func():", "    return \"legacy\""],
    "after_code": ["def new_func() -> str:", "    return \"modern\""],
    "before_label": "Before",
    "after_label": "After"
}
```

#### Problem Form (ENHANCED)

```html
┌─────────────────────────────────────┐
│ Title: [Reverse a Linked List   ] │
│                                     │
│ Problem Description:                │
│ ┌─────────────────────────────────┐ │
│ │ Given a linked list, reverse    │ │
│ │ it in-place...                  │ │
│ └─────────────────────────────────┘ │
│                                     │
│ Difficulty: [🟡 Medium         ▼] │
│   Options: 🟢 Easy               │
│            🟡 Medium             │
│            🔴 Hard                │
└─────────────────────────────────────┘
```

**Color Coding:**
- Easy → Green background
- Medium → Orange background
- Hard → Red background

#### Solution Form (ENHANCED)

```html
┌─────────────────────────────────────┐
│ Solution Code:                      │
│ ┌─────────────────────────────────┐ │
│ │ def reverse_list(head):         │ │
│ │     prev = None                 │ │
│ │     curr = head                 │ │
│ │     while curr:                 │ │
│ │         next = curr.next        │ │
│ │         curr.next = prev        │ │
│ │         prev = curr             │ │
│ │         curr = next             │ │
│ │     return prev                 │ │
│ └─────────────────────────────────┘ │
│                                     │
│ Explanation:                        │
│ ┌─────────────────────────────────┐ │
│ │ We use three pointers to        │ │
│ │ reverse links in-place...       │ │
│ └─────────────────────────────────┘ │
└─────────────────────────────────────┘
```

#### Exercise Form (ENHANCED)

```html
┌─────────────────────────────────────┐
│ Title: [Implement Binary Search ] │
│                                     │
│ Instructions:                       │
│ ┌─────────────────────────────────┐ │
│ │ Write a function that performs  │ │
│ │ binary search on a sorted array │ │
│ └─────────────────────────────────┘ │
│                                     │
│ Hints (one per line):               │
│ ┌─────────────────────────────────┐ │
│ │ Start with mid = (low+high)//2  │ │
│ │ Compare target with mid element │ │
│ │ Adjust search range accordingly │ │
│ └─────────────────────────────────┘ │
└─────────────────────────────────────┘
```

#### Checkpoint Form (ENHANCED)

```html
┌─────────────────────────────────────┐
│ ✅ What We've Learned:              │
│ ┌─────────────────────────────────┐ │
│ │ Variables and data types        │ │
│ │ Control flow (if/else)          │ │
│ │ Loops (for/while)               │ │
│ │ Functions and parameters        │ │
│ └─────────────────────────────────┘ │
│                                     │
│ 🎯 Coming Up Next:                  │
│ ┌─────────────────────────────────┐ │
│ │ Object-oriented programming     │ │
│ │ Classes and inheritance         │ │
│ │ Error handling                  │ │
│ │ File I/O                        │ │
│ └─────────────────────────────────┘ │
└─────────────────────────────────────┘
```

### Universal Duration Controls (NEW Phase 1)

**Every scene type now includes:**

```html
──────────────────────────────────────
  Min Duration (s)  │  Max Duration (s)
  [3.0           ]  │  [15.0          ]
──────────────────────────────────────
ℹ️ System generates audio, then adjusts
   to fit duration range
```

**How It Works:**
1. System generates TTS audio from narration
2. Measures actual audio duration
3. Adjusts within min/max bounds:
   - Too short → Adds padding/pauses
   - Too long → Speeds slightly (natural limit)
   - Just right → Uses exact audio duration

**Defaults:**
- Min: 3.0 seconds (prevents rushed scenes)
- Max: 15.0 seconds (maintains engagement)

**Use Cases:**
- Short scenes (3-5s): Titles, quotes, transitions
- Medium scenes (5-10s): Lists, commands, code
- Long scenes (10-15s): Complex explanations, solutions

---

## Multilingual Generation

### Overview

Generate videos in **28+ languages** with per-language voice customization.

### New in Phase 2 (October 11, 2025)

✅ **Builder Integration** - Multilingual now available in Scene Builder
✅ **Per-Language Voices** - Assign different voices to each language
✅ **Live Counter** - "Selected: X language(s)"
✅ **Educational Info** - Explains translation and voice adaptation

### Supported Languages (28+)

**European:**
🇬🇧 English, 🇪🇸 Spanish, 🇫🇷 French, 🇩🇪 German, 🇮🇹 Italian, 🇵🇹 Portuguese, 🇳🇱 Dutch, 🇷🇺 Russian, 🇵🇱 Polish, 🇸🇪 Swedish, 🇳🇴 Norwegian, 🇩🇰 Danish, 🇫🇮 Finnish, 🇬🇷 Greek, 🇨🇿 Czech, 🇭🇺 Hungarian

**Asian:**
🇯🇵 Japanese, 🇨🇳 Chinese (Simplified), 🇰🇷 Korean, 🇮🇳 Hindi, 🇹🇭 Thai, 🇻🇳 Vietnamese, 🇮🇩 Indonesian, 🇲🇾 Malay, 🇵🇭 Filipino

**Middle Eastern:**
🇸🇦 Arabic, 🇮🇱 Hebrew, 🇹🇷 Turkish

### Multilingual in Builder (NEW Phase 2)

**Enable Multilingual Mode:**

```html
┌──────────────────────────────────────┐
│ 🌐 Multilingual Settings             │
├──────────────────────────────────────┤
│                                      │
│ ☑ Enable Multilingual Mode          │
│                                      │
│ Source Language:                     │
│ [English (en)                    ▼] │
│                                      │
│ Target Languages: (Selected: 3)      │
│ ☑ Spanish    ☑ French   ☑ German   │
│ ☐ Italian    ☐ Portuguese ☐ Dutch   │
│ ☐ Japanese   ☐ Chinese    ☐ Korean   │
│ ... (28 total languages)             │
│                                      │
│ Per-Language Voice Assignment:       │
│ Spanish:  [Aria (Female)         ▼] │
│ French:   [Andrew (Male)         ▼] │
│ German:   [Brandon (Male Warm)   ▼] │
│                                      │
└──────────────────────────────────────┘
```

**How It Works:**
1. Content automatically translated from source to each target
2. Separate video files generated per language
3. AI narration adapts to each language's rhythm
4. Visual elements remain consistent

**Output Structure:**
```
outputs/
  my_video_en/video.mp4    # English
  my_video_es/video.mp4    # Spanish
  my_video_fr/video.mp4    # French
  my_video_de/video.mp4    # German
```

### Translation Methods

**Claude AI (Recommended):**
- High-quality, context-aware translation
- Preserves technical terminology
- Cost: ~$0.01 per 1000 words
- Requires: ANTHROPIC_API_KEY

**Google Translate (Free):**
- Fast, reliable baseline
- Good for general content
- Cost: Free
- No API key required

---

## AI Narration

### Overview

**Claude AI Script Enhancement** improves narration quality and naturalness.

### Clarifications (Phase 2 Update)

**What It Is:**
- Script content improvement (not TTS upgrade)
- Makes narration more natural and engaging
- Optimizes for spoken delivery

**What It's NOT:**
- NOT a better voice/TTS engine (voice quality unchanged)
- NOT required (template narration is professional quality)

### Cost & Requirements

**Cost:** ~$0.03 per video
- Scene-based: ~$0.006 per scene
- Video set: ~$0.03 per video in set

**Time:** +3-5 seconds per scene
- Adds API call latency
- Worth it for important content

**Requirements:**
- `ANTHROPIC_API_KEY` environment variable
- Sufficient API credits (~$5 minimum recommended)

**When Enabled:**
```
⚠️ Requires ANTHROPIC_API_KEY
   Set in environment variables or .env file
```

### Template Narration (Default)

**Advantages:**
- FREE (no API costs)
- INSTANT (no API latency)
- PROFESSIONAL (high-quality TTS)
- FUNCTIONAL (works great for technical content)

**Use For:**
- Documentation videos
- Technical tutorials
- Internal training
- Budget-constrained projects

### AI Narration (Opt-In)

**Advantages:**
- NATURAL (conversational tone)
- ENGAGING (better flow)
- CONTEXTUAL (scene-aware)
- POLISHED (refined language)

**Use For:**
- Sales/marketing videos
- Public-facing content
- Educational courses
- Brand content

---

## Advanced Features

### Scene Preview

**Available:** Quick Start (`/create`)

**Purpose:** Validate content interpretation before generation

**How to Use:**
1. Enter document or YouTube URL
2. Click "👁️ Preview Scenes"
3. Review parsed scene structure
4. Generate or edit in Builder

**Preview Display:**
- Scene number badges
- Color-coded scene types
- Scene titles and content (truncated)
- Voice assignments
- Duration estimates

**Next Steps:**
- ✅ Satisfied → Click "Generate Video"
- 🛠️ Need edits → "Use Scene Builder" link

### Color Psychology Tooltips (Phase 3 Planned)

**Coming Soon:** Hover tooltips on color buttons

**Example:**
```
Blue: Professional, Trustworthy
Best for: Corporate, Finance, Healthcare
```

### Voice Preview Buttons (Phase 3 Planned)

**Coming Soon:** 🔊 Preview buttons in Builder (like Quick Start)

### Export to YAML/Python (Phase 4 Planned)

**Coming Soon:** "View as Code" to see generated `VideoConfig`

---

## Workflows

### Workflow 1: Quick Document Video

```
1. Navigate to /create
2. Paste README.md content
3. Select voice: Andrew (Male)
4. Select color: Blue
5. Leave AI narration OFF (use template)
6. Click "Generate Video"
7. Monitor progress at /progress
8. Download video from outputs/
```

**Time:** ~5 minutes total

### Workflow 2: Educational Video Set

```
1. Navigate to /builder
2. Add scenes:
   - Learning Objectives (3 goals)
   - Problem (difficulty: Hard)
   - Solution (code + explanation)
   - Exercise (with 3 hints)
   - Checkpoint (learned vs next)
3. Set duration ranges (5-12s per scene)
4. Enable multilingual: English → Spanish, French
5. Assign voices per language
6. Enable AI narration (ANTHROPIC_API_KEY set)
7. Generate video set
8. Get 3 videos (1 per language)
```

**Time:** ~15 minutes total

### Workflow 3: YouTube Summary Video

```
1. Navigate to /create
2. Select "YouTube" tab
3. Paste video URL
4. Preview scenes
5. Adjust if needed
6. Select voice rotation: 2 tracks (conversation style)
7. Generate
```

**Time:** ~7 minutes total

---

## Troubleshooting

### Scene Preview Not Working

**Symptom:** Preview button does nothing

**Solutions:**
1. Check browser console for JavaScript errors
2. Verify Alpine.js loaded (check dev tools)
3. Ensure document/URL field is filled
4. Clear browser cache and reload

### AI Narration Fails

**Symptom:** "API key required" error

**Solutions:**
1. Verify `ANTHROPIC_API_KEY` is set:
   ```bash
   echo $ANTHROPIC_API_KEY
   ```
2. Check API key validity at console.anthropic.com
3. Ensure sufficient API credits
4. Fallback: Disable AI enhancement, use template

### Multilingual Generation Incomplete

**Symptom:** Only some languages generated

**Solutions:**
1. Check logs for translation errors
2. Verify all target languages selected
3. Ensure source language correct
4. Try Google Translate if Claude AI fails
5. Check disk space for multiple video outputs

### Duration Controls Ignored

**Symptom:** Scene durations don't match min/max

**Solutions:**
1. Verify min < max (e.g., min=3, max=15)
2. Check audio actually generated (TTS success)
3. Unrealistic ranges → System uses defaults
4. Check narration length (very short/long text)

### Builder Scenes Not Saving

**Symptom:** Scenes disappear on refresh

**Solutions:**
1. Ensure you clicked "Add Scene" button
2. Check Alpine.js state in dev tools
3. Don't refresh during scene editing
4. Use "Generate" to persist to backend
5. Browser localStorage may be full → Clear

---

## Summary

### Feature Parity Progress

| Phase | Feature Parity | Key Changes |
|-------|---------------|-------------|
| **Baseline** | 60% | 6/12 scene forms, no duration controls |
| **Phase 1** | 80% | 12/12 scene forms, universal duration, voice rotation |
| **Phase 2** | **90%** | **AI clarity, multilingual Builder, scene preview** |
| Phase 3 | 95% (planned) | Tooltips, voice preview, duration explanations |
| Phase 4 | 100% (planned) | Export, discoverability, bridge guides |

### What's New (October 11, 2025)

✨ **Phase 1:**
- All 12 scene types with complete parameter forms
- Min/max duration controls on every scene
- Voice rotation pattern explainer

✨ **Phase 2:**
- AI narration clarity (cost, requirements, BETA badge)
- Multilingual configuration in Builder
- Scene preview in Quick Start

### Getting Help

- **Documentation:** Check `/docs` folder
- **API Reference:** `/docs/api/API_PARAMETERS_REFERENCE.md`
- **Architecture:** `/docs/architecture/UI_ALIGNMENT_ARCHITECTURE.md`
- **Gap Analysis:** `/docs/UI_API_GAP_ANALYSIS.md`
- **Phase Reports:** `/docs/UI_ALIGNMENT_PHASE_1_COMPLETE.md`, `/docs/UI_ALIGNMENT_PHASE_2_COMPLETE.md`

---

**Created:** October 11, 2025
**UI Alignment Project:** 60% → 90% feature parity achieved
**Maintained:** Documentation Specialist Agent
