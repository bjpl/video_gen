# UX Clarity Improvements - Video Generation Configuration UI

**Document Version:** 1.0
**Date:** November 23, 2025
**Status:** Research Complete - Ready for Implementation

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Current UX Issues](#current-ux-issues)
3. [User Confusion Points](#user-confusion-points)
4. [Improved Design Patterns](#improved-design-patterns)
5. [Context-Aware Help Text](#context-aware-help-text)
6. [Visual Output Examples](#visual-output-examples)
7. [Progressive Disclosure](#progressive-disclosure)
8. [Validation Messages](#validation-messages)
9. [Expected Output Preview](#expected-output-preview)
10. [Implementation Priority](#implementation-priority)

---

## Executive Summary

This document identifies critical UX clarity issues in the video generation configuration UI and proposes concrete improvements. The primary problems center around **ambiguous settings** that leave users uncertain about:

- Whether duration applies per video or total
- How language selection multiplies output count
- How multiple voices work across videos
- What video ID naming means for sets

**Impact:** Users may generate unexpected output counts, waste resources, or abandon the tool due to confusion about results.

---

## Current UX Issues

### Issue 1: Ambiguous Duration Field

**Current Implementation:**
```html
<!-- video-config.html lines 12-33 -->
<label class="block text-sm font-medium text-gray-700 mb-2">
    Default Duration (can override per video)
</label>
<input type="range" min="30" max="300" step="10" ...>
<span x-text="duration + 's'"></span>
```

**Problems:**
1. "Default Duration" is vague - default for what?
2. No indication if this is per-video or total duration
3. "(can override per video)" implies multiple videos but doesn't explain when
4. When in Video Set mode with 4 videos, does 120s mean:
   - Each video is 120 seconds (total 480s)?
   - All videos combined total 120 seconds (30s each)?

**User Mental Model:** Users typically expect "duration" to mean the total output they receive, not a per-unit setting.

---

### Issue 2: Language Selection Multiplier Ambiguity

**Current Implementation:**
```html
<!-- multi-language-selector.html lines 45-48 -->
<p class="language-selector__description">
    Select languages for video generation. Videos will be created for each selected language.
</p>
```

**Problems:**
1. The phrase "Videos will be created for each selected language" is buried in small text
2. No numerical preview of output count
3. Combined with Video Set mode, the multiplication is completely unclear:
   - 4 videos in set + 3 languages = 12 videos? Or 4 videos with 3 audio tracks each?
4. Users don't see cost implications until review step (too late)

**Example Confusion Scenario:**
- User selects "Video Set" with 4 videos
- User selects English, Spanish, French
- User expects: 4 videos with multilingual support
- Actual output: 12 separate video files (4 x 3 languages)

---

### Issue 3: Voice Selection Confusion

**Current Implementation:**
```html
<!-- multi-voice-selector.html lines 17-18 -->
<p class="voice-selector__subtitle">
    Select voices for each language. Multiple voices will rotate for variety.
</p>
```

**Problems:**
1. "Rotate for variety" is unclear - how does rotation work?
2. Does it rotate within a single video's scenes?
3. Does it assign different voices to different videos in a set?
4. If I select 3 voices for English with 4 videos in a set, what happens?
   - Voice 1 for video 1, Voice 2 for video 2, Voice 3 for video 3, Voice 1 for video 4?
   - All 3 voices within each video, alternating by scene?

**Technical Reality:** Voices rotate per-scene within a video, but users think they're selecting "a voice for my video."

---

### Issue 4: Video ID Naming Mystery

**Current Implementation:**
```html
<!-- create-unified.html lines 196-202 -->
<label class="block text-sm font-medium text-gray-700 mb-2">Video ID</label>
<input type="text" x-model="config.videoId" placeholder="my-video">
```

**Problems:**
1. No explanation of what "Video ID" means
2. For single video: Is this the filename?
3. For video sets: Does it become a prefix? `my-video-1`, `my-video-2`?
4. For multilingual: Is it `my-video-en`, `my-video-es`?
5. For set + multilingual: `my-video-1-en`, `my-video-1-es`?
6. Users cannot predict output file names

---

### Issue 5: Video Mode Selection Lacking Output Preview

**Current Implementation:**
```html
<!-- create-unified.html lines 226-237 -->
<button @click="config.videoMode = 'single'">
    Single Video - Create one complete video from the entire document
</button>
<button @click="config.videoMode = 'set'">
    Video Set - Split document into multiple videos (by H2 headings)
</button>
```

**Problems:**
1. "Split by H2 headings" assumes user knows their document structure
2. No preview of how many videos will be created from their document
3. Manual "Number of Videos" input (2-10) doesn't match document structure
4. What if document has 6 H2 headings but user sets 4 videos? What gets combined?

---

## User Confusion Points

### Critical Confusion Matrix

| Setting | User Expectation | Actual Behavior | Confusion Level |
|---------|------------------|-----------------|-----------------|
| Duration: 120s | "My video will be 2 minutes" | Each video in set is 2 minutes | HIGH |
| 4 videos + 3 languages | "4 videos, 3 language options" | 12 video files generated | CRITICAL |
| 3 voices selected | "One voice narrates my video" | Voices alternate per scene | MEDIUM |
| Video ID: "tutorial" | Filename is "tutorial.mp4" | Could be tutorial-1-en.mp4, etc. | HIGH |
| Video Set: 4 videos | "4 videos from my document" | Content split may not match expectation | MEDIUM |

### User Journey Pain Points

```
Step 1: User uploads document
        [Clear - No issues]

Step 2: User selects "Video Set" with 4 videos
        [Confusion: "How will my content be split?"]

Step 3: User sets duration to 120 seconds
        [Critical: "Is this total or per video?"]

Step 4: User selects 3 languages
        [Critical: "Am I getting 4 or 12 videos?"]

Step 5: User selects multiple voices per language
        [Confusion: "How will these be used?"]

Step 6: User enters Video ID "my-tutorial"
        [Confusion: "What will my files be named?"]

Step 7: Review screen shows cost
        [Surprise: "Why is cost so high?"]
        [Realization: "Oh, it's 12 videos, not 4!"]
```

---

## Improved Design Patterns

### Pattern 1: Output Preview Card (Always Visible)

**Solution:** Add a persistent sidebar showing exactly what will be generated.

```
+------------------------------------------+
|  OUTPUT PREVIEW                          |
+------------------------------------------+
|                                          |
|  You will receive:                       |
|                                          |
|  [12] video files                        |
|       4 videos x 3 languages             |
|                                          |
|  Each video: ~120 seconds                |
|  Total content: ~24 minutes              |
|                                          |
|  Files generated:                        |
|  - my-tutorial-01-en.mp4                 |
|  - my-tutorial-01-es.mp4                 |
|  - my-tutorial-01-fr.mp4                 |
|  - my-tutorial-02-en.mp4                 |
|  - ... (8 more)                          |
|                                          |
|  Est. cost: $0.36                        |
|  Est. time: ~8 minutes                   |
|                                          |
+------------------------------------------+
```

**Implementation:**
```html
<!-- New component: output-preview-card.html -->
<div class="output-preview-card sticky top-4" x-data="outputPreview()">
    <h3 class="font-bold text-gray-900 mb-4">
        Output Preview
    </h3>

    <!-- Video Count Calculator -->
    <div class="output-count mb-4">
        <div class="text-4xl font-bold text-blue-600" x-text="totalVideoCount">
            12
        </div>
        <div class="text-sm text-gray-600">
            video files will be generated
        </div>
        <div class="text-xs text-gray-500 mt-1" x-show="videoCount > 1 || languageCount > 1">
            <span x-text="videoCount"></span> video(s) &times;
            <span x-text="languageCount"></span> language(s)
        </div>
    </div>

    <!-- Duration Breakdown -->
    <div class="duration-info mb-4 p-3 bg-gray-50 rounded">
        <div class="flex justify-between text-sm">
            <span>Per video:</span>
            <span class="font-medium" x-text="perVideoDuration + 's'"></span>
        </div>
        <div class="flex justify-between text-sm">
            <span>Total content:</span>
            <span class="font-medium" x-text="formatTotalDuration()"></span>
        </div>
    </div>

    <!-- File Names Preview -->
    <div class="file-preview mb-4">
        <div class="text-sm font-medium text-gray-700 mb-2">Files:</div>
        <div class="max-h-32 overflow-y-auto text-xs font-mono bg-gray-100 p-2 rounded">
            <template x-for="file in previewFileNames.slice(0, 5)">
                <div x-text="file" class="text-gray-600"></div>
            </template>
            <div x-show="previewFileNames.length > 5" class="text-gray-400 mt-1">
                ... and <span x-text="previewFileNames.length - 5"></span> more
            </div>
        </div>
    </div>

    <!-- Cost/Time Estimate -->
    <div class="estimates grid grid-cols-2 gap-2 text-sm">
        <div class="p-2 bg-green-50 rounded">
            <div class="text-xs text-green-600">Est. Cost</div>
            <div class="font-bold text-green-800" x-text="'$' + estimatedCost.toFixed(2)"></div>
        </div>
        <div class="p-2 bg-blue-50 rounded">
            <div class="text-xs text-blue-600">Est. Time</div>
            <div class="font-bold text-blue-800" x-text="estimatedTime"></div>
        </div>
    </div>
</div>
```

---

### Pattern 2: Contextual Duration Labels

**Before:**
```
Default Duration (can override per video)
[--------o--------] 120s
```

**After:**
```
Duration PER VIDEO
[--------o--------] 120s

+-----------------------------------------------+
|  With 4 videos selected, total content        |
|  will be approximately 8 minutes (480s)       |
+-----------------------------------------------+
```

**Implementation:**
```html
<div>
    <label class="block text-sm font-medium text-gray-700 mb-2">
        Duration
        <span class="font-bold text-blue-600">per video</span>
    </label>
    <div class="flex items-center gap-4">
        <input type="range" x-model.number="config.duration"
               min="30" max="300" step="10" class="flex-1">
        <span class="text-sm font-medium w-16 text-right"
              x-text="config.duration + 's'"></span>
    </div>

    <!-- Context-aware total duration display -->
    <div x-show="config.videoMode === 'set' || selectedLanguages.length > 1"
         class="mt-2 p-2 bg-blue-50 border border-blue-200 rounded text-sm">
        <span class="text-blue-800">
            Total content:
            <strong x-text="formatDuration(config.duration * totalVideoCount)"></strong>
        </span>
        <span class="text-blue-600 text-xs block mt-1"
              x-text="'(' + totalVideoCount + ' videos x ' + config.duration + 's each)'">
        </span>
    </div>
</div>
```

---

### Pattern 3: Interactive Language Selection with Impact Preview

**Before:**
```
Target Languages (3 selected)
[x] English  [x] Spanish  [x] French
```

**After:**
```
Target Languages (3 selected)
[x] English  [x] Spanish  [x] French

+--------------------------------------------------+
|  Each language creates a separate video file.    |
|                                                  |
|  Your selection will generate:                   |
|  - 4 videos in English                           |
|  - 4 videos in Spanish                           |
|  - 4 videos in French                            |
|  --------------------------------                |
|  = 12 video files total                          |
|                                                  |
|  +$0.09 translation cost for 2 languages         |
+--------------------------------------------------+
```

**Implementation:**
```html
<!-- Enhanced language selector with impact preview -->
<div class="language-impact-preview"
     x-show="selectedLanguages.length > 0">
    <div class="p-4 bg-purple-50 border border-purple-200 rounded-lg mt-4">
        <div class="font-medium text-purple-900 mb-2">
            Each language creates a separate video file
        </div>

        <div class="space-y-1 text-sm">
            <template x-for="lang in selectedLanguages">
                <div class="flex items-center gap-2 text-purple-800">
                    <span x-text="getLanguageFlag(lang)"></span>
                    <span x-text="videoCount + ' video(s) in ' + getLanguageName(lang)"></span>
                </div>
            </template>
        </div>

        <div class="border-t border-purple-300 mt-3 pt-3">
            <div class="flex justify-between items-center">
                <span class="font-bold text-purple-900">Total files:</span>
                <span class="text-2xl font-bold text-purple-700"
                      x-text="videoCount * selectedLanguages.length"></span>
            </div>
        </div>

        <!-- Translation cost notice -->
        <div x-show="selectedLanguages.length > 1"
             class="mt-3 text-xs text-purple-600">
            +$<span x-text="((selectedLanguages.length - 1) * 0.03).toFixed(2)"></span>
            translation cost for <span x-text="selectedLanguages.length - 1"></span> additional language(s)
        </div>
    </div>
</div>
```

---

### Pattern 4: Voice Rotation Explainer

**Before:**
```
Voice Selection
Select voices for each language. Multiple voices will rotate for variety.

English (2 voices selected)
[x] Andrew (Male)    [x] Aria (Female)
```

**After:**
```
Voice Selection
Multiple voices alternate scene-by-scene for a dynamic presentation.

English (2 voices selected)
[x] Andrew (Male)    [x] Aria (Female)

+--------------------------------------------------+
|  Voice Rotation Preview                          |
|                                                  |
|  Scene 1: Andrew (Male)    "Introduction..."     |
|  Scene 2: Aria (Female)    "Overview of..."      |
|  Scene 3: Andrew (Male)    "In this section..."  |
|  Scene 4: Aria (Female)    "Key points..."       |
|  ...                                             |
|                                                  |
|  Voices alternate to keep viewers engaged        |
+--------------------------------------------------+
```

**Implementation:**
```html
<!-- Voice rotation preview component -->
<div class="voice-rotation-explainer p-4 bg-cyan-50 border border-cyan-200 rounded-lg">
    <div class="font-medium text-cyan-900 mb-3 flex items-center gap-2">
        <span>Voice Rotation Preview</span>
    </div>

    <div class="space-y-2">
        <template x-for="(scene, index) in sampleScenes.slice(0, 4)">
            <div class="flex items-center gap-3 text-sm">
                <span class="w-20 text-cyan-600">Scene <span x-text="index + 1"></span>:</span>
                <span class="font-medium text-cyan-800"
                      x-text="getRotatingVoice(index)"></span>
                <span class="text-cyan-600 text-xs italic truncate flex-1"
                      x-text="'\"' + scene.preview + '...\"'"></span>
            </div>
        </template>
        <div class="text-cyan-500 text-xs">...</div>
    </div>

    <div class="mt-3 pt-3 border-t border-cyan-300 text-xs text-cyan-700">
        Voices alternate by scene to create variety and maintain engagement
    </div>
</div>
```

---

### Pattern 5: Video ID with Naming Preview

**Before:**
```
Video ID
[my-tutorial          ]
```

**After:**
```
Video ID (base name for your files)
[my-tutorial          ]

+--------------------------------------------------+
|  Your files will be named:                       |
|                                                  |
|  Single video mode:                              |
|    my-tutorial-en.mp4                            |
|                                                  |
|  Video Set mode (4 videos, 3 languages):         |
|    my-tutorial-01-en.mp4                         |
|    my-tutorial-01-es.mp4                         |
|    my-tutorial-01-fr.mp4                         |
|    my-tutorial-02-en.mp4                         |
|    ...                                           |
+--------------------------------------------------+
```

**Implementation:**
```html
<div>
    <label class="block text-sm font-medium text-gray-700 mb-2">
        Video ID
        <span class="text-gray-500 font-normal">(base name for your files)</span>
    </label>
    <input type="text" x-model="config.videoId"
           placeholder="my-tutorial"
           class="w-full px-4 py-2 border-2 rounded-lg">

    <!-- Naming preview -->
    <div class="mt-3 p-3 bg-gray-50 border border-gray-200 rounded text-sm">
        <div class="font-medium text-gray-700 mb-2">File naming preview:</div>
        <div class="font-mono text-xs space-y-1 max-h-24 overflow-y-auto">
            <template x-for="name in getFileNamePreviews().slice(0, 5)">
                <div class="text-gray-600" x-text="name"></div>
            </template>
            <div x-show="getFileNamePreviews().length > 5" class="text-gray-400">
                + <span x-text="getFileNamePreviews().length - 5"></span> more files
            </div>
        </div>
    </div>
</div>
```

---

## Context-Aware Help Text

### Dynamic Labels Based on Selection State

| Setting State | Label Text |
|---------------|------------|
| Single video, 1 language | "Duration: 120 seconds" |
| Single video, 3 languages | "Duration per video: 120s (360s total across 3 languages)" |
| 4-video set, 1 language | "Duration per video: 120s (480s total content)" |
| 4-video set, 3 languages | "Duration per video: 120s (1,440s = 24min total across 12 videos)" |

### Implementation Pattern

```javascript
// Context-aware label generator
function getDurationLabel() {
    const videoCount = config.videoMode === 'set' ? config.videoCount : 1;
    const langCount = selectedLanguages.length;
    const totalVideos = videoCount * langCount;
    const totalSeconds = config.duration * totalVideos;

    if (totalVideos === 1) {
        return `Duration: ${config.duration} seconds`;
    }

    const breakdown = [];
    if (videoCount > 1) breakdown.push(`${videoCount} videos`);
    if (langCount > 1) breakdown.push(`${langCount} languages`);

    return `Duration per video: ${config.duration}s (${formatDuration(totalSeconds)} total across ${totalVideos} videos)`;
}
```

---

## Visual Output Examples

### Example 1: Single Video, Single Language (Simplest Case)

```
+------------------------------------------+
|  OUTPUT PREVIEW                          |
+------------------------------------------+
|                                          |
|  You will receive:                       |
|                                          |
|  [1] video file                          |
|                                          |
|  Duration: 120 seconds                   |
|                                          |
|  File:                                   |
|  my-tutorial-en.mp4                      |
|                                          |
|  Est. cost: $0.03                        |
|  Est. time: ~2 minutes                   |
|                                          |
+------------------------------------------+
```

### Example 2: Video Set with Multiple Languages (Complex Case)

```
+------------------------------------------+
|  OUTPUT PREVIEW                          |
+------------------------------------------+
|                                          |
|  You will receive:                       |
|                                          |
|  [12] video files                        |
|       4 videos x 3 languages             |
|                                          |
|  Per video: 120 seconds                  |
|  Total content: 24 minutes               |
|                                          |
|  Breakdown by language:                  |
|  - English: 4 videos (8 min)             |
|  - Spanish: 4 videos (8 min)             |
|  - French:  4 videos (8 min)             |
|                                          |
|  Files (showing first 6):                |
|  my-tutorial-01-en.mp4                   |
|  my-tutorial-01-es.mp4                   |
|  my-tutorial-01-fr.mp4                   |
|  my-tutorial-02-en.mp4                   |
|  my-tutorial-02-es.mp4                   |
|  my-tutorial-02-fr.mp4                   |
|  ... and 6 more                          |
|                                          |
|  Est. cost: $0.36                        |
|  Est. time: ~12 minutes                  |
|                                          |
+------------------------------------------+
```

### ASCII Flow Diagram: Setting Multiplication

```
                    Single Video Mode
                          |
            +-------------+-------------+
            |                           |
      1 Language                  3 Languages
            |                           |
       1 video                     3 videos
    (my-video-en)          (my-video-en, -es, -fr)


                    Video Set Mode (4 videos)
                          |
            +-------------+-------------+
            |                           |
      1 Language                  3 Languages
            |                           |
      4 videos                    12 videos
  (my-video-01-en              (my-video-01-en
   my-video-02-en               my-video-01-es
   my-video-03-en               my-video-01-fr
   my-video-04-en)              my-video-02-en
                                my-video-02-es
                                ... etc)
```

---

## Progressive Disclosure

### Level 1: Simple Mode (Default View)

Show only essential fields:
- Input source
- Video ID
- Duration
- Primary language
- Generate button

### Level 2: Advanced Options (Expandable)

Reveal when user clicks "Advanced Options":
- Video Mode (Single/Set)
- Multiple languages
- Multiple voices
- Translation method

### Level 3: Full Configuration (Expert Mode)

All options visible:
- Custom voice per language
- Scene-level voice assignment
- Output format options
- Advanced timing controls

### Implementation

```html
<div x-data="{ advancedOpen: false }">
    <!-- Level 1: Essential Fields (Always Visible) -->
    <div class="essential-fields">
        <!-- Video ID, Duration, Primary Language -->
    </div>

    <!-- Advanced Toggle -->
    <button @click="advancedOpen = !advancedOpen"
            class="text-blue-600 hover:text-blue-800 text-sm flex items-center gap-2 my-4">
        <span x-text="advancedOpen ? 'Hide' : 'Show'"></span> Advanced Options
        <svg :class="advancedOpen ? 'rotate-180' : ''" class="w-4 h-4 transition-transform">
            <!-- chevron icon -->
        </svg>
    </button>

    <!-- Level 2: Advanced Options (Collapsible) -->
    <div x-show="advancedOpen" x-collapse>
        <div class="p-4 bg-gray-50 rounded-lg space-y-4">
            <!-- Video Mode Selector -->
            <!-- Multiple Languages -->
            <!-- Multiple Voices -->
        </div>
    </div>
</div>
```

---

## Validation Messages

### Pre-submission Warnings

Show warnings before user submits if settings may produce unexpected results:

```html
<!-- Warning: High video count -->
<div x-show="totalVideoCount > 10"
     class="p-3 bg-amber-50 border-l-4 border-amber-400 text-amber-800 text-sm">
    <strong>Large Output Warning:</strong>
    You're about to generate <span x-text="totalVideoCount"></span> video files.
    This will take approximately <span x-text="estimatedTime"></span> and cost
    ~$<span x-text="estimatedCost.toFixed(2)"></span>.
</div>

<!-- Warning: Missing voice selection -->
<div x-show="hasLanguageWithoutVoice"
     class="p-3 bg-red-50 border-l-4 border-red-400 text-red-800 text-sm">
    <strong>Missing Voice:</strong>
    Please select at least one voice for each language.
    <ul class="mt-1 ml-4 list-disc">
        <template x-for="lang in languagesWithoutVoice">
            <li x-text="getLanguageName(lang)"></li>
        </template>
    </ul>
</div>

<!-- Info: First-time multilingual -->
<div x-show="selectedLanguages.length > 1 && !hasSeenMultilingualInfo"
     class="p-3 bg-blue-50 border-l-4 border-blue-400 text-blue-800 text-sm">
    <strong>Multilingual Mode:</strong>
    Each language you select creates a complete, separate video file.
    Translation is handled automatically using
    <span x-text="config.translationMethod === 'claude' ? 'Claude AI' : 'Google Translate'"></span>.
    <button @click="dismissMultilingualInfo()" class="underline">Got it</button>
</div>
```

### Constraint Validation

```javascript
const validationRules = {
    videoId: {
        required: true,
        pattern: /^[a-z0-9-_]+$/i,
        maxLength: 50,
        messages: {
            required: 'Video ID is required',
            pattern: 'Use only letters, numbers, hyphens, and underscores',
            maxLength: 'Video ID must be 50 characters or less'
        }
    },
    duration: {
        min: 30,
        max: 600,
        messages: {
            min: 'Minimum duration is 30 seconds',
            max: 'Maximum duration is 10 minutes (600 seconds)'
        }
    },
    videoCount: {
        min: 2,
        max: 10,
        conditional: (config) => config.videoMode === 'set',
        messages: {
            min: 'Video sets require at least 2 videos',
            max: 'Maximum 10 videos per set'
        }
    },
    languages: {
        min: 1,
        max: 10,
        messages: {
            min: 'Select at least one language',
            max: 'Maximum 10 languages per generation'
        }
    }
};
```

---

## Expected Output Preview

### Real-Time Preview Component

The preview updates instantly as users change any setting:

```javascript
Alpine.data('outputPreview', () => ({
    // Computed properties
    get totalVideoCount() {
        const videoCount = this.config.videoMode === 'set' ? this.config.videoCount : 1;
        return videoCount * this.selectedLanguages.length;
    },

    get totalDurationSeconds() {
        return this.config.duration * this.totalVideoCount;
    },

    get previewFileNames() {
        const files = [];
        const baseId = this.config.videoId || 'video';
        const videoCount = this.config.videoMode === 'set' ? this.config.videoCount : 1;

        for (let v = 1; v <= videoCount; v++) {
            for (const lang of this.selectedLanguages) {
                if (videoCount > 1) {
                    files.push(`${baseId}-${String(v).padStart(2, '0')}-${lang}.mp4`);
                } else {
                    files.push(`${baseId}-${lang}.mp4`);
                }
            }
        }
        return files;
    },

    get estimatedCost() {
        // Base cost per video + translation costs
        const baseCost = 0.03 * this.totalVideoCount;
        const translationCost = (this.selectedLanguages.length - 1) * 0.03 *
                               (this.config.videoMode === 'set' ? this.config.videoCount : 1);
        return baseCost + translationCost;
    },

    get estimatedTime() {
        // Rough estimate: 30 seconds per video + 10 seconds per scene
        const estimatedScenes = Math.ceil(this.config.duration / 20);
        const timePerVideo = 30 + (estimatedScenes * 10);
        const totalSeconds = timePerVideo * this.totalVideoCount;
        return this.formatTime(totalSeconds);
    },

    formatDuration(seconds) {
        if (seconds < 60) return `${seconds}s`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
        const hours = Math.floor(seconds / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${mins}m`;
    },

    formatTime(seconds) {
        if (seconds < 60) return `~${seconds} seconds`;
        return `~${Math.ceil(seconds / 60)} minutes`;
    }
}));
```

---

## Implementation Priority

### Phase 1: Critical (Week 1)

| Priority | Item | Impact | Effort |
|----------|------|--------|--------|
| P0 | Output Preview Card | Eliminates all multiplication confusion | Medium |
| P0 | Duration "per video" label | Prevents duration misunderstanding | Low |
| P0 | Language selection impact preview | Shows video count multiplication | Medium |

### Phase 2: Important (Week 2)

| Priority | Item | Impact | Effort |
|----------|------|--------|--------|
| P1 | Video ID naming preview | Prevents file naming confusion | Low |
| P1 | Voice rotation explainer | Clarifies voice behavior | Medium |
| P1 | Pre-submission warnings | Catches unexpected configurations | Low |

### Phase 3: Enhancement (Week 3)

| Priority | Item | Impact | Effort |
|----------|------|--------|--------|
| P2 | Progressive disclosure | Reduces initial complexity | Medium |
| P2 | Context-aware help text | Dynamic explanations | Medium |
| P2 | Document structure preview | Shows video split points | High |

---

## Summary of Key Changes

### Before/After Comparison

| Aspect | Before | After |
|--------|--------|-------|
| Duration | "Default Duration" | "Duration **per video** (480s total across 4 videos)" |
| Languages | "3 selected" | "3 languages = 12 video files (4 x 3)" |
| Voices | "Will rotate" | Visual scene-by-scene rotation preview |
| Video ID | Input field only | Input + live file name preview |
| Output | Cost only at review | Persistent output preview sidebar |

### Expected Outcomes

1. **Reduced Support Tickets:** Users understand output before generating
2. **Fewer Abandoned Sessions:** Clear expectations = confident generation
3. **Better Resource Planning:** Users see cost/time upfront
4. **Higher Satisfaction:** Output matches expectations

---

## Appendix: User Testing Questions

To validate these improvements, ask users:

1. "How many video files will be created with these settings?"
2. "What will the file names be?"
3. "How long will each video be?"
4. "How will the selected voices be used?"
5. "What is the estimated total cost?"

**Success Metric:** Users should answer all questions correctly from the UI alone without reading documentation.

---

*Document prepared by UX Research Agent*
*Last Updated: November 23, 2025*
