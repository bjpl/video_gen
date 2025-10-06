# Scene Editor Component - Implementation Guide

## Overview
Complete inline scene editor for Quick Start video creation UI, allowing users to build custom video scenes without using the Advanced Builder.

## Component Location
`C:\Users\brand\Development\Project_Workspace\active-development\video_gen\app\templates\create.html`

**Insert Position:** Inside the "Per-Video Configuration" advanced panel, after the "Duration Override" section (around line 392).

---

## Implementation Files

### 1. HTML Component
**File:** `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\app\templates\scene_editor_component.html`

**Features:**
- Collapsible scene editor panel with scene count badge
- 6 scene type quick-add buttons (Title, Code, List, Outro, Quiz, Slide)
- Dynamic forms based on scene type
- Drag handle for reordering (visual indicator)
- Remove button per scene
- Empty state message when no scenes exist

**Scene Types & Fields:**

1. **Title Scene** (🎬)
   - Main Title (text input)
   - Subtitle (text input, optional)

2. **Command/Code Scene** (💻)
   - Section Header (text input)
   - Description (text input)
   - Commands (textarea, one per line)

3. **List Scene** (📋)
   - List Header (text input)
   - Description (text input, optional)
   - List Items (textarea, one per line)

4. **Outro Scene** (👋)
   - Closing Message (text input)
   - Call to Action (text input, optional)

5. **Quiz Scene** (❓)
   - Question (text input)
   - Options (textarea, one per line)
   - Correct Answer (text input)

6. **Slide Scene** (📊)
   - Slide Header (text input)
   - Slide Content (textarea)

---

### 2. JavaScript Functions
**File:** `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\app\templates\scene_editor_functions.js`

**Functions to Add:**

#### `addScene(mode, videoIdx, sceneType)`
Creates and adds a new scene to the video's scene array based on the selected type.

**Parameters:**
- `mode`: 'single' or 'set'
- `videoIdx`: Index of video in videos array (0 for single mode)
- `sceneType`: 'title', 'command', 'list', 'outro', 'quiz', 'slide'

**Scene Templates:**
```javascript
{
  title: { type: 'title', title: '', subtitle: '' },
  command: { type: 'command', header: '', description: '', commands: '' },
  list: { type: 'list', header: '', description: '', items: '' },
  outro: { type: 'outro', message: '', cta: '' },
  quiz: { type: 'quiz', question: '', options: '', answer: '' },
  slide: { type: 'slide', header: '', content: '' }
}
```

#### `removeScene(mode, videoIdx, sceneIdx)`
Removes a scene from the video's scene array.

**Parameters:**
- `mode`: 'single' or 'set'
- `videoIdx`: Index of video in videos array
- `sceneIdx`: Index of scene to remove

---

## Data Structure Updates

### Single Video Mode
```javascript
single: {
  // ... existing fields ...
  videos: [{
    title: '',
    voices: ['male'],
    duration: null,
    scenes: [{ type: 'title', title: '', subtitle: '' }],  // NEW
    showScenes: false  // NEW
  }]
}
```

### Video Set Mode
```javascript
set: {
  // ... existing fields ...
  videos: [
    {
      title: 'Video 1',
      voices: ['male'],
      duration: null,
      scenes: [{ type: 'title', title: '', subtitle: '' }],  // NEW
      showScenes: false  // NEW
    },
    // ... more videos
  ]
}
```

---

## Backend Integration

### Update API Payload
Both `generateSingle()` and `generateSet()` functions need to include scenes in the video data:

**Single Video:**
```javascript
const videoData = {
  video_id: 'single_' + Date.now(),
  title: this.single.videos[0].title || this.single.title || 'Single Video',
  voices: this.single.videos[0].voices,
  duration: this.single.videos[0].duration || this.single.duration,
  scenes: this.single.videos[0].scenes || []  // Include scenes
};
```

**Video Set:**
```javascript
const videosData = this.set.videos.map((video, i) => ({
  video_id: `video_${i+1}`,
  title: video.title || `Video ${i+1}`,
  voices: video.voices,
  duration: video.duration || this.set.duration,
  scenes: video.scenes || []  // Include scenes
}));
```

---

## Integration Steps

### Step 1: Update Data Structures
In `create.html`, modify the initial data in the `videoCreator()` function:

```javascript
// For single.videos[0]
videos: [{
  title: '',
  voices: ['male'],
  duration: null,
  scenes: [{ type: 'title', title: '', subtitle: '' }],
  showScenes: false
}]

// For set.videos (each video)
videos: [
  {
    title: 'Video 1',
    voices: ['male'],
    duration: null,
    scenes: [{ type: 'title', title: '', subtitle: '' }],
    showScenes: false
  },
  // ...
]
```

### Step 2: Add Functions
Insert the `addScene()` and `removeScene()` functions into the Alpine.js component after `removeVoiceTrack()`:

```javascript
removeVoiceTrack(mode, videoIdx, voiceIdx) {
  // ... existing code ...
},

addScene(mode, videoIdx, sceneType) {
  // ... new code from scene_editor_functions.js ...
},

removeScene(mode, videoIdx, sceneIdx) {
  // ... new code from scene_editor_functions.js ...
},
```

### Step 3: Update `updateVideoList()`
Modify the `updateVideoList()` function to initialize scenes for new videos:

```javascript
updateVideoList(mode) {
  const config = mode === 'single' ? this.single : this.set;
  const currentCount = config.videos.length;
  const targetCount = config.videoCount;

  if (targetCount > currentCount) {
    for (let i = currentCount; i < targetCount; i++) {
      config.videos.push({
        title: `Video ${i + 1}`,
        voices: ['male'],
        duration: null,
        scenes: [{ type: 'title', title: '', subtitle: '' }],  // NEW
        showScenes: false  // NEW
      });
    }
  } else if (targetCount < currentCount) {
    config.videos = config.videos.slice(0, targetCount);
  }
},
```

### Step 4: Insert HTML Component
In `create.html`, insert the scene editor HTML (from `scene_editor_component.html`) after the "Duration Override" section:

**Find this location (around line 392):**
```html
<!-- Per-Video Duration Override -->
<div>
  <!-- ... duration override fields ... -->
</div>

<!-- INSERT SCENE EDITOR HERE -->

<!-- Scene Builder Integration -->
<div class="mt-4 p-3 bg-blue-50 border border-blue-200 rounded-lg">
```

### Step 5: Update Generate Functions
Modify `generateSingle()` and `generateSet()` to include scenes in the payload (see Backend Integration section above).

---

## Video Set Mode Implementation

The scene editor should also be added for each video in the video set mode. Add a similar component inside the per-video configuration panel in the set mode section (if it exists, or create it similar to single mode).

**For Video Set Per-Video Config:**
```html
<template x-for="(video, vIdx) in set.videos" :key="vIdx">
  <div class="border rounded-lg p-4 mb-4">
    <h4 x-text="`Video ${vIdx + 1}: ${video.title}`"></h4>

    <!-- Voice tracks for this video -->
    <!-- ... -->

    <!-- Duration override for this video -->
    <!-- ... -->

    <!-- Scene Editor for this video -->
    <div class="mt-4 border-t pt-4">
      <button @click="video.showScenes = !video.showScenes" type="button"
              class="w-full flex items-center justify-between px-4 py-3 bg-purple-50 hover:bg-purple-100 border border-purple-200 rounded-lg transition-all">
        <div class="flex items-center gap-2">
          <span class="text-lg">📝</span>
          <span class="font-semibold text-gray-900">Edit Scenes</span>
          <span class="text-xs bg-purple-500 text-white px-2 py-0.5 rounded-full" x-text="(video.scenes || []).length + ' scenes'"></span>
        </div>
        <svg class="w-5 h-5 transition-transform" :class="video.showScenes ? 'rotate-180' : ''" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
        </svg>
      </button>

      <div x-show="video.showScenes" x-collapse class="mt-3 space-y-3">
        <!-- Scene type buttons using vIdx instead of 0 -->
        <div>
          <label class="block text-xs font-medium text-gray-600 mb-2">ADD SCENE TYPE</label>
          <div class="grid grid-cols-3 sm:grid-cols-6 gap-2">
            <button @click="addScene('set', vIdx, 'title')" type="button"
                    class="px-2 py-2 text-xs bg-white hover:bg-blue-50 border border-blue-300 rounded-lg font-medium transition-colors">
              🎬 Title
            </button>
            <!-- ... other scene type buttons using vIdx -->
          </div>
        </div>

        <!-- Scene list for this video using vIdx -->
        <div class="space-y-2">
          <template x-for="(scene, sIdx) in (video.scenes || [])" :key="sIdx">
            <!-- ... scene card with removeScene('set', vIdx, sIdx) -->
          </template>
        </div>
      </div>
    </div>
  </div>
</template>
```

---

## UI Behavior

### Default State
- Scene editor panel is **collapsed** by default
- Each new video starts with **one title scene** (empty fields)
- Scene count badge shows "1 scenes" initially

### Adding Scenes
1. User clicks "Edit Scenes" button → panel expands
2. User clicks scene type button (e.g., "💻 Code")
3. New scene card appears at bottom of list with appropriate input fields
4. Scene count badge updates

### Removing Scenes
1. User clicks "×" button on scene card
2. Scene is removed from array
3. Scene count badge updates
4. If last scene removed, empty state appears

### Scene Data Flow
1. User fills in scene fields (Alpine.js two-way binding via `x-model`)
2. Data stored in `video.scenes` array
3. On generate, scenes passed to backend API in video payload
4. Backend processes scenes and creates video frames

---

## Styling

### Color Coding
- **Title Scene:** Blue borders/focus rings
- **Command Scene:** Green borders/focus rings
- **List Scene:** Yellow borders/focus rings
- **Outro Scene:** Purple borders/focus rings
- **Quiz Scene:** Pink borders/focus rings
- **Slide Scene:** Cyan borders/focus rings

### Responsive Design
- Scene type buttons: 3 columns on mobile, 6 on desktop
- Input fields: Full width with appropriate padding
- Scene cards: Hover effect (border changes to blue)

---

## Testing Checklist

- [ ] Scene editor panel toggles correctly
- [ ] Each scene type button creates correct template
- [ ] Scene count badge updates accurately
- [ ] Scene removal works without errors
- [ ] Input fields bind data correctly
- [ ] Empty state displays when no scenes
- [ ] Scenes included in API payload
- [ ] Works in both single and set modes
- [ ] Multiple videos in set mode can have independent scenes
- [ ] Scenes persist when toggling panel
- [ ] Form validation (if implemented)

---

## Future Enhancements

1. **Drag & Drop Reordering:** Implement SortableJS or similar for scene reordering
2. **Scene Duplication:** Add "duplicate" button to copy existing scene
3. **Scene Templates:** Pre-filled scene templates (e.g., "Tutorial Intro")
4. **Scene Preview:** Show visual preview of how scene will look
5. **Import/Export Scenes:** Save scene configurations as JSON
6. **Scene Validation:** Warn if required fields are empty
7. **Scene Timing:** Set duration per scene instead of global
8. **Voice Assignment per Scene:** Different voices for different scenes

---

## File Paths Reference

- **Main Template:** `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\app\templates\create.html`
- **HTML Component:** `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\app\templates\scene_editor_component.html`
- **JS Functions:** `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\app\templates\scene_editor_functions.js`
- **This Document:** `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\docs\SCENE_EDITOR_IMPLEMENTATION.md`

---

## Support & Questions

For issues or questions about scene editor implementation:
1. Check Alpine.js console for JavaScript errors
2. Verify data structure initialization
3. Ensure scene templates match backend expectations
4. Test with browser dev tools to inspect scene data

---

**Implementation Status:** Ready for integration
**Agent:** Scene Editor Component (Agent 5)
**Date:** 2025-10-05
