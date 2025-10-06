# Video Generation UI - Implementation Plan

## 📊 Current Status Analysis

### ✅ **What's Working**
1. **UI Structure**
   - ✅ Landing page with 2 clear paths
   - ✅ 2-step wizard (Type Selection → Configuration)
   - ✅ Beautiful navigation and breadcrumbs
   - ✅ Step progress indicators
   - ✅ Quick templates system

2. **Frontend Features**
   - ✅ 4 input methods (Manual, Document, YouTube, YAML)
   - ✅ Per-video configuration (title, voices[], duration)
   - ✅ Multi-voice tracks per video (1-4 tracks)
   - ✅ Video count control for all modes
   - ✅ Global settings (duration, AI, colors)
   - ✅ Multilingual toggle with language selection
   - ✅ Real-time validation
   - ✅ Generation summaries
   - ✅ Toast notifications
   - ✅ CSS animations

3. **Backend**
   - ✅ FastAPI server running
   - ✅ Task ID consistency fixed
   - ✅ State management
   - ✅ Progress tracking endpoints
   - ✅ Programmatic API working

### ❌ **What's Broken/Missing**

#### **Critical Blockers**
1. **Document Adapter Not Implemented**
   - Error: "Document parsing not yet implemented"
   - Status: Adapter exists but `adapt()` method not implemented
   - Impact: Can't parse README/Markdown files

2. **YouTube Adapter Not Implemented**
   - Likely same issue as document
   - Impact: Can't parse YouTube videos

3. **Voice Arrays Not Passed to Backend**
   - Frontend sends `voices: ['male', 'female']`
   - Backend models expect single `voice: str`
   - Impact: Multi-voice feature doesn't work

#### **Missing Features**
1. **Per-Language Voice Selection**
   - Can select languages, but can't assign different voices per language
   - Example: EN = Andrew, ES = male_spanish, FR = female_french
   - UI component not implemented

2. **Scene Content Editing (Manual Mode)**
   - Can configure videos but can't add/edit scene content
   - Need mini scene builder or content textarea
   - Link to /builder exists but no inline editing

3. **Voice Previewing**
   - Can't listen to voice samples before selecting
   - Would improve UX significantly

4. **Batch Scene Operations**
   - No bulk editing for video sets
   - Apply same scenes to multiple videos

5. **Progress Page Issues**
   - SSE errors when task fails
   - No detailed error display
   - Missing retry/restart options

---

## 🎯 Implementation Plan - Prioritized

### **Phase 1: Core Functionality (Critical)** 🔴

#### **1.1 Fix Document Adapter** (HIGH PRIORITY)
**File**: `app/input_adapters/document.py`
**Tasks**:
- [ ] Implement `adapt()` method
- [ ] Add markdown parsing logic
- [ ] Extract sections as scenes
- [ ] Handle GitHub URL fetching
- [ ] Create scene types from content structure
- [ ] Return proper VideoSet structure

**Acceptance**:
- Can paste README.md → generates videos
- Can input GitHub URL → fetches and parses
- Auto-detects video count from sections

---

#### **1.2 Fix YouTube Adapter** (HIGH PRIORITY)
**File**: `app/input_adapters/youtube.py`
**Tasks**:
- [ ] Implement `adapt()` method
- [ ] Integrate YouTube transcript API
- [ ] Parse transcript into scenes
- [ ] Handle playlists (multiple videos)
- [ ] Time-based scene splitting
- [ ] Return VideoSet structure

**Acceptance**:
- Single video URL → transcript → scenes
- Playlist URL → multiple videos
- Auto-timing based on transcript timestamps

---

#### **1.3 Fix Voice Array Handling** (HIGH PRIORITY)
**Files**: `app/main.py`, backend models
**Tasks**:
- [ ] Update Video model to accept `voices: List[str]` instead of `voice: str`
- [ ] Update scene generation to handle voice arrays
- [ ] Implement voice rotation/alternation logic
- [ ] Pass voice arrays through pipeline
- [ ] Update audio generation to support multiple voices

**Acceptance**:
- Can configure Video 1 with [Andrew, Aria]
- Backend receives and processes voice arrays
- Audio generated with alternating voices

---

### **Phase 2: Per-Language Voice Selection** 🟡

#### **2.1 UI Component for Language-Voice Mapping**
**File**: `app/templates/create.html`
**Tasks**:
- [ ] Add voice selection dropdown per language
- [ ] Show when multilingual toggle is ON
- [ ] Auto-populate with language-appropriate voices
- [ ] Store as `{ en: 'male', es: 'male_spanish', fr: 'female_french' }`
- [ ] Display in summary

**UI Design**:
```
🌍 Multilingual Settings
Target Languages (3 selected):
┌────────────────────────────────────┐
│ EN  English    ▼ Andrew (Male)     │
│ ES  Español    ▼ Jorge (Male)      │
│ FR  Français   ▼ Amélie (Female)   │
└────────────────────────────────────┘
```

**Acceptance**:
- Each language has independent voice selection
- Defaults to best voice for that language
- Shows language name + local name
- Visual indication of selected voices

---

#### **2.2 Backend Support for Language-Voice Mapping**
**Files**: `app/main.py`, translation service
**Tasks**:
- [ ] Update MultilingualRequest model
- [ ] Pass language-voice mapping to translation service
- [ ] Generate audio with correct voice per language
- [ ] Maintain voice consistency across translated videos

**Acceptance**:
- API accepts `language_voices: {en: 'male', es: 'male_spanish'}`
- Each language version uses specified voice
- Voice metadata stored in task state

---

### **Phase 3: Scene Content Editing** 🟡

#### **3.1 Inline Scene Builder for Manual Mode**
**File**: `app/templates/create.html`
**Tasks**:
- [ ] Add collapsible "Scene Content" panel
- [ ] Quick scene type buttons (Title, Code, List, Outro)
- [ ] Simple form fields per scene type
- [ ] Scene preview
- [ ] Drag-and-drop reordering

**UI Design**:
```
🎬 Per-Video Settings
├─ Video 1: "Introduction"
│  ├─ Voices: [Andrew]
│  ├─ Duration: 60s
│  └─ 📝 Scenes (3) [Expand]
│     ├─ 🎬 Title: "Welcome"
│     ├─ 📋 List: 3 bullet points
│     └─ ✅ Outro: "Let's begin!"
```

**Acceptance**:
- Can add/edit/remove scenes per video
- Scene data passed to backend
- Works with multi-voice (assigns voices to scenes)

---

#### **3.2 Connect to Advanced Builder**
**Tasks**:
- [ ] "Edit in Advanced Builder" button per video
- [ ] Pass video config to builder
- [ ] Return from builder to Quick Start
- [ ] Preserve multilingual settings

---

### **Phase 4: Enhanced UX Features** 🟢

#### **4.1 Voice Preview System**
**Tasks**:
- [ ] Add "🔊 Preview" button next to each voice dropdown
- [ ] Play 3-5 second sample for each voice
- [ ] Use Web Audio API or embedded samples
- [ ] Cache audio samples

**UI**:
```
Voice Tracks:
Track 1: ▼ Andrew (Male)  [🔊 Preview]
```

---

#### **4.2 Better Progress Tracking**
**File**: `app/templates/progress.html`
**Tasks**:
- [ ] Show which stage is currently running
- [ ] Display per-video progress in sets
- [ ] Show per-language progress
- [ ] Add retry button for failed tasks
- [ ] Download links when complete
- [ ] Error details in expandable panel

---

#### **4.3 Template Library**
**Tasks**:
- [ ] Save custom configurations as templates
- [ ] Template browser/gallery
- [ ] Import/export templates (JSON)
- [ ] Community template sharing

---

#### **4.4 Batch Operations**
**Tasks**:
- [ ] "Apply to All" for voice selection
- [ ] "Apply to All" for duration
- [ ] Copy settings from Video 1 → All videos
- [ ] Bulk scene generation

---

### **Phase 5: Backend Improvements** 🟢

#### **5.1 Implement YAML Adapter**
- [ ] Parse YAML structure
- [ ] Validate schema
- [ ] Convert to VideoSet

#### **5.2 Scene-to-Voice Mapping**
- [ ] Assign voices to scenes based on content
- [ ] Rotation strategy for multi-voice
- [ ] Speaker attribution in dialogues

#### **5.3 AI Enhancement Integration**
- [ ] Hook up `useAI` flag to Claude API
- [ ] Enhanced narration generation
- [ ] Better scene descriptions

---

## 📋 Detailed Task Breakdown

### **Task 1: Fix Document Adapter**
**Priority**: 🔴 CRITICAL
**Estimated Time**: 2-3 hours
**Files**:
- `app/input_adapters/document.py`
- `video_gen/stages/input_stage.py`

**Steps**:
1. Implement markdown parsing (sections → videos)
2. Add GitHub API integration for URL fetching
3. Map markdown structure to scene types
4. Handle headings, code blocks, lists
5. Set appropriate durations based on content length
6. Test with sample README files

**Acceptance Criteria**:
- ✅ Can parse local .md files
- ✅ Can fetch from GitHub URLs
- ✅ Auto-generates video structure
- ✅ Creates appropriate scene types

---

### **Task 2: Add Per-Language Voice Selection**
**Priority**: 🟡 HIGH
**Estimated Time**: 2 hours
**Files**:
- `app/templates/create.html`
- `app/main.py`

**Steps**:
1. Add voice dropdown per selected language
2. Store as `language_voices: {en: 'male', es: 'male_spanish'}`
3. Update API to accept language-voice mapping
4. Display in summary (e.g., "3 languages, 3 voices")
5. Default to best voice for each language

**UI Component**:
```html
<div x-show="multilingual">
  <label>Voice per Language</label>
  <template x-for="lang in targetLanguages">
    <div class="flex items-center gap-2">
      <span x-text="lang.toUpperCase()"></span>
      <select x-model="languageVoices[lang]">
        <option v-for="voice in getVoicesForLang(lang)">
      </select>
    </div>
  </template>
</div>
```

**Acceptance Criteria**:
- ✅ Voice dropdown appears for each selected language
- ✅ Auto-populates with language-appropriate voices
- ✅ Stores mapping correctly
- ✅ Passes to backend API
- ✅ Shows in summary

---

### **Task 3: Fix Voice Array Handling**
**Priority**: 🔴 CRITICAL
**Estimated Time**: 1-2 hours
**Files**:
- `app/models.py`
- `video_gen/shared/models.py`
- `video_gen/stages/audio_stage.py`

**Steps**:
1. Update Video Pydantic model:
   ```python
   class Video(BaseModel):
       voices: List[str]  # Instead of voice: str
   ```
2. Update scene voice assignment logic
3. Implement voice rotation in audio generation
4. Test with 2+ voices per video

**Acceptance Criteria**:
- ✅ Can send `voices: ['male', 'female', 'male_warm']`
- ✅ Backend accepts and stores voice arrays
- ✅ Audio stage uses correct voice per scene
- ✅ Rotation/alternation strategy works

---

### **Task 4: Add Scene Content Editing**
**Priority**: 🟡 HIGH
**Estimated Time**: 3-4 hours
**Files**:
- `app/templates/create.html`
- New: `app/static/scene-editor.js`

**Steps**:
1. Add "📝 Edit Scenes" collapsible panel per video
2. Scene type selector (Title, Code, List, etc.)
3. Dynamic form fields based on scene type
4. Scene preview
5. Save scenes to video config
6. Pass to backend API

**UI Component**:
```
Video 1: "Introduction"
├─ Voices: [Andrew, Aria]
├─ Duration: 60s
└─ 📝 Scenes (3) [Expand]
   ├─ Scene 1: 🎬 Title
   │  └─ Title: "Welcome", Subtitle: "Let's start"
   ├─ Scene 2: 📋 List
   │  └─ Items: [Point 1, Point 2, Point 3]
   └─ Scene 3: ✅ Outro
      └─ CTA: "Subscribe for more!"
```

**Acceptance Criteria**:
- ✅ Can add/remove scenes
- ✅ Form adapts to scene type
- ✅ Scene data included in API payload
- ✅ Works with all input methods

---

### **Task 5: Enhance Progress Page**
**Priority**: 🟡 MEDIUM
**Estimated Time**: 1-2 hours
**Files**:
- `app/templates/progress.html`
- `app/main.py`

**Steps**:
1. Show current pipeline stage
2. Display detailed errors in expandable panel
3. Add retry button
4. Show output file paths when complete
5. Add download links
6. Improve SSE error handling

**UI Enhancements**:
```
⚡ Video Generation Progress

Status: PROCESSING  [✓ Input] [⏳ Parsing] [ Audio] [ Video]

Progress: ████████░░ 45%

Current Stage: Content Parsing
  ├─ Analyzing document structure...
  └─ 3 videos detected

Languages:
[✅ EN] [⏳ ES] [⏳ FR]

[If Error]:
❌ Error Details [Expand]
└─ Document parsing failed: Invalid markdown format
   Suggestion: Check file encoding
   [🔄 Retry]  [🏠 Back to Home]
```

---

## 🚀 Recommended Implementation Order

### **Sprint 1: Make It Work** (Days 1-2)
1. ✅ UI flow complete (DONE)
2. 🔴 **Fix document adapter** (CRITICAL)
3. 🔴 **Fix voice array handling** (CRITICAL)
4. 🔴 **Fix YouTube adapter** (CRITICAL)

**Goal**: Basic flow works end-to-end with manual + programmatic input

---

### **Sprint 2: Full Feature Parity** (Days 3-4)
1. 🟡 **Per-language voice selection**
2. 🟡 **Scene content editing**
3. 🟡 **Progress page improvements**

**Goal**: All UI features have backend support

---

### **Sprint 3: Polish & UX** (Days 5-6)
1. 🟢 Voice preview/testing
2. 🟢 Template save/load
3. 🟢 Batch operations
4. 🟢 Better error messages
5. 🟢 Keyboard shortcuts
6. 🟢 Mobile responsive improvements

**Goal**: Professional, polished user experience

---

## 📝 Detailed Implementation Specs

### **Spec: Per-Language Voice Selection**

**Frontend State**:
```javascript
multilingual: {
    enabled: true,
    sourceLanguage: 'en',
    targetLanguages: ['en', 'es', 'fr'],
    languageVoices: {
        en: 'male',
        es: 'male_spanish',
        fr: 'female_french'
    },
    translationMethod: 'claude'
}
```

**UI Component**:
```html
<div x-show="single.multilingual" class="mt-4">
  <h4>🎙️ Voice per Language</h4>
  <div class="space-y-2">
    <template x-for="lang in single.targetLanguages" :key="lang">
      <div class="flex items-center gap-3 p-2 bg-white border rounded">
        <span class="font-mono text-sm w-12" x-text="lang.toUpperCase()"></span>
        <span class="text-sm text-gray-600 w-32" x-text="getLanguageName(lang)"></span>
        <select x-model="single.languageVoices[lang]"
                class="flex-1 px-3 py-2 border rounded">
          <template x-for="voice in getVoicesForLang(lang)">
            <option :value="voice.id" x-text="voice.name"></option>
          </template>
        </select>
        <button @click="previewVoice(lang, single.languageVoices[lang])"
                class="text-sm bg-gray-100 hover:bg-gray-200 px-2 py-1 rounded">
          🔊 Preview
        </button>
      </div>
    </template>
  </div>
</div>
```

**Backend Changes**:
```python
class MultilingualRequest(BaseModel):
    video_set: VideoSet
    target_languages: List[str]
    source_language: str = "en"
    translation_method: Literal["claude", "google"] = "claude"
    language_voices: Optional[Dict[str, str]] = None  # NEW!

# In generate_multilingual():
for lang in request.target_languages:
    voice = request.language_voices.get(lang, get_default_voice(lang))
    # Use this voice for this language version
```

---

### **Spec: Scene Content Editing**

**Frontend State** (per video):
```javascript
videos: [{
    title: 'Video 1',
    voices: ['male', 'female'],
    duration: 60,
    scenes: [  // NEW!
        {
            type: 'title',
            title: 'Welcome',
            subtitle: 'Introduction to the Course'
        },
        {
            type: 'list',
            title: 'What You'll Learn',
            items: ['Topic 1', 'Topic 2', 'Topic 3']
        },
        {
            type: 'outro',
            message: 'Let's get started!',
            cta: 'Continue to next video'
        }
    ]
}]
```

**UI Component**:
```html
<div class="mt-4 border-t pt-4">
  <button @click="video.showScenes = !video.showScenes">
    📝 Edit Scenes (<span x-text="video.scenes.length"></span>)
  </button>

  <div x-show="video.showScenes" x-collapse>
    <!-- Scene Type Buttons -->
    <div class="grid grid-cols-6 gap-2 mb-3">
      <button @click="addScene(vIdx, 'title')">🎬 Title</button>
      <button @click="addScene(vIdx, 'command')">💻 Code</button>
      <button @click="addScene(vIdx, 'list')">📋 List</button>
      <!-- ... more scene types ... -->
    </div>

    <!-- Scene List -->
    <div class="space-y-2">
      <template x-for="(scene, sIdx) in video.scenes" :key="sIdx">
        <div class="p-3 border rounded">
          <div class="flex justify-between mb-2">
            <span>#<span x-text="sIdx+1"></span> <span x-text="getSceneIcon(scene.type)"></span></span>
            <button @click="removeScene(vIdx, sIdx)">×</button>
          </div>

          <!-- Dynamic form based on scene.type -->
          <div x-show="scene.type === 'title'">
            <input x-model="scene.title" placeholder="Title">
            <input x-model="scene.subtitle" placeholder="Subtitle">
          </div>

          <div x-show="scene.type === 'list'">
            <input x-model="scene.title" placeholder="Title">
            <textarea x-model="scene.items" rows="3" placeholder="Items (one per line)"></textarea>
          </div>

          <!-- ... other scene types ... -->
        </div>
      </template>
    </div>
  </div>
</div>
```

---

### **Spec: Voice Previewing**

**Implementation**:
```javascript
// Add to videoCreator()
voiceSamples: {
    male: '/static/samples/andrew.mp3',
    male_warm: '/static/samples/brandon.mp3',
    female: '/static/samples/aria.mp3',
    female_friendly: '/static/samples/ava.mp3'
},

previewVoice(voiceId) {
    const audio = new Audio(this.voiceSamples[voiceId]);
    audio.play();
}
```

**UI**:
- Small speaker icon next to each voice selection
- Plays 3-5 second sample
- Visual indicator while playing

---

## 🔧 Technical Architecture

### **Data Flow**

```
Frontend (Alpine.js)
    ↓
{
  mode: 'set',
  inputMethod: 'document',
  documentPath: 'README.md',
  videoCount: 5,  // Override
  videos: [
    {
      title: 'Video 1',
      voices: ['male', 'female'],  // Array!
      duration: 60,
      scenes: [...]  // Optional
    },
    ...
  ],
  multilingual: true,
  targetLanguages: ['en', 'es', 'fr'],
  languageVoices: {  // NEW!
    en: 'male',
    es: 'male_spanish',
    fr: 'female_french'
  }
}
    ↓
FastAPI Backend
    ↓
Pipeline (InputConfig)
    ↓
Document Adapter → VideoSet
    ↓
For each language:
  For each video:
    For each scene:
      Assign voice from rotation
      Generate audio with correct voice
      Create video frame
    ↓
Output: N videos × M languages
```

---

## ⚠️ Known Issues to Address

1. **Task ID mismatch**: Fixed ✅
2. **Progress page crashes**: Fixed ✅
3. **Document adapter not implemented**: TO DO 🔴
4. **Voice arrays not supported**: TO DO 🔴
5. **Per-language voices missing**: TO DO 🟡
6. **Scene editing missing**: TO DO 🟡
7. **Tailwind CDN warning**: TO DO 🟢 (use PostCSS build)

---

## 🎯 Success Metrics

When complete, users should be able to:

**Scenario 1**: "Create a course from my GitHub README in 3 languages"
- ✅ Paste GitHub URL
- ✅ Override video count (e.g., 5 videos)
- ✅ Customize each video (titles, voices, durations)
- ✅ Set EN=Andrew, ES=Jorge, FR=Amélie
- ✅ Generate → 15 videos created
- ✅ Track progress in real-time
- ✅ Download when complete

**Scenario 2**: "Make a multi-voice interview series"
- ✅ Manual mode, 3 videos
- ✅ Video 1: 2 voices (Andrew, Aria) - conversation
- ✅ Video 2: 3 voices (Andrew, Aria, Brandon) - panel discussion
- ✅ Video 3: 1 voice (Andrew) - conclusion
- ✅ Edit scenes with dialogue
- ✅ Preview voices before selecting
- ✅ Generate

---

## 📦 Files to Modify

### **Backend** (Critical)
- [ ] `app/input_adapters/document.py` - Implement adapter
- [ ] `app/input_adapters/youtube.py` - Implement adapter
- [ ] `app/models.py` - Support voice arrays
- [ ] `app/main.py` - Handle language-voice mapping
- [ ] `video_gen/shared/models.py` - Voice array support
- [ ] `video_gen/stages/audio_stage.py` - Multi-voice generation

### **Frontend** (High Priority)
- [ ] `app/templates/create.html` - Per-language voice UI
- [ ] `app/templates/create.html` - Scene editor component
- [ ] `app/templates/progress.html` - Better error display
- [ ] `app/static/scene-editor.js` - NEW file for scene management

### **Polish** (Medium Priority)
- [ ] Add voice sample audio files
- [ ] Template save/load system
- [ ] Build Tailwind production CSS
- [ ] Add keyboard shortcuts

---

## 🎓 Next Steps

**Immediate (Today)**:
1. Implement document adapter
2. Fix voice array backend support
3. Add per-language voice selection UI

**This Week**:
4. Implement scene content editing
5. Improve progress page
6. Add voice previewing

**Next Week**:
7. Template library
8. Batch operations
9. Polish and testing

---

**Status**: 📋 **Plan Complete - Ready for Implementation**
**Created**: 2025-10-05
**Priority**: Document adapter + Voice arrays (CRITICAL)
