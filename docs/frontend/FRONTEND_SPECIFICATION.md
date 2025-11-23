# Frontend Specification - SPARC Phase S

**Date:** November 22, 2025
**Version:** 1.0.0
**Status:** Specification Complete
**Author:** Architecture Agent

---

## 1. Executive Summary

This specification documents the current frontend architecture of the video_gen system and defines the requirements for modernization. The goal is to enhance the existing Alpine.js-based frontend with improved components for drag-drop uploads, real-time validation, preview panels, and multi-language support.

**Key Decision:** Enhance Alpine.js architecture (NOT migrate to React). The current stack (Alpine.js + TailwindCSS + HTMX) is well-suited for this application's needs.

---

## 2. Current Architecture Analysis

### 2.1 Technology Stack

| Layer | Technology | Version | Purpose |
|-------|------------|---------|---------|
| Framework | Alpine.js | 3.13.5 | Reactive components |
| Styling | TailwindCSS | CDN | Utility-first CSS |
| Templates | Jinja2/Flask | - | Server-side rendering |
| HTTP | HTMX | 1.9.10 | Partial page updates |
| State | Alpine.js $store | - | Global state management |

### 2.2 Current File Structure

```
app/
├── templates/
│   ├── base.html                    # Base layout (header, nav, footer)
│   ├── home.html                    # Landing page with 4 input method cards
│   ├── create-unified.html          # Main unified creator (942 lines)
│   ├── builder.html                 # Scene-by-scene builder
│   ├── advanced.html                # Advanced configuration
│   ├── progress.html                # Job progress tracking
│   └── components/
│       ├── document-form.html       # Document input form
│       ├── youtube-form.html        # YouTube URL form
│       ├── video-config.html        # Video configuration
│       ├── language-selector.html   # Language selection
│       ├── preset-cards.html        # Preset packages
│       └── ...
│
├── static/
│   ├── js/
│   │   ├── store/
│   │   │   └── app-state.js         # Global Alpine.js store (346 lines)
│   │   ├── validation.js            # Form validation (354 lines)
│   │   ├── cost-estimator.js        # Cost estimation (257 lines)
│   │   ├── presets.js               # Preset packages (263 lines)
│   │   ├── smart-defaults.js        # Smart defaults logic
│   │   └── p1-enhancements.js       # P1 week 2 enhancements
│   │
│   ├── css/
│   │   ├── style.css                # Main styles
│   │   ├── presets.css              # Preset card styles
│   │   └── components.css           # Component styles
│   │
│   └── voice-preview.js             # Voice preview functionality
```

### 2.3 Current Component Analysis

#### 2.3.1 unifiedCreator() Component (create-unified.html)

**Location:** `/app/templates/create-unified.html` (lines 464-939)

**State Properties:**
```javascript
{
  // Step Management
  currentStep: 1,                    // 1-4 wizard steps
  steps: [{title, subtitle}],        // Step metadata

  // Input Data
  inputType: 'url',                  // 'url' | 'file' | 'text'
  inputMethod: null,                 // 'document' | 'youtube' | 'yaml'
  inputData: {
    url: '',
    file: null,
    fileName: '',
    fileContent: '',                 // Actual file content
    text: ''
  },
  inputError: '',
  isReadingFile: false,

  // Configuration
  config: {
    videoId: '',
    duration: 120,
    languageMode: 'single',          // 'single' | 'multiple'
    targetLanguages: ['en'],
    primaryVoice: 'en-US-JennyNeural',
    color: 'blue',
    useAI: false
  },
  configErrors: {},
  selectedPreset: null,

  // Available Options
  availableLanguages: [{code, name}],

  // Cost Estimation
  costEstimate: {total, breakdown},

  // Generation State
  generationStarted: false,
  generationProgress: 0,
  generationStatus: 'Initializing...',
  generationComplete: false,
  generatedJobId: null
}
```

**Methods:**
| Method | Purpose | Lines |
|--------|---------|-------|
| `init()` | Initialize component, parse URL params | 522-557 |
| `nextStep()` | Advance wizard step | 559-566 |
| `previousStep()` | Go back one step | 568-572 |
| `isStepValid(step)` | Validate current step | 574-585 |
| `hasValidInput()` | Check input completeness | 587-602 |
| `validateInput()` | Validate input data | 604-615 |
| `validateConfig()` | Validate configuration | 617-626 |
| `handleFileUpload(event)` | Process file uploads | 628-702 |
| `readFileAsText(file)` | Read file as text | 705-711 |
| `readFileAsBase64(file)` | Read binary files | 714-726 |
| `isValidYamlSyntax(content)` | Basic YAML validation | 729-747 |
| `applyPreset(presetId)` | Apply preset config | 749-769 |
| `updateCostEstimate()` | Calculate costs | 771-783 |
| `startGeneration()` | Begin video generation | 785-877 |
| `pollJobStatus(taskId)` | Poll for completion | 879-913 |
| `reset()` | Reset to initial state | 915-937 |

#### 2.3.2 Alpine.js Global Store (app-state.js)

**Purpose:** Centralized state management with localStorage persistence

**Key Features:**
- Step tracking (1-4)
- Input method state per type
- Video configuration
- Generation progress stages
- Validation state
- UI preferences
- Auto-save to localStorage

#### 2.3.3 FormValidator Class (validation.js)

**Validators:**
- `video_id` - Alphanumeric with hyphens/underscores
- `url` - Generic HTTP/HTTPS URL
- `youtube_url` - YouTube URL patterns
- `file_path` - Cross-platform file paths
- `duration` - 10-600 seconds
- `video_count` - 1-20 videos

**Security Features:**
- Safe regex matching (ReDoS protection)
- Path traversal prevention
- Null byte detection
- XSS prevention (textContent, not innerHTML)
- ARIA accessibility attributes

#### 2.3.4 CostEstimator Class (cost-estimator.js)

**Pricing Model:**
- Input tokens: $3.00 per million
- Output tokens: $15.00 per million
- TTS: FREE (Edge-TTS)

**Estimation Methods:**
- Per-scene narration cost
- Per-scene translation cost
- Total video set cost
- Optimization tips generation

---

## 3. Requirements Specification

### 3.1 Functional Requirements

#### FR-1: Drag-Drop File Upload
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-1.1 | Support drag-drop zone with visual feedback | HIGH |
| FR-1.2 | Validate file types (.md, .txt, .pdf, .docx, .yaml, .yml) | HIGH |
| FR-1.3 | Validate file size (10MB for docs, 1MB for YAML) | HIGH |
| FR-1.4 | Show upload progress indicator | MEDIUM |
| FR-1.5 | Display file preview after upload | HIGH |
| FR-1.6 | Support click-to-browse fallback | HIGH |

#### FR-2: Real-Time Validation
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-2.1 | Debounced validation (500ms) as user types | HIGH |
| FR-2.2 | Visual feedback (green/red borders) | HIGH |
| FR-2.3 | Inline error messages with suggestions | HIGH |
| FR-2.4 | Success animations on valid input | LOW |
| FR-2.5 | ARIA accessibility support | HIGH |

#### FR-3: Preview Panel
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-3.1 | Show document structure (headings, sections) | HIGH |
| FR-3.2 | Display estimated scenes and duration | HIGH |
| FR-3.3 | Show YouTube video metadata (title, thumbnail) | HIGH |
| FR-3.4 | Display content recommendations | MEDIUM |
| FR-3.5 | Collapsible sections for long content | MEDIUM |

#### FR-4: Video Configuration
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.1 | Single video vs video set mode selection | HIGH |
| FR-4.2 | Multi-language selection (28+ languages) | HIGH |
| FR-4.3 | Multiple voices per language selection | HIGH |
| FR-4.4 | Voice preview playback | MEDIUM |
| FR-4.5 | Preset packages (Corporate, Creative, Educational) | HIGH |
| FR-4.6 | AI narration always enabled (no toggle) | HIGH |

#### FR-5: Progress Tracking
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-5.1 | Multi-stage progress bar | HIGH |
| FR-5.2 | Stage-specific status messages | HIGH |
| FR-5.3 | Real-time progress updates (SSE) | MEDIUM |
| FR-5.4 | Cancel operation support | LOW |
| FR-5.5 | Time remaining estimation | LOW |

### 3.2 Non-Functional Requirements

#### NFR-1: Performance
| ID | Requirement | Target |
|----|-------------|--------|
| NFR-1.1 | UI response time | < 100ms |
| NFR-1.2 | File upload initiation | < 500ms |
| NFR-1.3 | Validation feedback | < 300ms |
| NFR-1.4 | Page load time | < 2s |

#### NFR-2: Accessibility
| ID | Requirement | Standard |
|----|-------------|----------|
| NFR-2.1 | WCAG compliance | Level AA |
| NFR-2.2 | Screen reader support | Full |
| NFR-2.3 | Keyboard navigation | Complete |
| NFR-2.4 | Focus management | Proper |

#### NFR-3: Browser Support
| Browser | Version |
|---------|---------|
| Chrome | 90+ |
| Firefox | 88+ |
| Safari | 14+ |
| Edge | 90+ |

---

## 4. Migration Strategy

### 4.1 Approach: In-Place Enhancement

**Decision:** Enhance existing Alpine.js components rather than rewrite in React

**Rationale:**
1. Current architecture is sound and maintainable
2. Alpine.js + TailwindCSS combination works well
3. Minimal risk compared to full rewrite
4. Team familiarity with current stack
5. No build toolchain complexity

### 4.2 Enhancement Phases

```
Phase 1: DragDropZone Component
├── Create standalone Alpine component
├── Integrate with existing file upload
├── Add visual feedback states
└── Connect to validation API

Phase 2: ValidationFeedback Component
├── Extract validation logic to component
├── Add real-time feedback UI
├── Integrate with FormValidator class
└── Add ARIA attributes

Phase 3: PreviewPanel Component
├── Create collapsible preview UI
├── Connect to preview APIs
├── Handle document + YouTube previews
└── Add loading states

Phase 4: Enhanced Configuration
├── Add VideoModeSelector
├── Enhance MultiLanguageSelector
├── Add MultiVoiceSelector
├── Remove AI toggle (always on)
└── Update preset application

Phase 5: ProgressIndicator Component
├── Create multi-stage progress UI
├── Connect to SSE stream
├── Add cancel functionality
└── Add time estimation
```

### 4.3 Reusable Patterns

#### Pattern 1: Alpine Component Template
```javascript
function componentName() {
  return {
    // State
    state: initialValue,

    // Computed (use getters)
    get computedValue() {
      return this.state.transform();
    },

    // Methods
    init() {
      // Initialize component
    },

    handleEvent() {
      // Event handlers
    },

    async fetchData() {
      // API calls
    }
  };
}
```

#### Pattern 2: Event-Based Communication
```javascript
// Emit custom event
window.dispatchEvent(new CustomEvent('event-name', {
  detail: { data }
}));

// Listen for event
@event-name.window="handleEvent($event.detail)"
```

#### Pattern 3: Store Integration
```javascript
// Read from store
$store.appState.currentStep

// Update store
$store.appState.goToStep(2)
```

---

## 5. API Integration Points

### 5.1 Existing Endpoints

| Endpoint | Method | Purpose | Status |
|----------|--------|---------|--------|
| `/api/parse/document` | POST | Parse document content | Active |
| `/api/parse/youtube` | POST | Parse YouTube URL | Active |
| `/api/parse/yaml` | POST | Parse YAML config | Active |
| `/api/tasks/{id}` | GET | Get task status | Active |
| `/api/health` | GET | Health check | Active |

### 5.2 New Endpoints Required

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/validate/document` | POST | Real-time document validation |
| `/api/validate/youtube` | POST | Real-time YouTube URL validation |
| `/api/preview/document` | POST | Generate document preview |
| `/api/preview/youtube` | POST | Generate YouTube preview |
| `/api/languages` | GET | List available languages |
| `/api/languages/{code}/voices` | GET | Get voices for language |
| `/api/tasks/{id}/stream` | GET | SSE progress stream |

---

## 6. Component Specifications

### 6.1 DragDropZone

**Purpose:** Handle file drag-drop with visual feedback

**Props:**
| Prop | Type | Default | Description |
|------|------|---------|-------------|
| accept | string | '.md,.txt' | Accepted file types |
| maxSize | number | 10485760 | Max file size (bytes) |
| multiple | boolean | false | Allow multiple files |

**Events:**
| Event | Payload | Description |
|-------|---------|-------------|
| file-selected | File | File selected/dropped |
| validation-error | {message, suggestion} | Validation failed |
| upload-progress | number | Upload progress 0-100 |

**States:**
- `idle` - Default state
- `drag-over` - File being dragged over zone
- `uploading` - File being uploaded
- `success` - Upload complete
- `error` - Upload/validation failed

### 6.2 ValidationFeedback

**Purpose:** Display real-time validation feedback

**Props:**
| Prop | Type | Default | Description |
|------|------|---------|-------------|
| fieldName | string | - | Field to validate |
| value | any | - | Current field value |
| showIcon | boolean | true | Show status icon |

**States:**
- `pristine` - Not yet validated
- `validating` - Validation in progress
- `valid` - Validation passed
- `invalid` - Validation failed
- `warning` - Non-blocking warning

### 6.3 PreviewPanel

**Purpose:** Display content preview before generation

**Props:**
| Prop | Type | Default | Description |
|------|------|---------|-------------|
| type | string | - | 'document' or 'youtube' |
| preview | object | null | Preview data |
| collapsed | boolean | false | Initial collapse state |

**Slots:**
- `header` - Custom header content
- `footer` - Custom footer content

### 6.4 VideoModeSelector

**Purpose:** Select between single video and video set

**Props:**
| Prop | Type | Default | Description |
|------|------|---------|-------------|
| mode | string | 'single' | Current mode |
| videoCount | number | 1 | Number of videos (for set) |

**Events:**
| Event | Payload | Description |
|-------|---------|-------------|
| mode-changed | string | Mode changed |
| count-changed | number | Video count changed |

### 6.5 MultiLanguageSelector

**Purpose:** Select multiple target languages

**Props:**
| Prop | Type | Default | Description |
|------|------|---------|-------------|
| selected | array | ['en'] | Selected language codes |
| max | number | 10 | Max selections |

**Events:**
| Event | Payload | Description |
|-------|---------|-------------|
| selection-changed | array | Selected languages |

### 6.6 MultiVoiceSelector

**Purpose:** Select voices per language

**Props:**
| Prop | Type | Default | Description |
|------|------|---------|-------------|
| language | string | - | Language code |
| selected | array | [] | Selected voice IDs |

**Events:**
| Event | Payload | Description |
|-------|---------|-------------|
| voices-changed | {lang, voices} | Voice selection changed |
| preview-voice | {lang, voice} | Preview requested |

### 6.7 ProgressIndicator

**Purpose:** Display multi-stage generation progress

**Props:**
| Prop | Type | Default | Description |
|------|------|---------|-------------|
| taskId | string | - | Task ID to monitor |
| stages | array | [] | Stage definitions |
| autoStart | boolean | true | Start monitoring on mount |

**Events:**
| Event | Payload | Description |
|-------|---------|-------------|
| stage-changed | {stage, progress} | Stage updated |
| complete | object | Generation complete |
| error | object | Generation failed |

---

## 7. Data Flow Diagrams

### 7.1 File Upload Flow

```
User drops file
      |
      v
[DragDropZone] ---> [ValidationFeedback]
      |                    |
      |                    v
      |            Display error or success
      |
      v
Read file content
      |
      v
POST /api/validate/document
      |
      v
[PreviewPanel] <--- Preview data
      |
      v
Store in $store.appState.formData
```

### 7.2 Generation Flow

```
User clicks Generate
      |
      v
Collect config from $store
      |
      v
POST /api/parse/{type}
      |
      v
Receive task_id
      |
      v
[ProgressIndicator] ---> SSE /api/tasks/{id}/stream
      |                          |
      |                          v
      |                  Update progress UI
      |
      v
Navigate to /progress#{task_id}
```

---

## 8. Acceptance Criteria

### AC-1: DragDropZone
- [ ] User can drag files onto drop zone
- [ ] Visual feedback on drag-over
- [ ] Invalid files show error message
- [ ] Valid files show preview
- [ ] Click-to-browse works as fallback

### AC-2: ValidationFeedback
- [ ] Validation triggers on input (debounced)
- [ ] Error messages show inline
- [ ] Success shows green border/checkmark
- [ ] Screen readers announce changes

### AC-3: PreviewPanel
- [ ] Document preview shows sections
- [ ] YouTube preview shows thumbnail
- [ ] Sections are collapsible
- [ ] Loading state shown during fetch

### AC-4: Configuration
- [ ] Mode toggle works (single/set)
- [ ] Language selection updates voices
- [ ] Voice preview plays audio
- [ ] Presets apply correctly

### AC-5: Progress
- [ ] Progress bar updates in real-time
- [ ] Stage messages are accurate
- [ ] Cancel button stops generation
- [ ] Completion navigates to results

---

## 9. Appendices

### A. Supported File Types

| Type | Extensions | Max Size |
|------|------------|----------|
| Text | .txt, .md, .markdown | 10MB |
| Document | .pdf, .docx | 10MB |
| Config | .yaml, .yml | 1MB |

### B. Available Languages (28+)

English, Spanish, French, German, Italian, Portuguese, Dutch, Russian, Japanese, Chinese, Korean, Arabic, Hindi, Turkish, Polish, Swedish, Norwegian, Danish, Finnish, Greek, Hebrew, Thai, Vietnamese, Indonesian, Malay, Filipino, Czech, and more.

### C. Voice Options Per Language

Each language supports 1-4 voices with variations:
- Male/Female
- Professional/Casual
- Warm/Clear tone

---

**Document Version:** 1.0.0
**Last Updated:** November 22, 2025
**Next Phase:** Pseudocode (COMPONENT_PSEUDOCODE.md)
