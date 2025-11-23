# Frontend Architecture - SPARC Phase A

**Date:** November 22, 2025
**Version:** 1.0.0
**Status:** Architecture Complete
**Author:** Architecture Agent

---

## 1. Executive Summary

This document defines the frontend architecture for the video_gen modernization project. The architecture enhances the existing Alpine.js + TailwindCSS stack with new modular components, centralized state management, and improved API integration patterns.

**Key Architecture Decisions:**
1. Enhance Alpine.js (not migrate to React)
2. Component-based architecture with clear boundaries
3. Centralized state via Alpine.js $store
4. Event-driven inter-component communication
5. Progressive enhancement for resilience

---

## 2. High-Level Architecture

```
+------------------------------------------------------------------+
|                         Browser Client                            |
+------------------------------------------------------------------+
|                                                                   |
|  +--------------------+  +--------------------+  +--------------+ |
|  |   Component Layer  |  |    State Layer    |  |  API Layer   | |
|  +--------------------+  +--------------------+  +--------------+ |
|  | DragDropZone       |  | Alpine.js $store  |  | api-client.js| |
|  | ValidationFeedback |  |   - dragDrop      |  |              | |
|  | PreviewPanel       |  |   - videoConfig   |  | Endpoints:   | |
|  | VideoModeSelector  |  |   - languages     |  | - validate   | |
|  | MultiLanguageSelector| |   - generation    |  | - preview    | |
|  | MultiVoiceSelector |  |   - ui            |  | - generate   | |
|  | ProgressIndicator  |  +--------------------+  | - languages  | |
|  +--------------------+           |              | - tasks      | |
|           |                       |              +--------------+ |
|           v                       v                     |         |
|  +--------------------+  +--------------------+         |         |
|  |   Template Layer   |  |   Utility Layer   |         |         |
|  +--------------------+  +--------------------+         |         |
|  | base.html          |  | FormValidator     |<--------+         |
|  | create-unified.html|  | CostEstimator     |                   |
|  | components/*.html  |  | Presets           |                   |
|  +--------------------+  +--------------------+                   |
|                                                                   |
+------------------------------------------------------------------+
                                   |
                                   | HTTP/SSE
                                   v
+------------------------------------------------------------------+
|                      Flask Backend (API)                          |
+------------------------------------------------------------------+
| /api/validate/*  | /api/preview/*  | /api/parse/*  | /api/tasks/* |
+------------------------------------------------------------------+
```

---

## 3. Component Architecture

### 3.1 Component Hierarchy

```
UnifiedCreator (Root)
|
+-- Header
|   +-- StepIndicator
|   +-- Navigation
|
+-- Step 1: Input
|   +-- InputTypeSelector
|   |   +-- DocumentInput
|   |   |   +-- DragDropZone [NEW]
|   |   |   +-- ValidationFeedback [NEW]
|   |   +-- YouTubeInput
|   |   |   +-- URLInput
|   |   |   +-- ValidationFeedback [NEW]
|   |   +-- TextInput
|   |   +-- YAMLInput
|   |       +-- DragDropZone [NEW]
|   |
|   +-- PreviewPanel [NEW]
|       +-- DocumentPreview
|       +-- YouTubePreview
|
+-- Step 2: Configure
|   +-- PresetSelector (existing, enhanced)
|   +-- VideoModeSelector [NEW]
|   +-- MultiLanguageSelector [NEW/ENHANCED]
|   +-- MultiVoiceSelector [NEW]
|   +-- ColorPicker (existing)
|   +-- DurationSlider (existing)
|
+-- Step 3: Review
|   +-- ConfigSummary (existing)
|   +-- CostEstimate (existing, enhanced)
|
+-- Step 4: Generate
    +-- ProgressIndicator [NEW]
    +-- ResultPanel
```

### 3.2 Component Responsibilities

| Component | Responsibility | State Owner |
|-----------|----------------|-------------|
| DragDropZone | File selection, validation | Local + Store |
| ValidationFeedback | Real-time validation display | Local |
| PreviewPanel | Content preview display | Store |
| VideoModeSelector | Single/Set mode toggle | Store |
| MultiLanguageSelector | Language selection | Store |
| MultiVoiceSelector | Voice selection per language | Store |
| ProgressIndicator | Generation progress | Local + Store |

### 3.3 Component Communication

```
+-------------------+     Custom Events      +-------------------+
|   DragDropZone    |  ------------------>   |   PreviewPanel    |
|                   |  'file-ready'          |                   |
+-------------------+                        +-------------------+
        |                                            |
        | $store.dragDrop.file                       | $store.dragDrop.preview
        v                                            v
+---------------------------------------------------------------+
|                     Alpine.js $store                           |
|   - dragDrop: { file, preview, status }                       |
|   - videoConfig: { mode, languages, voices }                  |
|   - generation: { taskId, progress, stage }                   |
+---------------------------------------------------------------+
        ^                                            ^
        |                                            |
+-------------------+                        +-------------------+
| MultiLanguage     |  $watch('languages')   | MultiVoiceSelector|
| Selector          |  <-----------------    |                   |
+-------------------+                        +-------------------+
```

---

## 4. State Management

### 4.1 Store Structure

```javascript
// /static/js/store/app-state.js

Alpine.store('appState', {
  // ========== WIZARD STATE ==========
  wizard: {
    currentStep: 1,           // 1-4
    maxStepReached: 1,
    stepHistory: [],          // For back navigation
    canProceed: false         // Computed validation
  },

  // ========== INPUT STATE ==========
  input: {
    method: null,             // 'document' | 'youtube' | 'yaml' | 'text'
    type: 'file',             // 'file' | 'url' | 'text'

    // File input
    file: {
      object: null,           // File object
      name: '',
      content: '',            // Read content
      type: '',               // 'text' | 'pdf' | 'docx'
      size: 0
    },

    // URL input
    url: '',

    // Text input
    text: '',

    // Validation
    validation: {
      status: 'idle',         // 'idle' | 'validating' | 'valid' | 'invalid'
      error: null,
      suggestion: null
    },

    // Preview
    preview: {
      loaded: false,
      data: null,
      error: null
    }
  },

  // ========== VIDEO CONFIG STATE ==========
  videoConfig: {
    // Basic
    videoId: '',
    title: '',

    // Mode
    mode: 'single',           // 'single' | 'set'
    videoCount: 1,            // For set mode

    // Languages
    languageMode: 'single',   // 'single' | 'multiple'
    targetLanguages: ['en'],

    // Voices (per language)
    languageVoices: {
      'en': ['en-US-JennyNeural']
    },

    // Styling
    accentColor: 'blue',

    // Duration
    duration: 120,            // seconds

    // AI (always true in new architecture)
    useAI: true,

    // Preset
    selectedPreset: null
  },

  // ========== GENERATION STATE ==========
  generation: {
    status: 'idle',           // 'idle' | 'starting' | 'running' | 'complete' | 'failed'
    taskId: null,
    progress: 0,              // 0-100
    currentStage: null,
    stages: [],
    startTime: null,
    error: null,
    result: null
  },

  // ========== UI STATE ==========
  ui: {
    notifications: [],
    modals: {
      voicePreview: false,
      presetSelector: false
    },
    loading: {
      languages: false,
      voices: false,
      preview: false
    }
  },

  // ========== METHODS ==========

  // Wizard navigation
  goToStep(step) { /* ... */ },
  nextStep() { /* ... */ },
  previousStep() { /* ... */ },
  canAdvanceToStep(step) { /* ... */ },

  // Input management
  setInputMethod(method) { /* ... */ },
  setFile(file) { /* ... */ },
  setURL(url) { /* ... */ },
  setText(text) { /* ... */ },
  clearInput() { /* ... */ },

  // Configuration
  setVideoMode(mode) { /* ... */ },
  setLanguages(languages) { /* ... */ },
  setVoices(langCode, voices) { /* ... */ },
  applyPreset(presetId) { /* ... */ },

  // Generation
  startGeneration() { /* ... */ },
  updateProgress(data) { /* ... */ },
  completeGeneration(result) { /* ... */ },
  failGeneration(error) { /* ... */ },

  // Persistence
  saveToStorage() { /* ... */ },
  loadFromStorage() { /* ... */ },
  clearStorage() { /* ... */ },

  // Notifications
  notify(type, message) { /* ... */ },
  clearNotifications() { /* ... */ }
});
```

### 4.2 State Persistence Strategy

```javascript
// Persisted to localStorage
const PERSISTED_KEYS = [
  'wizard.currentStep',
  'wizard.maxStepReached',
  'input.method',
  'input.file.name',      // Not content (too large)
  'input.url',
  'input.text',
  'videoConfig.*',        // All config
  'generation.taskId'     // For recovery
];

// Session-only (not persisted)
const SESSION_KEYS = [
  'input.file.object',
  'input.file.content',
  'input.preview.*',
  'generation.progress',
  'generation.stages',
  'ui.*'
];
```

### 4.3 State Watchers

```javascript
// Auto-validate on input changes
$watch('input.url', debounce(() => validateURL(), 500));
$watch('input.text', debounce(() => validateText(), 500));

// Auto-fetch voices when languages change
$watch('videoConfig.targetLanguages', (newLangs) => {
  newLangs.forEach(lang => {
    if (!availableVoices[lang]) {
      fetchVoicesForLanguage(lang);
    }
  });
});

// Auto-save on changes
$watch('videoConfig', () => saveToStorage());
$watch('wizard.currentStep', () => saveToStorage());
```

---

## 5. File Structure

### 5.1 Current Structure (Reference)

```
app/
├── static/
│   ├── js/
│   │   ├── store/
│   │   │   └── app-state.js          # Global store
│   │   ├── validation.js             # FormValidator
│   │   ├── cost-estimator.js         # CostEstimator
│   │   ├── presets.js                # Preset packages
│   │   ├── smart-defaults.js         # Smart defaults
│   │   └── p1-enhancements.js        # P1 enhancements
│   │
│   ├── css/
│   │   ├── style.css                 # Main styles
│   │   ├── presets.css               # Preset styles
│   │   └── components.css            # Component styles
│   │
│   └── voice-preview.js              # Voice preview
│
└── templates/
    ├── base.html                     # Base layout
    ├── home.html                     # Landing page
    ├── create-unified.html           # Main creator
    ├── builder.html                  # Scene builder
    └── components/                   # Partial templates
```

### 5.2 Enhanced Structure (Target)

```
app/
├── static/
│   ├── js/
│   │   ├── store/
│   │   │   ├── app-state.js          # Enhanced global store
│   │   │   └── persistence.js        # Storage utilities [NEW]
│   │   │
│   │   ├── components/               # [NEW DIRECTORY]
│   │   │   ├── drag-drop-zone.js     # DragDropZone component
│   │   │   ├── validation-feedback.js # ValidationFeedback component
│   │   │   ├── preview-panel.js      # PreviewPanel component
│   │   │   ├── video-mode-selector.js # VideoModeSelector component
│   │   │   ├── multi-language-selector.js # MultiLanguageSelector component
│   │   │   ├── multi-voice-selector.js # MultiVoiceSelector component
│   │   │   └── progress-indicator.js # ProgressIndicator component
│   │   │
│   │   ├── api/                      # [NEW DIRECTORY]
│   │   │   ├── client.js             # API client
│   │   │   └── sse.js                # SSE utilities
│   │   │
│   │   ├── utils/                    # [NEW DIRECTORY]
│   │   │   ├── debounce.js           # Debounce utility
│   │   │   ├── format.js             # Formatting utilities
│   │   │   └── error-handler.js      # Error handling
│   │   │
│   │   ├── validation.js             # Enhanced FormValidator
│   │   ├── cost-estimator.js         # Enhanced CostEstimator
│   │   ├── presets.js                # Preset packages
│   │   └── voice-preview.js          # Voice preview
│   │
│   └── css/
│       ├── style.css                 # Main styles
│       ├── components.css            # Enhanced component styles
│       └── animations.css            # [NEW] Animation styles
│
└── templates/
    ├── base.html                     # Enhanced base layout
    ├── home.html                     # Landing page
    ├── create-unified.html           # Enhanced main creator
    ├── builder.html                  # Scene builder
    └── components/
        ├── drag-drop-zone.html       # [NEW] DragDrop template
        ├── validation-feedback.html  # [NEW] Validation template
        ├── preview-panel.html        # [NEW] Preview template
        ├── video-mode-selector.html  # [NEW] Mode selector template
        ├── language-selector.html    # Enhanced language selector
        ├── voice-selector.html       # [NEW] Voice selector template
        └── progress-indicator.html   # [NEW] Progress template
```

---

## 6. API Integration Architecture

### 6.1 API Client Design

```javascript
// /static/js/api/client.js

const API = {
  baseURL: '',  // Same origin

  // Request helpers
  async _request(endpoint, options = {}) {
    const url = this.baseURL + endpoint;
    const defaults = {
      headers: {
        'Content-Type': 'application/json'
      }
    };

    const config = { ...defaults, ...options };

    try {
      const response = await fetch(url, config);

      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new APIError(
          error.detail || `HTTP ${response.status}`,
          response.status,
          error
        );
      }

      return await response.json();
    } catch (error) {
      if (error instanceof APIError) throw error;
      throw new APIError('Network error', 0, { original: error });
    }
  },

  async _formRequest(endpoint, formData) {
    return this._request(endpoint, {
      method: 'POST',
      headers: {},  // Let browser set Content-Type for FormData
      body: formData
    });
  },

  // Document APIs
  document: {
    async validate(file) {
      const formData = new FormData();
      formData.append('file', file);
      return API._formRequest('/api/validate/document', formData);
    },

    async preview(file) {
      const formData = new FormData();
      formData.append('file', file);
      return API._formRequest('/api/preview/document', formData);
    },

    async parse(content, config) {
      return API._request('/api/parse/document', {
        method: 'POST',
        body: JSON.stringify({ content, ...config })
      });
    }
  },

  // YouTube APIs
  youtube: {
    async validate(url) {
      return API._request('/api/youtube/validate', {
        method: 'POST',
        body: JSON.stringify({ url })
      });
    },

    async preview(url, includeTranscript = false) {
      return API._request('/api/youtube/preview', {
        method: 'POST',
        body: JSON.stringify({ url, include_transcript_preview: includeTranscript })
      });
    },

    async parse(url, config) {
      return API._request('/api/parse/youtube', {
        method: 'POST',
        body: JSON.stringify({ url, ...config })
      });
    }
  },

  // YAML APIs
  yaml: {
    async validate(content) {
      return API._request('/api/validate/yaml', {
        method: 'POST',
        body: JSON.stringify({ content })
      });
    },

    async parse(content, config) {
      return API._request('/api/parse/yaml', {
        method: 'POST',
        body: JSON.stringify({ content, ...config })
      });
    }
  },

  // Language APIs
  languages: {
    async list() {
      return API._request('/api/languages');
    },

    async getVoices(langCode) {
      return API._request(`/api/languages/${langCode}/voices`);
    },

    async previewVoice(langCode, voiceId, text) {
      return API._request('/api/voice-preview', {
        method: 'POST',
        body: JSON.stringify({ language: langCode, voice: voiceId, text })
      });
    }
  },

  // Task APIs
  tasks: {
    async getStatus(taskId) {
      return API._request(`/api/tasks/${taskId}`);
    },

    async cancel(taskId) {
      return API._request(`/api/tasks/${taskId}/cancel`, { method: 'POST' });
    },

    streamProgress(taskId, callbacks) {
      const sse = new SSEClient(`/api/tasks/${taskId}/stream`);
      sse.onMessage(callbacks.onProgress);
      sse.onError(callbacks.onError);
      sse.onComplete(callbacks.onComplete);
      return sse;
    }
  }
};

// Error class
class APIError extends Error {
  constructor(message, status, details) {
    super(message);
    this.name = 'APIError';
    this.status = status;
    this.details = details;
  }

  get isValidationError() { return this.status === 400; }
  get isAuthError() { return this.status === 401 || this.status === 403; }
  get isNotFound() { return this.status === 404; }
  get isServerError() { return this.status >= 500; }
}

// Export
window.API = API;
window.APIError = APIError;
```

### 6.2 SSE Client

```javascript
// /static/js/api/sse.js

class SSEClient {
  constructor(url) {
    this.url = url;
    this.eventSource = null;
    this.callbacks = {
      message: null,
      error: null,
      complete: null
    };
    this.retryCount = 0;
    this.maxRetries = 3;
  }

  connect() {
    this.eventSource = new EventSource(this.url);

    this.eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);

        if (data.status === 'complete') {
          this.callbacks.complete?.(data);
          this.disconnect();
        } else {
          this.callbacks.message?.(data);
        }

        this.retryCount = 0;  // Reset on success
      } catch (error) {
        console.error('SSE parse error:', error);
      }
    };

    this.eventSource.onerror = (error) => {
      console.error('SSE error:', error);

      if (this.retryCount < this.maxRetries) {
        this.retryCount++;
        setTimeout(() => this.reconnect(), 1000 * this.retryCount);
      } else {
        this.callbacks.error?.(new Error('SSE connection failed'));
        this.disconnect();
      }
    };

    return this;
  }

  reconnect() {
    this.disconnect();
    this.connect();
  }

  disconnect() {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
  }

  onMessage(callback) {
    this.callbacks.message = callback;
    return this;
  }

  onError(callback) {
    this.callbacks.error = callback;
    return this;
  }

  onComplete(callback) {
    this.callbacks.complete = callback;
    return this;
  }
}

window.SSEClient = SSEClient;
```

---

## 7. CSS/Styling Architecture

### 7.1 Design System

```css
/* /static/css/design-system.css */

:root {
  /* Colors - Primary */
  --color-primary-50: #eff6ff;
  --color-primary-100: #dbeafe;
  --color-primary-500: #3b82f6;
  --color-primary-600: #2563eb;
  --color-primary-700: #1d4ed8;

  /* Colors - Semantic */
  --color-success: #22c55e;
  --color-warning: #f59e0b;
  --color-error: #ef4444;
  --color-info: #3b82f6;

  /* Spacing */
  --space-1: 0.25rem;
  --space-2: 0.5rem;
  --space-3: 0.75rem;
  --space-4: 1rem;
  --space-6: 1.5rem;
  --space-8: 2rem;

  /* Border Radius */
  --radius-sm: 0.25rem;
  --radius-md: 0.5rem;
  --radius-lg: 0.75rem;
  --radius-xl: 1rem;

  /* Shadows */
  --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.05);
  --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
  --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);

  /* Transitions */
  --transition-fast: 150ms ease;
  --transition-normal: 200ms ease;
  --transition-slow: 300ms ease;
}
```

### 7.2 Component Styles

```css
/* /static/css/components.css */

/* ========== Drag Drop Zone ========== */
.drag-drop-zone {
  @apply border-2 border-dashed border-gray-300 rounded-xl p-8;
  @apply transition-all duration-200;
  @apply bg-gray-50 hover:bg-gray-100;
}

.drag-drop-zone.drag-active {
  @apply border-blue-500 bg-blue-50;
  @apply ring-4 ring-blue-100;
}

.drag-drop-zone.valid {
  @apply border-green-500 bg-green-50;
}

.drag-drop-zone.invalid {
  @apply border-red-500 bg-red-50;
}

.drag-drop-zone__icon {
  @apply text-6xl mb-4;
}

.drag-drop-zone__text {
  @apply text-gray-600 text-center;
}

/* ========== Validation Feedback ========== */
.validation-feedback {
  @apply flex items-center gap-2 mt-2;
}

.validation-feedback__icon {
  @apply flex-shrink-0;
}

.validation-feedback__message {
  @apply text-sm;
}

.validation-feedback--valid {
  @apply text-green-600;
}

.validation-feedback--invalid {
  @apply text-red-600;
}

.validation-feedback--warning {
  @apply text-yellow-600;
}

/* ========== Preview Panel ========== */
.preview-panel {
  @apply bg-white rounded-lg shadow-md border border-gray-200;
  @apply overflow-hidden;
}

.preview-panel__header {
  @apply flex items-center justify-between;
  @apply px-4 py-3 bg-gray-50 border-b border-gray-200;
}

.preview-panel__title {
  @apply font-semibold text-gray-900;
}

.preview-panel__content {
  @apply p-4;
}

.preview-panel__section {
  @apply py-3 border-b border-gray-100 last:border-0;
}

/* ========== Language Chip ========== */
.language-chip {
  @apply inline-flex items-center gap-1.5;
  @apply px-3 py-1.5 rounded-full;
  @apply text-sm font-medium;
  @apply transition-colors duration-150;
}

.language-chip--selected {
  @apply bg-blue-100 text-blue-800;
}

.language-chip--unselected {
  @apply bg-gray-100 text-gray-700 hover:bg-gray-200;
}

/* ========== Voice Card ========== */
.voice-card {
  @apply flex items-center gap-3;
  @apply p-3 rounded-lg border border-gray-200;
  @apply hover:border-blue-300 hover:bg-blue-50;
  @apply transition-all duration-150;
  @apply cursor-pointer;
}

.voice-card--selected {
  @apply border-blue-500 bg-blue-50;
}

.voice-card__info {
  @apply flex-1;
}

.voice-card__name {
  @apply font-medium text-gray-900;
}

.voice-card__description {
  @apply text-sm text-gray-500;
}

.voice-card__preview {
  @apply p-2 rounded-full hover:bg-blue-100;
}

/* ========== Progress Indicator ========== */
.progress-indicator {
  @apply bg-white rounded-lg shadow-md p-6;
}

.progress-indicator__bar {
  @apply w-full h-3 bg-gray-200 rounded-full overflow-hidden;
}

.progress-indicator__fill {
  @apply h-full bg-blue-500 rounded-full;
  @apply transition-all duration-500 ease-out;
}

.progress-indicator__stages {
  @apply mt-6 space-y-3;
}

.progress-indicator__stage {
  @apply flex items-center gap-3;
}

.progress-indicator__stage-icon {
  @apply w-6 h-6 flex items-center justify-center;
  @apply rounded-full text-sm font-medium;
}

.progress-indicator__stage-icon--complete {
  @apply bg-green-100 text-green-600;
}

.progress-indicator__stage-icon--active {
  @apply bg-blue-100 text-blue-600;
}

.progress-indicator__stage-icon--pending {
  @apply bg-gray-100 text-gray-400;
}
```

### 7.3 Animations

```css
/* /static/css/animations.css */

/* Fade In */
@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

.animate-fade-in {
  animation: fadeIn 200ms ease-out;
}

/* Slide Up */
@keyframes slideUp {
  from {
    opacity: 0;
    transform: translateY(10px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.animate-slide-up {
  animation: slideUp 300ms ease-out;
}

/* Pulse */
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

.animate-pulse {
  animation: pulse 2s infinite;
}

/* Spin */
@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.animate-spin {
  animation: spin 1s linear infinite;
}

/* Progress Bar Fill */
@keyframes progressFill {
  from { width: 0; }
}

.animate-progress {
  animation: progressFill 500ms ease-out;
}

/* Drag Active Pulse */
@keyframes dragPulse {
  0%, 100% {
    box-shadow: 0 0 0 0 rgba(59, 130, 246, 0.4);
  }
  50% {
    box-shadow: 0 0 0 10px rgba(59, 130, 246, 0);
  }
}

.drag-drop-zone.drag-active {
  animation: dragPulse 1s infinite;
}
```

---

## 8. Deployment Architecture

### 8.1 Build Process

**Current:** No build process (CDN for dependencies)

**Target:** Minimal build for optimization (optional)

```bash
# Development (no build needed)
python -m uvicorn app.main:app --reload

# Production (optional optimization)
npx tailwindcss -i static/css/style.css -o static/css/dist/style.min.css --minify
npx terser static/js/*.js -o static/js/dist/bundle.min.js
```

### 8.2 Caching Strategy

```python
# Flask static file caching
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 86400  # 1 day

# Versioned assets
<script src="/static/js/app.js?v={{ version }}"></script>
```

### 8.3 CDN Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| Alpine.js | 3.13.5 | Reactive components |
| TailwindCSS | 3.x | Utility CSS (CDN) |
| HTMX | 1.9.10 | Partial updates |

---

## 9. Error Handling Architecture

### 9.1 Error Boundary Pattern

```javascript
// /static/js/utils/error-handler.js

const ErrorHandler = {
  // User-friendly error messages
  messages: {
    network: 'Unable to connect. Please check your internet connection.',
    validation: 'Please fix the errors above and try again.',
    server: 'Something went wrong. Please try again later.',
    notFound: 'The requested resource was not found.',
    timeout: 'The request timed out. Please try again.'
  },

  handle(error, context = {}) {
    console.error(`[${context.component || 'App'}] Error:`, error);

    // Determine message
    let message = this.messages.server;

    if (error instanceof APIError) {
      if (error.isValidationError) {
        message = error.message || this.messages.validation;
      } else if (error.isNotFound) {
        message = this.messages.notFound;
      } else if (error.isServerError) {
        message = this.messages.server;
      }
    } else if (error.message?.includes('fetch')) {
      message = this.messages.network;
    }

    // Show notification
    this.notify(message, 'error', error.details?.suggestion);

    // Track error
    this.track(error, context);

    return message;
  },

  notify(message, type = 'error', suggestion = null) {
    window.dispatchEvent(new CustomEvent('show-message', {
      detail: { message, type, suggestion }
    }));
  },

  track(error, context) {
    // Send to analytics if available
    if (window.analytics) {
      window.analytics.track('error', {
        message: error.message,
        component: context.component,
        stack: error.stack
      });
    }
  }
};

window.ErrorHandler = ErrorHandler;
```

### 9.2 Component Error Handling

```javascript
// In component
async function handleSubmit() {
  try {
    result = await API.document.validate(file);
    // Success handling
  } catch (error) {
    ErrorHandler.handle(error, { component: 'DragDropZone' });
  }
}
```

---

## 10. Accessibility Architecture

### 10.1 ARIA Patterns

```html
<!-- Drag Drop Zone -->
<div role="button"
     tabindex="0"
     aria-label="Upload file. Press Enter or Space to browse files"
     aria-describedby="drop-zone-help"
     @keydown.enter="$refs.fileInput.click()"
     @keydown.space="$refs.fileInput.click()">
  <!-- Content -->
</div>
<div id="drop-zone-help" class="sr-only">
  Drag and drop a file here, or press Enter to browse files.
  Supported formats: MD, TXT, PDF, DOCX. Maximum size: 10MB.
</div>

<!-- Progress Indicator -->
<div role="progressbar"
     aria-valuenow="45"
     aria-valuemin="0"
     aria-valuemax="100"
     aria-label="Video generation progress">
  <div aria-live="polite" class="sr-only">
    45% complete. Generating scenes.
  </div>
</div>

<!-- Language Selector -->
<div role="listbox"
     aria-label="Select languages"
     aria-multiselectable="true">
  <div role="option"
       :aria-selected="isSelected('en')"
       tabindex="0"
       @keydown.enter="toggle('en')"
       @keydown.space.prevent="toggle('en')">
    English
  </div>
</div>
```

### 10.2 Focus Management

```javascript
// Focus trap for modals
function trapFocus(element) {
  const focusable = element.querySelectorAll(
    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
  );
  const first = focusable[0];
  const last = focusable[focusable.length - 1];

  element.addEventListener('keydown', (e) => {
    if (e.key === 'Tab') {
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  });

  first.focus();
}
```

---

## 11. Performance Considerations

### 11.1 Lazy Loading

```javascript
// Load voices only when language section is expanded
async function loadVoicesOnExpand(langCode) {
  if (!availableVoices[langCode]) {
    await fetchVoicesForLanguage(langCode);
  }
}
```

### 11.2 Debouncing

```javascript
// Debounce validation
const debouncedValidate = Alpine.debounce((value) => {
  validateInput(value);
}, 500);
```

### 11.3 Virtualization (Future)

For large language lists, consider virtual scrolling:
```javascript
// Only render visible items
const visibleLanguages = languages.slice(scrollOffset, scrollOffset + visibleCount);
```

---

## 12. Testing Strategy

### 12.1 Component Tests

```javascript
// Using Alpine.js testing utilities
describe('DragDropZone', () => {
  it('should accept valid file types', async () => {
    const component = Alpine.evaluate(DragDropZone());
    const file = new File(['content'], 'test.md', { type: 'text/markdown' });

    await component.processFile(file);

    expect(component.validationStatus).toBe('valid');
    expect(component.fileName).toBe('test.md');
  });

  it('should reject invalid file types', async () => {
    const component = Alpine.evaluate(DragDropZone());
    const file = new File(['content'], 'test.exe', { type: 'application/exe' });

    await component.processFile(file);

    expect(component.validationStatus).toBe('invalid');
    expect(component.validationError).toContain('Invalid file type');
  });
});
```

### 12.2 Integration Tests

```python
# Using Playwright
async def test_file_upload_flow():
    page = await browser.new_page()
    await page.goto('/create')

    # Drag and drop file
    await page.set_input_files('input[type="file"]', 'test.md')

    # Wait for validation
    await page.wait_for_selector('.validation-feedback--valid')

    # Check preview loaded
    preview = await page.query_selector('.preview-panel')
    assert preview is not None
```

---

## 13. Implementation Roadmap

### Phase 1: Foundation (Days 1-3)
- [ ] Set up enhanced file structure
- [ ] Create API client
- [ ] Enhance global store
- [ ] Add CSS design system

### Phase 2: Core Components (Days 4-8)
- [ ] Implement DragDropZone
- [ ] Implement ValidationFeedback
- [ ] Implement PreviewPanel
- [ ] Integrate with existing templates

### Phase 3: Configuration (Days 9-12)
- [ ] Implement VideoModeSelector
- [ ] Implement MultiLanguageSelector
- [ ] Implement MultiVoiceSelector
- [ ] Update preset system

### Phase 4: Progress & Polish (Days 13-16)
- [ ] Implement ProgressIndicator
- [ ] Add SSE integration
- [ ] Add error handling
- [ ] Add animations

### Phase 5: Testing & Launch (Days 17-21)
- [ ] Write component tests
- [ ] Write integration tests
- [ ] Accessibility audit
- [ ] Performance optimization
- [ ] Deploy to production

---

**Document Version:** 1.0.0
**Last Updated:** November 22, 2025
**Next Phase:** Refinement (Implementation)
