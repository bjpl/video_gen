# Component Specifications - video_gen UI Redesign

**Date:** November 17, 2025
**Author:** UI Architecture Specialist
**Version:** 1.0
**Status:** Design Phase

---

## 📋 Executive Summary

This document defines the component architecture for the video_gen UI redesign, breaking down the current 2,572-line monolithic `create.html` into 8-10 reusable, maintainable components. The architecture mirrors the backend's unified pipeline and CLI patterns, creating a clean, modern interface aligned with the system's architecture.

**Key Metrics:**
- **Current:** 2,572 lines (create.html) + 927 lines (builder.html) = 3,499 lines
- **Target:** ~1,000 lines total across modular components
- **Reduction:** 71% code reduction
- **Maintainability:** 10x improvement via component reuse

---

## 🎯 Design Principles

### 1. **Architecture Alignment**
- UI mirrors the 6-stage backend pipeline
- Input methods map to backend adapters (Document, YouTube, Wizard, YAML)
- Single unified workflow (like CLI's unified entry point)

### 2. **Progressive Disclosure**
- Show only relevant options at each step
- Wizard-style stepper guides users through process
- Advanced options hidden by default

### 3. **Component Reusability**
- Each component is self-contained
- Props-based configuration
- Alpine.js for reactivity
- No component exceeds 150 lines

### 4. **State Management**
- Centralized Alpine.js store
- Unidirectional data flow
- Clear state ownership
- Persistent state across steps

---

## 🏗️ Component Hierarchy

```
┌─────────────────────────────────────────────────────────┐
│                    App Shell (base.html)                 │
│  ┌────────────────────────────────────────────────────┐ │
│  │           Page: Create (/create)                    │ │
│  │                                                     │ │
│  │  [StepIndicator]                                   │ │
│  │  ┌──────────────────────────────────────────────┐ │ │
│  │  │  Step 1: Input Method Selection              │ │ │
│  │  │  ┌────────────────────────────────────────┐  │ │ │
│  │  │  │   <PresetSelector>                      │  │ │ │
│  │  │  │   <InputMethodSelector>                 │  │ │ │
│  │  │  └────────────────────────────────────────┘  │ │ │
│  │  └──────────────────────────────────────────────┘ │ │
│  │  ┌──────────────────────────────────────────────┐ │ │
│  │  │  Step 2: Input-Specific Configuration       │ │ │
│  │  │  ┌────────────────────────────────────────┐  │ │ │
│  │  │  │   <DocumentInputForm>                   │  │ │ │
│  │  │  │   <YouTubeInputForm>                    │  │ │ │
│  │  │  │   <WizardInputForm>                     │  │ │ │
│  │  │  │   <YAMLInputForm>                       │  │ │ │
│  │  │  └────────────────────────────────────────┘  │ │ │
│  │  └──────────────────────────────────────────────┘ │ │
│  │  ┌──────────────────────────────────────────────┐ │ │
│  │  │  Step 3: Video Configuration                │ │ │
│  │  │  ┌────────────────────────────────────────┐  │ │ │
│  │  │  │   <LanguageSelector>                    │  │ │ │
│  │  │  │   <VoiceSelector>                       │  │ │ │
│  │  │  │   <VideoSettings>                       │  │ │ │
│  │  │  │   <CostEstimator>                       │  │ │ │
│  │  │  └────────────────────────────────────────┘  │ │ │
│  │  └──────────────────────────────────────────────┘ │ │
│  │  ┌──────────────────────────────────────────────┐ │ │
│  │  │  Step 4: Review & Generate                  │ │ │
│  │  │  ┌────────────────────────────────────────┐  │ │ │
│  │  │  │   <GenerationSummary>                   │  │ │ │
│  │  │  │   <ScenePreview>                        │  │ │ │
│  │  │  └────────────────────────────────────────┘  │ │ │
│  │  └──────────────────────────────────────────────┘ │ │
│  └─────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

---

## 📦 Core Components (8 Total)

### **Component 1: PresetSelector**

**Purpose:** Quick-start templates for common use cases
**Location:** `components/preset-selector.html`
**Lines:** ~120 lines

**Props:**
```javascript
{
  selectedPreset: String | null,  // Current selected preset
  onSelect: Function,             // Callback when preset selected
  mode: 'single' | 'set'          // Single video or video set
}
```

**State:**
```javascript
{
  presets: [
    {
      id: 'corporate',
      name: 'Corporate Presentation',
      icon: '💼',
      description: 'Professional multi-language business videos',
      features: ['4 languages (EN/ES/FR/DE)', 'Professional male voice', ...],
      config: {
        languageMode: 'multiple',
        targetLanguages: ['en', 'es', 'fr', 'de'],
        primaryVoice: 'male',
        color: 'blue',
        duration: 120
      }
    },
    // ... more presets
  ]
}
```

**Template Structure:**
```html
<div class="preset-grid">
  <template x-for="preset in presets">
    <div @click="selectPreset(preset)"
         :class="selectedPreset === preset.id ? 'selected' : ''"
         class="preset-card">
      <div x-text="preset.icon" class="preset-icon"></div>
      <h3 x-text="preset.name"></h3>
      <p x-text="preset.description"></p>
      <ul class="preset-features">
        <template x-for="feature in preset.features">
          <li x-text="feature"></li>
        </template>
      </ul>
    </div>
  </template>
</div>
```

**API:**
- `selectPreset(preset)` - Applies preset configuration to parent state
- `getPresetConfig(presetId)` - Returns configuration object for preset

**Dependencies:**
- Alpine.js for reactivity
- Tailwind CSS for styling
- Parent state store for configuration application

---

### **Component 2: InputMethodSelector**

**Purpose:** Choose content source (Document/YouTube/Wizard/YAML)
**Location:** `components/input-method-selector.html`
**Lines:** ~80 lines

**Props:**
```javascript
{
  selectedMethod: String,     // Current selected method
  onChange: Function,         // Callback when method changes
  mode: 'single' | 'set'      // Context for appropriate methods
}
```

**State:**
```javascript
{
  methods: [
    { id: 'document', icon: '📄', name: 'Document', description: 'Parse README/Markdown' },
    { id: 'youtube', icon: '📺', name: 'YouTube', description: 'From YouTube URL' },
    { id: 'wizard', icon: '🧙', name: 'Wizard', description: 'Step-by-step builder' },
    { id: 'yaml', icon: '📝', name: 'YAML', description: 'From YAML file' }
  ]
}
```

**Template Structure:**
```html
<div class="input-method-grid">
  <template x-for="method in methods">
    <button @click="selectMethod(method.id)"
            :class="selectedMethod === method.id ? 'selected' : ''"
            class="method-card">
      <span x-text="method.icon"></span>
      <h4 x-text="method.name"></h4>
      <p x-text="method.description"></p>
    </button>
  </template>
</div>
```

**API:**
- `selectMethod(methodId)` - Sets selected method and triggers onChange

**Dependencies:**
- Alpine.js
- Parent state for method storage

---

### **Component 3: DocumentInputForm**

**Purpose:** Configuration for document-based input
**Location:** `components/document-input-form.html`
**Lines:** ~100 lines

**Props:**
```javascript
{
  documentPath: String,       // Current document path
  onChange: Function,         // Callback on path change
  autoDetect: Boolean         // Enable smart defaults
}
```

**State:**
```javascript
{
  documentPath: '',
  detectedType: null,         // 'github' | 'local' | 'url'
  validationStatus: 'idle',   // 'idle' | 'validating' | 'valid' | 'invalid'
  suggestions: []             // Smart suggestions based on detection
}
```

**Template Structure:**
```html
<div class="document-input">
  <label>Document Path or URL</label>
  <input x-model="documentPath"
         @input.debounce.500ms="detectType"
         @change="onChange(documentPath)"
         placeholder="README.md or https://github.com/user/repo">

  <!-- Validation feedback -->
  <div x-show="validationStatus === 'valid'" class="validation-success">
    ✓ Valid <span x-text="detectedType"></span> path
  </div>

  <!-- Smart suggestions -->
  <div x-show="suggestions.length > 0" class="suggestions">
    <template x-for="suggestion in suggestions">
      <button @click="applySuggestion(suggestion)" x-text="suggestion.label"></button>
    </template>
  </div>
</div>
```

**API:**
- `detectType()` - Analyzes path and detects type (GitHub URL, local file, etc.)
- `validatePath()` - Validates path format
- `applySuggestion(suggestion)` - Applies smart default

**Dependencies:**
- Alpine.js
- Validation utilities (`/static/js/validation.js`)
- Smart defaults service (`/static/js/smart-defaults.js`)

---

### **Component 4: LanguageSelector**

**Purpose:** Language configuration (single or multilingual)
**Location:** `components/language-selector.html`
**Lines:** ~150 lines

**Props:**
```javascript
{
  languageMode: 'single' | 'multiple',  // Mode selection
  primaryLanguage: String,               // Single mode language
  sourceLanguage: String,                // Multi mode source
  targetLanguages: Array<String>,        // Multi mode targets
  availableLanguages: Array<Language>,   // All supported languages
  onChange: Function                     // Callback on configuration change
}
```

**State:**
```javascript
{
  languageMode: 'single',
  primaryLanguage: 'en',
  sourceLanguage: 'en',
  targetLanguages: ['en'],
  languageSearch: '',
  filteredLanguages: []
}
```

**Template Structure:**
```html
<div class="language-selector">
  <!-- Mode Toggle -->
  <div class="mode-toggle">
    <button @click="languageMode = 'single'"
            :class="languageMode === 'single' ? 'active' : ''">
      Single Language
    </button>
    <button @click="languageMode = 'multiple'"
            :class="languageMode === 'multiple' ? 'active' : ''">
      Multilingual
    </button>
  </div>

  <!-- Single Language Mode -->
  <div x-show="languageMode === 'single'">
    <select x-model="primaryLanguage" @change="onChange">
      <template x-for="lang in availableLanguages">
        <option :value="lang.code" x-text="lang.name"></option>
      </template>
    </select>
  </div>

  <!-- Multiple Language Mode -->
  <div x-show="languageMode === 'multiple'">
    <!-- Source language -->
    <div class="source-language">
      <label>Source Language</label>
      <select x-model="sourceLanguage" @change="onChange">
        <template x-for="lang in availableLanguages">
          <option :value="lang.code" x-text="lang.name"></option>
        </template>
      </select>
    </div>

    <!-- Target languages (multi-select) -->
    <div class="target-languages">
      <label>Target Languages</label>
      <input x-model="languageSearch"
             placeholder="Search languages...">
      <div class="language-grid">
        <template x-for="lang in filteredLanguages">
          <label class="language-checkbox">
            <input type="checkbox"
                   :value="lang.code"
                   @change="toggleLanguage(lang.code)">
            <span x-text="lang.name"></span>
          </label>
        </template>
      </div>
      <p class="selection-count">
        Selected: <span x-text="targetLanguages.length"></span> languages
      </p>
    </div>
  </div>
</div>
```

**API:**
- `toggleLanguage(langCode)` - Add/remove language from targets
- `setMode(mode)` - Switch between single/multiple mode
- `filterLanguages()` - Filter by search query

**Dependencies:**
- Alpine.js
- Language data from `/api/languages`

---

### **Component 5: VoiceSelector**

**Purpose:** Voice selection per language
**Location:** `components/voice-selector.html`
**Lines:** ~120 lines

**Props:**
```javascript
{
  languageMode: 'single' | 'multiple',
  primaryLanguage: String,
  primaryVoice: String,
  languageVoices: Object<String, String>,  // { langCode: voiceId }
  targetLanguages: Array<String>,
  onChange: Function
}
```

**State:**
```javascript
{
  availableVoices: {
    'en': [
      { id: 'male', name: 'Andrew (Male) - Professional', preview: '/audio/male.mp3' },
      { id: 'male_warm', name: 'Brandon (Warm) - Engaging', preview: '/audio/male_warm.mp3' },
      { id: 'female', name: 'Aria (Female) - Clear', preview: '/audio/female.mp3' },
      { id: 'female_friendly', name: 'Ava (Friendly) - Pleasant', preview: '/audio/female_friendly.mp3' }
    ],
    // ... other languages
  },
  playingPreview: null
}
```

**Template Structure:**
```html
<div class="voice-selector">
  <!-- Single Language Voice -->
  <div x-show="languageMode === 'single'">
    <label>Voice</label>
    <div class="voice-grid">
      <template x-for="voice in getVoicesForLang(primaryLanguage)">
        <button @click="selectVoice(voice.id)"
                :class="primaryVoice === voice.id ? 'selected' : ''"
                class="voice-card">
          <span x-text="voice.name"></span>
          <button @click.stop="playPreview(voice.preview)" class="play-btn">
            <span x-show="playingPreview === voice.id">⏸</span>
            <span x-show="playingPreview !== voice.id">▶</span>
          </button>
        </button>
      </template>
    </div>
  </div>

  <!-- Per-Language Voice Assignment -->
  <div x-show="languageMode === 'multiple'">
    <label>Voice per Language</label>
    <div class="language-voice-list">
      <template x-for="lang in targetLanguages">
        <div class="language-voice-row">
          <span x-text="getLanguageName(lang)" class="language-name"></span>
          <select x-model="languageVoices[lang]"
                  @change="onChange">
            <template x-for="voice in getVoicesForLang(lang)">
              <option :value="voice.id" x-text="voice.name"></option>
            </template>
          </select>
          <button @click="playPreview(getVoicePreview(lang, languageVoices[lang]))"
                  class="play-btn">▶</button>
        </div>
      </template>
    </div>
  </div>
</div>
```

**API:**
- `getVoicesForLang(langCode)` - Returns available voices for language
- `selectVoice(voiceId)` - Sets voice for current context
- `playPreview(audioUrl)` - Plays voice preview audio

**Dependencies:**
- Alpine.js
- Audio preview player
- Voice data service

---

### **Component 6: VideoSettings**

**Purpose:** Common video configuration (duration, color, AI)
**Location:** `components/video-settings.html`
**Lines:** ~100 lines

**Props:**
```javascript
{
  duration: Number,           // Video duration in seconds
  color: String,              // Accent color
  useAI: Boolean,             // AI-enhanced narration
  showAdvanced: Boolean,      // Show advanced options
  onChange: Function
}
```

**State:**
```javascript
{
  duration: 60,
  color: 'blue',
  useAI: false,
  showAdvanced: false,
  colors: [
    { id: 'blue', name: 'Blue', usage: 'Professional, corporate' },
    { id: 'purple', name: 'Purple', usage: 'Premium, creative' },
    { id: 'orange', name: 'Orange', usage: 'Energetic, marketing' },
    { id: 'green', name: 'Green', usage: 'Success, environmental' },
    { id: 'pink', name: 'Pink', usage: 'Playful, lifestyle' },
    { id: 'cyan', name: 'Cyan', usage: 'Tech, innovation' }
  ]
}
```

**Template Structure:**
```html
<div class="video-settings">
  <!-- Duration -->
  <div class="setting-group">
    <label>Target Duration</label>
    <div class="duration-slider">
      <input type="range"
             x-model="duration"
             min="30" max="600" step="30"
             @input="onChange">
      <span x-text="formatDuration(duration)"></span>
    </div>
  </div>

  <!-- Accent Color -->
  <div class="setting-group">
    <label>Accent Color</label>
    <div class="color-grid">
      <template x-for="colorOption in colors">
        <button @click="color = colorOption.id; onChange()"
                :class="color === colorOption.id ? 'selected' : ''"
                class="color-card">
          <div :class="`bg-${colorOption.id}-500`" class="color-swatch"></div>
          <span x-text="colorOption.name"></span>
          <span x-text="colorOption.usage" class="color-usage"></span>
        </button>
      </template>
    </div>
  </div>

  <!-- AI Enhancement -->
  <div class="setting-group">
    <label class="checkbox-label">
      <input type="checkbox" x-model="useAI" @change="onChange">
      <span>AI-Enhanced Narration</span>
    </label>
    <p class="setting-description">
      Use Claude AI to enhance script pacing and clarity (+$0.01-0.03 per video)
    </p>
  </div>

  <!-- Advanced Options Toggle -->
  <button @click="showAdvanced = !showAdvanced" class="toggle-advanced">
    <span x-show="!showAdvanced">Show Advanced Options ▼</span>
    <span x-show="showAdvanced">Hide Advanced Options ▲</span>
  </button>

  <!-- Advanced Options (collapsed) -->
  <div x-show="showAdvanced" x-collapse class="advanced-options">
    <!-- Additional advanced settings here -->
  </div>
</div>
```

**API:**
- `formatDuration(seconds)` - Formats seconds to MM:SS
- `toggleAdvanced()` - Shows/hides advanced options

**Dependencies:**
- Alpine.js
- Tailwind CSS utilities

---

### **Component 7: CostEstimator**

**Purpose:** Real-time cost and time estimation
**Location:** `components/cost-estimator.html`
**Lines:** ~80 lines

**Props:**
```javascript
{
  config: Object,             // Full video configuration
  mode: 'single' | 'set',
  onUpdate: Function          // Callback with updated estimates
}
```

**State:**
```javascript
{
  estimatedCost: {
    min: 0.02,
    max: 0.05,
    breakdown: {
      narration: 0.01,
      translation: 0.01,
      rendering: 0.01,
      ai_enhancement: 0.02
    }
  },
  estimatedTime: {
    min: 45,                  // seconds
    max: 90,
    stages: [
      { name: 'Scene Generation', time: 10 },
      { name: 'Audio Generation', time: 30 },
      { name: 'Translation', time: 20 },
      { name: 'Rendering', time: 30 }
    ]
  }
}
```

**Template Structure:**
```html
<div class="cost-estimator">
  <div class="estimate-card">
    <h4>Estimated Cost</h4>
    <div class="cost-range">
      <span class="cost-min">$<span x-text="estimatedCost.min.toFixed(2)"></span></span>
      <span class="cost-separator">-</span>
      <span class="cost-max">$<span x-text="estimatedCost.max.toFixed(2)"></span></span>
    </div>

    <!-- Cost Breakdown (expandable) -->
    <details class="cost-breakdown">
      <summary>View Breakdown</summary>
      <ul>
        <template x-for="(cost, service) in estimatedCost.breakdown">
          <li>
            <span x-text="formatServiceName(service)"></span>:
            <span>$<span x-text="cost.toFixed(3)"></span></span>
          </li>
        </template>
      </ul>
    </details>
  </div>

  <div class="estimate-card">
    <h4>Estimated Time</h4>
    <div class="time-range">
      <span x-text="formatTime(estimatedTime.min)"></span>
      <span class="time-separator">-</span>
      <span x-text="formatTime(estimatedTime.max)"></span>
    </div>

    <!-- Time Breakdown (expandable) -->
    <details class="time-breakdown">
      <summary>View Stages</summary>
      <ul>
        <template x-for="stage in estimatedTime.stages">
          <li>
            <span x-text="stage.name"></span>:
            <span x-text="formatTime(stage.time)"></span>
          </li>
        </template>
      </ul>
    </details>
  </div>
</div>
```

**API:**
- `calculate()` - Recalculates estimates based on config
- `formatServiceName(service)` - Formats service key to readable name
- `formatTime(seconds)` - Formats seconds to human-readable

**Dependencies:**
- Alpine.js
- Cost estimation logic (`/static/js/cost-estimator.js`)

---

### **Component 8: GenerationSummary**

**Purpose:** Final review before generation
**Location:** `components/generation-summary.html`
**Lines:** ~120 lines

**Props:**
```javascript
{
  config: Object,             // Complete configuration
  mode: 'single' | 'set',
  onGenerate: Function,       // Generate callback
  onEdit: Function            // Edit callback
}
```

**State:**
```javascript
{
  expanded: {
    input: false,
    languages: false,
    videos: false,
    settings: false
  }
}
```

**Template Structure:**
```html
<div class="generation-summary">
  <h3>Review Configuration</h3>

  <!-- Input Summary -->
  <div class="summary-section">
    <button @click="expanded.input = !expanded.input" class="section-header">
      <span>Input Method</span>
      <span x-show="!expanded.input">▼</span>
      <span x-show="expanded.input">▲</span>
    </button>
    <div x-show="expanded.input" x-collapse class="section-content">
      <div class="summary-row">
        <span class="label">Method:</span>
        <span x-text="config.inputMethod"></span>
      </div>
      <div class="summary-row" x-show="config.inputMethod === 'document'">
        <span class="label">Document:</span>
        <span x-text="config.documentPath"></span>
      </div>
      <!-- Other input-specific details -->
    </div>
  </div>

  <!-- Language Summary -->
  <div class="summary-section">
    <button @click="expanded.languages = !expanded.languages" class="section-header">
      <span>Languages & Voices</span>
      <span x-show="!expanded.languages">▼</span>
      <span x-show="expanded.languages">▲</span>
    </button>
    <div x-show="expanded.languages" x-collapse class="section-content">
      <div x-show="config.languageMode === 'single'">
        <div class="summary-row">
          <span class="label">Language:</span>
          <span x-text="getLanguageName(config.primaryLanguage)"></span>
        </div>
        <div class="summary-row">
          <span class="label">Voice:</span>
          <span x-text="getVoiceName(config.primaryVoice)"></span>
        </div>
      </div>
      <div x-show="config.languageMode === 'multiple'">
        <div class="summary-row">
          <span class="label">Source:</span>
          <span x-text="getLanguageName(config.sourceLanguage)"></span>
        </div>
        <div class="summary-row">
          <span class="label">Targets:</span>
          <span x-text="config.targetLanguages.map(getLanguageName).join(', ')"></span>
        </div>
      </div>
    </div>
  </div>

  <!-- Video Summary -->
  <div class="summary-section">
    <button @click="expanded.videos = !expanded.videos" class="section-header">
      <span>Videos (<span x-text="mode === 'single' ? '1' : config.videos.length"></span>)</span>
      <span x-show="!expanded.videos">▼</span>
      <span x-show="expanded.videos">▲</span>
    </button>
    <div x-show="expanded.videos" x-collapse class="section-content">
      <template x-for="(video, idx) in getVideos(mode, config)">
        <div class="video-summary">
          <strong x-text="`Video ${idx + 1}: ${video.title}`"></strong>
          <span x-text="`Voices: ${video.voiceTracks.length}`"></span>
        </div>
      </template>
    </div>
  </div>

  <!-- Settings Summary -->
  <div class="summary-section">
    <button @click="expanded.settings = !expanded.settings" class="section-header">
      <span>Settings</span>
      <span x-show="!expanded.settings">▼</span>
      <span x-show="expanded.settings">▲</span>
    </button>
    <div x-show="expanded.settings" x-collapse class="section-content">
      <div class="summary-row">
        <span class="label">Duration:</span>
        <span x-text="formatDuration(config.duration)"></span>
      </div>
      <div class="summary-row">
        <span class="label">Color:</span>
        <span x-text="config.color"></span>
      </div>
      <div class="summary-row">
        <span class="label">AI Enhancement:</span>
        <span x-text="config.useAI ? 'Enabled' : 'Disabled'"></span>
      </div>
    </div>
  </div>

  <!-- Action Buttons -->
  <div class="action-buttons">
    <button @click="onEdit()" class="btn-secondary">
      ← Edit Configuration
    </button>
    <button @click="onGenerate()" class="btn-primary">
      Generate Video →
    </button>
  </div>
</div>
```

**API:**
- `getLanguageName(code)` - Converts language code to name
- `getVoiceName(voiceId)` - Converts voice ID to display name
- `getVideos(mode, config)` - Returns video list based on mode
- `formatDuration(seconds)` - Formats duration

**Dependencies:**
- Alpine.js
- Alpine Collapse plugin

---

## 🔄 Component Interactions

### **State Flow Architecture**

```
┌─────────────────────────────────────────────────────────┐
│           Alpine.js Global Store (State Manager)         │
│                                                          │
│  state: {                                               │
│    currentStep: 1,                                      │
│    selectedPreset: null,                                │
│    inputMethod: 'manual',                               │
│    languageMode: 'single',                              │
│    primaryLanguage: 'en',                               │
│    targetLanguages: ['en'],                             │
│    config: { ... }                                      │
│  }                                                       │
└─────────────────────────────────────────────────────────┘
                          ↓
           ┌──────────────┼──────────────┐
           ↓              ↓              ↓
    [PresetSelector] [InputSelector] [LanguageSelector]
           ↓              ↓              ↓
        onChange      onChange       onChange
           ↓              ↓              ↓
    ┌────────────────────────────────────────┐
    │    Store.updateConfig(partialConfig)    │
    └────────────────────────────────────────┘
                          ↓
               [All components re-render]
```

### **Event Communication**

**Custom Events:**
- `config-updated` - Fired when any configuration changes
- `validation-error` - Fired when validation fails
- `preview-ready` - Fired when scene preview available
- `generation-started` - Fired when video generation begins
- `generation-progress` - Fired with progress updates

**Event Flow:**
```javascript
// Component fires event
window.dispatchEvent(new CustomEvent('config-updated', {
  detail: { field: 'primaryLanguage', value: 'es' }
}));

// Other components listen
window.addEventListener('config-updated', (event) => {
  this.updateDependentState(event.detail);
});
```

---

## 📐 API Contracts

### **Component Props Interface**

All components follow this prop structure:

```typescript
interface ComponentProps {
  // Data props (read-only)
  [key: string]: any;

  // Callback props (actions)
  onChange?: (value: any) => void;
  onValidate?: (value: any) => ValidationResult;
  onError?: (error: Error) => void;

  // Configuration props
  disabled?: boolean;
  readonly?: boolean;
  className?: string;
}
```

### **State Store Interface**

Centralized state management:

```typescript
interface VideoCreationStore {
  // Navigation
  currentStep: number;
  mode: 'single' | 'set';

  // Configuration
  config: {
    inputMethod: 'manual' | 'document' | 'youtube' | 'yaml';
    selectedPreset: string | null;

    // Language config
    languageMode: 'single' | 'multiple';
    primaryLanguage: string;
    primaryVoice: string;
    sourceLanguage: string;
    targetLanguages: string[];
    languageVoices: Record<string, string>;

    // Video config
    duration: number;
    color: string;
    useAI: boolean;

    // Videos
    videos: Video[];
  };

  // Actions
  updateConfig(partial: Partial<Config>): void;
  goToStep(step: number): void;
  applyPreset(presetId: string): void;
  generate(): Promise<void>;
}
```

---

## 🎨 Styling Conventions

### **CSS Class Naming (BEM-inspired)**

```css
/* Component namespace */
.preset-selector { }
.preset-selector__grid { }
.preset-selector__card { }
.preset-selector__card--selected { }

/* State modifiers */
.is-active { }
.is-loading { }
.is-disabled { }
.is-valid { }
.is-invalid { }

/* Utility classes (Tailwind) */
.flex { }
.grid { }
.rounded-lg { }
.shadow-md { }
```

### **Responsive Breakpoints**

```css
/* Mobile first */
@media (min-width: 640px) { /* sm */ }
@media (min-width: 768px) { /* md */ }
@media (min-width: 1024px) { /* lg */ }
@media (min-width: 1280px) { /* xl */ }
```

---

## 🧪 Testing Strategy

### **Component Testing**

Each component requires:
1. **Unit tests** - Isolated component logic
2. **Integration tests** - Component interactions
3. **Visual regression tests** - UI consistency

**Test Structure:**
```javascript
describe('PresetSelector', () => {
  describe('Preset Selection', () => {
    it('should select corporate preset', () => {
      // Arrange
      const wrapper = mount(PresetSelector, { props: { ... } });

      // Act
      wrapper.find('.preset-card--corporate').trigger('click');

      // Assert
      expect(wrapper.emitted('change')).toBeTruthy();
      expect(wrapper.vm.selectedPreset).toBe('corporate');
    });
  });

  describe('Configuration Application', () => {
    it('should apply preset configuration', () => {
      // Test configuration application
    });
  });
});
```

---

## 📊 Performance Targets

### **Component Metrics**

| Component | Max Lines | Load Time | Render Time |
|-----------|-----------|-----------|-------------|
| PresetSelector | 120 | <50ms | <100ms |
| InputMethodSelector | 80 | <30ms | <50ms |
| DocumentInputForm | 100 | <40ms | <80ms |
| LanguageSelector | 150 | <60ms | <120ms |
| VoiceSelector | 120 | <50ms | <100ms |
| VideoSettings | 100 | <40ms | <80ms |
| CostEstimator | 80 | <30ms | <60ms |
| GenerationSummary | 120 | <50ms | <100ms |

### **Total Page Metrics**

- **Initial Load:** <500ms
- **Time to Interactive:** <1s
- **First Contentful Paint:** <300ms
- **Largest Contentful Paint:** <800ms

---

## 🔒 Accessibility Requirements

### **WCAG 2.1 AA Compliance**

All components must meet:
- **Keyboard Navigation:** Full keyboard support
- **Screen Reader:** Proper ARIA labels
- **Color Contrast:** 4.5:1 minimum ratio
- **Focus Indicators:** Visible focus states
- **Error Messages:** Clear, descriptive errors

**Example:**
```html
<button
  role="button"
  aria-label="Select corporate preset"
  aria-pressed="false"
  tabindex="0"
  @keydown.enter="selectPreset('corporate')"
  @keydown.space="selectPreset('corporate')">
  Corporate Preset
</button>
```

---

## 📝 Implementation Checklist

### **Phase 1: Component Extraction (Day 1)**
- [ ] Extract PresetSelector from create.html
- [ ] Extract InputMethodSelector
- [ ] Extract DocumentInputForm
- [ ] Extract LanguageSelector
- [ ] Create base Alpine.js store
- [ ] Test component isolation

### **Phase 2: Component Implementation (Day 2)**
- [ ] Implement VoiceSelector
- [ ] Implement VideoSettings
- [ ] Implement CostEstimator
- [ ] Implement GenerationSummary
- [ ] Wire up component interactions
- [ ] Test state management

### **Phase 3: Integration (Day 3)**
- [ ] Build unified Create page with components
- [ ] Implement step navigation
- [ ] Test full workflow
- [ ] Performance optimization
- [ ] Accessibility audit

### **Phase 4: Testing & Documentation (Day 4)**
- [ ] Unit tests for each component
- [ ] Integration tests
- [ ] Visual regression tests
- [ ] Component documentation
- [ ] Usage examples

---

## 🎯 Success Metrics

### **Code Quality**
- 71% reduction in total code (3,499 → 1,000 lines)
- 100% component reusability
- <150 lines per component
- 0 code duplication

### **Performance**
- <1s time to interactive
- <500ms initial page load
- 60fps animations
- <100ms component render time

### **Maintainability**
- 10x easier to maintain (modular architecture)
- Self-contained components
- Clear API contracts
- Comprehensive tests

### **User Experience**
- Single clear path (no confusion)
- Progressive disclosure
- Real-time feedback
- Accessible (WCAG 2.1 AA)

---

## 📚 References

### **Related Documents**
- [UI Architecture Proposal](/docs/ui-redesign/UI_ARCHITECTURE_PROPOSAL.md)
- [Backend Pipeline Documentation](/docs/architecture/)
- [CLI Documentation](/README.md)

### **Dependencies**
- [Alpine.js Documentation](https://alpinejs.dev/)
- [Tailwind CSS Documentation](https://tailwindcss.com/)
- [HTMX Documentation](https://htmx.org/)

---

**Document Status:** ✅ Complete
**Next Steps:** Begin Phase 1 implementation with component extraction
**Review Date:** November 18, 2025
