# State Management Documentation

**Version:** 2.0.0
**Last Updated:** November 22, 2025
**Author:** Frontend Architecture Agent

---

## Overview

The video_gen frontend uses Alpine.js for reactive state management with a centralized store pattern. This document covers the enhanced state management system implemented in Phase 4.2.

## Architecture

```
+------------------+     +------------------+     +------------------+
|   UI Components  |<--->|   Alpine Store   |<--->|   Persistence    |
+------------------+     +------------------+     +------------------+
        ^                        ^                        ^
        |                        |                        |
        v                        v                        v
+------------------+     +------------------+     +------------------+
|    Event Bus     |     |   API Client     |     | StorageManager   |
+------------------+     +------------------+     +------------------+
```

## State Structure

### Full State Tree

```javascript
Alpine.store('appState', {
  // Version tracking
  _version: '2.0.0',
  _initialized: false,

  // Wizard state
  currentStep: 1,
  maxStepReached: 1,

  // Input state
  input: {
    type: 'document',      // 'document' | 'youtube' | 'wizard' | 'yaml'
    source: null,          // URL or reference
    file: null,            // File object
    content: null,         // Parsed content
    isValid: false,
    validationErrors: [],
    validationWarnings: []
  },

  // Preview state
  preview: {
    data: null,
    type: null,
    isLoading: false,
    error: null,
    sections: [],
    estimatedScenes: 0,
    estimatedDuration: 0
  },

  // Video configuration
  videoConfig: {
    videoId: '',
    title: '',
    mode: 'single',        // 'single' | 'set'
    videoCount: 1,
    languageMode: 'single',
    targetLanguages: ['en'],
    languageVoices: { 'en': ['en-US-JennyNeural'] },
    aspectRatio: '16:9',
    accentColor: 'blue',
    duration: 120,
    useAiNarration: true,
    narration: { enabled: true, style: 'professional', speed: 1.0 },
    slides: [],
    customizations: {},
    selectedPreset: null
  },

  // Languages state
  languages: {
    available: [],
    selected: ['en'],
    isLoading: false,
    error: null,
    lastFetched: null
  },

  // Voices state
  voices: {
    byLanguage: {},
    selected: { 'en': [] },
    isLoading: {},
    error: null,
    previewing: null
  },

  // Progress state
  progress: {
    isProcessing: false,
    taskId: null,
    currentStage: null,
    progress: 0,
    stages: [...],
    timeElapsed: 0,
    timeRemaining: null,
    startTime: null,
    error: null,
    result: null
  },

  // UI state
  ui: {
    activeSection: 'input',
    showPreview: false,
    showProgress: false,
    sidebarCollapsed: false,
    darkMode: false,
    toasts: [],
    notifications: [],
    modals: { ... },
    loading: { ... }
  }
})
```

## Accessing State

### From Alpine Components

```html
<!-- Direct access -->
<div x-data>
  <span x-text="$store.appState.currentStep"></span>
</div>

<!-- With reactivity -->
<div x-data x-effect="console.log($store.appState.progress.progress)">
  Progress: <span x-text="$store.appState.progress.progress + '%'"></span>
</div>
```

### From JavaScript

```javascript
// Get store reference
const store = Alpine.store('appState');

// Read values
console.log(store.currentStep);
console.log(store.languages.selected);

// Call methods
store.selectLanguage('es');
store.startProgress('task-123');
```

## Updating State

### Direct Updates

```javascript
// Simple values
Alpine.store('appState').currentStep = 2;

// Nested values
Alpine.store('appState').videoConfig.title = 'My Video';

// Arrays
Alpine.store('appState').languages.selected.push('fr');
```

### Using Store Methods (Recommended)

```javascript
const store = Alpine.store('appState');

// Navigation
store.goToStep(2);
store.nextStep();
store.previousStep();

// Input management
store.selectInputMethod('youtube');
store.setInputFile(file, content);
store.setInputURL('https://youtube.com/watch?v=...');
store.clearInput();

// Language management
store.selectLanguage('es');
store.deselectLanguage('es');
store.toggleLanguage('fr');

// Voice management
store.setVoicesForLanguage('en', voicesArray);
store.selectVoice('en', 'voice-id');
store.deselectVoice('en', 'voice-id');

// Progress management
store.startProgress('task-123');
store.updateProgress({ stage: 'rendering', progress: 75 });
store.completeProgress({ videoUrl: '/output/video.mp4' });
store.failProgress('Network error');
store.cancelProgress();

// Preview management
store.setPreview(data, 'document');
store.setPreviewLoading(true);
store.setPreviewError('Failed to load');
store.clearPreview();

// Validation
store.validateState();

// Persistence
store.saveToStorage();
store.loadFromStorage();
store.clearStorage();

// Reset
store.reset();
```

## Persistence

### What Gets Persisted

The following state is saved to localStorage:
- `currentStep`
- `maxStepReached`
- `selectedInputMethod`
- `videoConfig` (full object)
- `languages.selected`
- `voices.selected`
- `ui.darkMode`
- `ui.sidebarCollapsed`

### What Does NOT Get Persisted

Session-only state:
- `input.file` (File objects can't be serialized)
- `input.content` (too large)
- `preview.data`
- `progress.*` (regenerated each session)
- `ui.notifications`
- `ui.toasts`

### Storage Options

```javascript
// Using StorageManager (recommended)
window.storage.set('key', value, ttl);
window.storage.get('key', defaultValue);
window.storage.has('key');
window.storage.remove('key');
window.storage.clear();

// Get storage stats
const stats = window.storage.getStats();
console.log(stats.totalSizeKB);
```

## Event Bus

### Standard Events

```javascript
// Event types are defined in EventTypes constant
const { EventTypes } = window;

// Input events
EventTypes.INPUT_FILE_SELECTED    // 'input:file-selected'
EventTypes.INPUT_FILE_VALIDATED   // 'input:file-validated'
EventTypes.INPUT_URL_CHANGED      // 'input:url-changed'
EventTypes.INPUT_CLEARED          // 'input:cleared'

// Preview events
EventTypes.PREVIEW_LOADING        // 'preview:loading'
EventTypes.PREVIEW_LOADED         // 'preview:loaded'
EventTypes.PREVIEW_ERROR          // 'preview:error'

// Language events
EventTypes.LANGUAGE_SELECTED      // 'language:selected'
EventTypes.LANGUAGES_LOADED       // 'languages:loaded'

// Progress events
EventTypes.PROGRESS_STARTED       // 'progress:started'
EventTypes.PROGRESS_UPDATED       // 'progress:updated'
EventTypes.PROGRESS_COMPLETED     // 'progress:completed'
EventTypes.PROGRESS_FAILED        // 'progress:failed'

// UI events
EventTypes.UI_TOAST_SHOW          // 'ui:toast-show'
EventTypes.UI_STEP_CHANGED        // 'ui:step-changed'
```

### Using the Event Bus

```javascript
// Subscribe to events
const unsubscribe = window.eventBus.on('progress:updated', (data) => {
  console.log('Progress:', data.progress);
});

// Subscribe once
window.eventBus.once('progress:completed', (data) => {
  console.log('Done!', data.result);
});

// Emit events
window.eventBus.emit('input:file-selected', { file: myFile });

// Unsubscribe
unsubscribe();
// or
window.eventBus.off('progress:updated', handler);

// Clear all listeners
window.eventBus.clear();
window.eventBus.clear('progress:*'); // Clear specific namespace
```

### Wildcard Subscriptions

```javascript
// Listen to all events in a namespace
window.eventBus.on('progress:*', (data, eventName) => {
  console.log(`Event ${eventName}:`, data);
});

// Listen to ALL events (debugging)
window.eventBus.on('*', (data, eventName) => {
  console.log(`[${eventName}]`, data);
});
```

### Using from Alpine Components

```html
<div x-data x-init="
  $on('language:selected', (data) => {
    console.log('Language selected:', data.langCode);
  });
">
  <button @click="$emit('language:selected', { langCode: 'es' })">
    Select Spanish
  </button>
</div>
```

## API Client

### Basic Usage

```javascript
// Document operations
const validation = await window.api.document.validate(file);
const preview = await window.api.document.preview(file);

// YouTube operations
const ytValidation = await window.api.youtube.validate(url);
const ytPreview = await window.api.youtube.preview(url, true);

// Language operations
const languages = await window.api.languages.list();
const voices = await window.api.languages.getVoices('en');

// Task operations
const status = await window.api.tasks.getStatus('task-123');
await window.api.tasks.cancel('task-123');
```

### Error Handling

```javascript
try {
  const result = await window.api.document.validate(file);
} catch (error) {
  if (error instanceof APIError) {
    if (error.isValidationError) {
      // Handle 400 errors
      console.log('Validation failed:', error.details);
    } else if (error.isServerError) {
      // Handle 5xx errors
      window.errorHandler.handle(error);
    }
  }
}
```

### Caching

```javascript
// GET requests are cached by default (1 minute TTL)
const languages = await window.api.languages.list();

// Skip cache
const fresh = await window.api.get('/api/languages', { useCache: false });

// Invalidate cache
window.api.invalidateCache('/api/languages');
window.api.invalidateCache(); // Clear all
```

## Error Handling

### Using ErrorHandler

```javascript
// Handle an error
window.errorHandler.handle(error, {
  component: 'DragDropZone',
  showToast: true
});

// Show a toast
window.errorHandler.showToast('File uploaded successfully', 'success');
window.errorHandler.showToast('Invalid format', 'error');

// Get error history
const recentErrors = window.errorHandler.getHistory(10);
```

### Error Categories

- `network` - Connection issues
- `timeout` - Request timed out
- `validation` - 400 errors
- `unauthorized` - 401 errors
- `forbidden` - 403 errors
- `notFound` - 404 errors
- `server` - 5xx errors
- `unknown` - Other errors

## Best Practices

### 1. Use Store Methods

```javascript
// Good - uses method with side effects
store.selectLanguage('es');

// Avoid - direct mutation misses side effects
store.languages.selected.push('es');
```

### 2. Subscribe to Events for Cross-Component Communication

```javascript
// In LanguageSelector
store.selectLanguage('es');

// In VoiceSelector (reacts automatically)
window.eventBus.on('language:selected', async ({ langCode }) => {
  const voices = await window.api.languages.getVoices(langCode);
  store.setVoicesForLanguage(langCode, voices);
});
```

### 3. Handle Errors Consistently

```javascript
// Always use errorHandler for user-facing errors
try {
  await riskyOperation();
} catch (error) {
  window.errorHandler.handle(error, {
    component: 'MyComponent'
  });
}
```

### 4. Clean Up Event Listeners

```javascript
// Store unsubscribe function
const unsubscribe = window.eventBus.on('event', handler);

// Call on component destroy
unsubscribe();
```

### 5. Use Type-Safe Event Names

```javascript
// Good - uses constant
window.eventBus.emit(EventTypes.PROGRESS_UPDATED, data);

// Avoid - magic string
window.eventBus.emit('progress:updated', data);
```

## Debugging

### Enable Debug Mode

```javascript
// Event bus
window.eventBus.setDebug(true);

// Error handler
window.errorHandler.setDebug(true);
```

### Inspect State

```javascript
// Get summary
console.log(Alpine.store('appState').getSummary());

// Export full state
console.log(Alpine.store('appState').exportState());

// Storage stats
console.log(window.storage.getStats());

// Event bus stats
console.log(window.eventBus.getStats());
```

### Common Issues

1. **State not updating**: Make sure you're using Alpine-reactive updates
2. **Events not firing**: Check event name spelling and listener registration
3. **Storage not persisting**: Check browser localStorage settings
4. **API errors**: Check network tab and error handler history

---

## Migration from v1.x

If upgrading from v1.x, the following changes apply:

1. **Namespace changes**:
   - `formData.document.file` -> `input.file`
   - `generation.*` -> `progress.*` (legacy still works)

2. **New namespaces**:
   - `preview.*` - Preview panel state
   - `languages.*` - Language selection
   - `voices.*` - Voice selection

3. **Method changes**:
   - `startGeneration()` -> `startProgress(taskId)`
   - `updateGenerationProgress()` -> `updateProgress(data)`

Legacy methods are preserved for backward compatibility.
