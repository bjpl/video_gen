# UI Components - video_gen

Reusable template components extracted from `create.html` for the UI redesign.

## Component Inventory

### 1. `input-selector.html`
**Purpose:** Content source selection
- Supports 4 input types: manual, document, YouTube, YAML
- Uses Alpine.js reactive state with mode parameter
- Fully responsive grid layout

**Usage:**
```html
{% include 'components/input-selector.html' with mode='single' %}
```

**Parameters:**
- `mode`: 'single' or 'set'

---

### 2. `document-form.html`
**Purpose:** Document path/URL input
- File path or GitHub repository URL input
- Smart defaults detection (P1 feature)
- Content-type badge showing detected document type

**Usage:**
```html
{% include 'components/document-form.html' with mode='single' %}
```

**Parameters:**
- `mode`: 'single' or 'set'

**Features:**
- P1: Detects content type and applies smart defaults
- Validation for file paths and URLs
- Accessible input with aria-labels

---

### 3. `youtube-form.html`
**Purpose:** YouTube URL input
- Adapts placeholder based on mode (video vs playlist)
- URL validation
- Contextual help text

**Usage:**
```html
{% include 'components/youtube-form.html' with mode='single' %}
```

**Parameters:**
- `mode`: 'single' or 'set'

---

### 4. `language-selector.html`
**Purpose:** Language configuration
- Single-language mode: Simple picker
- Multiple-language mode: Source + target languages + translation method
- Quick preset buttons (EN+ES, European, Asian)
- Grid layout with checkboxes for language selection

**Usage:**
```html
{% include 'components/language-selector.html' with mode='single' %}
```

**Parameters:**
- `mode`: 'single' or 'set'

**Features:**
- 28+ language support
- Translation method selector (Claude API vs Google Translate)
- Visual language grid with 4-column layout

---

### 5. `video-config.html`
**Purpose:** Global video settings
- Duration slider (30-300s)
- AI enhancement toggle with cost info
- Accent color selector (6 colors with psychology tooltips)
- P1: Recommended badges for optimal settings

**Usage:**
```html
{% include 'components/video-config.html' with mode='single' %}
```

**Parameters:**
- `mode`: 'single' or 'set'

**Features:**
- P1: Recommended badges for AI narration and colors
- BETA badge on AI enhancement
- API key requirement notice (conditional display)
- Color psychology tooltips

---

### 6. `preset-cards.html`
**Purpose:** Preset packages (P1 feature)
- 3 presets: Corporate, Creative, Educational
- Each includes: icon, features list, cost badge, expandable use cases
- Selection state management
- Manual configuration fallback

**Usage:**
```html
{% include 'components/preset-cards.html' %}
```

**Presets:**
1. **Corporate**: 4 languages, professional voice, blue theme
2. **Creative**: 1 language, warm voice, purple theme
3. **Educational**: 2 languages, friendly voice, green theme

**Features:**
- P1: Smart defaults applied on preset selection
- Cost estimation per preset
- Expandable use cases (5+ examples per preset)
- Visual selection state with hover effects

---

### 7. `generation-summary.html`
**Purpose:** Configuration summary display
- Shows selected input method, duration, voice tracks, languages
- Visual badges for enabled features (AI, multilingual, multi-voice)
- 2x2 grid layout

**Usage:**
```html
{% include 'components/generation-summary.html' with mode='single' %}
```

**Parameters:**
- `mode`: 'single' or 'set'

**Features:**
- Real-time reactive updates via Alpine.js
- Visual badges for enabled features
- Clean card-based layout

---

## Design Patterns

### Alpine.js Integration
All components use Alpine.js directives:
- `x-model`: Two-way data binding
- `x-show`: Conditional display
- `x-text`: Dynamic text content
- `@click`: Event handlers
- `:class`: Dynamic CSS classes

### Accessibility
- Semantic HTML
- ARIA labels on inputs
- Keyboard navigation support
- Screen reader friendly

### Responsive Design
- Tailwind CSS utility classes
- Grid layouts with responsive breakpoints
- Mobile-first approach

### P1 Improvements Preserved
- Smart defaults detection
- Recommended badges
- Cost estimation
- Time estimation
- Preset packages
- Content type detection

---

## Next Steps

1. **CSS Extraction**: Extract component-specific styles to separate file
2. **JavaScript Extraction**: Extract Alpine.js logic to shared functions
3. **Validation Library**: Create validation utilities for forms
4. **Component Testing**: Add unit tests for each component
5. **Storybook Integration**: Document component variations

---

## Component Dependencies

### Shared State (Alpine.js)
Components rely on shared Alpine.js state:
- `allLanguages`: Language list
- `getVoicesForLang()`: Voice lookup function
- `toggleLanguage()`: Language selection handler
- `detectAndApplyDefaults()`: Smart defaults function
- `isRecommended()`: Recommendation logic

### CSS Dependencies
- Tailwind CSS utility classes
- Custom component styles (to be extracted)
- P1 preset styles

---

**Created:** 2025-11-17
**UI Redesign Sprint**
**Component Extraction Specialist Agent**
