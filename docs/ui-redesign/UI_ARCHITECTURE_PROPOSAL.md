# UI Architecture Redesign Proposal

**Date:** November 17, 2025
**Objective:** Clean, modern UI aligned with backend architecture and CLI patterns

---

## 🎯 Current State Analysis

### Problems Identified:

**1. Fragmented UI Flow**
- ❌ `create.html` (2,572 lines) - Monolithic, hard to maintain
- ❌ `builder.html` (927 lines) - Duplicate of create with different UX
- ❌ Two paths to same goal (confusing)
- ❌ No clear alignment with backend's unified pipeline

**2. Architectural Mismatch**
- ✅ **CLI:** Single entry point (`create_video.py`) → choose input method → configure → generate
- ✅ **Backend:** Unified pipeline → adapters → stages → output
- ❌ **UI:** Multiple entry points, unclear flow, doesn't mirror architecture

**3. Mixed Paradigms**
- HTMX + Alpine.js + Vanilla JS + jQuery (all mixed)
- Inconsistent state management
- Duplicate code across templates

---

## ✨ Proposed Architecture

### Core Principle: **Mirror the CLI's Unified Entry Point**

```
┌──────────────────────────────────────────────────────┐
│              UNIFIED VIDEO CREATION                  │
│                                                      │
│  Step 1: Choose Input Method                        │
│    📄 Document  |  📺 YouTube  |  🧙 Wizard  |  📋 YAML │
│                                                      │
│  Step 2: Input-Specific Configuration               │
│    [Dynamic form based on selected method]          │
│                                                      │
│  Step 3: Video Configuration                        │
│    [Common settings: voice, language, duration]     │
│                                                      │
│  Step 4: Review & Generate                          │
│    [Preview + Generate button]                      │
│                                                      │
│  Step 5: Monitor Progress                           │
│    [Real-time pipeline stage tracking]              │
└──────────────────────────────────────────────────────┘
```

---

## 🏗️ New Page Structure

### **Page 1: Home (`/`)** - 100 lines
**Purpose:** Landing page with clear value proposition

**Content:**
- Hero: "Professional Videos from Any Source"
- 4 Input Methods as cards (Document, YouTube, Wizard, YAML)
- Each card → navigates to unified creation flow
- Quick stats: "6-stage pipeline, 29 languages, 12 scene types"

---

### **Page 2: Create (`/create`)** - 400 lines max
**Purpose:** Unified creation workflow (replaces both create.html and builder.html)

**Layout:**
```
┌────────────────────────────────────────┐
│ Progress: [1]─[2]─[3]─[4]             │ ← Wizard-style stepper
├────────────────────────────────────────┤
│                                        │
│  [Dynamic content based on step]       │
│                                        │
│  Step 1: Input Method Selection        │
│    📄 Document  📺 YouTube  🧙 Wizard   │
│                                        │
│  [Back]                    [Continue]  │
└────────────────────────────────────────┘
```

**Components (extracted, reusable):**
- `<input-method-selector>` - Choose method
- `<document-input>` - Document-specific fields
- `<youtube-input>` - YouTube-specific fields
- `<wizard-input>` - Wizard-specific fields
- `<video-config>` - Common configuration
- `<language-selector>` - Multilingual options
- `<generation-summary>` - Review before generation

---

### **Page 3: Jobs (`/jobs`)** - 200 lines
**Purpose:** Monitor generation progress (replaces progress.html)

**Features:**
- Real-time pipeline stage tracking
- Job queue status
- Download/preview completed videos
- Error handling with retry

**Layout mirrors CLI output:**
```
🎬 Active Jobs (2)
├─ video_001 [████████░░] 80% - Stage 5/6: Rendering
└─ video_002 [███░░░░░░░] 30% - Stage 2/6: Generating Audio

✅ Completed (5)
📋 Queued (0)
```

---

### **Page 4: Advanced (`/advanced`)** - 300 lines
**Purpose:** Direct pipeline access for power users

**Features:**
- Direct API access
- Custom scene builder
- Template management
- Batch operations

---

## 🎨 Design System

### **Component Architecture**

**1. Reusable Components (Alpine.js)**
```javascript
// components/input-selector.js
Alpine.data('inputSelector', () => ({
    method: null,
    methods: ['document', 'youtube', 'wizard', 'yaml'],
    select(method) { this.method = method }
}))
```

**2. Page-Level Orchestration (HTMX)**
- Progressive enhancement
- Server-side rendering
- SEO-friendly
- No heavy client-side frameworks

**3. Styling (Tailwind CSS)**
- Consistent spacing system
- Predefined color palette matching accent colors
- Component classes extracted to CSS
- Dark mode support

---

## 📋 New Route Structure

### Simplified Routes:

```python
# UI Pages
GET  /                  → Home (input method selection)
GET  /create            → Unified creation workflow
GET  /jobs              → Job monitoring
GET  /advanced          → Power user features

# API Endpoints (unchanged)
POST /api/generate      → Generate video
POST /api/parse/*       → Parse inputs
GET  /api/tasks/:id     → Task status
GET  /api/videos/jobs   → Job list
```

---

## 🔄 Data Flow (Aligned with Backend)

```
UI Step 1: Input Method
    ↓
[User selects: Document]
    ↓
UI Step 2: Document Input
    ↓
POST /api/parse/document → DocumentAdapter
    ↓
UI Step 3: Review Parsed Structure
    ↓
UI Step 4: Configure (voice, language, color)
    ↓
POST /api/generate → Pipeline (6 stages)
    ↓
UI Step 5: Monitor Progress (real-time)
    ↓
Download/Preview
```

---

## 🎯 Benefits

### **For Users:**
- ✅ Single clear path (no confusion between create/builder)
- ✅ Matches CLI mental model (familiar for developers)
- ✅ Progressive disclosure (only show relevant options)
- ✅ Fast, responsive, modern

### **For Maintenance:**
- ✅ Small, focused templates (100-400 lines each)
- ✅ Reusable components
- ✅ Aligned with backend architecture
- ✅ Easy to test and extend

### **Technical:**
- ✅ Clean separation of concerns
- ✅ Consistent state management
- ✅ One JS paradigm (Alpine.js for reactivity)
- ✅ HTMX for progressive enhancement
- ✅ No build step required

---

## 📦 Component Breakdown

### Extracted from create.html (2,572 lines):

**New Structure:**
```
templates/
├── pages/
│   ├── home.html (100 lines)
│   ├── create.html (400 lines)
│   ├── jobs.html (200 lines)
│   └── advanced.html (300 lines)
├── components/
│   ├── input-selector.html (50 lines)
│   ├── document-form.html (80 lines)
│   ├── youtube-form.html (80 lines)
│   ├── wizard-form.html (100 lines)
│   ├── video-config.html (120 lines)
│   ├── language-selector.html (100 lines)
│   ├── preset-cards.html (80 lines)
│   └── generation-summary.html (60 lines)
└── base.html (150 lines)

static/js/
├── core/
│   ├── state-manager.js (Alpine store)
│   ├── api-client.js (fetch wrapper)
│   └── validation.js
├── components/
│   ├── input-selector.js
│   ├── video-config.js
│   ├── presets.js
│   └── cost-estimator.js
└── utils/
    ├── formatters.js
    └── helpers.js
```

---

## 🚀 Implementation Plan

### Phase 1: Foundation (Day 1)
- ✅ Create design system (colors, spacing, typography)
- ✅ Build base layout with navigation
- ✅ Extract reusable components from existing templates
- ✅ Establish Alpine.js state management pattern

### Phase 2: Core Pages (Day 2)
- ✅ New home page (input method selection)
- ✅ Unified create flow (wizard-style stepper)
- ✅ Jobs/monitoring page
- ✅ Component library

### Phase 3: Advanced Features (Day 3)
- ✅ Advanced/power user page
- ✅ Template management
- ✅ Batch operations
- ✅ API documentation integration

### Phase 4: Polish & Testing (Day 4)
- ✅ Accessibility audit (WCAG AA)
- ✅ Performance optimization
- ✅ Cross-browser testing
- ✅ Documentation updates

---

## 🎨 Visual Design Principles

1. **Clean & Minimal**
   - White space is good
   - One primary action per screen
   - Progressive disclosure

2. **Modern Conventions**
   - Card-based layouts
   - Inline validation
   - Loading states
   - Toast notifications

3. **Architecture-Aligned**
   - UI mirrors 6-stage pipeline visually
   - Input methods match adapters
   - Scene types clearly mapped

4. **Command-Line Inspired**
   - Terminal-like aesthetics (optional dark theme)
   - Clear step-by-step flow like CLI args
   - Keyboard shortcuts
   - Quick actions

---

## 📐 Example: New Create Page Structure

```html
<!-- create.html - ~400 lines total -->
<div x-data="createWorkflow()">
    <!-- Progress Stepper -->
    <nav class="stepper">
        <step :active="currentStep === 1">1. Input</step>
        <step :active="currentStep === 2">2. Configure</step>
        <step :active="currentStep === 3">3. Review</step>
        <step :active="currentStep === 4">4. Generate</step>
    </nav>

    <!-- Step 1: Input Method -->
    <div x-show="currentStep === 1">
        {% include 'components/input-selector.html' %}
    </div>

    <!-- Step 2: Method-Specific Input -->
    <div x-show="currentStep === 2">
        <div x-show="inputMethod === 'document'">
            {% include 'components/document-form.html' %}
        </div>
        <div x-show="inputMethod === 'youtube'">
            {% include 'components/youtube-form.html' %}
        </div>
        <!-- etc -->
    </div>

    <!-- Step 3: Video Configuration -->
    <div x-show="currentStep === 3">
        {% include 'components/video-config.html' %}
    </div>

    <!-- Step 4: Review & Generate -->
    <div x-show="currentStep === 4">
        {% include 'components/generation-summary.html' %}
    </div>
</div>
```

---

## 🔑 Key Decisions

1. **Single Creation Flow** - Merge create.html + builder.html → one wizard
2. **Component Extraction** - Break 2,572 lines into 8-10 reusable components
3. **State Management** - Alpine.js store for consistent state across steps
4. **API-First** - UI is thin layer over existing API endpoints
5. **Progressive Enhancement** - Works without JS, enhanced with JS

---

## Next Steps

**Ready to proceed with implementation?**

I'll start by:
1. Creating the new page structure
2. Extracting components from existing templates
3. Building the unified creation workflow
4. Migrating features to clean, modular architecture

**Estimated time:** 4-6 hours with testing
**Impact:** 60% reduction in code, 10x easier to maintain, fully aligned with architecture
