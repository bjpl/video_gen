# UI Alignment Architecture

**Date:** October 11, 2025
**Project:** video_gen - Professional Video Generation System
**Purpose:** Comprehensive architecture for achieving 100% UI/API feature parity
**Current Parity:** 60% → **Target:** 100%

---

## Executive Summary

### Goals

This architecture document provides detailed technical specifications for bringing the Video Builder UI to **full feature parity** with the Programmatic API. The API supports 12 scene types with rich parameters, 4 voices with rotation patterns, multilingual expansion, and advanced duration controls. The UI currently implements ~60% of these features.

**Primary Objectives:**
1. Unlock all 12 scene types with complete visual_content forms
2. Expose scene-level duration controls (min/max)
3. Clarify voice rotation patterns for users
4. Enhance AI narration toggle with cost/benefit information
5. Integrate multilingual configuration into Builder
6. Maintain backward compatibility with existing workflows

**Success Metrics:**
- Feature parity: 60% → 100%
- Scene type forms: 6/12 → 12/12
- User clarity: +40% (measured via tooltips, labels, explanations)
- Zero breaking changes to existing functionality

### Scope

**In Scope:**
- Builder UI enhancements (scene forms, duration controls)
- Quick Start UI clarifications (voice rotation, AI narration)
- Both pages: Color psychology, multilingual integration
- Testing strategy for all new components

**Out of Scope:**
- Backend API changes (API is complete)
- New scene type creation (12 types are sufficient)
- Major redesign of existing UI patterns
- Mobile-specific optimizations (desktop-first)

---

## Component Architecture

### Architecture Overview Diagram

```
┌────────────────────────────────────────────────────────────────────┐
│                     UI ALIGNMENT ARCHITECTURE                       │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ QUICK START (/create)                                        │  │
│  │ ┌────────────┬────────────┬──────────────┬─────────────────┐│  │
│  │ │ Voice      │ Duration   │ AI Narration │ Multilingual    ││  │
│  │ │ Rotation   │ Controls   │ Clarity      │ (COMPLETE)      ││  │
│  │ │ Explainer  │ (Global)   │ Enhancement  │                 ││  │
│  │ │ [NEW]      │ [EXISTING] │ [ENHANCE]    │ [EXISTING]      ││  │
│  │ └────────────┴────────────┴──────────────┴─────────────────┘│  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                │                                   │
│                                ▼                                   │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ BUILDER (/builder)                                           │  │
│  │ ┌───────────────────────────────────────────────────────────┐│  │
│  │ │ SCENE FORMS (12 Types)                                    ││  │
│  │ │ ┌──────────┬──────────┬──────────┬──────────┬───────────┐││  │
│  │ │ │ title    │ command  │ list     │ outro    │ quiz      │││  │
│  │ │ │ [EXISTS] │ [EXISTS] │ [EXISTS] │ [EXISTS] │ [EXISTS]  │││  │
│  │ │ └──────────┴──────────┴──────────┴──────────┴───────────┘││  │
│  │ │ ┌──────────┬──────────┬──────────┬──────────┬───────────┐││  │
│  │ │ │ code_    │ quote    │ learning_│ problem  │ solution  │││  │
│  │ │ │ compare  │ [NEW]    │ obj [NEW]│ [ENHANCE]│ [NEW]     │││  │
│  │ │ │ [NEW]    │          │          │          │           │││  │
│  │ │ └──────────┴──────────┴──────────┴──────────┴───────────┘││  │
│  │ │ ┌──────────┬──────────┐                                  ││  │
│  │ │ │ exercise │checkpoint│                                  ││  │
│  │ │ │ [NEW]    │ [NEW]    │                                  ││  │
│  │ │ └──────────┴──────────┘                                  ││  │
│  │ └───────────────────────────────────────────────────────────┘│  │
│  │ ┌───────────────────────────────────────────────────────────┐│  │
│  │ │ DURATION CONTROLS (Per-Scene)                             ││  │
│  │ │ [min_duration] [max_duration] [info tooltip]  [ALL NEW]  ││  │
│  │ └───────────────────────────────────────────────────────────┘│  │
│  │ ┌───────────────────────────────────────────────────────────┐│  │
│  │ │ VOICE CONTROLS (Per-Scene)                                ││  │
│  │ │ [voice dropdown] [rotation pattern info]  [ENHANCE]      ││  │
│  │ └───────────────────────────────────────────────────────────┘│  │
│  │ ┌───────────────────────────────────────────────────────────┐│  │
│  │ │ MULTILINGUAL CONFIG                                       ││  │
│  │ │ [language mode] [target languages] [voice per lang] [NEW]││  │
│  │ └───────────────────────────────────────────────────────────┘│  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ SHARED COMPONENTS (Both Pages)                               │  │
│  │ ┌────────────────┬──────────────────┬─────────────────────┐ │  │
│  │ │ Color Palette  │ Export to YAML   │ Voice Preview      │ │  │
│  │ │ + Tooltips     │ (Code View)      │ Buttons            │ │  │
│  │ │ [ENHANCE]      │ [NEW - Phase 4]  │ [ENHANCE]          │ │  │
│  │ └────────────────┴──────────────────┴─────────────────────┘ │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  OUTPUT: 100% Feature Parity, Zero Breaking Changes                │
└────────────────────────────────────────────────────────────────────┘
```

### Component Breakdown

#### 1. Scene Type Forms (Builder)

**Current State:**
- 6/12 types have complete forms (title, command, list, outro, quiz, slide)
- 6/12 types use generic text area fallback (code_comparison, quote, learning_objectives, problem, solution, exercise, checkpoint)

**Architecture:**

```
SceneFormComponent
├── SceneTypeSelector (existing - 12 buttons)
├── DynamicSceneForm (new - conditional rendering)
│   ├── TitleSceneForm (existing)
│   ├── CommandSceneForm (existing)
│   ├── ListSceneForm (existing)
│   ├── OutroSceneForm (existing)
│   ├── QuizSceneForm (existing)
│   ├── CodeComparisonForm (NEW)
│   ├── QuoteForm (NEW)
│   ├── LearningObjectivesForm (NEW - enhanced)
│   ├── ProblemForm (NEW - enhanced with difficulty)
│   ├── SolutionForm (NEW - code + explanation split)
│   ├── ExerciseForm (NEW - instructions + hints)
│   └── CheckpointForm (NEW - two-column layout)
├── DurationControls (NEW - injected into all forms)
├── VoiceSelector (existing - enhanced with rotation info)
└── SceneActionButtons (existing - move/delete)
```

**Key Decisions:**
1. Use Alpine.js `x-if` directives for conditional form rendering
2. Each scene form is self-contained template block
3. All forms inject duration controls at bottom (consistent pattern)
4. Validation happens on submit, not field-level (keep UI simple)

#### 2. Duration Controls Component

**New Component:** DurationControlsWidget

```html
<!-- Injected into every scene form -->
<div class="duration-controls">
    <div class="grid grid-cols-2 gap-3">
        <div>
            <label>Min Duration (s) <span class="info-icon">ℹ️</span></label>
            <input type="number" x-model.number="scene.min_duration"
                   min="1" max="60" step="0.5" placeholder="3.0">
        </div>
        <div>
            <label>Max Duration (s) <span class="info-icon">ℹ️</span></label>
            <input type="number" x-model.number="scene.max_duration"
                   min="1" max="60" step="0.5" placeholder="15.0">
        </div>
    </div>
    <p class="help-text">System generates audio, then adjusts to fit range</p>
</div>
```

**Alpine.js Integration:**
```javascript
// In sceneBuilder() function
addScene(type) {
    const sceneTemplate = {
        type: type,
        voice: 'male',
        min_duration: 3.0,  // NEW - default
        max_duration: 15.0  // NEW - default
        // ... type-specific fields
    };
    this.scenes.push(sceneTemplate);
}
```

**Validation Logic:**
```javascript
validateSceneDuration(scene) {
    if (scene.min_duration > scene.max_duration) {
        return { valid: false, error: 'Min must be ≤ max' };
    }
    if (scene.min_duration < 1 || scene.max_duration > 60) {
        return { valid: false, error: 'Duration must be 1-60 seconds' };
    }
    return { valid: true };
}
```

#### 3. Voice Rotation Explainer (Quick Start)

**New Component:** VoiceRotationInfoBox

```html
<!-- Inserted after multi-voice tracks section in create.html -->
<div class="voice-rotation-explainer bg-blue-50 border border-blue-200 rounded-lg p-4">
    <div class="font-semibold text-sm text-blue-900 mb-2 flex items-center gap-2">
        <span>🔄</span>
        <span>How Voice Rotation Works</span>
    </div>
    <div class="text-xs text-blue-800 space-y-2">
        <div class="grid grid-cols-2 gap-3">
            <div>
                <strong>1 Track:</strong> Same voice for all scenes
                <div class="font-mono text-xs bg-blue-100 px-2 py-1 mt-1 rounded">
                    Male → Male → Male
                </div>
            </div>
            <div>
                <strong>2 Tracks:</strong> Alternates between voices
                <div class="font-mono text-xs bg-blue-100 px-2 py-1 mt-1 rounded">
                    Male → Female → Male
                </div>
            </div>
        </div>
        <div>
            <strong>3+ Tracks:</strong> Rotates through all voices in order
            <div class="font-mono text-xs bg-blue-100 px-2 py-1 mt-1 rounded">
                Male → Female → Brandon → Ava → Male...
            </div>
        </div>
    </div>
    <div class="mt-3 pt-3 border-t border-blue-200 text-xs text-blue-700 italic">
        💡 Perfect for: Conversations, interviews, multi-speaker tutorials
    </div>
</div>
```

**Placement:** After line 724 in create.html (after voice tracks section, before AI enhancement)

#### 4. AI Narration Clarity Enhancement (Quick Start)

**Current Label:** "AI-Enhanced Narration" (misleading - sounds like TTS upgrade)

**Improved Component:**

```html
<!-- Replace existing toggle section (lines ~730-740 in create.html) -->
<div class="ai-narration-section">
    <!-- Toggle -->
    <label class="flex items-start gap-3 cursor-pointer">
        <input type="checkbox" x-model="single.useAI" class="mt-1">
        <div>
            <div class="font-medium text-sm flex items-center gap-2">
                <span>Claude AI Script Enhancement</span>
                <span class="bg-yellow-100 text-yellow-800 px-2 py-0.5 text-xs rounded-full">
                    BETA
                </span>
            </div>
            <div class="text-xs text-gray-600 mt-1">
                Improves narration script quality and naturalness
            </div>
            <div class="text-xs text-gray-500 mt-1 flex items-center gap-2">
                <span>💰 ~$0.03/video</span>
                <span>•</span>
                <span>⏱️ +3-5s per scene</span>
            </div>
        </div>
    </label>

    <!-- API Key Notice (shown when enabled) -->
    <div x-show="single.useAI"
         x-transition
         class="mt-3 p-3 bg-yellow-50 border border-yellow-200 rounded-lg text-xs">
        <div class="flex items-start gap-2">
            <span class="text-yellow-600">⚠️</span>
            <div>
                <strong>Requires ANTHROPIC_API_KEY</strong>
                <div class="mt-1 text-gray-600">
                    Set in environment variables or .env file
                </div>
                <a href="/docs/api#ai-narration"
                   target="_blank"
                   class="text-blue-600 hover:underline mt-1 inline-block">
                    Learn more →
                </a>
            </div>
        </div>
    </div>
</div>
```

**Key Changes:**
1. Renamed: "AI-Enhanced Narration" → "Claude AI Script Enhancement"
2. Added cost/time information prominently
3. Conditional API key notice when enabled
4. Learn more link to documentation

#### 5. Multilingual Configuration (Builder)

**New Section:** Add to builder.html after Video Information panel (after line 73)

```html
<!-- Multilingual Configuration Section -->
<div class="bg-white rounded-lg shadow-md p-6 mb-8">
    <h3 class="text-lg font-semibold text-gray-900 mb-4">
        🌍 Multilingual Settings
        <span class="text-sm font-normal text-gray-500 ml-2">(Optional)</span>
    </h3>

    <!-- Language Mode Toggle -->
    <div class="mb-4">
        <label class="flex items-center gap-2 cursor-pointer">
            <input type="checkbox"
                   x-model="videoSet.multilingualEnabled"
                   class="rounded">
            <span class="text-sm font-medium">Generate in multiple languages</span>
        </label>
    </div>

    <!-- Multilingual Options (shown when enabled) -->
    <div x-show="videoSet.multilingualEnabled"
         x-transition
         class="space-y-4 pl-6 border-l-2 border-blue-300">

        <!-- Source Language -->
        <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">
                Source Language
            </label>
            <select x-model="videoSet.sourceLanguage"
                    class="w-full px-4 py-2 border border-gray-300 rounded-lg">
                <option value="en">English</option>
                <option value="es">Spanish</option>
                <option value="fr">French</option>
                <option value="de">German</option>
                <!-- Add all 28+ languages -->
            </select>
        </div>

        <!-- Target Languages (Multi-select) -->
        <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">
                Target Languages (select multiple)
            </label>
            <div class="grid grid-cols-3 gap-2">
                <template x-for="lang in availableLanguages" :key="lang.code">
                    <label class="flex items-center gap-2 text-sm cursor-pointer">
                        <input type="checkbox"
                               :value="lang.code"
                               x-model="videoSet.targetLanguages">
                        <span x-text="lang.name"></span>
                    </label>
                </template>
            </div>
        </div>

        <!-- Quick Presets -->
        <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">
                Quick Presets
            </label>
            <div class="flex gap-2">
                <button @click="setLanguagePreset('en_es')"
                        class="px-3 py-1 text-xs bg-gray-100 hover:bg-gray-200 rounded">
                    EN + ES
                </button>
                <button @click="setLanguagePreset('european')"
                        class="px-3 py-1 text-xs bg-gray-100 hover:bg-gray-200 rounded">
                    European (EN/ES/FR/DE)
                </button>
                <button @click="setLanguagePreset('global')"
                        class="px-3 py-1 text-xs bg-gray-100 hover:bg-gray-200 rounded">
                    Global (EN/ES/FR/DE/PT/IT)
                </button>
            </div>
        </div>

        <!-- Output Count Preview -->
        <div class="bg-blue-50 border border-blue-200 rounded p-3 text-sm">
            <strong>Output:</strong>
            <span x-text="videoSet.targetLanguages.length || 0"></span> languages
            = <span x-text="videoSet.targetLanguages.length || 0"></span> videos
        </div>
    </div>
</div>
```

**Alpine.js Data:**
```javascript
// Add to sceneBuilder() return object
multilingualEnabled: false,
sourceLanguage: 'en',
targetLanguages: [],
availableLanguages: [
    { code: 'en', name: 'English' },
    { code: 'es', name: 'Spanish' },
    { code: 'fr', name: 'French' },
    { code: 'de', name: 'German' },
    // ... all 28 languages
],

setLanguagePreset(preset) {
    if (preset === 'en_es') {
        this.targetLanguages = ['en', 'es'];
    } else if (preset === 'european') {
        this.targetLanguages = ['en', 'es', 'fr', 'de'];
    } else if (preset === 'global') {
        this.targetLanguages = ['en', 'es', 'fr', 'de', 'pt', 'it'];
    }
}
```

---

## Implementation Phases

### Phase 1: Critical Gaps (Week 1) - HIGH PRIORITY

**Goal:** Unlock 50% more API features in Builder

**Tasks:**

1. **Scene-Specific Forms (6 new + 1 enhanced)**
   - Priority: CRITICAL
   - Files: `app/templates/builder.html`
   - Lines: ~236-242 (insert new templates)
   - Estimated effort: 8 hours

   ```html
   <!-- Add after existing scene forms -->

   <!-- 1. Code Comparison Form -->
   <template x-if="scene.type === 'code_comparison'">
       <div class="space-y-3">
           <div class="grid grid-cols-2 gap-3">
               <input type="text"
                      x-model="scene.before_label"
                      placeholder="Before Label (default: Before)"
                      class="px-3 py-2 border rounded">
               <input type="text"
                      x-model="scene.after_label"
                      placeholder="After Label (default: After)"
                      class="px-3 py-2 border rounded">
           </div>
           <div class="grid grid-cols-2 gap-3">
               <div>
                   <label class="block text-xs text-gray-600 mb-1">Original Code</label>
                   <textarea x-model="scene.before_code"
                             rows="8"
                             placeholder="def old():\n    pass"
                             class="w-full px-3 py-2 border rounded font-mono text-sm"></textarea>
               </div>
               <div>
                   <label class="block text-xs text-gray-600 mb-1">Refactored Code</label>
                   <textarea x-model="scene.after_code"
                             rows="8"
                             placeholder="def new():\n    return True"
                             class="w-full px-3 py-2 border rounded font-mono text-sm"></textarea>
               </div>
           </div>
           <p class="text-xs text-gray-500">💡 Max 10 lines per side for readability</p>
       </div>
   </template>

   <!-- 2. Quote Form -->
   <template x-if="scene.type === 'quote'">
       <div class="space-y-3">
           <textarea x-model="scene.quote_text"
                     rows="4"
                     placeholder="Quote text (e.g., 'Code is like humor...')"
                     class="w-full px-3 py-2 border rounded"></textarea>
           <input type="text"
                  x-model="scene.attribution"
                  placeholder="Attribution (optional, e.g., 'Cory House')"
                  class="w-full px-3 py-2 border rounded">
       </div>
   </template>

   <!-- 3. Learning Objectives Form (Enhanced) -->
   <template x-if="scene.type === 'learning_objectives'">
       <div class="space-y-3">
           <input type="text"
                  x-model="scene.title"
                  placeholder="Lesson Title (e.g., 'Lesson Goals')"
                  class="w-full px-3 py-2 border rounded">
           <div>
               <label class="block text-xs text-gray-600 mb-1">
                   Learning Objectives (one per line, max 5)
               </label>
               <textarea x-model="scene.objectives"
                         rows="5"
                         placeholder="Understand variables&#10;Use basic data types&#10;Write simple functions"
                         class="w-full px-3 py-2 border rounded"></textarea>
           </div>
           <p class="text-xs text-gray-500">
               ℹ️ Each line becomes a bullet point (max 5 for readability)
           </p>
       </div>
   </template>

   <!-- 4. Problem Form (Enhanced with Difficulty) -->
   <template x-if="scene.type === 'problem'">
       <div class="space-y-3">
           <input type="text"
                  x-model="scene.title"
                  placeholder="Problem Title (e.g., 'Reverse a String')"
                  class="w-full px-3 py-2 border rounded">
           <textarea x-model="scene.problem_text"
                     rows="4"
                     placeholder="Problem description"
                     class="w-full px-3 py-2 border rounded"></textarea>
           <div>
               <label class="block text-xs font-medium text-gray-700 mb-1">
                   Difficulty (affects accent color in scene)
               </label>
               <select x-model="scene.difficulty"
                       class="w-full px-3 py-2 border rounded">
                   <option value="easy">🟢 Easy (Green accent)</option>
                   <option value="medium">🟡 Medium (Orange accent)</option>
                   <option value="hard">🔴 Hard (Red accent)</option>
               </select>
           </div>
       </div>
   </template>

   <!-- 5. Solution Form (Code + Explanation Split) -->
   <template x-if="scene.type === 'solution'">
       <div class="space-y-3">
           <div>
               <label class="block text-xs font-medium text-gray-700 mb-1">
                   Solution Code (one line per line, max 12)
               </label>
               <textarea x-model="scene.code"
                         rows="8"
                         placeholder="def reverse_string(s):&#10;    return s[::-1]"
                         class="w-full px-3 py-2 border rounded font-mono text-sm"></textarea>
           </div>
           <div>
               <label class="block text-xs font-medium text-gray-700 mb-1">
                   Explanation
               </label>
               <textarea x-model="scene.explanation"
                         rows="3"
                         placeholder="Explain how the solution works"
                         class="w-full px-3 py-2 border rounded"></textarea>
           </div>
       </div>
   </template>

   <!-- 6. Exercise Form (Instructions + Hints) -->
   <template x-if="scene.type === 'exercise'">
       <div class="space-y-3">
           <input type="text"
                  x-model="scene.title"
                  placeholder="Exercise Title (e.g., 'Practice: Variables')"
                  class="w-full px-3 py-2 border rounded">
           <div>
               <label class="block text-xs font-medium text-gray-700 mb-1">
                   Instructions
               </label>
               <textarea x-model="scene.instructions"
                         rows="3"
                         placeholder="What the learner should do (e.g., 'Create three variables: name, age, city')"
                         class="w-full px-3 py-2 border rounded"></textarea>
           </div>
           <div>
               <label class="block text-xs font-medium text-gray-700 mb-1">
                   Hints (one per line, max 3)
               </label>
               <textarea x-model="scene.hints"
                         rows="3"
                         placeholder="Use descriptive names&#10;age should be an integer&#10;Use quotes for strings"
                         class="w-full px-3 py-2 border rounded"></textarea>
           </div>
       </div>
   </template>

   <!-- 7. Checkpoint Form (Two-Column Layout) -->
   <template x-if="scene.type === 'checkpoint'">
       <div class="space-y-3">
           <div class="grid grid-cols-2 gap-3">
               <div>
                   <label class="block text-xs font-medium text-gray-700 mb-1">
                       ✓ Learned Topics (max 6)
                   </label>
                   <textarea x-model="scene.learned_topics"
                             rows="6"
                             placeholder="Variables&#10;Data types&#10;Functions"
                             class="w-full px-3 py-2 border rounded"></textarea>
               </div>
               <div>
                   <label class="block text-xs font-medium text-gray-700 mb-1">
                       → Next Topics (max 6)
                   </label>
                   <textarea x-model="scene.next_topics"
                             rows="6"
                             placeholder="Classes&#10;Modules&#10;File I/O"
                             class="w-full px-3 py-2 border rounded"></textarea>
               </div>
           </div>
           <p class="text-xs text-gray-500">
               ℹ️ Left column: what was covered. Right column: what's coming next.
           </p>
       </div>
   </template>
   ```

   **JavaScript Updates (builder.html, ~lines 300-325):**
   ```javascript
   addScene(type) {
       const sceneTemplate = {
           type: type,
           voice: 'male',
           min_duration: 3.0,  // NEW
           max_duration: 15.0  // NEW
       };

       // Add type-specific defaults
       if (type === 'title') {
           sceneTemplate.title = '';
           sceneTemplate.subtitle = '';
       } else if (type === 'command') {
           sceneTemplate.title = '';
           sceneTemplate.description = '';
           sceneTemplate.commands = '';
       } else if (type === 'list') {
           sceneTemplate.title = '';
           sceneTemplate.items = '';
       } else if (type === 'outro') {
           sceneTemplate.message = '';
           sceneTemplate.cta = '';
       } else if (type === 'code_comparison') {
           sceneTemplate.before_code = '';
           sceneTemplate.after_code = '';
           sceneTemplate.before_label = 'Before';
           sceneTemplate.after_label = 'After';
       } else if (type === 'quote') {
           sceneTemplate.quote_text = '';
           sceneTemplate.attribution = '';
       } else if (type === 'learning_objectives') {
           sceneTemplate.title = '';
           sceneTemplate.objectives = '';
       } else if (type === 'problem') {
           sceneTemplate.title = '';
           sceneTemplate.problem_text = '';
           sceneTemplate.difficulty = 'medium';
       } else if (type === 'solution') {
           sceneTemplate.code = '';
           sceneTemplate.explanation = '';
       } else if (type === 'exercise') {
           sceneTemplate.title = '';
           sceneTemplate.instructions = '';
           sceneTemplate.hints = '';
       } else if (type === 'checkpoint') {
           sceneTemplate.learned_topics = '';
           sceneTemplate.next_topics = '';
       } else if (type === 'quiz') {
           sceneTemplate.question = '';
           sceneTemplate.options = '';
           sceneTemplate.answer = '';
       }

       this.scenes.push(sceneTemplate);
   }
   ```

2. **Scene Duration Controls (All Forms)**
   - Priority: CRITICAL
   - Files: `app/templates/builder.html`
   - Lines: Inject after each scene form's visual_content fields
   - Estimated effort: 2 hours

   ```html
   <!-- Add this block AFTER visual_content fields in EVERY scene type -->
   <div class="pt-3 mt-3 border-t border-gray-200">
       <div class="text-xs font-medium text-gray-600 mb-2">
           ⏱️ Duration Control
       </div>
       <div class="grid grid-cols-2 gap-3">
           <div>
               <label class="block text-xs text-gray-600 mb-1">
                   Min Duration (s)
               </label>
               <input type="number"
                      x-model.number="scene.min_duration"
                      min="1" max="60" step="0.5"
                      placeholder="3.0"
                      class="w-full px-3 py-2 text-sm border rounded">
           </div>
           <div>
               <label class="block text-xs text-gray-600 mb-1">
                   Max Duration (s)
               </label>
               <input type="number"
                      x-model.number="scene.max_duration"
                      min="1" max="60" step="0.5"
                      placeholder="15.0"
                      class="w-full px-3 py-2 text-sm border rounded">
           </div>
       </div>
       <p class="text-xs text-gray-500 mt-1">
           ℹ️ System generates audio, then adjusts to fit duration range
       </p>
   </div>
   ```

3. **Voice Rotation Explainer (Quick Start)**
   - Priority: HIGH
   - Files: `app/templates/create.html`
   - Lines: ~724 (after voice tracks, before AI enhancement)
   - Estimated effort: 1 hour

   ```html
   <!-- Insert after multi-voice tracks section -->
   <div class="mt-4 p-4 bg-blue-50 border border-blue-200 rounded-lg">
       <div class="font-semibold text-sm text-blue-900 mb-3 flex items-center gap-2">
           <span>🔄</span>
           <span>How Voice Rotation Works</span>
       </div>
       <div class="space-y-2 text-xs text-blue-800">
           <div class="grid grid-cols-2 gap-4">
               <div>
                   <strong>1 Track:</strong> Same voice for all scenes
                   <div class="mt-1 p-2 bg-blue-100 rounded font-mono text-xs">
                       Male → Male → Male
                   </div>
               </div>
               <div>
                   <strong>2 Tracks:</strong> Alternates between voices
                   <div class="mt-1 p-2 bg-blue-100 rounded font-mono text-xs">
                       Male → Female → Male
                   </div>
               </div>
           </div>
           <div>
               <strong>3+ Tracks:</strong> Rotates through all voices in order
               <div class="mt-1 p-2 bg-blue-100 rounded font-mono text-xs">
                   Male → Female → Brandon → Ava → Male...
               </div>
           </div>
       </div>
       <div class="mt-3 pt-3 border-t border-blue-200 text-xs text-blue-700 italic">
           💡 Perfect for: Conversations, interviews, multi-speaker tutorials
       </div>
   </div>
   ```

**Deliverables:**
- ✅ All 12 scene types have complete forms
- ✅ Duration controls in every scene form
- ✅ Voice rotation explained to users
- ✅ Tests for new scene form validation

**Success Criteria:**
- Users can create all 12 scene types in Builder
- Scene min/max duration persists to API correctly
- Voice rotation pattern is clear to 90%+ of users (measured via tooltip interactions)

---

### Phase 2: Enhanced UX (Week 2) - MEDIUM PRIORITY

**Goal:** Improve user understanding and confidence

**Tasks:**

1. **AI Narration Clarity Enhancement**
   - Priority: MEDIUM
   - Files: `app/templates/create.html`
   - Lines: ~730-740 (replace existing toggle)
   - Estimated effort: 1 hour

   ```html
   <!-- Replace existing AI enhancement section -->
   <div class="ai-narration-toggle">
       <label class="flex items-start gap-3 cursor-pointer p-3 border rounded-lg hover:bg-gray-50 transition-colors">
           <input type="checkbox"
                  x-model="single.useAI"
                  class="mt-1">
           <div class="flex-1">
               <div class="font-medium text-sm flex items-center gap-2">
                   <span>Claude AI Script Enhancement</span>
                   <span class="bg-yellow-100 text-yellow-800 px-2 py-0.5 text-xs rounded-full font-semibold">
                       BETA
                   </span>
               </div>
               <div class="text-xs text-gray-600 mt-1">
                   Improves narration script quality and naturalness using Claude AI
               </div>
               <div class="text-xs text-gray-500 mt-2 flex items-center gap-3">
                   <span class="flex items-center gap-1">
                       <span>💰</span>
                       <span>~$0.03/video</span>
                   </span>
                   <span>•</span>
                   <span class="flex items-center gap-1">
                       <span>⏱️</span>
                       <span>+3-5s per scene</span>
                   </span>
               </div>
           </div>
       </label>

       <!-- API Key Notice (conditional) -->
       <div x-show="single.useAI"
            x-transition
            class="mt-3 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
           <div class="flex items-start gap-2 text-xs">
               <span class="text-yellow-600 text-base">⚠️</span>
               <div class="flex-1">
                   <div class="font-semibold text-yellow-900">
                       Requires ANTHROPIC_API_KEY
                   </div>
                   <div class="text-gray-700 mt-1">
                       Set environment variable or add to .env file
                   </div>
                   <a href="/docs/api#ai-narration"
                      target="_blank"
                      class="text-blue-600 hover:underline mt-2 inline-flex items-center gap-1">
                       <span>Learn more about AI narration</span>
                       <span>→</span>
                   </a>
               </div>
           </div>
       </div>
   </div>
   ```

2. **Multilingual Configuration (Builder)**
   - Priority: MEDIUM
   - Files: `app/templates/builder.html`
   - Lines: ~73 (after Video Information section)
   - Estimated effort: 3 hours

   [See Component Architecture section 5 for full implementation]

3. **Quick Start Scene Preview**
   - Priority: MEDIUM (lower than multilingual)
   - Files: `app/templates/create.html`
   - Lines: After generation config, before submit
   - Estimated effort: 4 hours

   ```html
   <!-- Scene Preview Panel (shown after parsing document/YAML) -->
   <div x-show="scenes.length > 0"
        class="mt-6 bg-white rounded-lg shadow-md p-6">
       <h3 class="text-lg font-semibold mb-4">
           Parsed Scenes (<span x-text="scenes.length"></span>)
       </h3>

       <!-- Scene List -->
       <div class="space-y-3 max-h-96 overflow-y-auto">
           <template x-for="(scene, index) in scenes" :key="index">
               <div class="border rounded-lg p-3 bg-gray-50">
                   <div class="flex items-center justify-between mb-2">
                       <div class="flex items-center gap-2">
                           <span class="text-sm font-medium text-gray-500">
                               #<span x-text="index + 1"></span>
                           </span>
                           <span class="text-lg" x-text="getSceneIcon(scene.type)"></span>
                           <span class="font-medium" x-text="getSceneName(scene.type)"></span>
                       </div>
                       <button @click="editSceneInBuilder(index)"
                               class="text-xs text-blue-600 hover:underline">
                           Edit in Builder →
                       </button>
                   </div>
                   <div class="text-sm text-gray-600" x-text="scene.narration"></div>
               </div>
           </template>
       </div>

       <div class="mt-4 text-xs text-gray-500">
           💡 Scenes can be edited in the Builder for full control
       </div>
   </div>
   ```

**Deliverables:**
- ✅ AI narration toggle clearly labeled with cost/time
- ✅ Multilingual config in Builder (matches Quick Start)
- ✅ Scene preview in Quick Start (with edit links)

---

### Phase 3: Polish (Week 3) - LOW PRIORITY

**Goal:** Professional polish and user education

**Tasks:**

1. **Color Psychology Tooltips**
   - Priority: LOW
   - Files: Both `create.html` and `builder.html`
   - Estimated effort: 2 hours

   ```html
   <!-- Enhanced color button with tooltip (Quick Start) -->
   <button @click="single.color = 'blue'"
           x-data="{ showTip: false }"
           @mouseenter="showTip = true"
           @mouseleave="showTip = false"
           class="relative w-12 h-12 rounded-lg bg-blue-500 hover:scale-110 transition-transform">
       <!-- Tooltip -->
       <div x-show="showTip"
            x-transition
            class="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-3 py-2 bg-gray-900 text-white text-xs rounded shadow-lg whitespace-nowrap z-10 pointer-events-none">
           <div class="font-semibold">Blue: Professional</div>
           <div class="text-gray-300 text-xs">Best for: Corporate, Finance</div>
       </div>
   </button>

   <!-- Repeat for all 6 colors with appropriate text -->
   ```

   **Tooltip Content:**
   ```javascript
   const colorTooltips = {
       blue: {
           title: 'Blue: Professional',
           desc: 'Best for: Corporate, Finance, Healthcare'
       },
       orange: {
           title: 'Orange: Energetic',
           desc: 'Best for: Creative, Marketing, Youth'
       },
       purple: {
           title: 'Purple: Premium',
           desc: 'Best for: High-end, Creative, Spiritual'
       },
       green: {
           title: 'Green: Success',
           desc: 'Best for: Environmental, Health, Finance'
       },
       pink: {
           title: 'Pink: Playful',
           desc: 'Best for: Youth, Creative, Lifestyle'
       },
       cyan: {
           title: 'Cyan: Tech',
           desc: 'Best for: Technology, Science, Modern'
       }
   };
   ```

2. **Voice Preview Buttons (Builder)**
   - Priority: LOW
   - Files: `app/templates/builder.html`
   - Lines: ~244-249 (voice selector)
   - Estimated effort: 1 hour

   ```html
   <!-- Enhanced voice selector with preview -->
   <div class="flex items-center gap-2">
       <select x-model="scene.voice"
               class="flex-1 px-3 py-2 border border-gray-300 rounded text-sm">
           <option value="male">Andrew (Male)</option>
           <option value="male_warm">Brandon (Male Warm)</option>
           <option value="female">Aria (Female)</option>
           <option value="female_friendly">Ava (Female Friendly)</option>
       </select>
       <button @click="previewVoice(scene.voice)"
               class="px-3 py-2 bg-gray-100 hover:bg-gray-200 rounded text-sm">
           🔊
       </button>
   </div>
   ```

   **JavaScript:**
   ```javascript
   previewVoice(voice) {
       const audio = new Audio(`/static/audio/voice_samples/${voice}.mp3`);
       audio.play();
   }
   ```

3. **Duration Logic Explanation**
   - Priority: LOW
   - Files: Both UI files
   - Estimated effort: 30 minutes

   ```html
   <!-- Info icon with explanation -->
   <span class="info-icon cursor-help"
         title="System generates TTS audio, measures duration, then adjusts scene length to fit within min/max range. Adds silence if too short, speeds up slightly if too long.">
       ℹ️
   </span>
   ```

**Deliverables:**
- ✅ Color tooltips with psychology info
- ✅ Voice preview in Builder
- ✅ Duration logic tooltips

---

### Phase 4: Power User Features (Week 4) - NICE TO HAVE

**Goal:** API discoverability and programmatic adoption

**Tasks:**

1. **Export as YAML/Code View**
   - Priority: NICE TO HAVE
   - Files: Both `create.html` and `builder.html`
   - Estimated effort: 4 hours

   ```html
   <!-- Add button next to "Generate Video" -->
   <button @click="showCodeView = !showCodeView"
           class="px-4 py-2 bg-gray-100 hover:bg-gray-200 rounded-lg text-sm font-medium">
       <span x-show="!showCodeView">View as Code</span>
       <span x-show="showCodeView">Hide Code</span>
   </button>

   <!-- Code View Modal/Panel -->
   <div x-show="showCodeView"
        x-transition
        class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
       <div class="bg-white rounded-lg p-6 max-w-4xl w-full max-h-[90vh] overflow-y-auto">
           <div class="flex items-center justify-between mb-4">
               <h3 class="text-lg font-semibold">VideoConfig (Programmatic API)</h3>
               <button @click="showCodeView = false" class="text-gray-500 hover:text-gray-700">
                   ✕
               </button>
           </div>

           <!-- YAML Output -->
           <div class="mb-4">
               <div class="flex items-center justify-between mb-2">
                   <span class="text-sm font-medium">YAML Format</span>
                   <button @click="copyToClipboard('yaml')"
                           class="text-xs bg-blue-100 hover:bg-blue-200 px-2 py-1 rounded">
                       Copy
                   </button>
               </div>
               <pre class="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto text-xs font-mono"><code x-text="generateYAML()"></code></pre>
           </div>

           <!-- Python Code -->
           <div>
               <div class="flex items-center justify-between mb-2">
                   <span class="text-sm font-medium">Python Code</span>
                   <button @click="copyToClipboard('python')"
                           class="text-xs bg-blue-100 hover:bg-blue-200 px-2 py-1 rounded">
                       Copy
                   </button>
               </div>
               <pre class="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto text-xs font-mono"><code x-text="generatePythonCode()"></code></pre>
           </div>
       </div>
   </div>
   ```

   **JavaScript:**
   ```javascript
   generateYAML() {
       // Convert videoSet + scenes to YAML format
       return YAML.stringify({
           video_id: this.videoSet.set_id,
           title: this.videoSet.set_name,
           accent_color: this.videoSet.accent_color,
           scenes: this.scenes.map(s => ({
               scene_id: s.type + '_' + this.scenes.indexOf(s),
               scene_type: s.type,
               narration: s.narration || '',
               visual_content: this.extractVisualContent(s),
               voice: s.voice,
               min_duration: s.min_duration,
               max_duration: s.max_duration
           }))
       });
   }

   generatePythonCode() {
       return `from video_gen.shared.models import VideoConfig, SceneConfig

video = VideoConfig(
    video_id="${this.videoSet.set_id}",
    title="${this.videoSet.set_name}",
    description="Generated from UI",
    accent_color="${this.videoSet.accent_color}",
    scenes=[
${this.scenes.map((s, i) => this.generateSceneCode(s, i)).join(',\n')}
    ]
)`;
   }
   ```

**Deliverables:**
- ✅ Export to YAML button
- ✅ Export to Python code button
- ✅ Copy to clipboard functionality

---

## Technical Details

### HTML/Alpine.js Patterns

#### 1. Conditional Form Rendering

```html
<!-- Pattern: Use x-if for exclusive rendering (only one scene form visible) -->
<template x-if="scene.type === 'title'">
    <!-- Title form -->
</template>
<template x-if="scene.type === 'command'">
    <!-- Command form -->
</template>
<!-- Benefits: Clean separation, no CSS display:none, better performance -->
```

#### 2. Data Binding Patterns

```javascript
// Pattern: Nested object for scene data
scene = {
    type: 'title',
    voice: 'male',
    min_duration: 3.0,
    max_duration: 15.0,
    // Type-specific fields (flat structure, not nested)
    title: '',
    subtitle: ''
}

// Anti-pattern: Don't nest visual_content in UI
// ❌ scene.visual_content.title
// ✅ scene.title (flatten for easier binding)

// Transform on submit:
transformSceneForAPI(scene) {
    return {
        scene_id: scene.type + '_' + index,
        scene_type: scene.type,
        narration: scene.narration || this.generateNarration(scene),
        visual_content: this.extractVisualContent(scene),
        voice: scene.voice,
        min_duration: scene.min_duration,
        max_duration: scene.max_duration
    };
}
```

#### 3. Array/String Transformation

```javascript
// Pattern: Store as string in UI, split to array on submit
// UI: textarea with newline-separated values
scene.commands = "pip install fastapi\npip install uvicorn";

// On submit:
transformedScenes = this.scenes.map(scene => {
    const transformed = { ...scene };

    // Convert string arrays to actual arrays
    if (scene.commands && typeof scene.commands === 'string') {
        transformed.commands = scene.commands.split('\n').filter(c => c.trim());
    }
    if (scene.items && typeof scene.items === 'string') {
        transformed.items = scene.items.split('\n').filter(i => i.trim());
    }
    if (scene.objectives && typeof scene.objectives === 'string') {
        transformed.objectives = scene.objectives.split('\n').filter(o => o.trim());
    }
    if (scene.hints && typeof scene.hints === 'string') {
        transformed.hints = scene.hints.split('\n').filter(h => h.trim());
    }
    if (scene.learned_topics && typeof scene.learned_topics === 'string') {
        transformed.learned_topics = scene.learned_topics.split('\n').filter(t => t.trim());
    }
    if (scene.next_topics && typeof scene.next_topics === 'string') {
        transformed.next_topics = scene.next_topics.split('\n').filter(t => t.trim());
    }

    return transformed;
});
```

### API Integration Points

#### 1. Scene Validation Endpoint

**New:** `POST /api/validate-scene`

```python
@app.post("/api/validate-scene")
async def validate_scene(scene: dict):
    """Validate scene configuration before generation"""
    try:
        # Check scene_type
        valid_types = ['title', 'command', 'list', 'outro', 'code_comparison',
                      'quote', 'learning_objectives', 'quiz', 'exercise',
                      'problem', 'solution', 'checkpoint']
        if scene.get('type') not in valid_types:
            return {"valid": False, "error": f"Invalid scene type: {scene.get('type')}"}

        # Check visual_content requirements per type
        scene_type = scene['type']
        visual_content = extract_visual_content(scene)

        required_keys = {
            'title': ['title', 'subtitle'],
            'command': ['header', 'label', 'commands'],
            'list': ['header', 'description', 'items'],
            # ... all 12 types
        }

        missing = []
        for key in required_keys.get(scene_type, []):
            if key not in visual_content or not visual_content[key]:
                missing.append(key)

        if missing:
            return {"valid": False, "error": f"Missing required fields: {', '.join(missing)}"}

        # Check duration constraints
        if scene.get('min_duration', 0) > scene.get('max_duration', 100):
            return {"valid": False, "error": "Min duration must be ≤ max duration"}

        return {"valid": True}

    except Exception as e:
        return {"valid": False, "error": str(e)}
```

**Frontend Usage:**
```javascript
async validateScene(scene) {
    const response = await fetch('/api/validate-scene', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scene)
    });
    const result = await response.json();
    if (!result.valid) {
        alert('Scene validation failed: ' + result.error);
        return false;
    }
    return true;
}

async generateVideo() {
    // Validate all scenes first
    for (const scene of this.scenes) {
        if (!await this.validateScene(scene)) {
            return; // Stop if any scene invalid
        }
    }
    // Proceed with generation...
}
```

#### 2. Multilingual Expansion Endpoint

**Existing:** `POST /api/generate` (supports `languages` parameter)

**Frontend Usage:**
```javascript
async generateVideo() {
    const payload = {
        set_id: this.videoSet.set_id,
        set_name: this.videoSet.set_name,
        accent_color: this.videoSet.accent_color,
        videos: [{
            video_id: this.videoSet.set_id,
            title: this.videoSet.set_name,
            scenes: this.transformScenes()
        }]
    };

    // Add languages if multilingual enabled
    if (this.videoSet.multilingualEnabled && this.videoSet.targetLanguages.length > 0) {
        payload.languages = this.videoSet.targetLanguages;
    }

    const response = await fetch('/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });

    // ... handle response
}
```

---

## Workflow Diagrams

### 1. Scene Creation Workflow

```
User Opens Builder
       │
       ▼
┌──────────────────┐
│ Select Scene Type│ ← 12 buttons (left sidebar)
└──────────────────┘
       │
       ▼
┌──────────────────────────────────────────────┐
│ Scene Form Renders (conditional on type)     │
│ ┌──────────────────────────────────────────┐ │
│ │ Type-Specific Fields                     │ │
│ │ (title/subtitle, code, etc.)             │ │
│ └──────────────────────────────────────────┘ │
│ ┌──────────────────────────────────────────┐ │
│ │ Duration Controls (min/max) [INJECTED]   │ │
│ └──────────────────────────────────────────┘ │
│ ┌──────────────────────────────────────────┐ │
│ │ Voice Selector (dropdown + rotation info)│ │
│ └──────────────────────────────────────────┘ │
└──────────────────────────────────────────────┘
       │
       ▼
User Fills Form
       │
       ▼
Scene Added to List (right panel)
       │
       ▼
User Can:
├─ Reorder (↑↓ buttons)
├─ Edit (click to expand)
└─ Delete (× button)
       │
       ▼
Generate Video Button
       │
       ▼
┌──────────────────┐
│ Validate All     │ → If invalid: Show error, stop
│ Scenes           │ → If valid: Proceed
└──────────────────┘
       │
       ▼
Transform to API Format
       │
       ▼
POST /api/generate
       │
       ▼
SSE Progress Stream → Loading Modal → Complete
```

### 2. Voice Selection Workflow

```
Quick Start Mode
       │
       ▼
┌─────────────────────┐
│ Voice Configuration │
└─────────────────────┘
       │
       ├─ Single Language Mode
       │  └─ Add Voice Tracks (1-4)
       │     └─ Select voice per track
       │        └─ [NEW] Rotation Explainer Box Appears
       │           "1 track = same voice"
       │           "2 tracks = alternates"
       │           "3+ tracks = rotates in order"
       │
       └─ Multiple Language Mode
          └─ Select languages (checkboxes)
             └─ For each language:
                └─ Select voice (dropdown)
                   └─ Preview button (🔊)

Builder Mode (Per-Scene)
       │
       ▼
Scene Form
       │
       └─ Voice Dropdown (4 options)
          ├─ Andrew (Male) - Professional
          ├─ Brandon (Male Warm) - Engaging
          ├─ Aria (Female) - Clear
          └─ Ava (Female Friendly) - Pleasant
          │
          └─ [NEW] Preview Button (🔊)
             └─ Plays sample audio

Rotation Logic (Backend)
       │
       ▼
If video.voices = ["male", "female"]:
   Scene 1 → male
   Scene 2 → female
   Scene 3 → male
   Scene 4 → female

If scene.voice is set:
   Override rotation, use scene.voice
```

### 3. Duration Control Workflow

```
Scene Form (Builder)
       │
       ▼
┌────────────────────────────┐
│ Type-Specific Fields       │ ← User fills content
└────────────────────────────┘
       │
       ▼
┌────────────────────────────┐
│ Duration Controls [NEW]    │
│ ┌────────┬────────┐        │
│ │ Min (s)│ Max (s)│        │
│ │ [3.0]  │ [15.0] │ ← Defaults shown
│ └────────┴────────┘        │
│ ℹ️ Tooltip: "System      │
│    generates audio, then   │
│    adjusts to fit range"   │
└────────────────────────────┘
       │
       ▼
User Optionally Adjusts
(e.g., min=5.0, max=10.0)
       │
       ▼
Scene Saved with Duration
       │
       ▼
On Generation:
       │
       ├─ Backend generates TTS audio
       │  └─ Measures actual duration (e.g., 7.2s)
       │
       ├─ Check against min/max
       │  ├─ If 7.2s in [5.0, 10.0] → Use 7.2s
       │  ├─ If 2.0s < 5.0 → Pad to 5.0s
       │  └─ If 12.0s > 10.0 → Speed up to 10.0s
       │
       └─ Final scene duration set
```

### 4. Multilingual Generation Workflow

```
Builder UI
       │
       ▼
┌───────────────────────────────┐
│ Multilingual Settings [NEW]   │
│ ┌──────────────────────────┐  │
│ │ ☑ Enable Multilingual    │  │
│ └──────────────────────────┘  │
└───────────────────────────────┘
       │ (when checked)
       ▼
┌───────────────────────────────┐
│ Source Language: [English ▼]  │
│                                │
│ Target Languages:              │
│ ☑ English  ☑ Spanish           │
│ ☑ French   ☐ German            │
│ ☐ Portuguese                   │
│                                │
│ Quick Presets:                 │
│ [EN+ES] [European] [Global]    │
│                                │
│ Output: 3 languages = 3 videos │
└───────────────────────────────┘
       │
       ▼
User Selects 3 Languages (EN, ES, FR)
       │
       ▼
Generate Video Button
       │
       ▼
Transform to API Format:
{
    set_id: "my_video",
    videos: [{ ... }],
    languages: ["en", "es", "fr"]  ← Added
}
       │
       ▼
POST /api/generate
       │
       ▼
Backend Pipeline:
       │
       ├─ Stage 1: Parse (1 video)
       │
       ├─ Stage 2: Expand Languages
       │  ├─ my_video_en (English)
       │  ├─ my_video_es (Spanish - translated)
       │  └─ my_video_fr (French - translated)
       │
       ├─ Stage 3-6: Render each video
       │  └─ Same visuals, translated narration
       │
       └─ Output: 3 complete videos
```

---

## Testing Strategy

### Unit Tests (Per Component)

#### 1. Scene Form Validation Tests

```python
# tests/ui/test_scene_forms.py
import pytest
from app.api.validation import validate_scene_config

class TestSceneForms:

    def test_code_comparison_form_valid(self):
        """Test code_comparison scene with all required fields"""
        scene = {
            'type': 'code_comparison',
            'before_code': 'def old(): pass',
            'after_code': 'def new(): return True',
            'before_label': 'Before',
            'after_label': 'After',
            'min_duration': 3.0,
            'max_duration': 15.0,
            'voice': 'male'
        }
        result = validate_scene_config(scene)
        assert result['valid'] == True

    def test_code_comparison_form_missing_code(self):
        """Test code_comparison with missing before_code"""
        scene = {
            'type': 'code_comparison',
            'after_code': 'def new(): return True',
            'before_label': 'Before',
            'after_label': 'After'
        }
        result = validate_scene_config(scene)
        assert result['valid'] == False
        assert 'before_code' in result['error']

    def test_quote_form_valid(self):
        """Test quote scene with required fields"""
        scene = {
            'type': 'quote',
            'quote_text': 'Code is like humor',
            'attribution': 'Cory House',
            'min_duration': 4.0,
            'max_duration': 8.0,
            'voice': 'female'
        }
        result = validate_scene_config(scene)
        assert result['valid'] == True

    def test_problem_form_difficulty_colors(self):
        """Test problem scene difficulty affects color"""
        for difficulty in ['easy', 'medium', 'hard']:
            scene = {
                'type': 'problem',
                'title': 'Test Problem',
                'problem_text': 'Solve this',
                'difficulty': difficulty
            }
            result = validate_scene_config(scene)
            assert result['valid'] == True

    def test_duration_validation(self):
        """Test min_duration <= max_duration constraint"""
        scene = {
            'type': 'title',
            'title': 'Test',
            'subtitle': 'Test',
            'min_duration': 10.0,
            'max_duration': 5.0  # Invalid: min > max
        }
        result = validate_scene_config(scene)
        assert result['valid'] == False
        assert 'min' in result['error'].lower()
```

#### 2. Voice Rotation Tests

```python
# tests/ui/test_voice_rotation.py
import pytest
from app.api.generation import apply_voice_rotation

class TestVoiceRotation:

    def test_single_voice_rotation(self):
        """Test 1 voice = same voice for all scenes"""
        voices = ['male']
        scenes = [{'id': 1}, {'id': 2}, {'id': 3}]
        result = apply_voice_rotation(voices, scenes)
        assert result[0]['voice'] == 'male'
        assert result[1]['voice'] == 'male'
        assert result[2]['voice'] == 'male'

    def test_two_voice_alternation(self):
        """Test 2 voices = alternates"""
        voices = ['male', 'female']
        scenes = [{'id': 1}, {'id': 2}, {'id': 3}, {'id': 4}]
        result = apply_voice_rotation(voices, scenes)
        assert result[0]['voice'] == 'male'
        assert result[1]['voice'] == 'female'
        assert result[2]['voice'] == 'male'
        assert result[3]['voice'] == 'female'

    def test_four_voice_rotation(self):
        """Test 4 voices = rotates through all"""
        voices = ['male', 'male_warm', 'female', 'female_friendly']
        scenes = [{'id': i} for i in range(8)]
        result = apply_voice_rotation(voices, scenes)
        # First 4 scenes
        assert result[0]['voice'] == 'male'
        assert result[1]['voice'] == 'male_warm'
        assert result[2]['voice'] == 'female'
        assert result[3]['voice'] == 'female_friendly'
        # Second cycle
        assert result[4]['voice'] == 'male'
        assert result[5]['voice'] == 'male_warm'

    def test_per_scene_override(self):
        """Test scene.voice overrides rotation"""
        voices = ['male', 'female']
        scenes = [
            {'id': 1},
            {'id': 2, 'voice': 'male_warm'},  # Override
            {'id': 3}
        ]
        result = apply_voice_rotation(voices, scenes)
        assert result[0]['voice'] == 'male'
        assert result[1]['voice'] == 'male_warm'  # Override respected
        assert result[2]['voice'] == 'male'  # Continues rotation
```

#### 3. Multilingual Expansion Tests

```python
# tests/ui/test_multilingual_expansion.py
import pytest
from app.pipeline.stages.multilingual import expand_languages

class TestMultilingualExpansion:

    @pytest.mark.asyncio
    async def test_single_video_three_languages(self):
        """Test 1 video × 3 languages = 3 outputs"""
        video = {'video_id': 'test', 'scenes': [...]}
        languages = ['en', 'es', 'fr']

        result = await expand_languages(video, languages)

        assert len(result) == 3
        assert result[0]['video_id'] == 'test_en'
        assert result[1]['video_id'] == 'test_es'
        assert result[2]['video_id'] == 'test_fr'

    @pytest.mark.asyncio
    async def test_video_set_multilingual(self):
        """Test 3 videos × 2 languages = 6 outputs"""
        video_set = {
            'set_id': 'course',
            'videos': [
                {'video_id': 'lesson_01', 'scenes': [...]},
                {'video_id': 'lesson_02', 'scenes': [...]},
                {'video_id': 'lesson_03', 'scenes': [...]}
            ]
        }
        languages = ['en', 'es']

        result = await expand_languages(video_set, languages)

        assert len(result) == 6
        assert result[0]['video_id'] == 'lesson_01_en'
        assert result[1]['video_id'] == 'lesson_01_es'
        assert result[2]['video_id'] == 'lesson_02_en'
        # ... etc
```

### Integration Tests (End-to-End)

```python
# tests/ui/test_builder_integration.py
import pytest
from playwright.async_api import async_playwright

class TestBuilderIntegration:

    @pytest.mark.asyncio
    async def test_create_code_comparison_scene(self):
        """Test creating code_comparison scene in Builder UI"""
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()

            # Navigate to Builder
            await page.goto('http://localhost:5000/builder')

            # Click "Code Comparison" button
            await page.click('button:has-text("Code Comparison")')

            # Fill form
            await page.fill('input[x-model="scene.before_label"]', 'Original')
            await page.fill('input[x-model="scene.after_label"]', 'Improved')
            await page.fill('textarea[x-model="scene.before_code"]', 'def old(): pass')
            await page.fill('textarea[x-model="scene.after_code"]', 'def new(): return True')

            # Set duration
            await page.fill('input[x-model.number="scene.min_duration"]', '5')
            await page.fill('input[x-model.number="scene.max_duration"]', '10')

            # Verify scene added
            scenes = await page.locator('.scene-item').count()
            assert scenes == 1

            # Generate video
            await page.click('button:has-text("Generate Video")')

            # Wait for progress
            await page.wait_for_selector('.loading-modal', timeout=5000)

            await browser.close()

    @pytest.mark.asyncio
    async def test_voice_rotation_explanation_visible(self):
        """Test voice rotation explainer appears in Quick Start"""
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()

            await page.goto('http://localhost:5000/create')

            # Add voice tracks (trigger rotation explainer)
            await page.click('button:has-text("Add Voice Track")')
            await page.click('button:has-text("Add Voice Track")')

            # Check explainer visible
            explainer = await page.locator('.voice-rotation-explainer').is_visible()
            assert explainer == True

            # Check content
            content = await page.locator('.voice-rotation-explainer').text_content()
            assert '1 Track:' in content
            assert '2 Tracks:' in content
            assert 'Alternates' in content

            await browser.close()
```

### Manual Testing Checklist

**Phase 1 Testing:**
- [ ] All 12 scene types render correct forms
- [ ] Code comparison: before/after fields work
- [ ] Quote: quote_text and attribution fields work
- [ ] Learning objectives: objectives field splits on newline
- [ ] Problem: difficulty dropdown changes accent (verify in output)
- [ ] Solution: code and explanation fields separate
- [ ] Exercise: hints field splits on newline (max 3)
- [ ] Checkpoint: learned_topics and next_topics separate
- [ ] Duration controls: min/max fields in all scene forms
- [ ] Duration validation: min > max shows error
- [ ] Voice rotation: explainer box appears after 2+ tracks
- [ ] Voice rotation: example patterns shown correctly

**Phase 2 Testing:**
- [ ] AI narration: new label "Claude AI Script Enhancement"
- [ ] AI narration: cost/time info visible
- [ ] AI narration: API key notice appears when enabled
- [ ] Multilingual: enable checkbox reveals options
- [ ] Multilingual: target language checkboxes work
- [ ] Multilingual: presets (EN+ES, European, Global) work
- [ ] Multilingual: output count preview accurate
- [ ] Scene preview: shows parsed scenes in Quick Start
- [ ] Scene preview: "Edit in Builder" link works

**Phase 3 Testing:**
- [ ] Color tooltips: hover shows psychology info
- [ ] Color tooltips: all 6 colors have correct text
- [ ] Voice preview: 🔊 button plays sample audio
- [ ] Duration tooltip: ℹ️ shows TTS explanation

**Phase 4 Testing:**
- [ ] Export YAML: button shows YAML modal
- [ ] Export YAML: YAML format correct (validate against schema)
- [ ] Export Python: Python code correct (run in REPL)
- [ ] Copy to clipboard: works for both YAML and Python

---

## Backward Compatibility

### Ensuring Zero Breaking Changes

#### 1. Existing Scene Forms (6/12)

**Strategy:** Keep all existing forms unchanged, only ADD new ones

```html
<!-- EXISTING: Title scene form (DO NOT MODIFY) -->
<template x-if="scene.type === 'title'">
    <div class="space-y-3">
        <input type="text" x-model="scene.title" placeholder="Title" ...>
        <input type="text" x-model="scene.subtitle" placeholder="Subtitle" ...>
    </div>
</template>

<!-- NEW: Just inject duration controls below (doesn't affect existing logic) -->
<div class="duration-controls">
    <!-- Duration fields -->
</div>
```

**Test:** Verify existing title/command/list/outro/quiz scenes still work exactly as before

#### 2. JavaScript Data Structure

**Strategy:** Add new fields with defaults, don't modify existing

```javascript
// BEFORE (existing)
addScene(type) {
    const sceneTemplate = {
        type: type,
        voice: 'male'
    };
    // ... existing type-specific fields
    this.scenes.push(sceneTemplate);
}

// AFTER (enhanced)
addScene(type) {
    const sceneTemplate = {
        type: type,
        voice: 'male',
        min_duration: 3.0,  // NEW - has default
        max_duration: 15.0  // NEW - has default
    };
    // ... existing type-specific fields
    // ... NEW type-specific fields (only for new types)
    this.scenes.push(sceneTemplate);
}

// Backend handles missing fields gracefully:
// if scene.min_duration is undefined → use default 3.0
```

#### 3. API Payload Transformation

**Strategy:** Keep existing transformation, enhance conditionally

```javascript
// EXISTING transformation (keep as-is)
const payload = {
    set_id: this.videoSet.set_id,
    set_name: this.videoSet.set_name,
    accent_color: this.videoSet.accent_color,
    videos: [{
        video_id: this.videoSet.set_id,
        title: this.videoSet.set_name,
        scenes: transformedScenes
    }]
};

// NEW: Only add languages if multilingual enabled
if (this.videoSet.multilingualEnabled && this.videoSet.targetLanguages.length > 0) {
    payload.languages = this.videoSet.targetLanguages;
}
// If not enabled, payload is identical to before (backward compatible)
```

#### 4. CSS/Styling

**Strategy:** Use new class names, don't override existing

```html
<!-- EXISTING classes: keep unchanged -->
<div class="space-y-3">
    <input class="w-full px-3 py-2 border rounded" ...>
</div>

<!-- NEW components: use new class names -->
<div class="duration-controls pt-3 mt-3 border-t">
    <input class="duration-input" ...>
</div>
```

### Migration Path for Existing Videos

**Scenario:** User has saved video configs in localStorage (if implemented)

```javascript
// Migration function (run on page load)
migrateExistingScenes() {
    this.scenes = this.scenes.map(scene => {
        // Add new fields with defaults if missing
        return {
            ...scene,
            min_duration: scene.min_duration || 3.0,  // Add if missing
            max_duration: scene.max_duration || 15.0  // Add if missing
        };
    });
}

// Called on init:
init() {
    this.loadFromLocalStorage();
    this.migrateExistingScenes();  // Ensure all scenes have new fields
}
```

### Rollback Plan

If Phase 1 causes issues:

1. **Remove new scene forms:** Delete `<template x-if="scene.type === 'code_comparison'>` blocks
2. **Remove duration controls:** Delete injected `<div class="duration-controls">` blocks
3. **Remove JavaScript changes:** Revert `addScene()` to original version
4. **Keep existing 6 forms:** No changes needed

Result: System reverts to original 6/12 scene type support

---

## Code Examples

### Example 1: Complete Code Comparison Scene Form

```html
<!-- Full implementation with all features -->
<template x-if="scene.type === 'code_comparison'">
    <div class="space-y-4">
        <!-- Labels -->
        <div class="grid grid-cols-2 gap-3">
            <div>
                <label class="block text-xs font-medium text-gray-700 mb-1">
                    Before Label
                </label>
                <input type="text"
                       x-model="scene.before_label"
                       placeholder="Before"
                       class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
            </div>
            <div>
                <label class="block text-xs font-medium text-gray-700 mb-1">
                    After Label
                </label>
                <input type="text"
                       x-model="scene.after_label"
                       placeholder="After"
                       class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
            </div>
        </div>

        <!-- Code Fields -->
        <div class="grid grid-cols-2 gap-3">
            <div>
                <label class="block text-xs font-medium text-gray-700 mb-1">
                    Original Code
                    <span class="text-gray-500 font-normal">(one line per line, max 10)</span>
                </label>
                <textarea x-model="scene.before_code"
                          rows="10"
                          placeholder="def old_function():&#10;    result = []&#10;    for item in data:&#10;        result.append(item * 2)&#10;    return result"
                          class="w-full px-3 py-2 border border-gray-300 rounded-lg font-mono text-sm focus:ring-2 focus:ring-blue-500"></textarea>
            </div>
            <div>
                <label class="block text-xs font-medium text-gray-700 mb-1">
                    Refactored Code
                    <span class="text-gray-500 font-normal">(one line per line, max 10)</span>
                </label>
                <textarea x-model="scene.after_code"
                          rows="10"
                          placeholder="def new_function():&#10;    return [item * 2 for item in data]"
                          class="w-full px-3 py-2 border border-gray-300 rounded-lg font-mono text-sm focus:ring-2 focus:ring-blue-500"></textarea>
            </div>
        </div>

        <!-- Help Text -->
        <div class="bg-blue-50 border border-blue-200 rounded-lg p-3 text-xs text-blue-800">
            <div class="font-medium mb-1">💡 Pro Tips:</div>
            <ul class="list-disc list-inside space-y-1">
                <li>Keep code snippets under 10 lines per side for readability</li>
                <li>Use actual code that compiles/runs (helps viewers understand)</li>
                <li>Align before/after code at similar abstraction levels</li>
            </ul>
        </div>

        <!-- Duration Controls (injected component) -->
        <div class="pt-3 border-t border-gray-200">
            <div class="text-xs font-medium text-gray-600 mb-2">
                ⏱️ Duration Control
            </div>
            <div class="grid grid-cols-2 gap-3">
                <div>
                    <label class="block text-xs text-gray-600 mb-1">
                        Min Duration (seconds)
                    </label>
                    <input type="number"
                           x-model.number="scene.min_duration"
                           min="1" max="60" step="0.5"
                           placeholder="3.0"
                           class="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-xs text-gray-600 mb-1">
                        Max Duration (seconds)
                    </label>
                    <input type="number"
                           x-model.number="scene.max_duration"
                           min="1" max="60" step="0.5"
                           placeholder="15.0"
                           class="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                </div>
            </div>
            <p class="text-xs text-gray-500 mt-1 flex items-center gap-1">
                <span class="cursor-help" title="System generates TTS audio from narration, measures duration, then adjusts scene length to fit within min/max range. Adds silence if audio too short, speeds up slightly if too long.">
                    ℹ️
                </span>
                <span>System generates audio, then adjusts to fit duration range</span>
            </p>
        </div>
    </div>
</template>
```

### Example 2: Voice Rotation Explainer with Examples

```html
<div class="voice-rotation-explainer bg-gradient-to-r from-blue-50 to-indigo-50 border border-blue-200 rounded-lg p-5 shadow-sm">
    <!-- Header -->
    <div class="flex items-center gap-2 mb-4">
        <span class="text-2xl">🔄</span>
        <div>
            <h4 class="font-semibold text-blue-900">How Voice Rotation Works</h4>
            <p class="text-xs text-blue-700">Create engaging multi-speaker videos</p>
        </div>
    </div>

    <!-- Rotation Patterns -->
    <div class="space-y-3 text-sm">
        <!-- 1 Track -->
        <div class="bg-white rounded-lg p-3 border border-blue-100">
            <div class="font-medium text-blue-900 mb-2">
                📻 Single Voice (1 Track)
            </div>
            <div class="text-xs text-gray-600 mb-2">
                Same voice throughout - consistent, professional tone
            </div>
            <div class="bg-gray-100 rounded px-3 py-2 font-mono text-xs text-gray-700">
                Scene 1: Male → Scene 2: Male → Scene 3: Male
            </div>
            <div class="text-xs text-blue-600 mt-2 italic">
                Best for: Solo narration, formal content
            </div>
        </div>

        <!-- 2 Tracks -->
        <div class="bg-white rounded-lg p-3 border border-blue-100">
            <div class="font-medium text-blue-900 mb-2">
                🎭 Dialog Mode (2 Tracks)
            </div>
            <div class="text-xs text-gray-600 mb-2">
                Alternates between two voices - creates conversation effect
            </div>
            <div class="bg-gray-100 rounded px-3 py-2 font-mono text-xs text-gray-700">
                Scene 1: Male → Scene 2: Female → Scene 3: Male → Scene 4: Female
            </div>
            <div class="text-xs text-blue-600 mt-2 italic">
                Best for: Interviews, Q&A, contrasting perspectives
            </div>
        </div>

        <!-- 3+ Tracks -->
        <div class="bg-white rounded-lg p-3 border border-blue-100">
            <div class="font-medium text-blue-900 mb-2">
                🎪 Multi-Speaker (3+ Tracks)
            </div>
            <div class="text-xs text-gray-600 mb-2">
                Rotates through all voices in order - dynamic variety
            </div>
            <div class="bg-gray-100 rounded px-3 py-2 font-mono text-xs text-gray-700 whitespace-nowrap overflow-x-auto">
                S1: Male → S2: Brandon → S3: Aria → S4: Ava → S5: Male (cycle repeats)
            </div>
            <div class="text-xs text-blue-600 mt-2 italic">
                Best for: Roundtable discussions, diverse perspectives, variety
            </div>
        </div>
    </div>

    <!-- Pro Tip -->
    <div class="mt-4 pt-4 border-t border-blue-200">
        <div class="flex items-start gap-2 text-xs">
            <span class="text-blue-600">💡</span>
            <div class="text-blue-800">
                <strong>Pro Tip:</strong> Use 2 voices (alternating) for most tutorials.
                It keeps viewers engaged without being distracting.
            </div>
        </div>
    </div>
</div>
```

### Example 3: Multilingual Config with Presets

```javascript
// Complete Alpine.js component for multilingual config
function multilingualConfig() {
    return {
        enabled: false,
        sourceLanguage: 'en',
        targetLanguages: [],

        availableLanguages: [
            { code: 'en', name: 'English', flag: '🇺🇸' },
            { code: 'es', name: 'Spanish', flag: '🇪🇸' },
            { code: 'fr', name: 'French', flag: '🇫🇷' },
            { code: 'de', name: 'German', flag: '🇩🇪' },
            { code: 'pt', name: 'Portuguese', flag: '🇵🇹' },
            { code: 'it', name: 'Italian', flag: '🇮🇹' },
            { code: 'ja', name: 'Japanese', flag: '🇯🇵' },
            { code: 'zh', name: 'Chinese', flag: '🇨🇳' },
            { code: 'ko', name: 'Korean', flag: '🇰🇷' },
            { code: 'ru', name: 'Russian', flag: '🇷🇺' },
            { code: 'ar', name: 'Arabic', flag: '🇸🇦' },
            { code: 'hi', name: 'Hindi', flag: '🇮🇳' },
            { code: 'nl', name: 'Dutch', flag: '🇳🇱' },
            { code: 'pl', name: 'Polish', flag: '🇵🇱' },
            { code: 'sv', name: 'Swedish', flag: '🇸🇪' },
            { code: 'tr', name: 'Turkish', flag: '🇹🇷' },
            // ... add all 28+ languages
        ],

        presets: {
            'en_es': {
                name: 'EN + ES',
                languages: ['en', 'es'],
                desc: 'English and Spanish'
            },
            'european': {
                name: 'European',
                languages: ['en', 'es', 'fr', 'de'],
                desc: 'Major European languages'
            },
            'asian': {
                name: 'Asian',
                languages: ['en', 'ja', 'zh', 'ko'],
                desc: 'English + East Asian'
            },
            'global': {
                name: 'Global',
                languages: ['en', 'es', 'fr', 'de', 'pt', 'it'],
                desc: 'Top 6 global languages'
            }
        },

        setPreset(presetKey) {
            const preset = this.presets[presetKey];
            if (preset) {
                this.targetLanguages = [...preset.languages];
            }
        },

        get outputCount() {
            return this.targetLanguages.length || 0;
        },

        get outputMessage() {
            const count = this.outputCount;
            if (count === 0) return 'Select languages to see output count';
            if (count === 1) return '1 video (single language)';
            return `${count} videos (${count} languages)`;
        },

        toggleLanguage(langCode) {
            const index = this.targetLanguages.indexOf(langCode);
            if (index === -1) {
                this.targetLanguages.push(langCode);
            } else {
                this.targetLanguages.splice(index, 1);
            }
        },

        isSelected(langCode) {
            return this.targetLanguages.includes(langCode);
        }
    };
}
```

---

## Summary

This architecture document provides:

1. **Complete implementation specs** for all UI alignment components
2. **Phased rollout plan** (4 phases, prioritized by impact)
3. **Technical patterns** (HTML/Alpine.js best practices)
4. **API integration points** (validation, multilingual expansion)
5. **Workflow diagrams** (scene creation, voice selection, duration control, multilingual)
6. **Testing strategy** (unit, integration, manual checklists)
7. **Backward compatibility guarantees** (zero breaking changes)
8. **Ready-to-use code examples** (copy-paste implementation)

**Next Steps:**
1. Review and approve Phase 1 priorities
2. Assign implementation to coder agent
3. Execute Phase 1 (Week 1): Scene forms, duration controls, voice rotation explainer
4. Test and validate Phase 1
5. Proceed to Phase 2 (Week 2): AI clarity, multilingual, scene preview
6. Continue through Phase 3 and 4 as resources allow

**Target Outcome:**
- Feature parity: **60% → 100%**
- Scene type forms: **6/12 → 12/12**
- User clarity: **+40%** (tooltips, labels, explanations)
- Zero breaking changes to existing functionality
- Production-ready UI that fully reflects the powerful API underneath

---

*Document Created: October 11, 2025*
*Last Updated: October 11, 2025*
*Related Documents:*
- `/docs/UI_API_GAP_ANALYSIS.md` - Gap analysis (completed)
- `/docs/api/API_PARAMETERS_REFERENCE.md` - API documentation
- `/app/templates/builder.html` - Builder UI implementation
- `/app/templates/create.html` - Quick Start UI implementation
