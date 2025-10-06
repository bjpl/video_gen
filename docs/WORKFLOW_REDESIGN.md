# Workflow Redesign - Language-First Approach

## Problem Identified

Current workflow is confusing:
1. Configure videos with "global voice"
2. THEN enable multilingual
3. THEN assign per-language voices
4. Results in: Global voice + per-language voices (confusing!)

## Proposed Solution: Language-First Workflow

### New Logical Flow

```
Step 2: Configure

1️⃣ LANGUAGE SELECTION (First!)
   ├─ How many languages? [Single] or [Multiple]
   │
   ├─ If Single Language:
   │  └─ Pick one: ▼ English
   │
   └─ If Multiple Languages:
      ├─ Source: ▼ English
      └─ Targets: ☑ EN ☑ ES ☑ FR (checkboxes)

2️⃣ VOICE CONFIGURATION (Based on languages)
   │
   ├─ If Single Language:
   │  └─ Simple voice picker:
   │     Voice: ▼ Andrew (Male) [🔊]
   │
   └─ If Multiple Languages:
      └─ Voice per language:
         ├─ EN English  ▼ Andrew  [🔊]
         ├─ ES Español  ▼ Diego   [🔊]
         └─ FR Français ▼ Pierre  [🔊]

3️⃣ VIDEO CUSTOMIZATION
   ├─ Number of videos: ●──── 3
   ├─ Duration: ●──── 60s
   ├─ Accent Color: ● ● ● ●
   └─ AI Enhancement: [ON/OFF]

4️⃣ PER-VIDEO SETTINGS (Advanced - Optional)
   ├─ 🎬 Customize Each Video [Expand]
   │  ├─ Video 1
   │  │  ├─ Title: [____]
   │  │  ├─ Multiple Voice Tracks (conversation mode)
   │  │  │  Track 1: ▼ Andrew [🔊]
   │  │  │  Track 2: ▼ Aria   [🔊]
   │  │  └─ Duration: [60]
   │  └─ Video 2...
```

## Implementation Changes

### Section 1: Language Selection (NEW - Top of Step 2)

```html
<!-- Language Configuration (FIRST THING) -->
<div class="mb-6 p-4 bg-gradient-to-r from-blue-50 to-purple-50 border-2 border-blue-200 rounded-xl">
    <h3 class="font-bold text-gray-900 mb-4">🌍 Language Configuration</h3>

    <!-- Mode Toggle -->
    <div class="grid grid-cols-2 gap-4 mb-4">
        <button @click="[mode].languageMode = 'single'"
                :class="[mode].languageMode === 'single' ? 'border-blue-500 bg-blue-50' : 'border-gray-300'"
                class="p-4 border-2 rounded-lg">
            <div class="font-semibold">📍 Single Language</div>
            <div class="text-xs text-gray-600">Generate in one language</div>
        </button>
        <button @click="[mode].languageMode = 'multiple'"
                :class="[mode].languageMode === 'multiple' ? 'border-purple-500 bg-purple-50' : 'border-gray-300'"
                class="p-4 border-2 rounded-lg">
            <div class="font-semibold">🌍 Multiple Languages</div>
            <div class="text-xs text-gray-600">Auto-translate to many languages</div>
        </button>
    </div>

    <!-- Single Language Mode -->
    <div x-show="[mode].languageMode === 'single'">
        <label>Select Language</label>
        <select x-model="[mode].primaryLanguage">
            <option v-for="lang in allLanguages">
        </select>
    </div>

    <!-- Multiple Language Mode -->
    <div x-show="[mode].languageMode === 'multiple'">
        <label>Source Language</label>
        <select x-model="[mode].sourceLanguage">

        <label>Target Languages (select all)</label>
        <div class="language-grid">
            <checkbox for each language>
        </div>
    </div>
</div>
```

### Section 2: Voice Configuration (Adapts to Language Choice)

```html
<!-- Voice Configuration (Based on Language Selection) -->
<div class="mb-6 p-4 bg-gray-50 border border-gray-200 rounded-xl">
    <h3>🎙️ Voice Configuration</h3>

    <!-- If Single Language -->
    <div x-show="[mode].languageMode === 'single'">
        <label>Narrator Voice for {{primaryLanguage}}</label>
        <select x-model="[mode].primaryVoice">
            <option v-for="voice in getVoicesForLang(primaryLanguage)">
                {{voice.name}} [🔊]
            </option>
        </select>
    </div>

    <!-- If Multiple Languages -->
    <div x-show="[mode].languageMode === 'multiple'">
        <label>Voice per Language</label>
        <div class="space-y-2">
            <div v-for="lang in targetLanguages">
                {{lang}} ▼ {{voiceForLang[lang]}} [🔊]
            </div>
        </div>
    </div>
</div>
```

### Section 3: Multi-Voice PER VIDEO (Separate Concept)

This is for conversation/interview style - DIFFERENT from language voices:

```html
<!-- Per-Video Advanced Settings -->
<div class="mb-6">
    <button @click="showAdvanced = !showAdvanced">
        🎬 Advanced: Multi-Voice Conversations
    </button>

    <div x-show="showAdvanced">
        <p>💡 Use multiple voices IN ONE VIDEO for conversations/interviews</p>

        Video 1:
          Voice Tracks for Conversation:
            Track 1: ▼ Andrew (Host)
            Track 2: ▼ Aria (Expert)

        This creates: Video with 2 narrators alternating
        Combined with multilingual:
          EN version: Andrew + Aria
          ES version: Diego + Maria (their equivalents)
    </div>
</div>
```

## Data Structure Changes

```javascript
{
  languageMode: 'single' | 'multiple',

  // If languageMode === 'single'
  primaryLanguage: 'en',
  primaryVoice: 'male',

  // If languageMode === 'multiple'
  sourceLanguage: 'en',
  targetLanguages: ['en', 'es', 'fr'],
  languageVoices: {
    en: 'male',
    es: 'male_spanish',
    fr: 'male_french'
  },

  // Per-video multi-voice (optional, for conversations)
  videos: [{
    voiceTracks: ['male', 'female']  // These rotate in EACH language version
  }]
}
```

## How It Works Together

**Example: Multi-Language + Multi-Voice**

Languages: EN, ES, FR
Language Voices: EN=Andrew, ES=Diego, FR=Pierre

Video 1 Multi-Voice: [Track1, Track2] (for conversation)

Result:
- EN version: Track1=Andrew, Track2=Aria (English voices alternate)
- ES version: Track1=Diego, Track2=Maria (Spanish voices alternate)
- FR version: Track1=Pierre, Track2=Claire (French voices alternate)

## Benefits

1. **Clearer**: Language choice comes first (logical order)
2. **Simpler**: Single language = simple voice picker
3. **Intuitive**: Multi-language automatically shows per-language voices
4. **Flexible**: Multi-voice per video is separate advanced feature
5. **No Confusion**: No "global voice" conflicting with "per-language voices"

## UI Mockup

```
┌─────────────────────────────────────────┐
│ Step 2: Configure Video Settings       │
├─────────────────────────────────────────┤
│ 🌍 LANGUAGE (Choose First!)             │
│ ○ Single Language  ● Multiple Languages│
│                                         │
│ Source: ▼ English                       │
│ Targets: ☑EN ☑ES ☑FR [European preset] │
├─────────────────────────────────────────┤
│ 🎙️ VOICE (Based on Languages)          │
│ EN  ▼ Andrew  [🔊]                      │
│ ES  ▼ Diego   [🔊]                      │
│ FR  ▼ Pierre  [🔊]                      │
├─────────────────────────────────────────┤
│ ⚙️ VIDEO SETTINGS                       │
│ Videos: ●──── 3                         │
│ Duration: ●──── 60s                     │
│ Color: ● ● ● ●                          │
│ AI: [ON]                                │
├─────────────────────────────────────────┤
│ 🎬 Advanced: Multi-Voice Per Video      │
│ [Expand for conversation-style] ▼       │
│   Video 1: Host + Guest format          │
│     Track 1: Primary narrator           │
│     Track 2: Guest/Co-host [+ Add]      │
│   (These rotate in EACH language)       │
└─────────────────────────────────────────┘
```

Should I implement this redesigned workflow?
