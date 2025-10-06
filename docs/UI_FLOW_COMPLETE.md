# Video Generation UI - Complete Flow Documentation

## 🎯 User Journey

```
┌─────────────────────────────────────────────────────────────────┐
│                     LANDING PAGE (/)                             │
│                                                                  │
│  🎬 Professional Video Generation                               │
│  Create stunning videos with AI narration in 28+ languages      │
│                                                                  │
│  ┌──────────────────┐         ┌──────────────────┐            │
│  │  🎥 Quick Start  │         │  🧙 Advanced     │            │
│  │  Best for most   │         │  For power users │            │
│  │                  │         │                  │            │
│  │  • 4 inputs      │         │  • Scene-by-scene│            │
│  │  • Full control  │         │  • 12+ types     │            │
│  │  • Multi-voice   │         │  • Full custom   │            │
│  │  • 28+ langs     │         │  • Advanced      │            │
│  └──────────────────┘         └──────────────────┘            │
└─────────────────────────────────────────────────────────────────┘
           │                              │
           ↓                              ↓
    /create (/quick-start)         /builder
```

---

## 🎥 Quick Start Flow (/create)

### **Step 1: Choose Type**

```
┌─────────────────────────────────────────────────────────────┐
│  ⚡ QUICK TEMPLATES (One-Click Presets)                     │
│  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐                   │
│  │ 📚   │  │ 🎓   │  │ 💻   │  │ 🌍   │                   │
│  │Tutorial│ │Course│ │ Demo │ │Global│                   │
│  │3,EN+ES│  │10,mv │ │1,quick│ │5,10L│                   │
│  └──────┘  └──────┘  └──────┘  └──────┘                   │
│                                                             │
│  CHOOSE CREATION TYPE:                                     │
│  ┌──────────────────────┐  ┌──────────────────────┐       │
│  │  🎥 Single Video     │  │  📚 Video Set        │       │
│  │                      │  │                      │       │
│  │  • Quick setup       │  │  • Series/courses    │       │
│  │  • Tutorials         │  │  • Consistent brand  │       │
│  │  • Optional multi    │  │  • Batch processing  │       │
│  │                      │  │                      │       │
│  │  [Get Started →]     │  │  [Create Set →]      │       │
│  └──────────────────────┘  └──────────────────────┘       │
└─────────────────────────────────────────────────────────────┘
```

---

### **Step 2: Configure (Single Video)**

```
┌─────────────────────────────────────────────────────────────┐
│  🎥 Single Video Configuration                              │
│                                                             │
│  CONTENT SOURCE (choose one):                              │
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐                         │
│  │ ✍️   │ │ 📄  │ │ 📺  │ │ 📝  │                         │
│  │Manual│ │ Doc │ │ YT  │ │YAML │                         │
│  └─────┘ └─────┘ └─────┘ └─────┘                         │
│                                                             │
│  ▼ Input Field (changes based on source)                   │
│  ┌───────────────────────────────────────┐                │
│  │ [Video title / path / URL]            │                │
│  └───────────────────────────────────────┘                │
│                                                             │
│  ⚙️ GLOBAL SETTINGS                                        │
│  ┌─────────────────────────────────────────────────┐      │
│  │ Default Duration: ──────●─────── 60s            │      │
│  │ AI Enhancement:   [ON/OFF toggle]               │      │
│  │ Accent Color:     ● ● ● ● ● ●                   │      │
│  └─────────────────────────────────────────────────┘      │
│                                                             │
│  🎬 VIDEO CONFIGURATION [Advanced] ▼                       │
│  ┌─────────────────────────────────────────────────┐      │
│  │ Video Title: [_____________________]            │      │
│  │                                                  │      │
│  │ Voice Tracks (2):                    [+ Add]    │      │
│  │ ├─ Track 1: ▼ Andrew (Male)           ×        │      │
│  │ └─ Track 2: ▼ Aria (Female)           ×        │      │
│  │                                                  │      │
│  │ Duration Override: [90] seconds                 │      │
│  │                                                  │      │
│  │ 💡 Multiple voices alternate sections           │      │
│  │ [Open Advanced Builder →]                       │      │
│  └─────────────────────────────────────────────────┘      │
│                                                             │
│  🌍 MULTILINGUAL [ON/OFF toggle]                           │
│  ┌─────────────────────────────────────────────────┐      │
│  │ Source: ▼ English                               │      │
│  │ Targets: [EN] [ES] [FR] ...  (2 selected)      │      │
│  │ Method: ⭐ Claude AI | Google Translate         │      │
│  └─────────────────────────────────────────────────┘      │
│                                                             │
│  📋 GENERATION SUMMARY                                     │
│  ┌─────────────┬─────────────┬─────────────┬─────────────┐│
│  │Input: Manual│Duration: 60s│Voices: 2    │Langs: 1     ││
│  └─────────────┴─────────────┴─────────────┴─────────────┘│
│  ✓ AI Enhancement  ✓ Multi-voice (2 tracks)               │
│                                                             │
│  [▶ Generate Video]  ← Animated, validates input          │
└─────────────────────────────────────────────────────────────┘
```

---

### **Step 2: Configure (Video Set)**

```
┌─────────────────────────────────────────────────────────────┐
│  📚 Video Set Configuration                                 │
│                                                             │
│  CONTENT SOURCE (choose one):                              │
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐                         │
│  │ ✍️   │ │ 📄  │ │ 📺  │ │ 📝  │                         │
│  │Manual│ │ Doc │ │ YT  │ │YAML │                         │
│  └─────┘ └─────┘ └─────┘ └─────┘                         │
│                                                             │
│  ▼ Input Fields (based on source)                          │
│  [Set name]  [Number of videos: 3]                         │
│                                                             │
│  ⚙️ GLOBAL SETTINGS                                        │
│  ┌─────────────────────────────────────────────────┐      │
│  │ Num Videos: ──●── 3  (manual only)              │      │
│  │ Duration/Video: ──────●─────── 60s              │      │
│  │ AI Enhancement: [ON/OFF]                        │      │
│  │ Accent Color: ● ● ● ● ● ●                       │      │
│  └─────────────────────────────────────────────────┘      │
│                                                             │
│  🎬 PER-VIDEO SETTINGS [Advanced] (3 videos) ▼            │
│  ┌─────────────────────────────────────────────────┐      │
│  │ Number of Videos: ●──── 3                       │      │
│  │                                                  │      │
│  │ ❶ Video 1                                       │      │
│  │ ├─ Title: Tutorial Intro                        │      │
│  │ ├─ Voices (2):                       [+ Add]    │      │
│  │ │  ├─ Track 1: ▼ Andrew              ×         │      │
│  │ │  └─ Track 2: ▼ Brandon             ×         │      │
│  │ └─ Duration: [60]                               │      │
│  │                                                  │      │
│  │ ❷ Video 2                                       │      │
│  │ ├─ Title: Deep Dive                             │      │
│  │ ├─ Voices (1):                       [+ Add]    │      │
│  │ │  └─ Track 1: ▼ Aria                ×         │      │
│  │ └─ Duration: [Default]                          │      │
│  │                                                  │      │
│  │ ❸ Video 3                                       │      │
│  │ ├─ Title: Wrap Up                               │      │
│  │ ├─ Voices (3):                       [+ Add]    │      │
│  │ │  ├─ Track 1: ▼ Andrew              ×         │      │
│  │ │  ├─ Track 2: ▼ Aria                ×         │      │
│  │ │  └─ Track 3: ▼ Ava                 ×         │      │
│  │ └─ Duration: [45]                               │      │
│  └─────────────────────────────────────────────────┘      │
│                                                             │
│  🌍 MULTILINGUAL [ON/OFF]                                  │
│  (Same as single video...)                                 │
│                                                             │
│  📋 SUMMARY                                                │
│  Videos: 3  |  Avg: 60s  |  Tracks: 6  |  Langs: 3        │
│  Total to generate: 3 × 3 = 9 videos                      │
│                                                             │
│  [📚 Generate 3 Videos × 3 Languages]                      │
└─────────────────────────────────────────────────────────────┘
```

---

## 🧙 Advanced Builder Flow (/builder)

```
┌─────────────────────────────────────────────────────────────┐
│  Home → Scene Builder                                       │
│                                                             │
│  🧙 Advanced Scene Builder                                 │
│                                                             │
│  PROGRESS: ❶ Set Info → ❷ Add Scenes → ❸ Generate        │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━        │
│                                                             │
│  ┌─────────────┐  ┌─────────────────────────────────┐     │
│  │ ADD SCENE   │  │ SCENE EDITOR                    │     │
│  │             │  │                                 │     │
│  │ General:    │  │ Scenes (3):                     │     │
│  │ • 🎬 Title  │  │ #1 🎬 Title Slide               │     │
│  │ • 💻 Code   │  │ #2 💻 Command/Code              │     │
│  │ • 📋 List   │  │ #3 ✅ Outro                     │     │
│  │ • ✅ Outro  │  │                                 │     │
│  │             │  │ [Generate Video]                │     │
│  │ Educational:│  │                                 │     │
│  │ • 🎯 Learn  │  └─────────────────────────────────┘     │
│  │ • ❓ Problem│                                           │
│  │ • 💡 Solution                                           │
│  │ • ✓ Check  │                                           │
│  └─────────────┘                                           │
└─────────────────────────────────────────────────────────────┘
```

---

## ✨ Complete Feature Matrix

| Feature | Single | Set | Builder | Details |
|---------|--------|-----|---------|---------|
| **Input Methods** | ✅ 4 | ✅ 4 | ✅ Manual | Manual, Document, YouTube, YAML |
| **Video Count** | 1 | ✅ 1-20 | ✅ Unlimited | Slider for sets, auto-detect for parsing |
| **Per-Video Title** | ✅ | ✅ | ✅ | Custom name for each video |
| **Voice Tracks/Video** | ✅ 1-4 | ✅ 1-4 | ✅ | Multiple voices per video |
| **Voice Selection** | ✅ | ✅ | ✅ | Andrew, Brandon, Aria, Ava |
| **Duration** | ✅ | ✅ | ✅ | 30s-300s, per-video override |
| **AI Enhancement** | ✅ | ✅ | - | Claude API for better content |
| **Accent Colors** | ✅ 6 | ✅ 6 | ✅ 6 | Blue, Purple, Orange, Green, Pink, Cyan |
| **Multilingual** | ✅ | ✅ | - | 28+ languages with auto-translation |
| **Translation Method** | ✅ | ✅ | - | Claude AI (quality) / Google (free) |
| **Quick Templates** | ✅ | ✅ | - | Tutorial, Course, Demo, Global |
| **Scene Editor** | Link | Link | ✅ | 12+ scene types |
| **Real-time Validation** | ✅ | ✅ | ✅ | Input validation before submit |
| **Progress Tracking** | ✅ | ✅ | ✅ | Real-time SSE updates |

---

## 🎛️ Configuration Levels

### **Level 1: Global Settings**
Applied to all videos in the set
- Default duration
- AI enhancement (ON/OFF)
- Accent color theme
- Multilingual settings

### **Level 2: Per-Video Settings** (Advanced Panel)
Customizable for each individual video
- Video title
- Voice tracks (1-4 per video)
- Duration override
- Scene composition (in Builder)

### **Level 3: Per-Track Settings**
Configurable for each voice track
- Voice type (Andrew, Brandon, Aria, Ava)
- Voice personality/style

---

## 📊 Summary Display Logic

### **Single Video Summary**
```
┌──────────────┬──────────────┬──────────────┬──────────────┐
│ Input Method │ Duration     │ Voice Tracks │ Languages    │
│ ✍️ Manual    │ 90s          │ 2 voices     │ 1 language   │
└──────────────┴──────────────┴──────────────┴──────────────┘
✓ AI Enhancement  ✓ Multi-voice (2 tracks)
```

### **Video Set Summary**
```
┌──────────────┬──────────────┬──────────────┬──────────────┐
│ Videos       │ Avg Duration │ Total Tracks │ Languages    │
│ 3 videos     │ 60s          │ 6 tracks     │ 3 languages  │
└──────────────┴──────────────┴──────────────┴──────────────┘
✓ AI Enhancement  ✓ Multilingual  ✓ Multi-voice in some

Total videos to generate: 3 × 3 = 9
```

---

## 🎨 Visual Design Patterns

### **Color Coding**
- **Blue** (#3b82f6): Single videos, primary actions
- **Purple** (#8b5cf6): Video sets, advanced features
- **Green** (#10b981): Multilingual, success states
- **Yellow/Orange** (#f59e0b): Templates, quick actions
- **Red** (#ef4444): Errors, validation warnings
- **Gray** (#6b7280): Neutral, disabled states

### **UI Components**
- **Cards with Gradients**: Headers with gradient backgrounds
- **Collapsible Panels**: Advanced settings behind expandable sections
- **Range Sliders**: Custom-styled with gradient thumbs
- **Toggle Switches**: Animated with glow effects
- **Color Pickers**: Visual buttons with ring highlights
- **Status Messages**: Floating notifications with auto-dismiss

### **Animations**
- **Step transitions**: Slide in from right/left
- **Panel expansion**: Smooth height transitions
- **Button hovers**: Scale, translate, shadow effects
- **Toggle switches**: Smooth slide with glow
- **Progress bars**: Gradient fills with shadows
- **Notifications**: Fade in/out with slide

---

## 🚀 Quick Templates

### **📚 Tutorial**
- 3 videos
- EN + ES languages
- Mixed voices (1-2 per video)
- Durations: 60s, 120s, 45s

### **🎓 Course**
- 10 videos
- Single language
- Alternating male/female voices
- 180s default duration

### **💻 Demo**
- 1 video
- Quick 30s format
- Single warm voice
- Green theme

### **🌍 Global**
- 5 videos
- 10 languages (EN, ES, FR, DE, IT, PT, JA, ZH, KO, AR)
- Dual voices per video
- Claude AI translation
- 45s each
- **Total output**: 50 videos

---

## 💡 Pro Tips Displayed

1. **Use multiple voices** to create conversations or interviews
2. **Set different durations** per video for varied pacing
3. **Enable AI Enhancement** for richer narration and explanations
4. **Use Quick Templates** above to get started instantly

---

## 🔄 Example Use Cases

### **Case 1: Simple Tutorial**
```
Mode: Single Video
Input: Manual ("Git Basics Tutorial")
Duration: 60s
Voice: 1 track (Andrew)
AI: ON
Multilingual: OFF
→ Output: 1 video
```

### **Case 2: Interview Series**
```
Mode: Video Set
Input: Manual (5 videos)
Per-Video Config:
  Video 1: "Introduction" - 2 voices (Andrew + Aria)
  Video 2-4: "Interviews" - 3 voices (Andrew, Aria, Brandon)
  Video 5: "Conclusion" - 1 voice (Andrew)
Duration: Variable (60s, 120s, 120s, 120s, 45s)
→ Output: 5 videos with conversation-style narration
```

### **Case 3: Global Marketing**
```
Mode: Video Set
Input: YAML (marketing_campaign.yaml)
Videos: 5 (from YAML)
Multilingual: ON
  Languages: 10 (EN, ES, FR, DE, IT, PT, JA, ZH, KO, AR)
  Translation: Claude AI
→ Output: 50 videos (5 × 10 languages)
```

### **Case 4: Course from Documentation**
```
Mode: Video Set
Input: Document (GitHub README)
Videos: Auto-detected (splits document into chapters)
Duration: 120s per video
Voices: Mixed (alternating male/female)
Multilingual: EN + ES
→ Output: Auto-generated course in 2 languages
```

---

## 🎯 Validation Rules

### **Single Video**
- ✅ Manual: Always valid
- ✅ Document: Requires document path
- ✅ YouTube: Requires valid URL
- ✅ YAML: Requires file path

### **Video Set**
- ✅ Manual: Requires set name
- ✅ Document: Requires document path
- ✅ YouTube: Requires playlist/channel URL
- ✅ YAML: Requires file path

### **Voice Tracks**
- Minimum: 1 voice per video
- Maximum: 4 voices per video
- Can add/remove dynamically

---

## 📱 Responsive Design

- **Desktop** (>1024px): Full 2-3 column layouts
- **Tablet** (768-1024px): 2 column layouts, collapsible panels
- **Mobile** (<768px): Single column, stacked layouts

---

## 🔧 Technical Implementation

### **Frontend Stack**
- **Alpine.js**: Reactive state management
- **Tailwind CSS**: Utility-first styling
- **HTMX**: Server communication (jobs list)
- **Vanilla JS**: Custom components

### **State Management**
```javascript
{
  mode: 'single' | 'set',
  step: 1 | 2,
  loading: boolean,
  allLanguages: Array,

  single: {
    inputMethod: 'manual' | 'document' | 'youtube' | 'yaml',
    videos: [{ title, voices: [], duration }],
    multilingual: boolean,
    ...
  },

  set: {
    inputMethod: 'manual' | 'document' | 'youtube' | 'yaml',
    videos: [{ title, voices: [], duration }, ...],
    multilingual: boolean,
    ...
  }
}
```

### **API Endpoints Used**
- `POST /api/parse/document` - Document parsing
- `POST /api/parse/youtube` - YouTube transcript
- `POST /api/generate` - Standard generation
- `POST /api/generate/multilingual` - Multilingual generation
- `GET /api/languages` - Available languages
- `GET /api/languages/{code}/voices` - Language-specific voices
- `GET /api/tasks/{id}` - Task status polling
- `GET /api/tasks/{id}/stream` - SSE real-time updates

---

## 🎬 Generation Flow

```
User Configures
    ↓
Validation Check
    ↓
API Call (POST /api/...)
    ↓
Task Created (task_id returned)
    ↓
Redirect to /progress?task_id=xxx
    ↓
Real-time Progress Tracking (SSE + Polling)
    ↓
Completion / Download
```

---

## 🌟 Key Improvements Made

### **UI/UX**
✅ Clear 2-step wizard (Type → Configure)
✅ Visual progress indicator with animations
✅ Breadcrumb navigation on all pages
✅ Color-coded modes (Blue/Purple/Green)
✅ Collapsible advanced panels
✅ Quick template presets
✅ Real-time validation feedback
✅ Toast notifications for actions
✅ Smooth transitions and animations

### **Functionality**
✅ 4 input methods for both modes
✅ Per-video customization (title, voices, duration)
✅ Multi-voice support (1-4 tracks per video)
✅ Video count control for all input types
✅ Multilingual as optional step (not separate mode)
✅ Smart API routing based on configuration
✅ Comprehensive summaries before generation

### **Technical**
✅ Task ID consistency (fixed 500 errors)
✅ Progress page error handling
✅ Alpine.js state management
✅ CSS animations and transitions
✅ Responsive design patterns
✅ Custom range slider styling
✅ Toggle switch animations

---

## 🎯 Navigation Map

```
/ (Landing)
├── /create (Quick Start)
│   ├── Step 1: Type Selection
│   │   ├── Single Video
│   │   └── Video Set
│   └── Step 2: Configuration
│       ├── Input Method
│       ├── Global Settings
│       ├── Advanced (collapsible)
│       ├── Multilingual (toggle)
│       ├── Summary
│       └── Generate → /progress
│
├── /builder (Advanced)
│   ├── Video Info
│   ├── Scene Types Palette
│   ├── Scene Editor
│   └── Generate → /progress
│
└── /progress (Tracking)
    ├── Real-time updates (SSE)
    ├── Language progress grid
    └── Task information
```

---

## 🚀 Performance Features

- **Progressive Disclosure**: Hide complexity until needed
- **Lazy Loading**: Languages fetched on init
- **Optimistic UI**: Immediate feedback before API calls
- **Client-side Validation**: Fast feedback without roundtrip
- **Template System**: Instant configuration with presets
- **Auto-save State**: Configuration persists in Alpine state

---

**Status**: ✅ **Complete and Production-Ready**
**Server**: http://localhost:8000
**Last Updated**: 2025-10-05
