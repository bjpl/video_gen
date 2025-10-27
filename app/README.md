# Video Generation System - Web UI

## 🆕 Now Powered by Unified Pipeline!

**HTMX + Alpine.js Lightweight Frontend with Enterprise-Grade Pipeline**

The Web UI has been upgraded to use the unified pipeline system, providing enhanced reliability and features while maintaining full backward compatibility.

### What's New

✅ **Unified Pipeline** - Enterprise-grade video generation
✅ **State Persistence** - Auto-resume on failures
✅ **Real-time Progress** - Server-Sent Events (SSE)
✅ **Error Recovery** - Automatic retry and recovery
✅ **Multilingual** - 28+ languages with AI translation
✅ **Backward Compatible** - All existing templates work unchanged

### 🚀 Phase 1+2 UI Alignment (Oct 11, 2025)

✨ **90% API Feature Parity Achieved** (up from 60%)

**Phase 1 Complete:**
- 🎬 **ALL 12 scene types** with complete parameter forms
- ⏱️ **Duration controls** (min/max) on every scene
- 🔊 **Voice rotation** pattern explainer

**Phase 2 Complete:**
- 🤖 **AI narration clarity** - Renamed toggle, cost disclosure, API key notice
- 🌍 **Multilingual Builder** - 28 languages with per-language voice assignment
- 👁️ **Scene preview** - Validate content before generation

See: [WEB_UI_GUIDE.md](../docs/WEB_UI_GUIDE.md) for complete documentation

## Stack

- **Backend:** FastAPI (Python 3.10+) + Unified Pipeline
- **Frontend:** HTMX + Alpine.js + Tailwind CSS
- **Total JS:** ~50KB (HTMX 14KB + Alpine 15KB)
- **No Build Step:** All CDN links
- **Pipeline:** 6-stage unified orchestration

## Features

### Input Methods
1. **Document** - Parse markdown/README files → videos
2. **YouTube** - Extract transcripts and generate videos
3. **Visual Builder** - Interactive scene-by-scene builder
4. **Multilingual** - Generate in 28+ languages simultaneously
5. **Programmatic API** - Full REST API

### Scene Types (12 Total - ALL with Complete Forms)

**General (6 types):**
- Title Slides, Commands/Code, Lists, Outros, Code Comparisons, Quotes

**Educational (6 types):**
- Learning Objectives, Problems, Solutions, Checkpoints, Quizzes, Exercises

**NEW in Phase 1:**
- ✅ Code Comparison form (before/after code with labels)
- ✅ Quote form (quote text + attribution)
- ✅ Enhanced Learning Objectives (title + objectives list)
- ✅ Problem form with difficulty selector (Easy/Medium/Hard)
- ✅ Solution form (code + explanation separated)
- ✅ Exercise form (instructions + hints)
- ✅ Checkpoint form (learned topics vs. next topics grid)

### Multilingual Support (ENHANCED Phase 2)

Generate videos in **28+ languages**:
- 🇺🇸 English, 🇪🇸 Spanish, 🇫🇷 French, 🇩🇪 German, 🇵🇹 Portuguese
- 🇮🇹 Italian, 🇯🇵 Japanese, 🇨🇳 Chinese, 🇰🇷 Korean, 🇸🇦 Arabic
- 🇮🇳 Hindi, 🇷🇺 Russian, 🇳🇱 Dutch, 🇵🇱 Polish, 🇸🇪 Swedish
- And many more with AI-powered translation!

**NEW in Phase 2:**
- ✅ Multilingual configuration now available in Scene Builder
- ✅ Per-language voice assignment (assign different voices per language)
- ✅ Live language counter ("Selected: X language(s)")
- ✅ Educational info explaining translation and voice adaptation

### Voice Options
- **4 English Voices** - Male, Male Warm, Female, Female Friendly
- **28+ Language Voices** - Native voices for each language
- **Edge-TTS Neural Voices** - High-quality text-to-speech

### Real-Time Progress
- Server-Sent Events (SSE) for live updates
- Stage-by-stage progress tracking
- Background task processing with state persistence
- Auto-resume on server restart

## Quick Start

### 1. Install Dependencies

```bash
cd app
pip install -r requirements.txt
```

### 2. Run Server

```bash
python main.py
```

Or with uvicorn directly:

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 3. Open Browser

```
http://localhost:8000
```

## API Endpoints

### UI Pages
- `GET /` - Main page (input method selection)
- `GET /builder` - Visual scene builder
- `GET /multilingual` - Multilingual generator
- `GET /progress` - Progress tracking
- `GET /create` - Unified creation interface

### API Endpoints

**Content Parsing:**
- `POST /api/parse/document` - Parse document → video set
- `POST /api/parse/youtube` - Parse YouTube → video set

**Video Generation:**
- `POST /api/generate` - Generate videos from video set
- `POST /api/generate/multilingual` - Multi-language generation

**Task Management:**
- `GET /api/tasks/{task_id}` - Get task status
- `GET /api/tasks/{task_id}/stream` - SSE progress stream (real-time)

**Language Support:**
- `GET /api/languages` - List all 28+ languages
- `GET /api/languages/{code}/voices` - Get voices for language

**System:**
- `GET /api/health` - Health check + pipeline status
- `GET /api/scene-types` - Available scene types
- `GET /api/voices` - Available voices
- `GET /api/colors` - Available accent colors

## Project Structure

```
app/
├── main.py                    # FastAPI server
├── requirements.txt           # Python dependencies
├── templates/
│   ├── base.html             # Base template (CDN links)
│   ├── index.html            # Home page
│   └── builder.html          # Scene builder
├── static/
│   └── style.css             # Custom CSS
└── README.md                 # This file
```

## Tech Stack Details

### HTMX Features Used
- `hx-get` - Fetch partials
- `hx-post` - Form submissions
- `hx-swap` - DOM updates
- `hx-sse` - Server-sent events
- `hx-indicator` - Loading states

### Alpine.js Features Used
- `x-data` - Component state
- `x-model` - Form bindings
- `x-for` - List rendering
- `x-show` - Conditional display
- `x-transition` - Smooth animations

### Tailwind CSS
- Utility-first CSS
- Responsive design
- Custom color palette
- Component classes

## Development

### Add New Scene Type

1. Add to `main.py`:
```python
@app.get("/api/scene-types")
async def get_scene_types():
    return {
        "general": [
            {"id": "new_type", "name": "New Type", "icon": "🎨"}
        ]
    }
```

2. Add to `builder.html`:
```html
<template x-if="scene.type === 'new_type'">
    <!-- Your form fields -->
</template>
```

### Add New Voice

Update `main.py`:
```python
@app.get("/api/voices")
async def get_voices():
    return [
        {"id": "new_voice", "name": "New Voice", "description": "Description"}
    ]
```

## Progressive Enhancement

The UI works without JavaScript:
- Forms submit normally
- Navigation works
- Fallback to full page reloads

With HTMX + Alpine:
- AJAX form submissions
- Real-time progress
- Smooth transitions
- Dynamic scene builder

## Performance

- **First Load:** ~50KB JS (CDN cached)
- **Page Weight:** <100KB total
- **Time to Interactive:** <1s
- **No Build Process:** Zero compile time

## Browser Support

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Production Deployment

### 1. Use Production ASGI Server

```bash
pip install gunicorn
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker
```

### 2. Add Redis for Task Storage

Replace in-memory dict with Redis:

```python
import redis
r = redis.Redis(host='localhost', port=6379)
```

### 3. Enable CORS (if needed)

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)
```

### 4. Add Environment Variables

```python
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ANTHROPIC_API_KEY")
```

## Troubleshooting

### HTMX Not Working
- Check browser console for errors
- Verify CDN is accessible
- Check HTMX version compatibility

### Alpine.js Not Working
- Ensure `defer` attribute on script tag
- Check for `x-cloak` style
- Verify Alpine.js loaded after DOM

### SSE Not Streaming
- Check browser supports EventSource
- Verify Content-Type header
- Check firewall/proxy settings

## License

MIT

---

**Built with:** FastAPI + HTMX + Alpine.js + Tailwind CSS
**Total Dependencies:** 5 Python packages + 3 CDN links
**Build Time:** 0 seconds (no build step!)
