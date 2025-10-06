# Backend API Quick Reference

## Running the Server

```bash
# Development
cd app
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Production
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

**Access**: http://localhost:8000

---

## Quick Endpoint Reference

### Parse Document
```bash
curl -X POST http://localhost:8000/api/parse \
  -H "Content-Type: application/json" \
  -d '{
    "input_type": "document",
    "document_path": "README.md",
    "accent_color": "blue",
    "voice": "male"
  }'
```

**Response**: `{"job_id": "abc123", "scenes": [...]}`

---

### Parse YouTube
```bash
curl -X POST http://localhost:8000/api/parse \
  -H "Content-Type: application/json" \
  -d '{
    "input_type": "youtube",
    "youtube_url": "https://youtube.com/watch?v=VIDEO_ID",
    "duration": 60
  }'
```

---

### Generate Video
```bash
curl -X POST http://localhost:8000/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "scenes": [
      {"type": "title", "title": "Hello", "subtitle": "World"}
    ],
    "config": {"accent_color": "blue"}
  }'
```

**Response**: `{"job_id": "xyz789", "status": "queued"}`

---

### Check Status (Polling)
```bash
curl http://localhost:8000/api/status/xyz789/poll
```

**Response**:
```json
{
  "job_id": "xyz789",
  "status": "generating",
  "progress": 45,
  "message": "Rendering video..."
}
```

---

### SSE Stream (Server-Sent Events)
```bash
curl -N http://localhost:8000/api/status/xyz789
```

**Response** (stream):
```
data: {"job_id":"xyz789","status":"generating","progress":30}
data: {"job_id":"xyz789","status":"completed","progress":100}
```

---

## HTMX Examples

### Input Selection
```html
<div hx-get="/api/inputs"
     hx-trigger="load"
     hx-swap="innerHTML">
  Loading...
</div>
```

---

### Parse Document
```html
<form hx-post="/api/parse"
      hx-target="#scenes">
  <input name="input_type" value="document" type="hidden">
  <input name="document_path" placeholder="README.md">
  <button>Parse</button>
</form>
```

---

### Progress Display
```html
<div id="progress"
     hx-get="/api/status/xyz789/poll"
     hx-trigger="every 2s">
  <progress value="{progress}" max="100"></progress>
  <p>{message}</p>
</div>
```

---

## Scene Types

### General
- `title` - Title slide
- `command` - Code/terminal
- `list` - Bullet points
- `outro` - Closing slide
- `code_comparison` - Before/after code
- `quote` - Quotation

### Educational
- `learning_objectives` - Lesson goals
- `problem` - Coding challenge
- `solution` - Problem solution
- `checkpoint` - Progress review
- `quiz` - Multiple choice
- `exercise` - Practice task

---

## Voices

- `male` - Andrew (professional)
- `male_warm` - Brandon (engaging)
- `female` - Aria (clear)
- `female_friendly` - Ava (friendly)

---

## Colors

`blue`, `purple`, `orange`, `green`, `pink`, `cyan`

---

## File Structure

```
app/
├── main.py              # FastAPI app
├── models.py            # Pydantic models
├── utils.py             # Helpers
├── services/
│   └── video_service.py # Business logic
├── templates/           # HTML templates
└── requirements.txt     # Dependencies
```

---

## Testing

```bash
# Health check
curl http://localhost:8000/health

# List input methods
curl http://localhost:8000/api/inputs

# Get scene types
curl http://localhost:8000/api/scene-types

# Get voices
curl http://localhost:8000/api/voices

# Get colors
curl http://localhost:8000/api/colors
```

---

## Integration Points

### Document Parsing
`scripts/generate_script_from_document.py`

### YouTube Parsing
`scripts/youtube_to_programmatic.py`

### Audio Generation
`scripts/generate_all_videos_unified_v2.py`

### Video Generation
`scripts/generate_videos_from_timings_v3_simple.py`

---

## Error Handling

**400 Bad Request**
```json
{"detail": "Invalid input type"}
```

**404 Not Found**
```json
{"detail": "Job not found"}
```

**500 Server Error**
```json
{"detail": "Parse failed: Could not read document"}
```

---

## Environment Variables

```bash
# Optional: AI narration
export ANTHROPIC_API_KEY="sk-ant-..."

# API configuration
export API_HOST="0.0.0.0"
export API_PORT="8000"
```

---

## Quick Test

```bash
# 1. Start server
uvicorn main:app --reload

# 2. Open browser
http://localhost:8000

# 3. Test parse endpoint
curl -X POST http://localhost:8000/api/parse \
  -H "Content-Type: application/json" \
  -d '{"input_type":"document","document_path":"README.md"}'

# 4. Check status
curl http://localhost:8000/api/status/{job_id}/poll
```

---

**Full Documentation**: See `docs/API_DESIGN.md`
