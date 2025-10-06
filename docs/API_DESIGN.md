# FastAPI Backend Design Documentation

## Overview

Lightweight FastAPI backend for the video generation UI, designed for seamless HTMX + Alpine.js integration.

**Architecture**: FastAPI (async) + HTMX (frontend) + Existing Python Scripts (video generation)

---

## Key Features

- **HTMX-Friendly Responses**: Returns HTML fragments and JSON
- **Server-Sent Events (SSE)**: Real-time progress updates
- **Async Processing**: Background tasks for video generation
- **Job Queue**: In-memory job tracking (scalable to Redis/DB)
- **Script Integration**: Bridges web UI with existing scripts

---

## API Endpoints

### 1. Main Page

**GET /**

Serves the main HTML page with HTMX UI.

**Response**: HTML page with video generation interface

**Features**:
- Input method selection (document, YouTube, wizard)
- Scene builder interface
- Generate button
- Progress display area

---

### 2. List Input Methods

**GET /api/inputs**

Returns available input methods.

**Response**:
```json
{
  "methods": [
    {
      "id": "document",
      "name": "Document",
      "description": "Parse README, guides, markdown",
      "icon": "📄",
      "time_estimate": "30 seconds"
    },
    {
      "id": "youtube",
      "name": "YouTube",
      "description": "Fetch transcripts, create summaries",
      "icon": "📺",
      "time_estimate": "1-2 minutes"
    },
    {
      "id": "wizard",
      "name": "Wizard",
      "description": "Interactive guided creation",
      "icon": "🧙",
      "time_estimate": "5-15 minutes"
    }
  ]
}
```

---

### 3. Parse Input

**POST /api/parse**

Parse document, YouTube, or wizard input into structured scenes.

**Request Body**:
```json
{
  "input_type": "document",
  "document_path": "README.md",
  "accent_color": "blue",
  "voice": "male",
  "duration": 60,
  "use_ai": false
}
```

**Response**:
```json
{
  "job_id": "abc123",
  "status": "success",
  "message": "Successfully parsed document input",
  "scenes": [
    {
      "type": "title",
      "title": "Getting Started",
      "subtitle": "A Quick Introduction"
    },
    {
      "type": "command",
      "command_name": "Installation",
      "description": "Install dependencies",
      "commands": ["pip install -r requirements.txt"]
    }
  ],
  "metadata": {
    "source": "README.md",
    "scene_count": 2
  }
}
```

**Supported Input Types**:
- `document`: Local markdown or GitHub URL
- `youtube`: YouTube URL or video ID
- `wizard`: Interactive wizard data

---

### 4. Generate Video

**POST /api/generate**

Trigger video generation from parsed scenes.

**Request Body**:
```json
{
  "scenes": [
    {
      "type": "title",
      "title": "Getting Started",
      "subtitle": "A Quick Introduction"
    }
  ],
  "config": {
    "accent_color": "blue",
    "default_voice": "male",
    "use_ai_narration": false
  }
}
```

**Response**:
```json
{
  "job_id": "xyz789",
  "status": "queued",
  "message": "Video generation started",
  "estimated_time_seconds": 50
}
```

**Process**:
1. Creates background task
2. Returns job_id immediately
3. Client polls `/api/status/{job_id}` for updates

---

### 5. Job Status (SSE)

**GET /api/status/{job_id}**

Server-Sent Events stream for real-time progress updates.

**Response** (SSE stream):
```
data: {"job_id":"xyz789","status":"generating","progress":45,"message":"Generating scene 3 of 5"}

data: {"job_id":"xyz789","status":"completed","progress":100,"message":"Video complete!","video_url":"/videos/xyz789.mp4"}
```

**Status Values**:
- `queued`: Job created, waiting to start
- `parsing`: Parsing input content
- `generating`: Creating video
- `completed`: Video ready
- `error`: Generation failed

**HTMX Integration**:
```html
<div hx-get="/api/status/xyz789"
     hx-trigger="load"
     hx-swap="innerHTML"
     hx-sse="connect">
  <div hx-sse-swap="message">
    Progress: <span id="progress">0</span>%
  </div>
</div>
```

---

### 6. Job Status (Polling)

**GET /api/status/{job_id}/poll**

Alternative polling endpoint (for simpler HTMX integration).

**Response**:
```json
{
  "job_id": "xyz789",
  "status": "generating",
  "progress": 65,
  "message": "Rendering video...",
  "created_at": "2025-10-04T12:00:00Z",
  "output_path": null,
  "error": null
}
```

**HTMX Integration**:
```html
<div hx-get="/api/status/xyz789/poll"
     hx-trigger="every 2s"
     hx-swap="innerHTML">
  Loading...
</div>
```

---

### 7. List Templates

**GET /api/templates**

Returns available example templates.

**Response**:
```json
[
  {
    "id": "simple_tutorial",
    "name": "Simple Tutorial",
    "description": "Basic tutorial with title, commands, outro",
    "category": "tutorial",
    "scene_types": ["title", "command", "outro"],
    "estimated_duration": 60,
    "example_path": "inputs/example_simple.yaml"
  }
]
```

---

### 8. Get Template

**GET /api/templates/{template_id}**

Returns specific template content.

**Response**:
```json
{
  "id": "simple_tutorial",
  "name": "Simple Tutorial",
  "description": "Basic tutorial template",
  "scenes": [...]
}
```

---

## Data Models

### ParseRequest

```python
class ParseRequest(BaseModel):
    input_type: Literal["document", "youtube", "wizard"]

    # Document input
    document_path: Optional[str] = None
    document_url: Optional[HttpUrl] = None

    # YouTube input
    youtube_url: Optional[HttpUrl] = None
    youtube_id: Optional[str] = None

    # Common options
    accent_color: str = "blue"
    voice: str = "male"
    duration: int = 60
    use_ai: bool = False
```

### GenerateRequest

```python
class GenerateRequest(BaseModel):
    scenes: List[Dict[str, Any]]
    config: Dict[str, Any] = {}
```

### JobStatus

```python
class JobStatus(BaseModel):
    job_id: str
    status: Literal["queued", "parsing", "generating", "completed", "error"]
    progress: int  # 0-100
    message: str
    created_at: str
    output_path: Optional[str] = None
    error: Optional[str] = None
```

---

## Scene Types

### General Scenes

1. **title**: Large centered title
2. **command**: Terminal cards with code
3. **list**: Numbered items with descriptions
4. **outro**: Checkmark with call-to-action
5. **code_comparison**: Side-by-side code
6. **quote**: Centered quotes

### Educational Scenes

1. **learning_objectives**: Lesson goals
2. **problem**: Coding challenge
3. **solution**: Problem solution
4. **checkpoint**: Progress review
5. **quiz**: Multiple choice
6. **exercise**: Practice instructions

---

## Integration with Existing Scripts

### Document Parsing
```
/api/parse (document)
  ↓
generate_script_from_document.py
  ↓
Structured scenes
```

### YouTube Parsing
```
/api/parse (youtube)
  ↓
youtube_to_programmatic.py
  ↓
Structured scenes
```

### Video Generation
```
/api/generate
  ↓
generate_all_videos_unified_v2.py (audio)
  ↓
generate_videos_from_timings_v3_simple.py (video)
  ↓
Final MP4
```

---

## Job Processing Pipeline

```
1. POST /api/generate
   ↓
2. Create job (job_id)
   ↓
3. Background task starts
   ↓
4. Create YAML from scenes (10%)
   ↓
5. Generate audio (40%)
   ↓
6. Generate video (90%)
   ↓
7. Complete (100%)
```

**Client tracks progress via SSE or polling**

---

## Error Handling

### Parse Errors
```json
{
  "detail": "Parse failed: Could not read document"
}
```
**HTTP 500**

### Generate Errors
```json
{
  "detail": "Generation failed: Audio generation error"
}
```
**HTTP 500**

### Not Found
```json
{
  "detail": "Job not found"
}
```
**HTTP 404**

---

## Performance Considerations

### In-Memory Job Store
- **Current**: Dict-based (fast, non-persistent)
- **Production**: Replace with Redis or PostgreSQL
- **Reason**: Scalability, persistence across restarts

### Background Tasks
- Uses FastAPI's `BackgroundTasks`
- Async/await for non-blocking operations
- Subprocess calls for existing scripts

### SSE vs Polling
- **SSE**: Real-time, efficient (recommended)
- **Polling**: Simpler HTMX integration, more server load

---

## Configuration

### Environment Variables

```bash
# API configuration
API_HOST=0.0.0.0
API_PORT=8000
API_RELOAD=true

# Video generation
ANTHROPIC_API_KEY=sk-ant-...  # Optional, for AI narration
```

### File Structure

```
app/
├── main.py              # FastAPI app
├── models.py            # Pydantic models
├── utils.py             # Helper functions
├── services/
│   ├── __init__.py
│   └── video_service.py # Business logic
├── templates/
│   └── index.html       # Main UI
├── static/
│   ├── css/
│   └── js/
└── requirements.txt     # Dependencies
```

---

## Running the Backend

### Development

```bash
cd app
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

**Access**: http://localhost:8000

### Production

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

**With Gunicorn**:
```bash
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker
```

---

## HTMX Integration Examples

### Input Selection
```html
<div hx-get="/api/inputs"
     hx-trigger="load"
     hx-swap="innerHTML">
  Loading input methods...
</div>
```

### Parse Document
```html
<form hx-post="/api/parse"
      hx-target="#scenes-preview">
  <input name="input_type" value="document" type="hidden">
  <input name="document_path" placeholder="README.md">
  <button type="submit">Parse</button>
</form>
```

### Generate Video
```html
<button hx-post="/api/generate"
        hx-vals='{"scenes":[...],"config":{}}'
        hx-target="#progress-area">
  Generate Video
</button>
```

### Progress Display
```html
<div id="progress-area"
     hx-get="/api/status/{job_id}/poll"
     hx-trigger="every 2s"
     hx-swap="innerHTML">
  <div class="progress-bar" style="width: {progress}%"></div>
  <p>{message}</p>
</div>
```

---

## Security Considerations

### Input Validation
- All inputs validated via Pydantic models
- File paths sanitized to prevent directory traversal
- YouTube URLs validated before fetching

### Rate Limiting
- **Recommended**: Add rate limiting middleware
- **Example**: `slowapi` or `fastapi-limiter`

### CORS
```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"]
)
```

---

## Testing

### Unit Tests
```python
from fastapi.testclient import TestClient

client = TestClient(app)

def test_parse_document():
    response = client.post("/api/parse", json={
        "input_type": "document",
        "document_path": "README.md"
    })
    assert response.status_code == 200
    assert "scenes" in response.json()
```

### Integration Tests
- Test full pipeline: parse → generate → complete
- Verify SSE stream
- Check file outputs

---

## Deployment

### Docker
```dockerfile
FROM python:3.10-slim

WORKDIR /app
COPY app/ /app/
COPY scripts/ /scripts/

RUN pip install -r requirements.txt

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Docker Compose
```yaml
version: '3.8'
services:
  api:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./inputs:/app/inputs
      - ./output:/app/output
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
```

---

## Monitoring

### Health Check
```bash
curl http://localhost:8000/health
```

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2025-10-04T12:00:00Z"
}
```

### Metrics (Optional)
- Add Prometheus metrics
- Track: requests, job duration, success rate
- Use `prometheus_client` library

---

## Future Enhancements

1. **WebSocket Support**: Replace SSE with WebSockets
2. **Job Queue**: Add Celery or RQ for distributed processing
3. **Caching**: Cache parsed documents (Redis)
4. **Authentication**: Add user accounts and API keys
5. **Batch Processing**: Generate multiple videos at once
6. **Video Preview**: Thumbnail generation
7. **Template Editor**: Visual scene builder

---

## API Summary Table

| Endpoint | Method | Purpose | Response Type |
|----------|--------|---------|---------------|
| `/` | GET | Main UI | HTML |
| `/api/inputs` | GET | List input methods | JSON |
| `/api/parse` | POST | Parse input | JSON |
| `/api/generate` | POST | Start generation | JSON |
| `/api/status/{job_id}` | GET | SSE progress | SSE Stream |
| `/api/status/{job_id}/poll` | GET | Poll progress | JSON |
| `/api/templates` | GET | List templates | JSON |
| `/api/templates/{id}` | GET | Get template | JSON |
| `/health` | GET | Health check | JSON |

---

## Contact

For questions or issues with the API:
- See main project README
- Check existing scripts documentation
- Review HTMX documentation: https://htmx.org

---

**Last Updated**: 2025-10-04
**Version**: 1.0.0
**Status**: Ready for Frontend Integration
