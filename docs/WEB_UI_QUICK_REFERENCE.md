# Web UI Quick Reference

## Start Server

```bash
cd app
python main.py
```

Visit: http://localhost:8000

## API Endpoints

### Content Parsing
```bash
# Parse Document
POST /api/parse/document
{
  "content": "# My Doc\n\nContent...",
  "voice": "male",
  "accent_color": "blue"
}

# Parse YouTube
POST /api/parse/youtube
{
  "url": "https://youtube.com/watch?v=...",
  "duration": 60,
  "accent_color": "blue"
}
```

### Video Generation
```bash
# Generate Videos
POST /api/generate
{
  "set_id": "my_set",
  "set_name": "My Videos",
  "videos": [...],
  "accent_color": "blue"
}

# Multilingual
POST /api/generate/multilingual
{
  "video_set": {...},
  "target_languages": ["en", "es", "fr"],
  "source_language": "en",
  "translation_method": "claude"
}
```

### Task Management
```bash
# Get Status
GET /api/tasks/{task_id}

# Stream Progress (SSE)
GET /api/tasks/{task_id}/stream
```

### Languages
```bash
# List All Languages
GET /api/languages

# Get Language Voices
GET /api/languages/{code}/voices
```

### System
```bash
# Health Check
GET /api/health
```

## Status Values

| Pipeline | API | Meaning |
|----------|-----|---------|
| pending | processing | Queued |
| running | processing | In progress |
| completed | complete | Done |
| failed | failed | Error |

## Response Format

```json
{
  "task_id": "gen_1234567890",
  "status": "processing",
  "progress": 45,
  "message": "Generating audio...",
  "type": "generate",
  "errors": null,
  "result": null
}
```

## Integration Pattern

```python
# 1. Create InputConfig
input_config = InputConfig(
    input_type="document",
    source=content,
    accent_color="blue",
    voice="male"
)

# 2. Get pipeline
pipeline = get_pipeline()

# 3. Execute in background
background_tasks.add_task(
    execute_pipeline_task,
    pipeline,
    input_config
)
```

## Testing

```bash
# Run all tests
pytest tests/test_web_ui_integration.py -v

# Test health
curl http://localhost:8000/api/health

# Test document parsing
curl -X POST http://localhost:8000/api/parse/document \
  -H "Content-Type: application/json" \
  -d '{"content":"# Test","voice":"male","accent_color":"blue"}'
```

## Key Files

- `app/main.py` - FastAPI application
- `app/templates/` - HTML templates (unchanged)
- `tests/test_web_ui_integration.py` - Test suite
- `docs/WEB_UI_INTEGRATION.md` - Full documentation

## Features

- 28+ languages with AI translation
- Real-time progress via SSE
- State persistence and auto-resume
- All templates backward compatible
- Production-ready error handling
