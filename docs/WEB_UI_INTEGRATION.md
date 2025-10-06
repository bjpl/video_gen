# Web UI Integration with Unified Pipeline

## Overview

The Video Generation Web UI has been elegantly integrated with the unified pipeline system, providing a consistent, reliable, and production-ready video generation experience.

### Key Benefits

- ✅ **Consistency** - Same pipeline logic across CLI, API, and Web UI
- ✅ **Reliability** - Battle-tested pipeline with state persistence
- ✅ **Features** - Auto-resume, error recovery, real-time progress
- ✅ **Backward Compatible** - All existing templates work unchanged
- ✅ **Production Ready** - Proper logging, error handling, monitoring

## Architecture

### Before (Old System)

```
Web UI → Custom Logic → Various Scripts → Output
   ↓
Manual State Management
   ↓
Custom Error Handling
```

### After (Unified Pipeline)

```
Web UI → Pipeline Orchestrator → 6 Unified Stages → Output
             ↓
        State Manager (automatic persistence)
             ↓
        Event System (real-time updates)
             ↓
        Error Recovery (automatic retry)
```

### Pipeline Stages

The unified pipeline executes these stages automatically:

1. **Input Stage** - Adapts various inputs to VideoConfig
2. **Parsing Stage** - Parses and structures content
3. **Script Generation Stage** - Generates narration scripts
4. **Audio Generation Stage** - Generates TTS audio
5. **Video Generation Stage** - Renders video scenes
6. **Output Stage** - Combines and exports final video

## API Endpoints

All endpoints maintain backward-compatible contracts while using the unified pipeline internally.

### Document Parsing

**POST** `/api/parse/document`

```json
{
  "content": "# Your Document\n\nContent here...",
  "accent_color": "blue",
  "voice": "male"
}
```

**Response:**
```json
{
  "task_id": "doc_1234567890",
  "status": "started",
  "message": "Document parsing started"
}
```

### YouTube Parsing

**POST** `/api/parse/youtube`

```json
{
  "url": "https://youtube.com/watch?v=...",
  "duration": 60,
  "accent_color": "blue"
}
```

**Response:**
```json
{
  "task_id": "yt_1234567890",
  "status": "started",
  "message": "YouTube parsing started"
}
```

### Video Generation

**POST** `/api/generate`

```json
{
  "set_id": "my_video_set",
  "set_name": "My Videos",
  "videos": [
    {
      "video_id": "vid_1",
      "title": "My Video",
      "scenes": [
        {
          "scene_id": "scene_1",
          "scene_type": "title",
          "narration": "Welcome!",
          "visual_content": {
            "title": "Welcome",
            "subtitle": "To My Video"
          }
        }
      ]
    }
  ],
  "accent_color": "blue"
}
```

**Response:**
```json
{
  "task_id": "gen_1234567890",
  "status": "started",
  "message": "Video generation started"
}
```

### Multilingual Generation

**POST** `/api/generate/multilingual`

```json
{
  "video_set": { /* VideoSet object */ },
  "target_languages": ["en", "es", "fr", "de"],
  "source_language": "en",
  "translation_method": "claude"
}
```

**Response:**
```json
{
  "task_id": "ml_1234567890",
  "status": "started",
  "message": "Multilingual generation started for 4 languages",
  "languages": ["en", "es", "fr", "de"],
  "source_language": "en"
}
```

### Task Status

**GET** `/api/tasks/{task_id}`

**Response:**
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

### Progress Streaming (SSE)

**GET** `/api/tasks/{task_id}/stream`

Server-Sent Events stream providing real-time progress updates:

```
data: {"task_id":"gen_123","status":"processing","progress":25,"message":"Parsing content..."}

data: {"task_id":"gen_123","status":"processing","progress":50,"message":"Generating audio..."}

data: {"task_id":"gen_123","status":"complete","progress":100,"message":"Complete"}
```

### Language Support

**GET** `/api/languages`

Returns all 28+ supported languages with voice options.

**GET** `/api/languages/{code}/voices`

Returns available voices for a specific language.

### Utility Endpoints

- **GET** `/api/scene-types` - Available scene types
- **GET** `/api/voices` - Available voices
- **GET** `/api/colors` - Available accent colors
- **GET** `/api/health` - System health check

## Usage Examples

### Starting the Server

```bash
cd app
python main.py
```

Or with uvicorn:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Visit: http://localhost:8000

### Using the UI

1. **Main Page** (`/`) - Choose input method
2. **Builder** (`/builder`) - Visual scene builder
3. **Multilingual** (`/multilingual`) - Multi-language generation
4. **Progress** (`/progress`) - Track active tasks
5. **Create** (`/create`) - Unified creation interface

### Programmatic API Usage

```python
import requests

# Start document parsing
response = requests.post(
    "http://localhost:8000/api/parse/document",
    json={
        "content": "# My Tutorial\n\nLearn Python!",
        "voice": "male",
        "accent_color": "blue"
    }
)

task_id = response.json()["task_id"]

# Check status
status = requests.get(f"http://localhost:8000/api/tasks/{task_id}")
print(status.json())

# Stream progress
import sseclient

events = sseclient.SSEClient(
    f"http://localhost:8000/api/tasks/{task_id}/stream"
)

for event in events:
    data = json.loads(event.data)
    print(f"Progress: {data['progress']}% - {data['message']}")
```

## Integration Details

### Pipeline Integration

The Web UI integrates with the pipeline through a simple pattern:

```python
# 1. Create InputConfig
input_config = InputConfig(
    input_type="document",
    source=document_content,
    accent_color="blue",
    voice="male"
)

# 2. Get pipeline singleton
pipeline = get_pipeline()

# 3. Execute in background
background_tasks.add_task(
    execute_pipeline_task,
    pipeline,
    input_config
)
```

### State Management

The pipeline automatically:
- Persists state after each stage
- Enables resume on failure
- Tracks progress across all stages
- Stores artifacts and metadata

Task state is stored in: `.video_gen_state/{task_id}.json`

### Status Mapping

The integration maps pipeline statuses to API statuses for backward compatibility:

| Pipeline Status | API Status |
|----------------|------------|
| pending        | processing |
| running        | processing |
| paused         | processing |
| completed      | complete   |
| failed         | failed     |
| cancelled      | failed     |

### Error Handling

The pipeline provides automatic error handling:
- Exceptions are caught and logged
- State is persisted with error details
- Client receives proper HTTP error codes
- Detailed error messages in responses

## Testing

### Running Integration Tests

```bash
# Install test dependencies
pip install pytest httpx

# Run tests
pytest tests/test_web_ui_integration.py -v
```

### Test Coverage

The integration tests verify:
- ✅ All UI pages load correctly
- ✅ All API endpoints work
- ✅ Pipeline integration functions
- ✅ Backward compatibility maintained
- ✅ Error handling works properly
- ✅ Language support is available
- ✅ Health checks pass

### Manual Testing

```bash
# Start server
python app/main.py

# In another terminal, test health
curl http://localhost:8000/api/health

# Test document parsing
curl -X POST http://localhost:8000/api/parse/document \
  -H "Content-Type: application/json" \
  -d '{"content":"# Test","voice":"male","accent_color":"blue"}'
```

## Migration Notes

### What Changed

**Backend:**
- Now uses unified pipeline for all operations
- Replaced custom task storage with pipeline state manager
- Removed custom background task implementations
- Added proper logging and error handling

**Frontend:**
- **No changes required!** All templates work as-is
- API contracts remain the same
- Response formats are backward compatible

### What Stayed the Same

- All endpoint paths
- Request/response formats
- Template files (HTML/CSS/JS)
- UI/UX experience
- Language support

### Benefits

1. **Reliability** - Proven pipeline code
2. **Features** - Auto-resume, state persistence
3. **Consistency** - Same logic everywhere
4. **Maintainability** - Single code path
5. **Monitoring** - Unified event system

## Troubleshooting

### Common Issues

**Issue:** Pipeline not found
```
Error: No module named 'video_gen.pipeline'
```

**Solution:**
```bash
# Ensure video_gen package is in Python path
export PYTHONPATH=/path/to/video_gen:$PYTHONPATH
# Or in main.py it's added automatically
```

**Issue:** Task state not persisting
```
Error: Task not found
```

**Solution:**
- Check `.video_gen_state/` directory exists
- Verify write permissions
- Check state manager initialization

**Issue:** Imports failing
```
ImportError: cannot import name 'get_pipeline'
```

**Solution:**
- Verify video_gen package structure
- Check __init__.py files exist
- Reinstall package: `pip install -e .`

### Logging

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Check logs at: `logs/video_gen.log`

## Future Enhancements

Potential improvements:

1. **WebSocket Support** - Real-time bidirectional updates
2. **Redis Integration** - Distributed state management
3. **Queue System** - Celery/RabbitMQ for task distribution
4. **Caching** - Redis cache for API responses
5. **Authentication** - User accounts and API keys
6. **Rate Limiting** - Prevent abuse
7. **Monitoring** - Prometheus/Grafana integration

## Support

- **Documentation**: `/docs/` directory
- **Examples**: `/examples/` directory
- **Tests**: `/tests/` directory
- **Issues**: Report via project issue tracker

## Summary

The Web UI integration with the unified pipeline provides:

✅ **Production-ready** - Proper architecture and error handling
✅ **Backward compatible** - Existing code works unchanged
✅ **Feature-rich** - All pipeline capabilities available
✅ **Well-tested** - Comprehensive test suite
✅ **Documented** - Complete API and usage documentation

The integration is complete, tested, and ready for production use!
