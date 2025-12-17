# Structured Logging - Quick Reference

## Basic Usage

```python
import logging

logger = logging.getLogger(__name__)

# Simple log
logger.info("Operation completed")

# With context
logger.info("Task created", extra={"task_id": "gen_123", "user_id": 456})

# Error with stack trace
try:
    risky_operation()
except Exception as e:
    logger.error("Operation failed", extra={"task_id": "gen_123"}, exc_info=True)
```

## Environment Variables

```bash
# Development (colored, human-readable)
ENVIRONMENT=development
LOG_LEVEL=DEBUG

# Production (JSON, machine-readable)
ENVIRONMENT=production
LOG_LEVEL=INFO
LOG_FILE=/var/log/app/video_gen.log
```

## Request Correlation

```python
from app.utils.logging_config import get_request_id

# Get current request ID
request_id = get_request_id()

# It's automatically included in logs during requests
logger.info("Processing")  # Includes request_id automatically
```

## Common Patterns

### API Endpoint Logging
```python
@app.post("/api/generate")
async def generate(data: VideoSet):
    logger.info(
        "Generation started",
        extra={
            "set_id": data.set_id,
            "video_count": len(data.videos),
            "languages": data.languages
        }
    )
    # ... processing ...
    logger.info(
        "Generation completed",
        extra={"set_id": data.set_id, "duration_ms": 1500}
    )
```

### Pipeline Stage Logging
```python
logger.info(
    "Stage started",
    extra={
        "stage": "audio_generation",
        "task_id": task_id,
        "input_count": len(inputs)
    }
)

# ... processing ...

logger.info(
    "Stage completed",
    extra={
        "stage": "audio_generation",
        "task_id": task_id,
        "duration_ms": 2500,
        "output_count": len(outputs)
    }
)
```

### Error Handling
```python
try:
    result = process_document(path)
except FileNotFoundError as e:
    logger.error(
        "Document not found",
        extra={
            "path": path,
            "task_id": task_id,
            "error_type": "FileNotFoundError"
        }
    )
except ValidationError as e:
    logger.error(
        "Invalid document format",
        extra={
            "path": path,
            "validation_errors": str(e),
            "task_id": task_id
        },
        exc_info=True
    )
```

## Log Analysis Commands

```bash
# Pretty-print JSON logs
cat app.log | jq .

# Find logs for specific request
cat app.log | jq 'select(.request_id == "abc123")'

# Find errors
cat app.log | jq 'select(.level == "ERROR")'

# Find slow requests (>1000ms)
cat app.log | jq 'select(.context.duration_ms > 1000)'

# Group by endpoint
cat app.log | jq 'select(.path) | .path' | sort | uniq -c

# Average duration by endpoint
cat app.log | jq -s 'group_by(.path) | map({
  path: .[0].path,
  count: length,
  avg_ms: (map(.context.duration_ms // 0) | add / length)
})'
```

## Output Examples

### Development
```
2025-12-16 23:45:01 [abc123] INFO  app.api:generate:89 - Generation started
2025-12-16 23:45:03 [abc123] INFO  app.api:generate:95 - Generation completed
```

### Production (JSON)
```json
{
  "timestamp": "2025-12-16T23:45:01Z",
  "level": "INFO",
  "logger": "app.api",
  "message": "Generation started",
  "request_id": "abc123",
  "path": "/api/generate",
  "method": "POST",
  "file": "routes.py:89",
  "context": {
    "set_id": "tutorial_01",
    "video_count": 3,
    "languages": ["en", "es"]
  }
}
```

## Testing

```bash
# Test development mode
ENVIRONMENT=development python3 scripts/demo_logging.py

# Test production mode
ENVIRONMENT=production python3 scripts/demo_logging.py | jq .

# Run server with debug logging
LOG_LEVEL=DEBUG uvicorn app.main:app --reload

# Test with file output
LOG_FILE=/tmp/test.log uvicorn app.main:app
```

## Best Practices

1. **Always use extra for context**: `logger.info("msg", extra={...})`
2. **Include task/request IDs**: Makes tracing easier
3. **Log at appropriate levels**: DEBUG=trace, INFO=normal, WARNING=issues, ERROR=failures
4. **Use exc_info=True for errors**: Includes full stack trace
5. **Log stage timing**: Include duration_ms for performance tracking
6. **Avoid sensitive data**: Don't log passwords, tokens, API keys

## Log Levels

- **DEBUG**: Detailed trace information for debugging
- **INFO**: Normal operations and milestones
- **WARNING**: Potential issues or degraded performance
- **ERROR**: Operation failures that need attention
- **CRITICAL**: System-level failures requiring immediate action

## Integration Checklist

- [ ] Import `setup_logging` and `RequestLoggingMiddleware`
- [ ] Call `setup_logging()` before creating loggers
- [ ] Add `RequestLoggingMiddleware` to FastAPI app
- [ ] Set `ENVIRONMENT` and `LOG_LEVEL` env vars
- [ ] Test with demo script
- [ ] Verify request correlation in logs
- [ ] Configure log aggregation for production

## Support

See full documentation: `/docs/logging_integration_guide.md`
