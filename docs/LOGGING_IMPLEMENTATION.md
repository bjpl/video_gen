# Structured JSON Logging Implementation

## Summary

Structured JSON logging has been successfully implemented for the video_gen project. The system provides production-ready JSON logging with request correlation IDs and development-friendly colored output.

## Files Created

### 1. Core Logging Module
**File:** `/app/utils/logging_config.py`

Features:
- **JSONFormatter**: Formats logs as structured JSON with timestamp, level, logger, message, request_id, and context
- **ColoredFormatter**: Development-friendly colored output with request ID display
- **setup_logging()**: Auto-configures logging based on environment
- **RequestLoggingMiddleware**: FastAPI middleware for request tracking and correlation IDs
- **Context Variables**: Thread-safe request context storage (request_id, path, method)
- **Helper Functions**: `get_request_id()`, `log_with_context()`, `create_child_logger()`

### 2. Updated Utilities Module
**File:** `/app/utils/__init__.py`

Exports all logging functions for easy import throughout the application.

### 3. Documentation
**File:** `/docs/logging_integration_guide.md`

Comprehensive guide covering:
- Integration steps for main.py
- Environment configuration
- Output examples (development vs production)
- Usage patterns and best practices
- Request correlation
- Log analysis examples
- Deployment considerations

### 4. Demo Script
**File:** `/scripts/demo_logging.py`

Interactive demonstration showing:
- API request simulation with correlation IDs
- Different log levels
- Rich context usage
- Error handling with stack traces

## Integration Required

The logging system is ready to use but requires manual integration into `app/main.py` due to file modification conflicts. Follow these steps:

### Step 1: Update Imports in app/main.py

Replace lines 31-92 with:

```python
# Add app directory to path for utils import
app_dir = Path(__file__).parent
sys.path.insert(0, str(app_dir.parent))

# Load environment variables FIRST (needed for logging configuration)
from dotenv import load_dotenv
load_dotenv()
load_dotenv(Path(__file__).parent / ".env")

# Configure structured logging BEFORE other imports
from app.utils.logging_config import setup_logging, RequestLoggingMiddleware

setup_logging(
    level=os.getenv("LOG_LEVEL", "INFO"),
    json_logs=None,  # Auto-detect: JSON for production, standard for development
    log_file=os.getenv("LOG_FILE")  # Optional file output
)

# Get logger AFTER setup
logger = logging.getLogger(__name__)

# Import file validation utilities
try:
    from app.utils.file_validation import (
        validate_upload,
        preview_document_structure,
        create_validation_response,
        create_error_response,
        detect_document_format,
        sanitize_filename,
        get_upload_progress_stages,
        format_progress_message,
        convert_to_markdown,
        is_binary_content,
    )
except ImportError:
    pass

# Add scripts directory to path
scripts_dir = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

# Add parent directory to path for video_gen imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Initialize Sentry error tracking
from app.utils.sentry_config import init_sentry
init_sentry()

# ... continue with rest of imports (rate limiting, security headers, etc.)
```

**Key Changes:**
- Move `load_dotenv()` before logging setup
- Import `setup_logging` and `RequestLoggingMiddleware`
- Call `setup_logging()` before getting logger
- Remove old `logging.basicConfig()` call
- Get logger AFTER setup

### Step 2: Add Middleware (around line 125)

After `setup_rate_limiting(app)`, add:

```python
# Setup rate limiting BEFORE routes are defined
setup_rate_limiting(app)

# Setup security headers middleware
setup_security_headers(app)

# ADD THIS LINE:
# Setup request logging middleware for correlation IDs and timing
app.add_middleware(RequestLoggingMiddleware)
```

### Step 3: Environment Configuration

Add to `.env` or set environment variables:

```bash
# Development
LOG_LEVEL=INFO
ENVIRONMENT=development

# Production
LOG_LEVEL=INFO
ENVIRONMENT=production
LOG_FILE=/var/log/video_gen/app.log  # Optional
```

## Testing

### 1. Test the Demo Script

```bash
# Development mode (colored output)
ENVIRONMENT=development python3 scripts/demo_logging.py

# Production mode (JSON output)
ENVIRONMENT=production python3 scripts/demo_logging.py

# Pretty-print JSON
ENVIRONMENT=production python3 scripts/demo_logging.py 2>&1 | jq .
```

### 2. Test with Application

```bash
# Development
LOG_LEVEL=DEBUG ENVIRONMENT=development uvicorn app.main:app --reload

# Production
LOG_LEVEL=INFO ENVIRONMENT=production uvicorn app.main:app

# With file logging
LOG_FILE=/tmp/video_gen.log uvicorn app.main:app
```

### 3. Test Request Correlation

```bash
# Send request with custom ID
curl -H "X-Request-ID: test-12345" http://localhost:8000/api/health

# Check logs for correlation
cat /tmp/video_gen.log | jq 'select(.request_id == "test-12345")'
```

## Example Output

### Development Mode
```
2025-12-16 23:45:00 [abc12345] INFO     app.main:lifespan:102 - Pipeline initialized with 6 stages
2025-12-16 23:45:01 [xyz98765] INFO     app.middleware:dispatch:89 - POST /api/generate
2025-12-16 23:45:02 [xyz98765] INFO     app.middleware:dispatch:98 - POST /api/generate - 200
```

### Production Mode (JSON)
```json
{
  "timestamp": "2025-12-16T23:45:00Z",
  "level": "INFO",
  "logger": "app.main",
  "message": "Pipeline initialized with 6 stages",
  "file": "main.py:102",
  "function": "lifespan"
}
{
  "timestamp": "2025-12-16T23:45:01Z",
  "level": "INFO",
  "logger": "app.middleware",
  "message": "POST /api/generate",
  "request_id": "xyz98765",
  "path": "/api/generate",
  "method": "POST",
  "file": "logging_config.py:89",
  "function": "dispatch",
  "context": {
    "query_params": "",
    "client_host": "127.0.0.1",
    "user_agent": "Mozilla/5.0"
  }
}
{
  "timestamp": "2025-12-16T23:45:02Z",
  "level": "INFO",
  "logger": "app.middleware",
  "message": "POST /api/generate - 200",
  "request_id": "xyz98765",
  "path": "/api/generate",
  "method": "POST",
  "file": "logging_config.py:98",
  "function": "dispatch",
  "context": {
    "status_code": 200,
    "duration_ms": 42
  }
}
```

## Key Features

### 1. Automatic Environment Detection
- Detects TTY for development vs container/cloud for production
- Uses `ENVIRONMENT` env var for explicit control
- JSON format for production, colored format for development

### 2. Request Correlation
- Extracts or generates `X-Request-ID` header
- Stores in thread-safe context
- Includes in all logs during request
- Returns in response headers

### 3. Structured Context
- All logs include timestamp, level, logger, file, function
- Optional context fields via `extra` parameter
- Automatic request context (ID, path, method)
- Exception stack traces in JSON format

### 4. Performance Tracking
- Automatic request duration logging
- Stage-level timing in context
- Easy extraction of performance metrics

### 5. Production Ready
- Machine-parseable JSON
- Log aggregation compatible
- Searchable by request ID
- Error tracking integration

## Usage Examples

### Basic Logging
```python
logger.info("Server started", extra={"port": 8000, "host": "0.0.0.0"})
```

### With Request Context
```python
logger.info(
    "Video generation started",
    extra={
        "task_id": task_id,
        "video_count": 3,
        "languages": ["en", "es"]
    }
)
```

### Error Logging
```python
try:
    result = await operation()
except Exception as e:
    logger.error(
        "Operation failed",
        extra={"operation": "video_gen", "task_id": task_id},
        exc_info=True
    )
```

### Get Request ID
```python
from app.utils.logging_config import get_request_id

request_id = get_request_id()
if request_id:
    logger.info(f"Processing request {request_id}")
```

## Log Analysis

### Search by Request ID
```bash
cat app.log | jq 'select(.request_id == "abc123")'
```

### Find Slow Requests
```bash
cat app.log | jq 'select(.context.duration_ms > 1000)'
```

### Error Summary
```bash
cat app.log | jq 'select(.level == "ERROR") | {time: .timestamp, error: .message, request: .request_id}'
```

### Performance Metrics
```bash
cat app.log | jq 'select(.context.duration_ms) | {path, duration: .context.duration_ms}' | jq -s 'group_by(.path) | map({path: .[0].path, avg: (map(.duration) | add / length)})'
```

## Benefits

1. **Request Tracing**: Track requests across the system via correlation IDs
2. **Structured Search**: Easy to filter and analyze JSON logs
3. **Performance Monitoring**: Extract timing metrics from logs
4. **Error Context**: Better debugging with structured error data
5. **Development UX**: Readable colored logs during development
6. **Production Ready**: Machine-parseable for log aggregation
7. **Backward Compatible**: Existing log statements work as-is

## Next Steps

1. **Integrate into main.py** following steps above
2. **Test with development server** to verify output
3. **Configure production environment** with appropriate LOG_LEVEL
4. **Set up log aggregation** (e.g., CloudWatch, ELK, Datadog) for JSON logs
5. **Create dashboards** based on structured log data
6. **Monitor performance** using duration_ms metrics

## Deployment Notes

### Docker
```dockerfile
ENV ENVIRONMENT=production
ENV LOG_LEVEL=INFO
```

### Railway/Heroku
```bash
# Set in platform UI
ENVIRONMENT=production
LOG_LEVEL=INFO
```

### Systemd
```ini
Environment="ENVIRONMENT=production"
Environment="LOG_LEVEL=INFO"
```

## References

- Integration Guide: `/docs/logging_integration_guide.md`
- Demo Script: `/scripts/demo_logging.py`
- Logging Module: `/app/utils/logging_config.py`

---

**Implementation Status:** ✅ Complete - Ready for Integration

**Action Required:** Manual integration into `app/main.py` (Steps 1 & 2 above)
