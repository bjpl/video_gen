# Structured JSON Logging Integration Guide

This guide shows how to integrate the new structured JSON logging system into the video_gen FastAPI application.

## Overview

The new logging system provides:
- **JSON-formatted logs** for production (machine-readable)
- **Standard colored logs** for development (human-readable)
- **Request correlation IDs** via X-Request-ID header
- **Context-aware logging** with timestamps, levels, and metadata
- **Automatic environment detection** (development vs production)

## Integration Steps

### Step 1: Update app/main.py Imports

Replace the current logging setup in `app/main.py`:

```python
# BEFORE (lines 31-92):
# Add app directory to path for utils import
app_dir = Path(__file__).parent
sys.path.insert(0, str(app_dir.parent))

# Import file validation utilities
try:
    from app.utils.file_validation import (
        validate_upload,
        # ... other imports
    )
except ImportError:
    pass

# Add scripts directory to path
scripts_dir = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

# Add parent directory to path for video_gen imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Load environment variables
from dotenv import load_dotenv
load_dotenv()
load_dotenv(Path(__file__).parent / ".env")

# Initialize Sentry error tracking
from app.utils.sentry_config import init_sentry
init_sentry()

# ... other imports ...

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
```

**AFTER:**

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
        # ... other imports
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

# ... rest of imports ...
```

### Step 2: Add Request Logging Middleware

Add the middleware to the FastAPI app instance after `setup_rate_limiting(app)`:

```python
# In app/main.py, around line 125:

# Setup rate limiting BEFORE routes are defined
setup_rate_limiting(app)

# ADD THIS: Setup request logging middleware for correlation IDs
app.add_middleware(RequestLoggingMiddleware)
```

### Step 3: Environment Configuration

Create or update `.env` file with logging configuration:

```bash
# Logging Configuration
LOG_LEVEL=INFO              # DEBUG, INFO, WARNING, ERROR, CRITICAL
ENVIRONMENT=development     # development or production

# Optional: Log to file
# LOG_FILE=/var/log/video_gen/app.log
```

For production deployment:

```bash
# Production .env
LOG_LEVEL=INFO
ENVIRONMENT=production      # Enables JSON logging automatically
LOG_FILE=/var/log/video_gen/app.log
```

## Output Examples

### Development Mode (Standard Logging)

When `ENVIRONMENT=development` or running with a TTY:

```
2025-12-16 23:45:00 [abc12345] INFO     app.main:lifespan:102 - Pipeline initialized with 6 stages
2025-12-16 23:45:01 [xyz98765] INFO     app.middleware:dispatch:89 - POST /api/generate
2025-12-16 23:45:01 [xyz98765] INFO     app.routes:generate_videos:1376 - Video generation started: gen_1734394501
2025-12-16 23:45:02 [xyz98765] INFO     app.middleware:dispatch:98 - POST /api/generate - 200
```

### Production Mode (JSON Logging)

When `ENVIRONMENT=production` or running without TTY (containers, cloud):

```json
{"timestamp": "2025-12-16T23:45:00Z", "level": "INFO", "logger": "app.main", "message": "Pipeline initialized with 6 stages", "file": "main.py:102", "function": "lifespan"}
{"timestamp": "2025-12-16T23:45:01Z", "level": "INFO", "logger": "app.middleware", "message": "POST /api/generate", "request_id": "xyz98765", "path": "/api/generate", "method": "POST", "file": "logging_config.py:89", "function": "dispatch", "context": {"query_params": "", "client_host": "127.0.0.1", "user_agent": "Mozilla/5.0"}}
{"timestamp": "2025-12-16T23:45:01Z", "level": "INFO", "logger": "app.routes", "message": "Video generation started: gen_1734394501", "request_id": "xyz98765", "path": "/api/generate", "method": "POST", "file": "main.py:1376", "function": "generate_videos", "context": {"task_id": "gen_1734394501", "set_id": "tutorial_01"}}
{"timestamp": "2025-12-16T23:45:02Z", "level": "INFO", "logger": "app.middleware", "message": "POST /api/generate - 200", "request_id": "xyz98765", "path": "/api/generate", "method": "POST", "file": "logging_config.py:98", "function": "dispatch", "context": {"status_code": 200, "duration_ms": 42}}
```

## Usage in Code

### Basic Logging with Context

```python
logger.info(
    "Video generation started",
    extra={
        "task_id": task_id,
        "video_count": len(videos),
        "languages": languages
    }
)
```

Output (JSON):
```json
{
  "timestamp": "2025-12-16T23:45:01Z",
  "level": "INFO",
  "logger": "app.routes",
  "message": "Video generation started",
  "request_id": "abc123",
  "path": "/api/generate",
  "method": "POST",
  "file": "main.py:1376",
  "function": "generate_videos",
  "context": {
    "task_id": "gen_1734394501",
    "video_count": 3,
    "languages": ["en", "es", "fr"]
  }
}
```

### Error Logging with Stack Traces

```python
try:
    result = await risky_operation()
except Exception as e:
    logger.error(
        "Operation failed",
        extra={
            "operation": "video_generation",
            "task_id": task_id,
            "error_type": type(e).__name__
        },
        exc_info=True  # Includes full stack trace
    )
```

### Getting Request ID in Code

```python
from app.utils.logging_config import get_request_id

def some_function():
    request_id = get_request_id()
    if request_id:
        logger.info(f"Processing request {request_id}")
```

### Creating Child Loggers

```python
from app.utils.logging_config import create_child_logger

# Creates logger named "app.pipeline"
logger = create_child_logger("pipeline")

logger.info("Pipeline stage completed", extra={"stage": "audio_generation"})
```

## Request Correlation

The middleware automatically:
1. Extracts or generates `X-Request-ID` header
2. Stores it in thread-local context
3. Includes it in all logs during request processing
4. Returns it in response headers

### Client Usage

Send requests with custom correlation ID:

```bash
curl -H "X-Request-ID: my-custom-id-12345" \
  http://localhost:8000/api/generate
```

Or let the server generate one (returned in response headers):

```bash
curl -i http://localhost:8000/api/generate
# Response includes: X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
```

## Log Analysis Examples

### Search logs by request ID (JSON logs)

```bash
# Find all logs for a specific request
cat app.log | jq 'select(.request_id == "abc123")'

# Get duration metrics
cat app.log | jq 'select(.context.duration_ms) | {path, duration: .context.duration_ms}'

# Find errors
cat app.log | jq 'select(.level == "ERROR")'

# Get slow requests (>1000ms)
cat app.log | jq 'select(.context.duration_ms > 1000) | {path, duration: .context.duration_ms, request_id}'
```

### Monitor with standard tools

```bash
# tail -f with jq for pretty printing
tail -f app.log | jq .

# grep for specific patterns
tail -f app.log | jq 'select(.logger | contains("pipeline"))'
```

## Testing

### Test the logging configuration

```bash
cd /mnt/c/Users/brand/Development/Project_Workspace/active-development/video_gen

# Test JSON logging
ENVIRONMENT=production python app/utils/logging_config.py

# Test standard logging
ENVIRONMENT=development python app/utils/logging_config.py
```

### Test with the application

```bash
# Development mode
LOG_LEVEL=DEBUG ENVIRONMENT=development uvicorn app.main:app

# Production mode
LOG_LEVEL=INFO ENVIRONMENT=production uvicorn app.main:app

# With file logging
LOG_FILE=/tmp/video_gen.log uvicorn app.main:app
```

## Deployment Considerations

### Docker

Add to Dockerfile:

```dockerfile
ENV ENVIRONMENT=production
ENV LOG_LEVEL=INFO
ENV LOG_FILE=/var/log/app/video_gen.log

# Create log directory
RUN mkdir -p /var/log/app && chown appuser:appuser /var/log/app
```

### Railway/Heroku

Set environment variables in platform:

```bash
ENVIRONMENT=production
LOG_LEVEL=INFO
# Don't set LOG_FILE - logs go to stdout for cloud platforms
```

### Systemd

Create service with logging:

```ini
[Service]
Environment="ENVIRONMENT=production"
Environment="LOG_LEVEL=INFO"
Environment="LOG_FILE=/var/log/video_gen/app.log"
StandardOutput=journal
StandardError=journal
```

## Benefits

1. **Structured Search**: Easy to search and filter JSON logs
2. **Request Tracing**: Track requests across services via correlation IDs
3. **Metrics Extraction**: Extract performance metrics from logs
4. **Error Tracking**: Better error context with structured data
5. **Development UX**: Colored, readable logs during development
6. **Production Ready**: Machine-parseable JSON for log aggregation systems
7. **Automatic Detection**: No code changes needed between dev/prod

## Migration from Old Logging

The new system is backward compatible. Existing log statements work as-is:

```python
# This still works:
logger.info("Simple message")

# But you can enhance it with context:
logger.info("Enhanced message", extra={"user_id": 123, "action": "login"})
```

All logs now include request correlation IDs automatically when available.
