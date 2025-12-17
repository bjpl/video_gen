"""
Structured JSON logging configuration for the video generation system.

This module provides:
- JSON-formatted structured logging for production
- Standard logging for development
- Request correlation IDs via X-Request-ID header
- Context-aware logging with timestamps, levels, and metadata
- FastAPI middleware integration
"""
import logging
import json
import sys
import time
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from contextvars import ContextVar
from pathlib import Path

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# ============================================================================
# Context Variables for Request Tracking
# ============================================================================

# Thread-safe storage for request context
request_id_ctx: ContextVar[Optional[str]] = ContextVar('request_id', default=None)
request_path_ctx: ContextVar[Optional[str]] = ContextVar('request_path', default=None)
request_method_ctx: ContextVar[Optional[str]] = ContextVar('request_method', default=None)


# ============================================================================
# JSON Formatter
# ============================================================================

class JSONFormatter(logging.Formatter):
    """
    Custom JSON formatter for structured logging.

    Outputs log records as JSON objects with:
    - timestamp: ISO 8601 UTC timestamp
    - level: Log level (INFO, ERROR, etc.)
    - logger: Logger name
    - message: Log message
    - request_id: Correlation ID from request context
    - context: Additional context fields
    """

    def __init__(self, include_extra: bool = True):
        """
        Initialize JSON formatter.

        Args:
            include_extra: Whether to include extra fields from record
        """
        super().__init__()
        self.include_extra = include_extra

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as JSON.

        Args:
            record: The log record to format

        Returns:
            JSON-formatted log string
        """
        # Base log data
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add request correlation ID if available
        request_id = request_id_ctx.get()
        if request_id:
            log_data["request_id"] = request_id

        # Add request path and method if available
        request_path = request_path_ctx.get()
        if request_path:
            log_data["path"] = request_path

        request_method = request_method_ctx.get()
        if request_method:
            log_data["method"] = request_method

        # Add file location
        log_data["file"] = f"{record.filename}:{record.lineno}"

        # Add function name for context
        if record.funcName and record.funcName != "<module>":
            log_data["function"] = record.funcName

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields if enabled
        if self.include_extra:
            # Extract custom fields from record
            extra_fields = {}
            for key, value in record.__dict__.items():
                # Skip standard logging attributes
                if key not in [
                    'name', 'msg', 'args', 'created', 'filename', 'funcName',
                    'levelname', 'levelno', 'lineno', 'module', 'msecs',
                    'message', 'pathname', 'process', 'processName',
                    'relativeCreated', 'thread', 'threadName', 'exc_info',
                    'exc_text', 'stack_info'
                ]:
                    # Only add JSON-serializable values
                    try:
                        json.dumps(value)
                        extra_fields[key] = value
                    except (TypeError, ValueError):
                        extra_fields[key] = str(value)

            if extra_fields:
                log_data["context"] = extra_fields

        return json.dumps(log_data, ensure_ascii=False)


# ============================================================================
# Standard Formatter for Development
# ============================================================================

class ColoredFormatter(logging.Formatter):
    """
    Colored formatter for development logging.

    Adds color codes for different log levels.
    """

    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
    }
    RESET = '\033[0m'

    def format(self, record: logging.LogRecord) -> str:
        """Format with colors if terminal supports it."""
        # Add color to level name
        if sys.stderr.isatty() and record.levelname in self.COLORS:
            record.levelname = (
                f"{self.COLORS[record.levelname]}{record.levelname}{self.RESET}"
            )

        # Add request ID if available
        request_id = request_id_ctx.get()
        if request_id:
            record.request_id = f"[{request_id[:8]}]"
        else:
            record.request_id = ""

        return super().format(record)


# ============================================================================
# Logging Configuration
# ============================================================================

def setup_logging(
    level: str = None,
    json_logs: bool = None,
    log_file: Optional[str] = None
) -> None:
    """
    Configure application logging based on environment.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
               If None, reads from LOG_LEVEL env var, defaults to INFO
        json_logs: Whether to use JSON formatting
                   If None, auto-detects: JSON for production, standard for dev
        log_file: Optional file path for log output
                  If None, logs to stderr only
    """
    # Determine log level
    if level is None:
        level = os.getenv("LOG_LEVEL", "INFO").upper()

    # Auto-detect environment if json_logs not specified
    if json_logs is None:
        # Use JSON logs in production (when ENVIRONMENT=production)
        # or when running in containers/cloud (no TTY)
        environment = os.getenv("ENVIRONMENT", "development").lower()
        is_production = environment == "production"
        is_containerized = not sys.stderr.isatty()
        json_logs = is_production or is_containerized

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    root_logger.handlers.clear()

    # Create formatter
    if json_logs:
        formatter = JSONFormatter(include_extra=True)
    else:
        # Development format with colors and request ID
        fmt = (
            "%(asctime)s %(request_id)s %(levelname)-8s "
            "%(name)s:%(funcName)s:%(lineno)d - %(message)s"
        )
        formatter = ColoredFormatter(fmt, datefmt="%Y-%m-%d %H:%M:%S")

    # Console handler (stderr)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        # Always use JSON for file logs
        file_handler.setFormatter(JSONFormatter(include_extra=True))
        root_logger.addHandler(file_handler)

    # Set library log levels to reduce noise
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    # Log configuration
    logger = logging.getLogger(__name__)
    logger.info(
        f"Logging configured",
        extra={
            "level": level,
            "json_format": json_logs,
            "log_file": log_file,
            "environment": os.getenv("ENVIRONMENT", "development")
        }
    )


# ============================================================================
# FastAPI Middleware for Request Tracking
# ============================================================================

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware to inject request correlation IDs and log requests.

    Features:
    - Generates or extracts X-Request-ID header
    - Stores request ID in context for log correlation
    - Logs request/response with timing
    - Handles errors gracefully
    """

    async def dispatch(self, request: Request, call_next):
        """
        Process request and inject logging context.

        Args:
            request: FastAPI request object
            call_next: Next middleware/handler in chain

        Returns:
            Response with X-Request-ID header
        """
        # Generate or extract request ID
        request_id = request.headers.get("X-Request-ID")
        if not request_id:
            request_id = str(uuid.uuid4())

        # Store in context for logging
        request_id_ctx.set(request_id)
        request_path_ctx.set(request.url.path)
        request_method_ctx.set(request.method)

        # Start timer
        start_time = time.time()

        # Get logger
        logger = logging.getLogger("app.middleware")

        # Log request
        logger.info(
            f"{request.method} {request.url.path}",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "query_params": str(request.query_params),
                "client_host": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
            }
        )

        # Process request
        try:
            response = await call_next(request)

            # Calculate duration
            duration_ms = int((time.time() - start_time) * 1000)

            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id

            # Log response
            logger.info(
                f"{request.method} {request.url.path} - {response.status_code}",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                }
            )

            return response

        except Exception as e:
            # Calculate duration even on error
            duration_ms = int((time.time() - start_time) * 1000)

            # Log error
            logger.error(
                f"{request.method} {request.url.path} - Error",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "duration_ms": duration_ms,
                    "error": str(e),
                },
                exc_info=True
            )

            # Re-raise to let FastAPI handle it
            raise

        finally:
            # Clear context
            request_id_ctx.set(None)
            request_path_ctx.set(None)
            request_method_ctx.set(None)


# ============================================================================
# Utility Functions
# ============================================================================

def get_request_id() -> Optional[str]:
    """
    Get the current request ID from context.

    Returns:
        Request ID string or None if not in request context
    """
    return request_id_ctx.get()


def log_with_context(
    logger: logging.Logger,
    level: str,
    message: str,
    **context: Any
) -> None:
    """
    Log a message with additional context fields.

    Args:
        logger: Logger instance to use
        level: Log level (debug, info, warning, error, critical)
        message: Log message
        **context: Additional context fields to include
    """
    log_func = getattr(logger, level.lower())
    log_func(message, extra=context)


def create_child_logger(name: str) -> logging.Logger:
    """
    Create a child logger with the given name.

    Args:
        name: Logger name (will be prefixed with 'app.')

    Returns:
        Configured logger instance
    """
    return logging.getLogger(f"app.{name}")


# ============================================================================
# Example Usage
# ============================================================================

if __name__ == "__main__":
    # Example: Test both formatters

    print("=== JSON Logging (Production Mode) ===")
    setup_logging(level="INFO", json_logs=True)
    logger = logging.getLogger("test.module")

    logger.info("Server started", extra={"port": 8000, "host": "0.0.0.0"})
    logger.warning("High memory usage", extra={"memory_mb": 512, "threshold_mb": 400})
    logger.error("Database connection failed", extra={"retries": 3, "timeout": 5})

    # Simulate request context
    request_id_ctx.set("abc123")
    request_path_ctx.set("/api/generate")
    request_method_ctx.set("POST")
    logger.info("Request completed", extra={"duration_ms": 42, "status": 200})
    request_id_ctx.set(None)

    print("\n=== Standard Logging (Development Mode) ===")
    setup_logging(level="INFO", json_logs=False)
    logger = logging.getLogger("test.module")

    logger.info("Server started", extra={"port": 8000})
    logger.warning("High memory usage", extra={"memory_mb": 512})

    # With request context
    request_id_ctx.set("xyz789")
    logger.info("Request completed", extra={"duration_ms": 42})
    request_id_ctx.set(None)
