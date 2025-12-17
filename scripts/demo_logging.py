#!/usr/bin/env python3
"""
Demonstration script for structured JSON logging.

This script shows the logging output in both development and production modes.

Usage:
    # Development mode (colored, human-readable)
    ENVIRONMENT=development python scripts/demo_logging.py

    # Production mode (JSON, machine-readable)
    ENVIRONMENT=production python scripts/demo_logging.py

    # With file output
    LOG_FILE=/tmp/demo.log python scripts/demo_logging.py
"""
import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app.utils.logging_config import setup_logging, request_id_ctx, request_path_ctx, request_method_ctx
import logging

# Configure logging
setup_logging(
    level=os.getenv("LOG_LEVEL", "INFO"),
    json_logs=None,  # Auto-detect
    log_file=os.getenv("LOG_FILE")
)

# Get loggers
logger = logging.getLogger("demo")
api_logger = logging.getLogger("app.api")
pipeline_logger = logging.getLogger("app.pipeline")


def simulate_api_request():
    """Simulate an API request with correlation ID."""
    print("\n=== Simulating API Request ===\n")

    # Set request context (normally done by middleware)
    request_id_ctx.set("req-abc123def456")
    request_path_ctx.set("/api/generate")
    request_method_ctx.set("POST")

    # Log request start
    api_logger.info(
        "Request started",
        extra={
            "endpoint": "/api/generate",
            "client_ip": "192.168.1.100",
            "user_agent": "Mozilla/5.0"
        }
    )

    # Simulate processing
    pipeline_logger.info(
        "Pipeline stage started",
        extra={
            "stage": "audio_generation",
            "task_id": "gen_1734394501",
            "video_count": 3
        }
    )

    pipeline_logger.info(
        "Pipeline stage completed",
        extra={
            "stage": "audio_generation",
            "task_id": "gen_1734394501",
            "duration_ms": 1250
        }
    )

    # Log request completion
    api_logger.info(
        "Request completed",
        extra={
            "endpoint": "/api/generate",
            "status_code": 200,
            "duration_ms": 1500
        }
    )

    # Clear context
    request_id_ctx.set(None)
    request_path_ctx.set(None)
    request_method_ctx.set(None)


def simulate_error_handling():
    """Simulate error logging with exception info."""
    print("\n=== Simulating Error Handling ===\n")

    request_id_ctx.set("req-error999")
    request_path_ctx.set("/api/parse/document")
    request_method_ctx.set("POST")

    try:
        # Simulate an error
        raise ValueError("Invalid document format: Expected markdown, got binary data")
    except Exception as e:
        logger.error(
            "Document parsing failed",
            extra={
                "document_path": "/uploads/invalid_file.pdf",
                "error_type": type(e).__name__,
                "validation": "format_check"
            },
            exc_info=True  # Include full stack trace
        )

    request_id_ctx.set(None)
    request_path_ctx.set(None)
    request_method_ctx.set(None)


def demonstrate_log_levels():
    """Show different log levels."""
    print("\n=== Demonstrating Log Levels ===\n")

    logger.debug("Debug message: Detailed trace information", extra={"trace_id": 12345})
    logger.info("Info message: Normal operation", extra={"operation": "startup"})
    logger.warning("Warning message: Potential issue detected", extra={"memory_usage_mb": 512, "threshold_mb": 400})
    logger.error("Error message: Operation failed", extra={"retry_count": 3, "max_retries": 5})
    logger.critical("Critical message: System failure", extra={"component": "database", "status": "unavailable"})


def demonstrate_context_usage():
    """Show logging with rich context."""
    print("\n=== Demonstrating Rich Context ===\n")

    request_id_ctx.set("req-context-demo")

    logger.info(
        "Video generation task created",
        extra={
            "task_id": "gen_1734394501",
            "input_type": "document",
            "document_path": "/uploads/tutorial.md",
            "languages": ["en", "es", "fr"],
            "accent_color": "blue",
            "voice": "male",
            "estimated_duration_seconds": 180
        }
    )

    logger.info(
        "Processing stages",
        extra={
            "task_id": "gen_1734394501",
            "stages": [
                {"name": "input_adaptation", "status": "completed", "duration_ms": 100},
                {"name": "content_parsing", "status": "completed", "duration_ms": 500},
                {"name": "script_generation", "status": "running", "progress": 0.75},
                {"name": "audio_generation", "status": "pending"},
                {"name": "video_generation", "status": "pending"},
                {"name": "output_handling", "status": "pending"}
            ]
        }
    )

    request_id_ctx.set(None)


def main():
    """Run all demonstrations."""
    environment = os.getenv("ENVIRONMENT", "development")
    log_format = "JSON" if environment == "production" else "Standard"

    print(f"\n{'='*60}")
    print(f"  Structured Logging Demonstration")
    print(f"  Environment: {environment}")
    print(f"  Log Format: {log_format}")
    print(f"  Log Level: {os.getenv('LOG_LEVEL', 'INFO')}")
    if os.getenv("LOG_FILE"):
        print(f"  Log File: {os.getenv('LOG_FILE')}")
    print(f"{'='*60}")

    # Run demonstrations
    simulate_api_request()
    demonstrate_log_levels()
    demonstrate_context_usage()
    simulate_error_handling()

    print("\n" + "="*60)
    print("  Demonstration Complete")
    print("="*60 + "\n")

    if log_format == "JSON":
        print("\nTIP: Pipe output through 'jq' for pretty-printed JSON:")
        print("  ENVIRONMENT=production python scripts/demo_logging.py | jq .")
        print("\nSearch by request ID:")
        print("  ENVIRONMENT=production python scripts/demo_logging.py | jq 'select(.request_id == \"req-abc123def456\")'")
    else:
        print("\nTIP: Try production mode to see JSON output:")
        print("  ENVIRONMENT=production python scripts/demo_logging.py")


if __name__ == "__main__":
    main()
