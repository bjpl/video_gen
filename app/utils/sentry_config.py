"""
Sentry Error Tracking Configuration

Provides comprehensive error monitoring and performance tracking for the video generation system.

Features:
- Environment-aware initialization (production/staging/development)
- Release version tracking for deployment correlation
- User context tracking (when available)
- Request breadcrumbs for debugging
- Performance monitoring with configurable sample rates
- Custom context for pipeline errors
- Integration with FastAPI exception handlers

Environment Variables:
    SENTRY_DSN: Sentry Data Source Name (required for Sentry to work)
    ENVIRONMENT: Deployment environment (production/staging/development)
    RELEASE_VERSION: Version string for release tracking
    SENTRY_TRACES_SAMPLE_RATE: Performance monitoring sample rate (0.0-1.0)
    SENTRY_ENABLE_TRACING: Enable performance tracing (true/false)

Usage:
    from app.utils.sentry_config import init_sentry

    # Initialize during app startup
    init_sentry()
"""

import os
import logging
from typing import Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


def get_environment() -> str:
    """
    Detect the current deployment environment.

    Priority:
    1. ENVIRONMENT env var
    2. Railway-specific detection
    3. Default to 'development'

    Returns:
        Environment string: 'production', 'staging', or 'development'
    """
    # Explicit environment variable
    env = os.environ.get("ENVIRONMENT", "").lower()
    if env in ("production", "staging", "development"):
        return env

    # Railway environment detection
    if os.environ.get("RAILWAY_ENVIRONMENT"):
        railway_env = os.environ.get("RAILWAY_ENVIRONMENT", "").lower()
        if railway_env == "production":
            return "production"
        return "staging"

    # Check for other production indicators
    if os.environ.get("RAILWAY_STATIC_URL") or os.environ.get("RAILWAY_PUBLIC_DOMAIN"):
        return "production"

    # Default to development
    return "development"


def get_release_version() -> str:
    """
    Get the current release version for tracking.

    Priority:
    1. RELEASE_VERSION env var
    2. Git commit hash (if available)
    3. Railway deployment ID
    4. Default version string

    Returns:
        Version string for release tracking
    """
    # Explicit version
    if version := os.environ.get("RELEASE_VERSION"):
        return version

    # Try to get git commit hash
    try:
        git_dir = Path(__file__).parent.parent.parent / ".git"
        if git_dir.exists():
            head_file = git_dir / "HEAD"
            if head_file.exists():
                with open(head_file) as f:
                    ref = f.read().strip()
                    if ref.startswith("ref:"):
                        ref_path = git_dir / ref[5:]
                        if ref_path.exists():
                            with open(ref_path) as ref_f:
                                commit = ref_f.read().strip()[:8]
                                return f"git-{commit}"
    except Exception:
        pass

    # Railway deployment ID
    if deployment_id := os.environ.get("RAILWAY_DEPLOYMENT_ID"):
        return f"railway-{deployment_id[:8]}"

    # Default version
    return "video_gen-2.0.0"


def before_send(event: Dict[str, Any], hint: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Filter and enhance events before sending to Sentry.

    This function allows custom filtering and enrichment of error events.

    Args:
        event: The error event dictionary
        hint: Additional context about the event

    Returns:
        Modified event or None to drop the event
    """
    # Filter out specific errors that aren't actionable
    if "exc_info" in hint:
        exc_type, exc_value, tb = hint["exc_info"]

        # Don't send client disconnection errors
        if exc_type.__name__ in ("CancelledError", "ConnectionResetError"):
            return None

        # Don't send 404 errors for health checks
        if "404" in str(exc_value) and "/health" in str(exc_value):
            return None

    # Add custom tags based on error type
    if event.get("exception"):
        exception_values = event["exception"].get("values", [])
        if exception_values:
            exc_type = exception_values[0].get("type", "")

            # Tag pipeline-related errors
            if "Pipeline" in exc_type or "Stage" in exc_type:
                event.setdefault("tags", {})["error_category"] = "pipeline"

            # Tag API-related errors
            elif "HTTP" in exc_type or "Request" in exc_type:
                event.setdefault("tags", {})["error_category"] = "api"

            # Tag file-related errors
            elif "File" in exc_type or "IO" in exc_type:
                event.setdefault("tags", {})["error_category"] = "file_system"

    return event


def init_sentry() -> bool:
    """
    Initialize Sentry SDK with comprehensive configuration.

    This function sets up Sentry with environment-aware settings,
    performance monitoring, and custom error handling.

    Returns:
        True if Sentry was initialized successfully, False otherwise
    """
    dsn = os.environ.get("SENTRY_DSN")

    # Skip initialization if DSN not provided
    if not dsn:
        logger.info("Sentry DSN not configured - error tracking disabled")
        return False

    try:
        import sentry_sdk
        from sentry_sdk.integrations.fastapi import FastApiIntegration
        from sentry_sdk.integrations.starlette import StarletteIntegration
        from sentry_sdk.integrations.logging import LoggingIntegration

        environment = get_environment()
        release = get_release_version()

        # Configure performance monitoring
        enable_tracing = os.environ.get("SENTRY_ENABLE_TRACING", "true").lower() == "true"
        traces_sample_rate = float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0.1"))

        # Adjust sample rate based on environment
        if environment == "production":
            traces_sample_rate = min(traces_sample_rate, 0.1)  # Max 10% in production
        elif environment == "development":
            traces_sample_rate = 0.0  # Disable in development

        # Initialize Sentry
        sentry_sdk.init(
            dsn=dsn,
            environment=environment,
            release=release,

            # Integrations
            integrations=[
                FastApiIntegration(transaction_style="endpoint"),
                StarletteIntegration(transaction_style="endpoint"),
                LoggingIntegration(
                    level=logging.INFO,  # Capture info and above
                    event_level=logging.ERROR  # Send errors and above as events
                ),
            ],

            # Performance monitoring
            enable_tracing=enable_tracing,
            traces_sample_rate=traces_sample_rate,

            # Event filtering and enhancement
            before_send=before_send,

            # Additional options
            attach_stacktrace=True,
            send_default_pii=False,  # Don't send personally identifiable info
            max_breadcrumbs=50,

            # Request data
            request_bodies="medium",  # Include request bodies (sanitized)
        )

        logger.info(
            f"Sentry initialized successfully - "
            f"environment={environment}, release={release}, "
            f"tracing={enable_tracing}, sample_rate={traces_sample_rate}"
        )

        return True

    except ImportError:
        logger.warning("sentry-sdk not installed - error tracking disabled")
        return False
    except Exception as e:
        logger.error(f"Failed to initialize Sentry: {e}", exc_info=True)
        return False


def capture_pipeline_error(
    error: Exception,
    task_id: str,
    stage: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None
) -> None:
    """
    Capture a pipeline error with custom context.

    This function sends pipeline-specific errors to Sentry with
    enriched context for better debugging.

    Args:
        error: The exception that occurred
        task_id: The pipeline task ID
        stage: The pipeline stage where the error occurred
        context: Additional context dictionary
    """
    try:
        import sentry_sdk

        with sentry_sdk.push_scope() as scope:
            # Add pipeline context
            scope.set_tag("task_id", task_id)
            scope.set_tag("error_category", "pipeline")

            if stage:
                scope.set_tag("pipeline_stage", stage)
                scope.set_context("pipeline", {
                    "stage": stage,
                    "task_id": task_id
                })

            # Add custom context
            if context:
                scope.set_context("custom", context)

            # Capture the exception
            sentry_sdk.capture_exception(error)

    except Exception as e:
        logger.error(f"Failed to capture pipeline error in Sentry: {e}")


def capture_api_error(
    error: Exception,
    endpoint: str,
    method: str,
    status_code: Optional[int] = None,
    user_id: Optional[str] = None
) -> None:
    """
    Capture an API error with request context.

    Args:
        error: The exception that occurred
        endpoint: The API endpoint path
        method: HTTP method (GET, POST, etc.)
        status_code: HTTP status code if applicable
        user_id: User identifier if available
    """
    try:
        import sentry_sdk

        with sentry_sdk.push_scope() as scope:
            # Add API context
            scope.set_tag("endpoint", endpoint)
            scope.set_tag("http_method", method)
            scope.set_tag("error_category", "api")

            if status_code:
                scope.set_tag("status_code", str(status_code))

            if user_id:
                scope.set_user({"id": user_id})

            scope.set_context("api", {
                "endpoint": endpoint,
                "method": method,
                "status_code": status_code
            })

            # Capture the exception
            sentry_sdk.capture_exception(error)

    except Exception as e:
        logger.error(f"Failed to capture API error in Sentry: {e}")


def set_user_context(user_id: str, email: Optional[str] = None, username: Optional[str] = None) -> None:
    """
    Set user context for error tracking.

    This associates errors with specific users for better debugging.

    Args:
        user_id: Unique user identifier
        email: User email (optional)
        username: Username (optional)
    """
    try:
        import sentry_sdk

        user_data = {"id": user_id}
        if email:
            user_data["email"] = email
        if username:
            user_data["username"] = username

        sentry_sdk.set_user(user_data)

    except Exception as e:
        logger.error(f"Failed to set user context in Sentry: {e}")


def clear_user_context() -> None:
    """Clear user context (e.g., on logout)."""
    try:
        import sentry_sdk
        sentry_sdk.set_user(None)
    except Exception:
        pass


def add_breadcrumb(
    message: str,
    category: str = "default",
    level: str = "info",
    data: Optional[Dict[str, Any]] = None
) -> None:
    """
    Add a breadcrumb for debugging context.

    Breadcrumbs provide a trail of events leading up to an error.

    Args:
        message: Breadcrumb message
        category: Category for grouping (e.g., 'pipeline', 'api', 'auth')
        level: Severity level ('debug', 'info', 'warning', 'error', 'fatal')
        data: Additional structured data
    """
    try:
        import sentry_sdk

        sentry_sdk.add_breadcrumb(
            message=message,
            category=category,
            level=level,
            data=data or {}
        )

    except Exception:
        pass
