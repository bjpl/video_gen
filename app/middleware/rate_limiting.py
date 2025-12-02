"""
Rate Limiting Middleware using slowapi

Implements IP-based rate limiting to prevent DoS attacks and API abuse.
Configurable via environment variables for flexible deployment.

Environment Variables:
    RATE_LIMIT_DEFAULT: Default limit for most endpoints (default: "100/minute")
    RATE_LIMIT_UPLOAD: Limit for upload endpoints (default: "5/minute")
    RATE_LIMIT_GENERATE: Limit for video generation (default: "3/minute")
    RATE_LIMIT_PARSE: Limit for parsing endpoints (default: "10/minute")
    RATE_LIMIT_TASKS: Limit for task status polling (default: "60/minute")
    RATE_LIMIT_ENABLED: Enable/disable rate limiting (default: "true")

Usage:
    from app.middleware.rate_limiting import setup_rate_limiting, limiter

    app = FastAPI()
    setup_rate_limiting(app)

    @app.post("/api/generate")
    @limiter.limit(GENERATE_LIMIT)
    async def generate_videos(...):
        ...
"""

import os
import logging
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request, Response
from starlette.status import HTTP_429_TOO_MANY_REQUESTS

logger = logging.getLogger(__name__)

# ============================================================================
# Rate Limit Configuration (Environment-based)
# ============================================================================

# Enable/disable rate limiting globally
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"

# Default limit for most endpoints
DEFAULT_LIMIT = os.getenv("RATE_LIMIT_DEFAULT", "100/minute")

# Expensive operations (resource-intensive)
UPLOAD_LIMIT = os.getenv("RATE_LIMIT_UPLOAD", "5/minute")
GENERATE_LIMIT = os.getenv("RATE_LIMIT_GENERATE", "3/minute")

# Moderate operations
PARSE_LIMIT = os.getenv("RATE_LIMIT_PARSE", "10/minute")

# High-frequency operations (polling)
TASKS_LIMIT = os.getenv("RATE_LIMIT_TASKS", "60/minute")

# No limit for health checks
HEALTH_LIMIT = os.getenv("RATE_LIMIT_HEALTH", "1000/minute")


# ============================================================================
# Custom Key Function
# ============================================================================

def get_rate_limit_key(request: Request) -> str:
    """
    Get the rate limit key for the request.

    Uses IP address with fallback to forwarded headers for proxy setups.

    Args:
        request: FastAPI Request object

    Returns:
        IP address string for rate limiting
    """
    # Check for X-Forwarded-For header (proxy/load balancer)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Use first IP in chain (original client)
        return forwarded.split(",")[0].strip()

    # Check for X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    # Fallback to direct connection IP
    return get_remote_address(request)


# ============================================================================
# Limiter Instance
# ============================================================================

limiter = Limiter(
    key_func=get_rate_limit_key,
    default_limits=[DEFAULT_LIMIT],  # Apply default to all routes
    enabled=RATE_LIMIT_ENABLED,
    headers_enabled=False,  # Disabled - endpoints return dicts, not Response objects
    storage_uri="memory://"  # Use in-memory storage (Redis for production)
)


# ============================================================================
# Custom Rate Limit Exceeded Handler
# ============================================================================

async def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded) -> Response:
    """
    Custom handler for rate limit exceeded errors.

    Returns a JSON response with helpful information about the rate limit.

    Args:
        request: FastAPI Request object
        exc: RateLimitExceeded exception

    Returns:
        JSONResponse with rate limit information
    """
    from fastapi.responses import JSONResponse

    # Extract rate limit info from exception
    limit = exc.detail

    # Log rate limit hit
    client_ip = get_rate_limit_key(request)
    logger.warning(
        f"Rate limit exceeded for {client_ip} on {request.url.path}: {limit}"
    )

    # Build helpful error response
    response_data = {
        "error": "Rate limit exceeded",
        "message": "Too many requests. Please slow down and try again later.",
        "limit": limit,
        "endpoint": str(request.url.path),
        "retry_after": "Please wait before making another request"
    }

    return JSONResponse(
        status_code=HTTP_429_TOO_MANY_REQUESTS,
        content=response_data,
        headers={
            "Retry-After": "60",  # Suggest retry after 60 seconds
            "X-RateLimit-Limit": limit,
        }
    )


# ============================================================================
# Setup Function
# ============================================================================

def setup_rate_limiting(app):
    """
    Configure rate limiting for the FastAPI application.

    This function:
    1. Attaches the limiter to the app state
    2. Registers the custom exception handler
    3. Logs rate limiting configuration

    Args:
        app: FastAPI application instance
    """
    if not RATE_LIMIT_ENABLED:
        logger.warning("⚠️ Rate limiting is DISABLED via environment variable")
        return

    # Attach limiter to app state
    app.state.limiter = limiter

    # Register custom exception handler
    app.add_exception_handler(RateLimitExceeded, custom_rate_limit_handler)

    # Log configuration
    logger.info("✅ Rate limiting enabled with configuration:")
    logger.info(f"  • Default: {DEFAULT_LIMIT}")
    logger.info(f"  • Upload: {UPLOAD_LIMIT}")
    logger.info(f"  • Generate: {GENERATE_LIMIT}")
    logger.info(f"  • Parse: {PARSE_LIMIT}")
    logger.info(f"  • Tasks: {TASKS_LIMIT}")
    logger.info(f"  • Health: {HEALTH_LIMIT}")
    logger.info(f"  • Headers: Enabled")
    logger.info(f"  • Storage: Memory (consider Redis for production)")


# ============================================================================
# Helper Function for Route-Specific Limits
# ============================================================================

def get_limit_for_endpoint(endpoint_type: str) -> str:
    """
    Get the appropriate rate limit for an endpoint type.

    Args:
        endpoint_type: Type of endpoint (upload, generate, parse, tasks, health)

    Returns:
        Rate limit string (e.g., "5/minute")
    """
    limits = {
        "upload": UPLOAD_LIMIT,
        "generate": GENERATE_LIMIT,
        "parse": PARSE_LIMIT,
        "tasks": TASKS_LIMIT,
        "health": HEALTH_LIMIT,
    }
    return limits.get(endpoint_type, DEFAULT_LIMIT)


# ============================================================================
# Exempt Routes (No Rate Limiting)
# ============================================================================

# Routes that should NOT have rate limiting applied
EXEMPT_ROUTES = [
    "/static",  # Static files
    "/docs",  # API documentation
    "/openapi.json",  # OpenAPI spec
    "/redoc",  # ReDoc documentation
]


def is_route_exempt(path: str) -> bool:
    """
    Check if a route path is exempt from rate limiting.

    Args:
        path: URL path to check

    Returns:
        True if route is exempt, False otherwise
    """
    return any(path.startswith(exempt) for exempt in EXEMPT_ROUTES)
