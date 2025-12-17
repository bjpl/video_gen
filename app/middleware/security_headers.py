"""
Production Security Headers Middleware

Implements comprehensive security headers to protect against common web vulnerabilities:
- Clickjacking protection (X-Frame-Options)
- MIME type sniffing prevention (X-Content-Type-Options)
- XSS protection (X-XSS-Protection)
- HTTPS enforcement (Strict-Transport-Security)
- Content Security Policy (CSP)
- Referrer policy controls
- Feature/Permissions policy

Environment Variables:
    SECURITY_HEADERS_ENABLED: Enable/disable security headers (default: "true")
    ENVIRONMENT: Deployment environment ("production", "development", etc.)
    HSTS_MAX_AGE: HSTS max-age in seconds (default: "31536000" = 1 year)
    CSP_REPORT_ONLY: Enable CSP report-only mode (default: "false")
    HTTPS_REDIRECT_ENABLED: Enable HTTPS redirect (default: "true" in production)

Usage:
    from app.middleware.security_headers import setup_security_headers

    app = FastAPI()
    setup_security_headers(app)
"""

import os
import logging
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)

# ============================================================================
# Configuration (Environment-based)
# ============================================================================

# Enable/disable security headers globally
SECURITY_HEADERS_ENABLED = os.getenv("SECURITY_HEADERS_ENABLED", "true").lower() == "true"

# Deployment environment
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
IS_PRODUCTION = ENVIRONMENT == "production"

# HSTS configuration
HSTS_MAX_AGE = int(os.getenv("HSTS_MAX_AGE", "31536000"))  # 1 year default
HSTS_INCLUDE_SUBDOMAINS = os.getenv("HSTS_INCLUDE_SUBDOMAINS", "true").lower() == "true"
HSTS_PRELOAD = os.getenv("HSTS_PRELOAD", "false").lower() == "true"

# CSP configuration
CSP_REPORT_ONLY = os.getenv("CSP_REPORT_ONLY", "false").lower() == "true"
CSP_REPORT_URI = os.getenv("CSP_REPORT_URI", "")

# HTTPS redirect configuration
HTTPS_REDIRECT_ENABLED = os.getenv("HTTPS_REDIRECT_ENABLED", str(IS_PRODUCTION)).lower() == "true"
HTTPS_REDIRECT_PORT = int(os.getenv("HTTPS_REDIRECT_PORT", "443"))


# ============================================================================
# Security Header Definitions
# ============================================================================

def get_security_headers(is_production: bool = False) -> dict:
    """
    Get security headers based on environment.

    Args:
        is_production: Whether running in production environment

    Returns:
        Dictionary of security headers to apply
    """
    headers = {
        # Prevent clickjacking attacks
        "X-Frame-Options": "DENY",

        # Prevent MIME type sniffing
        "X-Content-Type-Options": "nosniff",

        # Enable XSS filter (legacy but still useful for older browsers)
        "X-XSS-Protection": "1; mode=block",

        # Control referrer information
        "Referrer-Policy": "strict-origin-when-cross-origin",

        # Restrict browser features and APIs
        "Permissions-Policy": "geolocation=(), camera=(), microphone=(), payment=(), usb=(), interest-cohort=()",

        # Remove server identification
        "X-Powered-By": "",  # Will actually remove the header
    }

    # Add HSTS only in production or if explicitly enabled
    if is_production or HTTPS_REDIRECT_ENABLED:
        hsts_value = f"max-age={HSTS_MAX_AGE}"
        if HSTS_INCLUDE_SUBDOMAINS:
            hsts_value += "; includeSubDomains"
        if HSTS_PRELOAD:
            hsts_value += "; preload"
        headers["Strict-Transport-Security"] = hsts_value

    # Content Security Policy
    csp_directives = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",  # Allow inline scripts for HTMX/Alpine.js
        "style-src 'self' 'unsafe-inline'",   # Allow inline styles
        "img-src 'self' data: https:",        # Allow images from same origin, data URLs, and HTTPS
        "font-src 'self' data:",              # Allow fonts from same origin and data URLs
        "connect-src 'self'",                 # API calls to same origin
        "media-src 'self'",                   # Media from same origin
        "object-src 'none'",                  # Block plugins
        "base-uri 'self'",                    # Restrict base tag
        "form-action 'self'",                 # Forms only to same origin
        "frame-ancestors 'none'",             # Prevent framing (redundant with X-Frame-Options)
        "upgrade-insecure-requests",          # Upgrade HTTP to HTTPS
    ]

    # Add report URI if configured
    if CSP_REPORT_URI:
        csp_directives.append(f"report-uri {CSP_REPORT_URI}")

    csp_value = "; ".join(csp_directives)

    # Use report-only mode for testing if enabled
    if CSP_REPORT_ONLY:
        headers["Content-Security-Policy-Report-Only"] = csp_value
        logger.info("CSP is in report-only mode")
    else:
        headers["Content-Security-Policy"] = csp_value

    return headers


# ============================================================================
# Security Headers Middleware
# ============================================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all HTTP responses.

    This middleware:
    1. Adds comprehensive security headers to responses
    2. Redirects HTTP to HTTPS in production (if enabled)
    3. Logs security header application
    """

    def __init__(self, app: ASGIApp, environment: str = "development"):
        """
        Initialize security headers middleware.

        Args:
            app: ASGI application
            environment: Deployment environment (production, development, etc.)
        """
        super().__init__(app)
        self.environment = environment.lower()
        self.is_production = self.environment == "production"
        self.security_headers = get_security_headers(self.is_production)

        logger.info(f"🔒 Security Headers Middleware initialized for {self.environment} environment")
        if self.is_production:
            logger.info("  • Production mode: Full security headers enabled")
            if HTTPS_REDIRECT_ENABLED:
                logger.info("  • HTTPS redirect: ENABLED")
        else:
            logger.info("  • Development mode: Security headers enabled (HSTS conditional)")

    async def dispatch(self, request: Request, call_next):
        """
        Process request and add security headers to response.

        Args:
            request: Incoming HTTP request
            call_next: Next middleware/route handler

        Returns:
            HTTP response with security headers
        """
        # HTTPS redirect in production (if enabled)
        if HTTPS_REDIRECT_ENABLED and not self._is_secure_request(request):
            return self._redirect_to_https(request)

        # Process request
        response = await call_next(request)

        # Add security headers to response
        for header, value in self.security_headers.items():
            if value:  # Only add non-empty values
                response.headers[header] = value
            elif header in response.headers:
                # Remove headers with empty values (e.g., X-Powered-By)
                del response.headers[header]

        return response

    def _is_secure_request(self, request: Request) -> bool:
        """
        Check if request is using HTTPS.

        Args:
            request: HTTP request to check

        Returns:
            True if request is secure (HTTPS), False otherwise
        """
        # Check URL scheme
        if request.url.scheme == "https":
            return True

        # Check X-Forwarded-Proto header (for proxies/load balancers)
        forwarded_proto = request.headers.get("X-Forwarded-Proto", "").lower()
        if forwarded_proto == "https":
            return True

        # Check X-Forwarded-SSL header
        forwarded_ssl = request.headers.get("X-Forwarded-SSL", "").lower()
        if forwarded_ssl == "on":
            return True

        return False

    def _redirect_to_https(self, request: Request) -> Response:
        """
        Redirect HTTP request to HTTPS.

        Args:
            request: HTTP request to redirect

        Returns:
            Redirect response to HTTPS URL
        """
        from starlette.responses import RedirectResponse

        # Build HTTPS URL
        url = request.url
        https_url = url.replace(scheme="https")

        # Update port if needed
        if HTTPS_REDIRECT_PORT != 443:
            https_url = https_url.replace(port=HTTPS_REDIRECT_PORT)

        logger.info(f"Redirecting HTTP to HTTPS: {url} -> {https_url}")

        # 301 Permanent Redirect for production
        return RedirectResponse(url=str(https_url), status_code=301)


# ============================================================================
# Setup Function
# ============================================================================

def setup_security_headers(app, environment: str = None):
    """
    Configure security headers middleware for the FastAPI application.

    This function:
    1. Adds security headers middleware to the app
    2. Configures HTTPS redirect for production
    3. Logs security configuration

    Args:
        app: FastAPI application instance
        environment: Optional environment override (uses ENVIRONMENT env var if not provided)
    """
    if not SECURITY_HEADERS_ENABLED:
        logger.warning("⚠️ Security headers are DISABLED via environment variable")
        return

    # Use provided environment or fall back to env var
    env = environment or ENVIRONMENT

    # Add security headers middleware
    app.add_middleware(SecurityHeadersMiddleware, environment=env)

    # Log configuration
    logger.info("✅ Security headers middleware configured:")
    logger.info(f"  • Environment: {env}")
    logger.info(f"  • X-Frame-Options: DENY")
    logger.info(f"  • X-Content-Type-Options: nosniff")
    logger.info(f"  • X-XSS-Protection: 1; mode=block")
    logger.info(f"  • Referrer-Policy: strict-origin-when-cross-origin")
    logger.info(f"  • Permissions-Policy: geolocation, camera, microphone restricted")

    if env == "production" or HTTPS_REDIRECT_ENABLED:
        logger.info(f"  • Strict-Transport-Security: max-age={HSTS_MAX_AGE}")
        if HTTPS_REDIRECT_ENABLED:
            logger.info(f"  • HTTPS Redirect: ENABLED (port {HTTPS_REDIRECT_PORT})")
    else:
        logger.info("  • Strict-Transport-Security: DISABLED (development mode)")
        logger.info("  • HTTPS Redirect: DISABLED (development mode)")

    if CSP_REPORT_ONLY:
        logger.info("  • Content-Security-Policy: REPORT-ONLY mode")
    else:
        logger.info("  • Content-Security-Policy: ENFORCING mode")


# ============================================================================
# Helper Functions
# ============================================================================

def get_security_report() -> dict:
    """
    Get current security configuration report.

    Returns:
        Dictionary with current security settings
    """
    return {
        "enabled": SECURITY_HEADERS_ENABLED,
        "environment": ENVIRONMENT,
        "is_production": IS_PRODUCTION,
        "https_redirect": HTTPS_REDIRECT_ENABLED,
        "hsts": {
            "enabled": IS_PRODUCTION or HTTPS_REDIRECT_ENABLED,
            "max_age": HSTS_MAX_AGE,
            "include_subdomains": HSTS_INCLUDE_SUBDOMAINS,
            "preload": HSTS_PRELOAD,
        },
        "csp": {
            "enabled": True,
            "report_only": CSP_REPORT_ONLY,
            "report_uri": CSP_REPORT_URI or None,
        },
        "headers": get_security_headers(IS_PRODUCTION),
    }


def validate_security_configuration() -> list:
    """
    Validate security configuration and return warnings.

    Returns:
        List of warning messages about security configuration
    """
    warnings = []

    if not SECURITY_HEADERS_ENABLED:
        warnings.append("Security headers are disabled")

    if IS_PRODUCTION and not HTTPS_REDIRECT_ENABLED:
        warnings.append("Production environment without HTTPS redirect")

    if IS_PRODUCTION and HSTS_MAX_AGE < 31536000:
        warnings.append(f"HSTS max-age is less than 1 year: {HSTS_MAX_AGE}")

    if CSP_REPORT_ONLY:
        warnings.append("CSP is in report-only mode (not enforcing)")

    if not CSP_REPORT_URI and CSP_REPORT_ONLY:
        warnings.append("CSP report-only mode without report URI")

    return warnings
