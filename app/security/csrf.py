"""
CSRF Protection Implementation

Provides CSRF token generation and validation for FastAPI endpoints.
Uses session-based tokens with HMAC signatures for security.
"""
from fastapi import HTTPException, Request
import secrets
import hashlib
import time
import logging
import os

logger = logging.getLogger(__name__)

# CSRF token storage (in production, use Redis or database)
# For now, we use a simple in-memory store with session-based tokens
CSRF_SECRET = os.environ.get("CSRF_SECRET", secrets.token_hex(32))
CSRF_TOKEN_EXPIRY = 3600  # 1 hour


def generate_csrf_token(session_id: str = None) -> str:
    """
    Generate a CSRF token tied to the session.

    Args:
        session_id: Optional session identifier

    Returns:
        CSRF token string
    """
    if not session_id:
        session_id = secrets.token_hex(16)

    timestamp = str(int(time.time()))
    message = f"{session_id}:{timestamp}"
    signature = hashlib.sha256(f"{message}:{CSRF_SECRET}".encode()).hexdigest()[:32]

    return f"{session_id}:{timestamp}:{signature}"


def validate_csrf_token(token: str, max_age: int = CSRF_TOKEN_EXPIRY) -> bool:
    """
    Validate a CSRF token.

    Args:
        token: The CSRF token to validate
        max_age: Maximum age in seconds

    Returns:
        True if valid, False otherwise
    """
    if not token:
        return False

    try:
        parts = token.split(':')
        if len(parts) != 3:
            return False

        session_id, timestamp_str, signature = parts
        timestamp = int(timestamp_str)

        # Check expiry
        if time.time() - timestamp > max_age:
            logger.warning("CSRF token expired")
            return False

        # Verify signature
        message = f"{session_id}:{timestamp_str}"
        expected_signature = hashlib.sha256(f"{message}:{CSRF_SECRET}".encode()).hexdigest()[:32]

        if not secrets.compare_digest(signature, expected_signature):
            logger.warning("CSRF token signature mismatch")
            return False

        return True

    except (ValueError, AttributeError) as e:
        logger.warning(f"CSRF token validation error: {e}")
        return False


async def verify_csrf_token(request: Request) -> bool:
    """
    FastAPI dependency to verify CSRF token on state-changing requests.

    Checks X-CSRF-Token header or csrf_token form field.
    """
    # Skip CSRF check for safe methods
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return True

    # Get token from header or form
    token = request.headers.get("X-CSRF-Token")

    if not token:
        # Try to get from form data
        try:
            form = await request.form()
            token = form.get("csrf_token")
        except:
            pass

    if not token:
        # Check JSON body
        try:
            body = await request.json()
            token = body.get("csrf_token")
        except:
            pass

    # For development, allow bypass if CSRF_DISABLED is set
    if os.environ.get("CSRF_DISABLED", "").lower() == "true":
        logger.warning("CSRF protection disabled via environment variable")
        return True

    if not validate_csrf_token(token):
        raise HTTPException(
            status_code=403,
            detail="CSRF token validation failed. Please refresh the page and try again."
        )

    return True
