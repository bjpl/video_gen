"""
Environment validation utilities for startup checks.

Validates required and optional environment variables to ensure safe
and proper deployment, especially in production environments.
"""
import os
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Raised when environment validation fails."""
    pass


class EnvironmentValidator:
    """
    Validates environment configuration on application startup.

    Checks for:
    - Required variables in production
    - Insecure defaults
    - Type validation (numeric values)
    - Optional but recommended settings
    """

    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.info: List[str] = []

    def validate_all(self) -> Dict[str, Any]:
        """
        Run all validation checks.

        Returns:
            Dictionary with validation results including errors, warnings, and info

        Raises:
            ValidationError: If critical validation errors are found
        """
        self._check_environment()
        self._check_csrf_secret()
        self._check_anthropic_api_key()
        self._check_port()
        self._check_sentry_dsn()
        self._check_paths()
        self._check_insecure_settings()

        # Build result
        result = {
            "valid": len(self.errors) == 0,
            "errors": self.errors,
            "warnings": self.warnings,
            "info": self.info,
            "environment": os.environ.get("ENVIRONMENT", "unknown")
        }

        # Log results
        self._log_results()

        # Raise exception if critical errors found
        if self.errors:
            raise ValidationError(
                f"Environment validation failed with {len(self.errors)} error(s). "
                f"See logs for details."
            )

        return result

    def _check_environment(self):
        """Validate ENVIRONMENT variable is set."""
        env = os.environ.get("ENVIRONMENT")

        if not env:
            self.errors.append(
                "ENVIRONMENT variable not set. Must be one of: development, staging, production"
            )
        elif env not in ["development", "staging", "production"]:
            self.warnings.append(
                f"ENVIRONMENT='{env}' is non-standard. Expected: development, staging, or production"
            )
        else:
            self.info.append(f"ENVIRONMENT: {env}")

    def _check_csrf_secret(self):
        """
        Validate CSRF_SECRET is properly configured.

        In production, CSRF_SECRET must be explicitly set and not use default.
        """
        env = os.environ.get("ENVIRONMENT", "development")
        csrf_secret = os.environ.get("CSRF_SECRET")

        if env == "production":
            if not csrf_secret:
                self.errors.append(
                    "CSRF_SECRET must be set in production. Generate with: "
                    "python -c \"import secrets; print(secrets.token_hex(32))\""
                )
            elif len(csrf_secret) < 32:
                self.warnings.append(
                    f"CSRF_SECRET is too short ({len(csrf_secret)} chars). "
                    "Recommended: 64+ characters"
                )
            else:
                self.info.append("CSRF_SECRET: configured (64+ chars)")
        else:
            if csrf_secret:
                self.info.append(f"CSRF_SECRET: configured ({len(csrf_secret)} chars)")
            else:
                self.warnings.append(
                    "CSRF_SECRET not set. Will auto-generate (not recommended for production)"
                )

    def _check_anthropic_api_key(self):
        """
        Validate ANTHROPIC_API_KEY if AI features are intended.

        This is optional but recommended for enhanced narration and translation.
        """
        api_key = os.environ.get("ANTHROPIC_API_KEY")

        if not api_key:
            self.warnings.append(
                "ANTHROPIC_API_KEY not set. AI-enhanced narration and translation disabled. "
                "Set this to enable Claude-powered features."
            )
        elif not api_key.startswith("sk-"):
            self.warnings.append(
                "ANTHROPIC_API_KEY format looks incorrect. Should start with 'sk-'"
            )
        else:
            # Mask key for logging
            masked_key = f"{api_key[:7]}...{api_key[-4:]}" if len(api_key) > 11 else "***"
            self.info.append(f"ANTHROPIC_API_KEY: configured ({masked_key})")

    def _check_port(self):
        """Validate PORT is numeric if set."""
        port = os.environ.get("PORT")

        if port:
            try:
                port_int = int(port)
                if port_int < 1 or port_int > 65535:
                    self.warnings.append(
                        f"PORT={port} is outside valid range (1-65535)"
                    )
                else:
                    self.info.append(f"PORT: {port}")
            except ValueError:
                self.errors.append(
                    f"PORT='{port}' is not a valid number"
                )
        else:
            self.info.append("PORT: using default (8000)")

    def _check_sentry_dsn(self):
        """Check for Sentry error tracking configuration."""
        sentry_dsn = os.environ.get("SENTRY_DSN")
        env = os.environ.get("ENVIRONMENT", "development")

        if env == "production" and not sentry_dsn:
            self.warnings.append(
                "SENTRY_DSN not set. Error tracking disabled in production. "
                "Consider setting up Sentry for production monitoring."
            )
        elif sentry_dsn:
            # Basic DSN format check
            if not sentry_dsn.startswith("https://"):
                self.warnings.append(
                    "SENTRY_DSN format looks incorrect. Should start with 'https://'"
                )
            else:
                self.info.append("SENTRY_DSN: configured")

    def _check_paths(self):
        """Validate configured paths exist and are writable."""
        env = os.environ.get("ENVIRONMENT", "development")

        # Check output directories
        output_dir = os.environ.get("OUTPUT_DIR", "outputs")
        cache_dir = os.environ.get("CACHE_DIR", "cache")
        log_dir = os.environ.get("LOG_DIR", "logs")

        for dir_name, dir_path in [
            ("OUTPUT_DIR", output_dir),
            ("CACHE_DIR", cache_dir),
            ("LOG_DIR", log_dir)
        ]:
            path = Path(dir_path)

            # Create if doesn't exist
            try:
                path.mkdir(parents=True, exist_ok=True)

                # Check writability
                test_file = path / ".write_test"
                try:
                    test_file.touch()
                    test_file.unlink()
                    self.info.append(f"{dir_name}: {dir_path} (writable)")
                except PermissionError:
                    if env == "production":
                        self.errors.append(
                            f"{dir_name}={dir_path} is not writable in production"
                        )
                    else:
                        self.warnings.append(
                            f"{dir_name}={dir_path} is not writable"
                        )
            except Exception as e:
                self.warnings.append(
                    f"Could not create {dir_name}={dir_path}: {e}"
                )

    def _check_insecure_settings(self):
        """Check for insecure development settings in production."""
        env = os.environ.get("ENVIRONMENT", "development")

        if env == "production":
            # Check DEBUG mode
            debug = os.environ.get("DEBUG", "false").lower()
            if debug == "true":
                self.errors.append(
                    "DEBUG=true is insecure in production. Set DEBUG=false"
                )

            # Check AUTO_RELOAD
            auto_reload = os.environ.get("AUTO_RELOAD", "false").lower()
            if auto_reload == "true":
                self.warnings.append(
                    "AUTO_RELOAD=true in production. This should be disabled."
                )

            # Check SHOW_ERROR_DETAILS
            show_errors = os.environ.get("SHOW_ERROR_DETAILS", "false").lower()
            if show_errors == "true":
                self.errors.append(
                    "SHOW_ERROR_DETAILS=true exposes sensitive information. "
                    "Set to false in production."
                )

            # Check CSRF_DISABLED
            csrf_disabled = os.environ.get("CSRF_DISABLED", "false").lower()
            if csrf_disabled == "true":
                self.errors.append(
                    "CSRF_DISABLED=true is a critical security risk. "
                    "Never disable CSRF protection in production."
                )

    def _log_results(self):
        """Log validation results."""
        if self.errors:
            logger.error("=" * 70)
            logger.error("ENVIRONMENT VALIDATION FAILED")
            logger.error("=" * 70)
            for error in self.errors:
                logger.error(f"❌ ERROR: {error}")

        if self.warnings:
            logger.warning("-" * 70)
            logger.warning("ENVIRONMENT WARNINGS")
            logger.warning("-" * 70)
            for warning in self.warnings:
                logger.warning(f"⚠️  WARNING: {warning}")

        if self.info:
            logger.info("-" * 70)
            logger.info("ENVIRONMENT INFO")
            logger.info("-" * 70)
            for info in self.info:
                logger.info(f"ℹ️  {info}")

        if not self.errors and not self.warnings:
            logger.info("✅ Environment validation passed with no issues")


def validate_environment() -> Dict[str, Any]:
    """
    Validate environment configuration.

    Convenience function to run all validation checks.

    Returns:
        Validation results dictionary

    Raises:
        ValidationError: If critical validation errors are found
    """
    validator = EnvironmentValidator()
    return validator.validate_all()
