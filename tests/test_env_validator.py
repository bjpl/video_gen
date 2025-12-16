"""
Tests for environment validation utilities.
"""
import os
import pytest
from pathlib import Path
from app.utils.env_validator import EnvironmentValidator, validate_environment, ValidationError


class TestEnvironmentValidator:
    """Test suite for EnvironmentValidator class."""

    def setup_method(self):
        """Save original environment before each test."""
        self.original_env = os.environ.copy()

    def teardown_method(self):
        """Restore original environment after each test."""
        os.environ.clear()
        os.environ.update(self.original_env)

    def test_development_environment_minimal(self):
        """Test validation passes with minimal development config."""
        os.environ["ENVIRONMENT"] = "development"

        validator = EnvironmentValidator()
        result = validator.validate_all()

        assert result["valid"] is True
        assert len(validator.errors) == 0

    def test_production_requires_environment(self):
        """Test that ENVIRONMENT variable is required."""
        # Clear ENVIRONMENT
        if "ENVIRONMENT" in os.environ:
            del os.environ["ENVIRONMENT"]

        validator = EnvironmentValidator()

        with pytest.raises(ValidationError):
            validator.validate_all()

        assert any("ENVIRONMENT" in error for error in validator.errors)

    def test_production_requires_csrf_secret(self):
        """Test that production requires CSRF_SECRET."""
        os.environ["ENVIRONMENT"] = "production"
        # Don't set CSRF_SECRET

        validator = EnvironmentValidator()

        with pytest.raises(ValidationError):
            validator.validate_all()

        assert any("CSRF_SECRET" in error for error in validator.errors)

    def test_production_with_proper_csrf_secret(self):
        """Test production validation passes with proper CSRF_SECRET."""
        os.environ["ENVIRONMENT"] = "production"
        os.environ["CSRF_SECRET"] = "a" * 64  # 64-char secret

        # Create required directories to avoid path warnings
        for dir_name in ["outputs", "cache", "logs"]:
            Path(dir_name).mkdir(exist_ok=True)

        validator = EnvironmentValidator()
        result = validator.validate_all()

        assert result["valid"] is True
        assert len(validator.errors) == 0

    def test_csrf_secret_length_warning(self):
        """Test warning for short CSRF_SECRET in production."""
        os.environ["ENVIRONMENT"] = "production"
        os.environ["CSRF_SECRET"] = "short"  # Too short

        # Create required directories to avoid path errors
        for dir_name in ["outputs", "cache", "logs"]:
            Path(dir_name).mkdir(exist_ok=True)

        validator = EnvironmentValidator()
        result = validator.validate_all()

        # Should pass but warn about short secret
        assert result["valid"] is True
        assert any("CSRF_SECRET" in warning and "too short" in warning.lower()
                   for warning in validator.warnings)

    def test_port_validation_numeric(self):
        """Test PORT must be numeric."""
        os.environ["ENVIRONMENT"] = "development"
        os.environ["PORT"] = "not_a_number"

        validator = EnvironmentValidator()

        with pytest.raises(ValidationError):
            validator.validate_all()

        assert any("PORT" in error for error in validator.errors)

    def test_port_validation_valid_range(self):
        """Test valid PORT passes validation."""
        os.environ["ENVIRONMENT"] = "development"
        os.environ["PORT"] = "8080"

        validator = EnvironmentValidator()
        result = validator.validate_all()

        assert result["valid"] is True
        assert "PORT: 8080" in validator.info

    def test_port_validation_out_of_range(self):
        """Test PORT outside valid range generates warning."""
        os.environ["ENVIRONMENT"] = "development"
        os.environ["PORT"] = "99999"  # Out of range

        validator = EnvironmentValidator()
        result = validator.validate_all()

        # Should warn, not error
        assert any("PORT" in warning for warning in validator.warnings)

    def test_anthropic_api_key_warning(self):
        """Test warning when ANTHROPIC_API_KEY not set."""
        os.environ["ENVIRONMENT"] = "development"

        validator = EnvironmentValidator()
        result = validator.validate_all()

        assert result["valid"] is True
        assert any("ANTHROPIC_API_KEY" in warning for warning in validator.warnings)

    def test_anthropic_api_key_configured(self):
        """Test ANTHROPIC_API_KEY is recognized when set."""
        os.environ["ENVIRONMENT"] = "development"
        os.environ["ANTHROPIC_API_KEY"] = "sk-ant-test-key-1234567890"

        validator = EnvironmentValidator()
        result = validator.validate_all()

        assert result["valid"] is True
        assert any("ANTHROPIC_API_KEY: configured" in info for info in validator.info)

    def test_debug_mode_in_production(self):
        """Test DEBUG=true in production is an error."""
        os.environ["ENVIRONMENT"] = "production"
        os.environ["DEBUG"] = "true"
        os.environ["CSRF_SECRET"] = "a" * 64

        validator = EnvironmentValidator()

        with pytest.raises(ValidationError):
            validator.validate_all()

        assert any("DEBUG" in error for error in validator.errors)

    def test_csrf_disabled_in_production(self):
        """Test CSRF_DISABLED=true in production is an error."""
        os.environ["ENVIRONMENT"] = "production"
        os.environ["CSRF_DISABLED"] = "true"
        os.environ["CSRF_SECRET"] = "a" * 64

        validator = EnvironmentValidator()

        with pytest.raises(ValidationError):
            validator.validate_all()

        assert any("CSRF_DISABLED" in error for error in validator.errors)

    def test_show_error_details_in_production(self):
        """Test SHOW_ERROR_DETAILS=true in production is an error."""
        os.environ["ENVIRONMENT"] = "production"
        os.environ["SHOW_ERROR_DETAILS"] = "true"
        os.environ["CSRF_SECRET"] = "a" * 64

        validator = EnvironmentValidator()

        with pytest.raises(ValidationError):
            validator.validate_all()

        assert any("SHOW_ERROR_DETAILS" in error for error in validator.errors)

    def test_sentry_dsn_warning_in_production(self):
        """Test warning when SENTRY_DSN not set in production."""
        os.environ["ENVIRONMENT"] = "production"
        os.environ["CSRF_SECRET"] = "a" * 64

        # Create required directories
        for dir_name in ["outputs", "cache", "logs"]:
            Path(dir_name).mkdir(exist_ok=True)

        validator = EnvironmentValidator()
        result = validator.validate_all()

        # Should pass but warn about Sentry
        assert result["valid"] is True
        assert any("SENTRY_DSN" in warning for warning in validator.warnings)

    def test_validate_environment_convenience_function(self):
        """Test validate_environment() convenience function."""
        os.environ["ENVIRONMENT"] = "development"

        result = validate_environment()

        assert result["valid"] is True
        assert result["environment"] == "development"
        assert "errors" in result
        assert "warnings" in result
        assert "info" in result

    def test_validation_result_structure(self):
        """Test validation result has proper structure."""
        os.environ["ENVIRONMENT"] = "development"

        validator = EnvironmentValidator()
        result = validator.validate_all()

        assert "valid" in result
        assert "errors" in result
        assert "warnings" in result
        assert "info" in result
        assert "environment" in result

        assert isinstance(result["valid"], bool)
        assert isinstance(result["errors"], list)
        assert isinstance(result["warnings"], list)
        assert isinstance(result["info"], list)
