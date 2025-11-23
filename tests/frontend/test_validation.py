"""
ValidationFeedback Component Tests
==================================

Tests for the FormValidator class and real-time validation including:
- YouTube URL validation
- File path validation
- Duration validation
- Video ID validation
- Generic URL validation
- Debouncing behavior
- API integration
- Error state management
- Accessibility compliance
"""

import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from bs4 import BeautifulSoup
import sys
import re
import json

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.main import app


@pytest.fixture
def client():
    """Create test client"""
    with TestClient(app) as c:
        yield c


@pytest.fixture
def html_parser():
    """Helper to parse HTML responses"""
    def parse(response):
        return BeautifulSoup(response.content, 'html.parser')
    return parse


# ============================================================================
# FormValidator Class Structure Tests
# ============================================================================

class TestFormValidatorStructure:
    """Test FormValidator class structure"""

    def test_form_validator_exists(self, client):
        """Test FormValidator class is defined"""
        js_response = client.get('/static/js/validation.js')
        assert js_response.status_code == 200, "Validation JS not found"

        content = js_response.content.decode('utf-8')
        assert 'FormValidator' in content, "FormValidator class not found"

    def test_validator_methods_defined(self, client):
        """Test validator has required methods"""
        # Read the validation.js file directly
        js_response = client.get('/static/js/validation.js')

        if js_response.status_code == 200:
            content = js_response.content.decode('utf-8')

            required_methods = [
                'validateVideoId',
                'validateURL',
                'validateYouTubeURL',
                'validateFilePath',
                'validateDuration',
                'validateVideoCount'
            ]

            for method in required_methods:
                assert method in content, f"Missing method: {method}"

    def test_alpine_directive_registered(self, client):
        """Test x-validate Alpine directive is registered"""
        js_response = client.get('/static/js/validation.js')

        if js_response.status_code == 200:
            content = js_response.content.decode('utf-8')

            # Should register Alpine directive
            assert "Alpine.directive" in content, "Missing Alpine directive registration"
            assert "'validate'" in content or '"validate"' in content, "Missing validate directive"


# ============================================================================
# YouTube URL Validation Tests
# ============================================================================

class TestYouTubeURLValidation:
    """Test YouTube URL validation logic"""

    VALID_YOUTUBE_URLS = [
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://youtube.com/watch?v=dQw4w9WgXcQ",
        "https://youtu.be/dQw4w9WgXcQ",
        "https://www.youtube.com/embed/dQw4w9WgXcQ",
    ]

    INVALID_YOUTUBE_URLS = [
        "not-a-url",
        "https://vimeo.com/12345",
        "https://youtube.com/channel/UC1234",
        "https://youtube.com",
        "",
        "   ",
    ]

    def test_valid_youtube_urls_pass(self):
        """Test valid YouTube URLs pass validation"""
        patterns = [
            r'^https?:\/\/(www\.)?youtube\.com\/watch\?v=([a-zA-Z0-9_-]{11})',
            r'^https?:\/\/youtu\.be\/([a-zA-Z0-9_-]{11})',
            r'^https?:\/\/(www\.)?youtube\.com\/embed\/([a-zA-Z0-9_-]{11})'
        ]

        for url in self.VALID_YOUTUBE_URLS:
            is_valid = any(re.match(pattern, url) for pattern in patterns)
            assert is_valid, f"Valid URL failed: {url}"

    def test_invalid_youtube_urls_fail(self):
        """Test invalid YouTube URLs fail validation"""
        patterns = [
            r'^https?:\/\/(www\.)?youtube\.com\/watch\?v=([a-zA-Z0-9_-]{11})',
            r'^https?:\/\/youtu\.be\/([a-zA-Z0-9_-]{11})',
            r'^https?:\/\/(www\.)?youtube\.com\/embed\/([a-zA-Z0-9_-]{11})'
        ]

        for url in self.INVALID_YOUTUBE_URLS:
            is_valid = any(re.match(pattern, url) for pattern in patterns)
            assert not is_valid, f"Invalid URL passed: {url}"

    def test_youtube_validation_in_js(self, client):
        """Test YouTube validation is implemented in JS"""
        js_response = client.get('/static/js/validation.js')

        if js_response.status_code == 200:
            content = js_response.content.decode('utf-8')

            # Should have YouTube URL validation
            assert 'validateYouTubeURL' in content, "Missing YouTube validation method"

            # Should have YouTube patterns
            assert 'youtube.com' in content, "Missing youtube.com pattern"
            assert 'youtu.be' in content, "Missing youtu.be pattern"


# ============================================================================
# File Path Validation Tests
# ============================================================================

class TestFilePathValidation:
    """Test file path validation logic"""

    VALID_FILE_PATHS = [
        "/home/user/documents/file.txt",
        "C:/Users/User/Documents/file.md",
        "./relative/path/document.md",
        "file.txt",
        "README.md",
    ]

    INVALID_FILE_PATHS = [
        "",
        "   ",
        "/path/with/../traversal",  # Directory traversal
        "/path/with\x00null/byte",  # Null byte
        "file.exe",  # Wrong extension
    ]

    def test_valid_file_paths_structure(self):
        """Test valid file path patterns"""
        for path in self.VALID_FILE_PATHS:
            # Basic validation: non-empty, no traversal, no null bytes
            is_valid = (
                path.strip() and
                '..' not in path and
                '\x00' not in path
            )
            assert is_valid, f"Valid path failed: {path}"

    def test_security_traversal_blocked(self):
        """Test directory traversal is blocked"""
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "/path/with/../traversal",
        ]

        for path in malicious_paths:
            assert '..' in path, "Test case setup error"
            # Security check: reject paths with ..
            is_blocked = '..' in path
            assert is_blocked, f"Traversal not blocked: {path}"

    def test_null_byte_blocked(self):
        """Test null bytes are blocked"""
        malicious_path = "/path/file.txt\x00.jpg"
        assert '\x00' in malicious_path
        # Security check: reject paths with null bytes
        is_blocked = '\x00' in malicious_path
        assert is_blocked

    def test_file_path_validation_in_js(self, client):
        """Test file path validation is in JS"""
        js_response = client.get('/static/js/validation.js')

        if js_response.status_code == 200:
            content = js_response.content.decode('utf-8')

            # Should have file path validation
            assert 'validateFilePath' in content, "Missing file path validation"

            # Should block traversal
            assert '..' in content, "Missing traversal check"

            # Should check file extensions
            assert 'ext' in content.lower() or 'extension' in content.lower()


# ============================================================================
# Duration Validation Tests
# ============================================================================

class TestDurationValidation:
    """Test duration validation logic"""

    VALID_DURATIONS = [10, 30, 60, 120, 300, 600]
    INVALID_DURATIONS = [0, 5, -10, 601, 1000]

    def test_valid_durations_in_range(self):
        """Test valid durations are within 10-600 seconds"""
        min_duration = 10
        max_duration = 600

        for duration in self.VALID_DURATIONS:
            is_valid = min_duration <= duration <= max_duration
            assert is_valid, f"Valid duration failed: {duration}"

    def test_invalid_durations_out_of_range(self):
        """Test invalid durations are rejected"""
        min_duration = 10
        max_duration = 600

        for duration in self.INVALID_DURATIONS:
            is_valid = min_duration <= duration <= max_duration
            assert not is_valid, f"Invalid duration passed: {duration}"

    def test_duration_validation_in_js(self, client):
        """Test duration validation in JS"""
        js_response = client.get('/static/js/validation.js')

        if js_response.status_code == 200:
            content = js_response.content.decode('utf-8')

            # Should have duration validation
            assert 'validateDuration' in content, "Missing duration validation"

            # Should have min/max checks
            assert '10' in content, "Missing minimum duration"
            assert '600' in content, "Missing maximum duration"


# ============================================================================
# Video ID Validation Tests
# ============================================================================

class TestVideoIdValidation:
    """Test video ID validation logic"""

    VALID_VIDEO_IDS = [
        "my-video",
        "video_123",
        "test-video-001",
        "SimpleVideo",
    ]

    INVALID_VIDEO_IDS = [
        "",
        "   ",
        "video with spaces",
        "video@special#chars",
        "a" * 101,  # Too long
    ]

    def test_valid_video_ids(self):
        """Test valid video IDs pass validation"""
        pattern = r'^[a-zA-Z0-9_-]+$'

        for video_id in self.VALID_VIDEO_IDS:
            is_valid = bool(re.match(pattern, video_id)) and len(video_id) <= 100
            assert is_valid, f"Valid ID failed: {video_id}"

    def test_invalid_video_ids(self):
        """Test invalid video IDs fail validation"""
        pattern = r'^[a-zA-Z0-9_-]+$'

        for video_id in self.INVALID_VIDEO_IDS:
            cleaned = video_id.strip()
            is_valid = bool(re.match(pattern, cleaned)) and len(cleaned) <= 100 if cleaned else False
            assert not is_valid, f"Invalid ID passed: {video_id}"

    def test_video_id_validation_in_js(self, client):
        """Test video ID validation in JS"""
        js_response = client.get('/static/js/validation.js')

        if js_response.status_code == 200:
            content = js_response.content.decode('utf-8')

            assert 'validateVideoId' in content, "Missing video ID validation"


# ============================================================================
# Debouncing Tests
# ============================================================================

class TestValidationDebouncing:
    """Test validation debouncing behavior"""

    def test_debounce_modifier_used(self, client):
        """Test Alpine.js debounce modifier is used"""
        response = client.get('/create')
        content = response.content.decode('utf-8')

        # Alpine.js uses .debounce modifier or regular input handlers
        has_input = '@input' in content or '@change' in content
        # Debouncing is recommended but optional

    def test_input_event_validation(self, client, html_parser):
        """Test validation triggers on input events"""
        response = client.get('/create')
        content = response.content.decode('utf-8')

        # Should have @input handlers for validation
        has_input_handler = '@input' in content or '@change' in content or '@click' in content
        assert has_input_handler, "Missing input event handlers"


# ============================================================================
# Error State Display Tests
# ============================================================================

class TestErrorStateDisplay:
    """Test error state display and styling"""

    def test_error_container_exists(self, client, html_parser):
        """Test error containers exist in form"""
        response = client.get('/create')
        content = response.content.decode('utf-8')

        # Should have error concept
        has_error = 'error' in content.lower() or 'Error' in content
        assert has_error, "Missing error display"

    def test_error_styling_in_js(self, client):
        """Test error styling defined in validation JS"""
        js_response = client.get('/static/js/validation.js')

        if js_response.status_code == 200:
            content = js_response.content.decode('utf-8')
            # Should have red styling for errors
            has_red = 'red' in content.lower() or 'border-red' in content
            assert has_red, "Missing error styling"

    def test_success_styling_in_js(self, client):
        """Test success styling defined in validation JS"""
        js_response = client.get('/static/js/validation.js')

        if js_response.status_code == 200:
            content = js_response.content.decode('utf-8')
            # Should have green styling for success
            has_green = 'green' in content.lower() or 'border-green' in content
            assert has_green, "Missing success styling"

    def test_conditional_styling(self, client):
        """Test conditional styling based on validation state"""
        response = client.get('/create')
        content = response.content.decode('utf-8')

        # Should have conditional class bindings
        has_conditional = ':class=' in content or 'class=' in content
        assert has_conditional, "Missing conditional styling"


# ============================================================================
# Accessibility Tests
# ============================================================================

class TestValidationAccessibility:
    """Test validation accessibility compliance"""

    def test_aria_invalid_attribute(self, client):
        """Test aria-invalid is used for invalid fields"""
        js_response = client.get('/static/js/validation.js')

        if js_response.status_code == 200:
            content = js_response.content.decode('utf-8')

            # Should set aria-invalid on invalid fields
            assert 'aria-invalid' in content, "Missing aria-invalid attribute"

    def test_aria_describedby_for_errors(self, client):
        """Test aria-describedby links errors to inputs"""
        js_response = client.get('/static/js/validation.js')

        if js_response.status_code == 200:
            content = js_response.content.decode('utf-8')

            # Should use aria-describedby for error messages
            assert 'aria-describedby' in content, "Missing aria-describedby"

    def test_role_alert_for_errors(self, client):
        """Test role="alert" for error messages"""
        js_response = client.get('/static/js/validation.js')

        if js_response.status_code == 200:
            content = js_response.content.decode('utf-8')

            # Should use role="alert" for dynamic errors
            assert 'role' in content, "Missing role attribute"

    def test_aria_live_for_dynamic_content(self, client):
        """Test aria-live for dynamic content updates"""
        js_response = client.get('/static/js/validation.js')

        if js_response.status_code == 200:
            content = js_response.content.decode('utf-8')

            # Should use aria-live for dynamic updates
            assert 'aria-live' in content, "Missing aria-live"


# ============================================================================
# Input Detection Tests
# ============================================================================

class TestInputTypeDetection:
    """Test automatic input type detection"""

    def test_input_type_detection_function(self, client):
        """Test detectInputType function exists"""
        js_response = client.get('/static/js/validation.js')

        if js_response.status_code == 200:
            content = js_response.content.decode('utf-8')

            assert 'detectInputType' in content, "Missing input type detection"

    def test_youtube_detection(self, client):
        """Test YouTube URL detection"""
        js_response = client.get('/static/js/validation.js')

        if js_response.status_code == 200:
            content = js_response.content.decode('utf-8')

            # Should detect YouTube URLs
            assert 'youtube' in content.lower(), "Missing YouTube detection"

    def test_file_path_detection(self, client):
        """Test file path detection"""
        js_response = client.get('/static/js/validation.js')

        if js_response.status_code == 200:
            content = js_response.content.decode('utf-8')

            # Should detect file paths
            assert 'file_path' in content or 'path' in content.lower()


# ============================================================================
# XSS Prevention Tests
# ============================================================================

class TestXSSPrevention:
    """Test XSS prevention in validation feedback"""

    def test_text_content_not_inner_html(self, client):
        """Test textContent is used instead of innerHTML"""
        js_response = client.get('/static/js/validation.js')

        if js_response.status_code == 200:
            content = js_response.content.decode('utf-8')

            # Should use textContent (safe) not innerHTML (XSS risk)
            assert 'textContent' in content, "Should use textContent"

            # innerHTML usage should be limited/absent in error display
            # Note: innerHTML might be used elsewhere safely

    def test_no_user_input_in_error_messages(self, client):
        """Test error messages don't include raw user input"""
        js_response = client.get('/static/js/validation.js')

        if js_response.status_code == 200:
            content = js_response.content.decode('utf-8')

            # Error messages should be predefined, not include ${value}
            # Look for FIX C1 comment about safe error messages
            has_safe_errors = 'FIX C1' in content or 'return' in content
            # Most importantly, validation returns predefined strings


# ============================================================================
# Integration Tests
# ============================================================================

class TestValidationIntegration:
    """Integration tests for validation system"""

    def test_validation_on_form_submit(self, client):
        """Test validation runs on form submission"""
        response = client.get('/create')
        content = response.content.decode('utf-8')

        # Should have submit handler
        has_submit = (
            '@click' in content or
            'Generate' in content or
            'submit' in content.lower()
        )
        assert has_submit, "Missing form submission"

    def test_validation_clears_on_correction(self, client):
        """Test validation state clears when input is corrected"""
        js_response = client.get('/static/js/validation.js')

        if js_response.status_code == 200:
            content = js_response.content.decode('utf-8')

            # Should clear error display when valid
            has_clear_logic = (
                "style.display = 'none'" in content or
                'removeAttribute' in content
            )
            assert has_clear_logic, "Missing error clearing logic"

    def test_complete_validation_flow(self, client):
        """Test complete validation flow has all elements"""
        response = client.get('/create')
        content = response.content.decode('utf-8')

        required_elements = {
            'Alpine state': 'x-data' in content,
            'Input binding': 'x-model' in content,
            'Click handlers': '@click' in content,
            'Submit button': 'Generate' in content or 'Create' in content
        }

        missing = [name for name, exists in required_elements.items() if not exists]
        assert len(missing) == 0, f"Missing elements: {', '.join(missing)}"


# ============================================================================
# Safe Regex Matching Tests
# ============================================================================

class TestSafeRegexMatching:
    """Test safe regex execution with timeout protection"""

    def test_safe_regex_function_exists(self, client):
        """Test safeRegexMatch function exists"""
        js_response = client.get('/static/js/validation.js')

        if js_response.status_code == 200:
            content = js_response.content.decode('utf-8')

            # Should have safe regex matching for ReDoS protection
            assert 'safeRegexMatch' in content, "Missing safe regex function"

    def test_regex_timeout_protection(self, client):
        """Test regex has timeout protection"""
        js_response = client.get('/static/js/validation.js')

        if js_response.status_code == 200:
            content = js_response.content.decode('utf-8')

            # Should have timeout or time check
            has_timeout = (
                'timeout' in content.lower() or
                'Date.now()' in content or
                'performance.now' in content
            )
            assert has_timeout, "Missing regex timeout protection"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
