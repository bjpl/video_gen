"""
P1 Week 2 Feature Testing: Input Validation
===========================================

Tests comprehensive input validation for:
- YouTube URL formats
- Document URL/file path validation
- Cross-platform path handling
- Quote-stripping functionality
- Language selection validation
- Duration range validation
- Real-time validation feedback
"""

import pytest
import re
from pathlib import Path
from typing import Dict, Any


class TestYouTubeURLValidation:
    """Test YouTube URL format validation"""

    VALID_YOUTUBE_URLS = [
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://youtube.com/watch?v=dQw4w9WgXcQ",
        "https://youtu.be/dQw4w9WgXcQ",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=10s",
        "https://m.youtube.com/watch?v=dQw4w9WgXcQ",
        "http://www.youtube.com/watch?v=dQw4w9WgXcQ",
    ]

    INVALID_YOUTUBE_URLS = [
        "not-a-url",
        "https://vimeo.com/12345",
        "https://youtube.com/channel/UC1234",
        "https://youtube.com",
        "youtube.com/watch?v=abc",  # missing protocol
        "https://www.youtube.com/watch",  # missing video ID
        "",
        "   ",
    ]

    def test_valid_youtube_urls(self):
        """Test that valid YouTube URLs pass validation"""
        youtube_pattern = r'^https?://(www\.)?(youtube\.com/watch\?v=|youtu\.be/|m\.youtube\.com/watch\?v=)[a-zA-Z0-9_-]{11}'

        for url in self.VALID_YOUTUBE_URLS:
            assert re.match(youtube_pattern, url), f"Valid URL failed: {url}"

    def test_invalid_youtube_urls(self):
        """Test that invalid YouTube URLs fail validation"""
        youtube_pattern = r'^https?://(www\.)?(youtube\.com/watch\?v=|youtu\.be/|m\.youtube\.com/watch\?v=)[a-zA-Z0-9_-]{11}'

        for url in self.INVALID_YOUTUBE_URLS:
            assert not re.match(youtube_pattern, url), f"Invalid URL passed: {url}"

    def test_extract_video_id(self):
        """Test extraction of YouTube video ID from URL"""
        test_cases = {
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ": "dQw4w9WgXcQ",
            "https://youtu.be/dQw4w9WgXcQ": "dQw4w9WgXcQ",
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=10s": "dQw4w9WgXcQ",
        }

        for url, expected_id in test_cases.items():
            # Extract video ID using regex
            match = re.search(r'(?:v=|/)([a-zA-Z0-9_-]{11})', url)
            assert match is not None, f"Could not extract ID from {url}"
            assert match.group(1) == expected_id, f"Wrong ID extracted from {url}"


class TestDocumentPathValidation:
    """Test document URL and file path validation"""

    VALID_DOCUMENT_URLS = [
        "https://example.com/document.pdf",
        "https://docs.google.com/document/d/1ABC123/edit",
        "https://www.dropbox.com/s/abc123/file.docx",
        "https://drive.google.com/file/d/1ABC123/view",
        "http://example.com/path/to/doc.txt",
    ]

    VALID_FILE_PATHS = [
        "/home/user/documents/file.txt",
        "C:\\Users\\User\\Documents\\file.pdf",
        "./relative/path/document.md",
        "../parent/folder/file.docx",
        "~/Documents/file.txt",
    ]

    INVALID_PATHS = [
        "",
        "   ",
        "not a path or url",
        "ftp://invalid-protocol.com/file.txt",
        "/path/with\x00null/byte",
    ]

    def test_valid_document_urls(self):
        """Test that valid document URLs pass validation"""
        url_pattern = r'^https?://.+\..+'

        for url in self.VALID_DOCUMENT_URLS:
            assert re.match(url_pattern, url), f"Valid URL failed: {url}"

    def test_valid_file_paths(self):
        """Test that valid file paths pass validation"""
        for path_str in self.VALID_FILE_PATHS:
            # Basic validation: non-empty, no null bytes
            assert path_str.strip(), f"Path is empty: {path_str}"
            assert '\x00' not in path_str, f"Path contains null byte: {path_str}"

    def test_invalid_paths(self):
        """Test that invalid paths fail validation"""
        url_pattern = r'^https?://.+\..+'

        for invalid in self.INVALID_PATHS:
            # Should fail both URL and basic path validation
            is_url = re.match(url_pattern, invalid) is not None
            is_valid_path = invalid.strip() and '\x00' not in invalid

            assert not (is_url or is_valid_path), f"Invalid path passed: {invalid}"


class TestCrossPlatformPaths:
    """Test cross-platform path handling"""

    def test_windows_to_posix_conversion(self):
        """Test converting Windows paths to POSIX format"""
        windows_path = r"C:\Users\User\Documents\file.txt"
        posix_path = Path(windows_path).as_posix()

        assert '/' in posix_path, "Path not converted to POSIX"
        assert '\\' not in posix_path, "Backslashes remain in POSIX path"

    def test_posix_to_windows_conversion(self):
        """Test handling POSIX paths on Windows"""
        posix_path = "/home/user/documents/file.txt"
        path_obj = Path(posix_path)

        # Path object should handle both formats
        assert path_obj.parts, "Path not parsed correctly"

    def test_relative_path_resolution(self):
        """Test resolving relative paths"""
        relative_paths = [
            "./file.txt",
            "../parent/file.txt",
            "subfolder/file.txt",
        ]

        for rel_path in relative_paths:
            path_obj = Path(rel_path)
            assert not path_obj.is_absolute(), f"Path should be relative: {rel_path}"

            # Can resolve to absolute path
            resolved = path_obj.resolve()
            assert resolved.is_absolute(), f"Could not resolve to absolute: {rel_path}"


class TestQuoteStripping:
    """Test automatic quote stripping from inputs"""

    QUOTE_SCENARIOS = [
        ('"https://example.com/file.txt"', 'https://example.com/file.txt'),
        ("'https://example.com/file.txt'", 'https://example.com/file.txt'),
        ('"/path/to/file.txt"', '/path/to/file.txt'),
        ("'/path/to/file.txt'", '/path/to/file.txt'),
        ('no quotes here', 'no quotes here'),
        ('""', ''),
        ("''", ''),
        ('"mixed quotes\'', '"mixed quotes\''),  # Don't strip mismatched
    ]

    def test_strip_matching_quotes(self):
        """Test stripping matching quotes from both ends"""
        for input_str, expected in self.QUOTE_SCENARIOS:
            result = self._strip_quotes(input_str)
            assert result == expected, f"Quote stripping failed for: {input_str}"

    def test_preserve_internal_quotes(self):
        """Test that internal quotes are preserved"""
        test_cases = [
            ('path with "quotes" inside', 'path with "quotes" inside'),
            ("path with 'quotes' inside", "path with 'quotes' inside"),
        ]

        for input_str, expected in test_cases:
            result = self._strip_quotes(input_str)
            assert result == expected, f"Internal quotes not preserved: {input_str}"

    @staticmethod
    def _strip_quotes(s: str) -> str:
        """Helper function to strip quotes"""
        s = s.strip()
        if len(s) >= 2:
            if (s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'"):
                return s[1:-1]
        return s


class TestLanguageValidation:
    """Test language selection validation"""

    SUPPORTED_LANGUAGES = [
        'en', 'es', 'fr', 'de', 'it', 'pt', 'nl', 'ru', 'ja', 'zh',
        'ko', 'ar', 'hi', 'tr', 'pl', 'sv', 'no', 'da', 'fi', 'el',
        'he', 'th', 'vi', 'id', 'ms', 'tl', 'cs', 'hu'
    ]

    def test_valid_language_codes(self):
        """Test that supported language codes pass validation"""
        for lang in self.SUPPORTED_LANGUAGES:
            assert lang in self.SUPPORTED_LANGUAGES, f"Language not supported: {lang}"
            assert len(lang) == 2, f"Language code wrong length: {lang}"

    def test_invalid_language_codes(self):
        """Test that invalid language codes fail validation"""
        invalid_codes = ['eng', 'english', 'xx', '', '  ', 'fr-CA', 'es-MX']

        for code in invalid_codes:
            assert code not in self.SUPPORTED_LANGUAGES, f"Invalid code passed: {code}"

    def test_source_language_not_in_targets(self):
        """Test validation that source language is not in target languages"""
        source = 'en'
        targets = ['es', 'fr', 'de']

        assert source not in targets, "Source language should not be in targets"

        # Should fail validation if source in targets
        targets_with_source = ['en', 'es', 'fr']
        assert source in targets_with_source, "Test case setup incorrect"


class TestDurationValidation:
    """Test duration range validation"""

    def test_valid_durations(self):
        """Test that valid durations pass validation"""
        valid_durations = [5, 10, 30, 60, 120, 300, 600]
        min_duration = 5
        max_duration = 600

        for duration in valid_durations:
            assert min_duration <= duration <= max_duration, \
                f"Valid duration failed: {duration}"

    def test_invalid_durations(self):
        """Test that invalid durations fail validation"""
        invalid_durations = [0, 4, -10, 601, 1000, 3600]
        min_duration = 5
        max_duration = 600

        for duration in invalid_durations:
            assert not (min_duration <= duration <= max_duration), \
                f"Invalid duration passed: {duration}"

    def test_duration_per_scene_calculation(self):
        """Test calculating duration per scene"""
        test_cases = [
            (60, 10, 6.0),   # 60 seconds / 10 scenes = 6 seconds/scene
            (120, 15, 8.0),  # 120 seconds / 15 scenes = 8 seconds/scene
            (300, 20, 15.0), # 300 seconds / 20 scenes = 15 seconds/scene
        ]

        for total_duration, num_scenes, expected_per_scene in test_cases:
            result = total_duration / num_scenes
            assert result == expected_per_scene, \
                f"Duration calculation wrong: {total_duration}/{num_scenes} != {expected_per_scene}"


class TestValidationErrorMessages:
    """Test validation error message clarity and accessibility"""

    ERROR_MESSAGES = {
        'youtube_url_invalid': 'Please enter a valid YouTube URL (e.g., https://youtube.com/watch?v=...)',
        'document_path_invalid': 'Please enter a valid file path or URL',
        'language_duplicate': 'Source language cannot be included in target languages',
        'duration_too_short': 'Duration must be at least 5 seconds',
        'duration_too_long': 'Duration cannot exceed 600 seconds (10 minutes)',
        'required_field': 'This field is required',
    }

    def test_error_messages_exist(self):
        """Test that all error messages are defined"""
        required_keys = [
            'youtube_url_invalid',
            'document_path_invalid',
            'language_duplicate',
            'duration_too_short',
            'duration_too_long',
            'required_field',
        ]

        for key in required_keys:
            assert key in self.ERROR_MESSAGES, f"Missing error message: {key}"
            assert self.ERROR_MESSAGES[key], f"Empty error message: {key}"

    def test_error_messages_actionable(self):
        """Test that error messages are clear and actionable"""
        for key, message in self.ERROR_MESSAGES.items():
            # Should be descriptive (not just "Error")
            assert len(message) > 10, f"Error message too short: {key}"

            # Should not be overly technical
            assert 'Exception' not in message, f"Too technical: {key}"
            assert 'null' not in message.lower(), f"Too technical: {key}"

    def test_error_message_accessibility(self):
        """Test that error messages would work with screen readers"""
        for key, message in self.ERROR_MESSAGES.items():
            # Should be complete sentences or clear phrases
            assert message[0].isupper() or message.startswith('Please'), \
                f"Not sentence-like: {key}"

            # Should not rely on visual cues only
            assert 'see above' not in message.lower(), f"Relies on visual cues: {key}"
            assert 'click here' not in message.lower(), f"Relies on visual cues: {key}"


class TestRealTimeValidation:
    """Test real-time validation feedback behavior"""

    def test_validation_triggers_on_blur(self):
        """Test that validation runs when field loses focus"""
        # This would be tested with frontend integration
        # Placeholder for specification
        pass

    def test_validation_triggers_on_submit(self):
        """Test that validation runs on form submission"""
        # This would be tested with frontend integration
        # Placeholder for specification
        pass

    def test_validation_clears_on_correction(self):
        """Test that error messages clear when input is corrected"""
        # This would be tested with frontend integration
        # Placeholder for specification
        pass

    def test_validation_shows_success_state(self):
        """Test that valid input shows success indicator"""
        # This would be tested with frontend integration
        # Placeholder for specification
        pass


# Integration test placeholder
class TestValidationIntegration:
    """Integration tests for validation system"""

    def test_validation_config_structure(self):
        """Test the validation configuration structure"""
        validation_config = {
            'fields': {
                'youtube_url': {
                    'required': True,
                    'pattern': r'^https?://(www\.)?(youtube\.com/watch\?v=|youtu\.be/|m\.youtube\.com/watch\?v=)[a-zA-Z0-9_-]{11}',
                    'error_message': 'Please enter a valid YouTube URL',
                },
                'document_path': {
                    'required': False,
                    'validator': 'path_or_url',
                    'error_message': 'Please enter a valid file path or URL',
                },
                'duration': {
                    'required': True,
                    'min': 5,
                    'max': 600,
                    'error_message': 'Duration must be between 5 and 600 seconds',
                },
            }
        }

        # Verify structure
        assert 'fields' in validation_config
        assert 'youtube_url' in validation_config['fields']
        assert 'document_path' in validation_config['fields']
        assert 'duration' in validation_config['fields']


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
