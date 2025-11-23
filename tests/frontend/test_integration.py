"""
Frontend Integration Tests
==========================

Integration tests for component interactions including:
- DragDrop -> Validation -> Preview flow
- Language selector -> Voice selector integration
- Preview -> Configuration -> Generation flow
- State management across components
- Event bus communication
- API client integration with all endpoints
- Error propagation between components
- State persistence across page reloads
"""

import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from bs4 import BeautifulSoup
import sys
import json
import time
from unittest.mock import Mock, patch, MagicMock
from io import BytesIO

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.main import app


@pytest.fixture
def client():
    """Create test client"""
    # Disable CSRF for testing
    import os
    os.environ["CSRF_DISABLED"] = "true"
    with TestClient(app) as c:
        yield c
    os.environ.pop("CSRF_DISABLED", None)


@pytest.fixture
def html_parser():
    """Helper to parse HTML responses"""
    def parse(response):
        return BeautifulSoup(response.content, 'html.parser')
    return parse


@pytest.fixture
def sample_markdown_file():
    """Create a sample markdown file for testing"""
    content = b"""# Test Document

## Introduction

This is a test document for integration testing.

- Point 1
- Point 2
- Point 3

## Getting Started

Here is some code:

```python
print("Hello, World!")
```

## Conclusion

Thank you for reading.
"""
    return {
        "filename": "test_document.md",
        "content": content,
        "content_type": "text/markdown"
    }


# ============================================================================
# DragDrop -> Validation -> Preview Flow Tests
# ============================================================================

class TestDragDropValidationPreviewFlow:
    """Test the complete drag-drop to preview flow integration"""

    def test_validation_endpoint_accepts_valid_file(self, client, sample_markdown_file):
        """Test validation API accepts valid markdown file"""
        files = {
            "file": (
                sample_markdown_file["filename"],
                BytesIO(sample_markdown_file["content"]),
                sample_markdown_file["content_type"]
            )
        }

        response = client.post("/api/validate/document", files=files)

        assert response.status_code == 200
        data = response.json()
        assert data.get("valid") is True
        assert "errors" not in data or len(data.get("errors", [])) == 0

    def test_validation_rejects_invalid_file_type(self, client):
        """Test validation API rejects invalid file types"""
        files = {
            "file": (
                "script.exe",
                BytesIO(b"binary content"),
                "application/octet-stream"
            )
        }

        response = client.post("/api/validate/document", files=files)

        assert response.status_code == 400
        data = response.json()
        assert data.get("valid") is False
        assert len(data.get("errors", [])) > 0

    def test_preview_endpoint_returns_structure(self, client, sample_markdown_file):
        """Test preview API returns document structure"""
        files = {
            "file": (
                sample_markdown_file["filename"],
                BytesIO(sample_markdown_file["content"]),
                sample_markdown_file["content_type"]
            )
        }

        response = client.post("/api/preview/document", files=files)

        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "success"
        assert "preview" in data
        preview = data["preview"]
        assert "section_count" in preview or "sections" in preview

    def test_validation_then_preview_flow(self, client, sample_markdown_file):
        """Test sequential validation then preview flow"""
        # Step 1: Validate
        files = {
            "file": (
                sample_markdown_file["filename"],
                BytesIO(sample_markdown_file["content"]),
                sample_markdown_file["content_type"]
            )
        }
        validation_response = client.post("/api/validate/document", files=files)
        assert validation_response.status_code == 200
        assert validation_response.json().get("valid") is True

        # Step 2: Preview (re-create file handle)
        files = {
            "file": (
                sample_markdown_file["filename"],
                BytesIO(sample_markdown_file["content"]),
                sample_markdown_file["content_type"]
            )
        }
        preview_response = client.post("/api/preview/document", files=files)
        assert preview_response.status_code == 200
        assert preview_response.json().get("status") == "success"


# ============================================================================
# Language Selector -> Voice Selector Integration Tests
# ============================================================================

class TestLanguageVoiceIntegration:
    """Test language and voice selection integration"""

    def test_get_supported_languages(self, client):
        """Test fetching supported languages"""
        response = client.get("/api/languages")

        assert response.status_code == 200
        data = response.json()
        assert "languages" in data
        assert len(data["languages"]) > 0

    def test_get_voices_for_language(self, client):
        """Test fetching voices for specific language"""
        response = client.get("/api/languages/en/voices")

        assert response.status_code == 200
        data = response.json()
        assert "voices" in data
        assert len(data["voices"]) > 0

    def test_get_voices_for_unsupported_language(self, client):
        """Test handling unsupported language code"""
        response = client.get("/api/languages/xyz/voices")

        assert response.status_code == 404

    def test_language_selection_affects_voice_options(self, client):
        """Test that different languages have different voice options"""
        # Get English voices
        en_response = client.get("/api/languages/en/voices")
        en_voices = en_response.json().get("voices", [])

        # Get Spanish voices (if available)
        es_response = client.get("/api/languages/es/voices")

        if es_response.status_code == 200:
            es_voices = es_response.json().get("voices", [])
            # Voice IDs should be different
            en_ids = {v.get("id") for v in en_voices}
            es_ids = {v.get("id") for v in es_voices}
            # At least some should be different
            assert len(en_ids) > 0
            assert len(es_ids) > 0

    def test_multiple_language_selection(self, client):
        """Test selecting multiple languages returns correct count"""
        response = client.get("/api/languages")
        data = response.json()

        languages = data.get("languages", [])
        # Pick first 3 languages
        selected = [lang["code"] for lang in languages[:3]]

        # Each language should have voices available
        for lang_code in selected:
            voice_response = client.get(f"/api/languages/{lang_code}/voices")
            if voice_response.status_code == 200:
                assert len(voice_response.json().get("voices", [])) > 0


# ============================================================================
# Preview -> Configuration -> Generation Flow Tests
# ============================================================================

class TestPreviewConfigurationGenerationFlow:
    """Test the preview to generation flow"""

    def test_supported_formats_endpoint(self, client):
        """Test getting supported document formats"""
        response = client.get("/api/document/supported-formats")

        assert response.status_code == 200
        data = response.json()
        assert "formats" in data
        formats = data["formats"]
        assert any(f.get("extension") == ".md" for f in formats)

    def test_progress_stages_endpoint(self, client):
        """Test getting progress stage definitions"""
        response = client.get("/api/upload/progress-stages")

        assert response.status_code == 200
        data = response.json()
        # Should have defined stages
        assert isinstance(data, (dict, list))

    def test_scene_types_endpoint(self, client):
        """Test getting available scene types"""
        response = client.get("/api/scene-types")

        assert response.status_code == 200
        data = response.json()
        assert "general" in data or "educational" in data

    def test_colors_endpoint(self, client):
        """Test getting available accent colors"""
        response = client.get("/api/colors")

        assert response.status_code == 200
        colors = response.json()
        assert isinstance(colors, list)
        assert "blue" in colors

    def test_voices_endpoint(self, client):
        """Test getting available voices"""
        response = client.get("/api/voices")

        assert response.status_code == 200
        voices = response.json()
        assert isinstance(voices, list)
        assert any(v.get("id") == "male" for v in voices)


# ============================================================================
# State Management Integration Tests
# ============================================================================

class TestStateManagementIntegration:
    """Test state management across components"""

    def test_create_page_loads_with_state_init(self, client, html_parser):
        """Test create page initializes Alpine.js state"""
        response = client.get("/create")
        content = response.content.decode('utf-8')

        # Should have Alpine.js state initialization
        assert 'x-data' in content
        # Should load state management script
        assert 'app-state' in content or 'Alpine' in content

    def test_create_page_has_form_bindings(self, client, html_parser):
        """Test create page has form data bindings"""
        response = client.get("/create")
        content = response.content.decode('utf-8')

        # Should have x-model bindings for form data
        assert 'x-model' in content

    def test_create_page_has_step_navigation(self, client, html_parser):
        """Test create page has step navigation"""
        response = client.get("/create")
        content = response.content.decode('utf-8')

        # Should have step-related state or navigation
        has_steps = (
            'step' in content.lower() or
            'currentStep' in content or
            'Step' in content
        )
        assert has_steps


# ============================================================================
# Event Bus / Component Communication Tests
# ============================================================================

class TestEventBusCommunication:
    """Test event-based component communication"""

    def test_page_has_dispatch_capability(self, client):
        """Test page uses $dispatch for events"""
        response = client.get("/create")
        content = response.content.decode('utf-8')

        # Should have event dispatch capability
        has_dispatch = (
            '$dispatch' in content or
            '@' in content  # Alpine event listeners
        )
        assert has_dispatch

    def test_page_has_event_listeners(self, client):
        """Test page has event listeners for cross-component communication"""
        response = client.get("/create")
        content = response.content.decode('utf-8')

        # Should have event listeners
        event_patterns = ['@click', '@change', '@input', '@submit', '@keyup']
        has_listeners = any(pattern in content for pattern in event_patterns)
        assert has_listeners


# ============================================================================
# API Client Integration Tests
# ============================================================================

class TestAPIClientIntegration:
    """Test API client integration with all endpoints"""

    def test_health_check(self, client):
        """Test health check endpoint"""
        response = client.get("/api/health")

        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "healthy"

    def test_csrf_token_endpoint(self, client):
        """Test CSRF token endpoint"""
        response = client.get("/api/csrf-token")

        assert response.status_code == 200
        data = response.json()
        assert "csrf_token" in data

    def test_template_list_endpoint(self, client):
        """Test template list endpoint"""
        response = client.get("/api/templates/list")

        assert response.status_code == 200
        data = response.json()
        assert "templates" in data

    def test_all_api_endpoints_accessible(self, client):
        """Test all main API endpoints are accessible"""
        endpoints = [
            ("/api/health", "GET"),
            ("/api/voices", "GET"),
            ("/api/colors", "GET"),
            ("/api/languages", "GET"),
            ("/api/scene-types", "GET"),
            ("/api/document/supported-formats", "GET"),
            ("/api/upload/progress-stages", "GET"),
            ("/api/templates/list", "GET"),
        ]

        for endpoint, method in endpoints:
            if method == "GET":
                response = client.get(endpoint)
            else:
                response = client.post(endpoint)

            # Should not return 404 (endpoint should exist)
            assert response.status_code != 404, f"Endpoint {endpoint} not found"


# ============================================================================
# Error Propagation Tests
# ============================================================================

class TestErrorPropagation:
    """Test error handling and propagation between components"""

    def test_validation_error_response_format(self, client):
        """Test validation errors have consistent format"""
        files = {
            "file": (
                "invalid.xyz",
                BytesIO(b"content"),
                "application/octet-stream"
            )
        }

        response = client.post("/api/validate/document", files=files)

        assert response.status_code == 400
        data = response.json()
        # Should have valid/errors structure
        assert "valid" in data or "errors" in data

    def test_invalid_task_returns_error(self, client):
        """Test requesting invalid task returns appropriate error"""
        response = client.get("/api/tasks/nonexistent_task_id")

        # API may return 404 or 500 depending on implementation
        assert response.status_code in [404, 500]

    def test_invalid_youtube_url_validation(self, client):
        """Test invalid YouTube URL returns proper error"""
        response = client.post(
            "/api/youtube/validate",
            json={"url": "not-a-valid-url"}
        )

        assert response.status_code == 200  # Returns validation result, not error
        data = response.json()
        assert data.get("is_valid") is False


# ============================================================================
# State Persistence Tests
# ============================================================================

class TestStatePersistence:
    """Test state persistence across interactions"""

    def test_app_state_script_included(self, client):
        """Test app state management script is included"""
        response = client.get("/create")
        content = response.content.decode('utf-8')

        # Should include state management
        assert 'store' in content.lower() or 'appState' in content

    def test_localStorage_usage_pattern(self, client):
        """Test page uses localStorage for persistence"""
        response = client.get("/create")
        content = response.content.decode('utf-8')

        # Check for localStorage patterns in loaded scripts
        scripts_response = client.get("/static/js/store/app-state.js")
        if scripts_response.status_code == 200:
            script_content = scripts_response.content.decode('utf-8')
            assert 'localStorage' in script_content


# ============================================================================
# Cross-Component Data Flow Tests
# ============================================================================

class TestCrossComponentDataFlow:
    """Test data flow between components"""

    def test_input_selector_to_form_data_flow(self, client, html_parser):
        """Test input method selection flows to form"""
        response = client.get("/create")
        content = response.content.decode('utf-8')

        # Should have input method state that affects form visibility
        has_input_state = (
            'inputMethod' in content or
            'selectedMethod' in content or
            'x-show' in content
        )
        assert has_input_state

    def test_form_data_to_generation_flow(self, client):
        """Test form data is used in generation request"""
        # Parse document endpoint should accept form data
        response = client.post(
            "/api/parse/document",
            json={
                "content": "/path/to/document.md",
                "accent_color": "blue",
                "voice": "male",
                "video_count": 1
            }
        )

        # Should accept the request (even if path doesn't exist)
        assert response.status_code in [200, 500]  # 500 if file not found, but endpoint works


# ============================================================================
# Full Workflow Integration Tests
# ============================================================================

class TestFullWorkflowIntegration:
    """Test complete workflow scenarios"""

    def test_document_workflow_endpoints_exist(self, client):
        """Test all document workflow endpoints exist"""
        endpoints = [
            "/api/validate/document",
            "/api/preview/document",
            "/api/parse/document",
            "/api/upload/document",
        ]

        for endpoint in endpoints:
            response = client.post(endpoint)
            # Should not return 404 (endpoint exists)
            assert response.status_code != 404, f"Missing endpoint: {endpoint}"

    def test_youtube_workflow_endpoints_exist(self, client):
        """Test all YouTube workflow endpoints exist"""
        endpoints = [
            "/api/youtube/validate",
            "/api/youtube/preview",
            "/api/parse/youtube",
        ]

        for endpoint in endpoints:
            response = client.post(endpoint)
            # Should not return 404 (endpoint exists)
            assert response.status_code != 404, f"Missing endpoint: {endpoint}"

    def test_generation_workflow_endpoints_exist(self, client):
        """Test generation workflow endpoints exist"""
        endpoints = [
            "/api/generate",
            "/api/generate/multilingual",
        ]

        for endpoint in endpoints:
            response = client.post(endpoint)
            # Should not return 404 (endpoint exists)
            assert response.status_code != 404, f"Missing endpoint: {endpoint}"


# ============================================================================
# Component Interaction Stress Tests
# ============================================================================

class TestComponentInteractionStress:
    """Test component interactions under stress"""

    def test_rapid_api_calls(self, client):
        """Test rapid consecutive API calls"""
        endpoints = ["/api/health", "/api/voices", "/api/colors"]

        for _ in range(10):
            for endpoint in endpoints:
                response = client.get(endpoint)
                assert response.status_code == 200

    def test_concurrent_validation_requests(self, client, sample_markdown_file):
        """Test handling concurrent validation requests"""
        results = []

        for _ in range(5):
            files = {
                "file": (
                    sample_markdown_file["filename"],
                    BytesIO(sample_markdown_file["content"]),
                    sample_markdown_file["content_type"]
                )
            }
            response = client.post("/api/validate/document", files=files)
            results.append(response.status_code)

        # All should succeed
        assert all(status == 200 for status in results)


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
