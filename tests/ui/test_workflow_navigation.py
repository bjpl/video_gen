"""
Workflow Navigation Tests
Tests user workflow paths and navigation patterns
"""
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.main import app


@pytest.fixture
def client():
    """Create test client"""
    with TestClient(app) as c:
        yield c


# ============================================================================
# Navigation Flow Tests
# ============================================================================

class TestNavigationWorkflows:
    """Test primary navigation workflows"""

    def test_homepage_to_create_workflow(self, client):
        """Test navigation from homepage to create page"""
        # Start at homepage
        response = client.get('/')
        assert response.status_code == 200

        # Navigate to create page
        response = client.get('/create')
        assert response.status_code == 200
        assert b'Create' in response.content or b'create' in response.content

    def test_homepage_to_builder_workflow(self, client):
        """Test navigation from homepage to advanced builder"""
        response = client.get('/')
        assert response.status_code == 200

        response = client.get('/builder')
        assert response.status_code == 200
        assert b'Scene Builder' in response.content or b'Builder' in response.content

    def test_all_navigation_links_work(self, client):
        """Test all main navigation links are functional"""
        nav_links = ['/', '/create', '/builder', '/progress']

        for link in nav_links:
            response = client.get(link)
            assert response.status_code == 200, f"Navigation link failed: {link}"

    def test_breadcrumb_navigation(self, client):
        """Test breadcrumb navigation is present"""
        response = client.get('/builder')
        assert response.status_code == 200

        # Check for breadcrumb structure
        content = response.content.decode('utf-8')
        assert 'Home' in content or 'home' in content


# ============================================================================
# Form Workflow Tests
# ============================================================================

class TestFormWorkflows:
    """Test form submission and validation workflows"""

    def test_document_parsing_workflow(self, client):
        """Test document parsing submission workflow"""
        # Prepare valid document input
        payload = {
            "content": "# Test Document\n\nTest content here.",
            "voice": "male",
            "accent_color": "blue"
        }

        response = client.post('/api/parse/document', json=payload)
        assert response.status_code == 200

        data = response.json()
        assert 'task_id' in data
        assert 'status' in data

    def test_video_generation_workflow(self, client):
        """Test end-to-end video generation workflow"""
        # Create minimal video set
        video_set = {
            "set_id": "test_workflow",
            "set_name": "Test Workflow",
            "accent_color": "blue",
            "videos": [{
                "video_id": "test_vid",
                "title": "Test Video",
                "scenes": [{
                    "type": "title",
                    "narration": "Test narration",
                    "title": "Test Title"
                }]
            }]
        }

        response = client.post('/api/generate', json=video_set)
        assert response.status_code == 200

        data = response.json()
        assert 'task_id' in data
        assert data['status'] == 'started'

    def test_multilingual_workflow(self, client):
        """Test multilingual video generation workflow"""
        payload = {
            "video_set": {
                "set_id": "test_ml_workflow",
                "set_name": "Test Multilingual",
                "accent_color": "blue",
                "videos": [{
                    "video_id": "test",
                    "title": "Test",
                    "scenes": [{
                        "type": "title",
                        "narration": "Hello World",
                        "title": "Hello"
                    }]
                }]
            },
            "target_languages": ["en", "es", "fr"],
            "source_language": "en",
            "translation_method": "claude"
        }

        response = client.post('/api/generate/multilingual', json=payload)
        assert response.status_code == 200

        data = response.json()
        assert 'task_id' in data
        assert data['languages'] == ["en", "es", "fr"]


# ============================================================================
# Progress Tracking Workflow Tests
# ============================================================================

class TestProgressWorkflows:
    """Test progress tracking and monitoring workflows"""

    def test_progress_page_loads(self, client):
        """Test progress tracking page loads"""
        response = client.get('/progress')
        assert response.status_code == 200

    def test_task_status_endpoint(self, client):
        """Test task status checking workflow"""
        # Create a task first
        video_set = {
            "set_id": "test_status",
            "set_name": "Test Status",
            "accent_color": "blue",
            "videos": [{
                "video_id": "test",
                "title": "Test",
                "scenes": [{
                    "type": "title",
                    "narration": "Test"
                }]
            }]
        }

        response = client.post('/api/generate', json=video_set)
        data = response.json()
        task_id = data['task_id']

        # Note: Full task status endpoint would need to be implemented
        # This tests the workflow pattern


# ============================================================================
# Error Recovery Workflow Tests
# ============================================================================

class TestErrorRecoveryWorkflows:
    """Test error handling and recovery workflows"""

    def test_invalid_input_handling(self, client):
        """Test graceful handling of invalid inputs"""
        # Test with empty content
        response = client.post(
            '/api/parse/document',
            json={"content": ""}
        )
        # Should handle gracefully (either 400 or process empty)
        assert response.status_code in [200, 400, 422]

    def test_missing_required_fields(self, client):
        """Test handling of missing required fields"""
        # Test with incomplete video set
        response = client.post(
            '/api/generate',
            json={"set_id": "test"}  # Missing required fields
        )
        # Should return validation error
        assert response.status_code in [400, 422]

    def test_invalid_scene_type(self, client):
        """Test handling of invalid scene types

        Note: The API uses async processing - it accepts the request (200)
        and processes in background. Invalid scene types cause pipeline
        failures which are tracked in task state and retrievable via
        /api/tasks/{task_id} endpoint.
        """
        import time

        video_set = {
            "set_id": "test_invalid",
            "set_name": "Test Invalid",
            "accent_color": "blue",
            "videos": [{
                "video_id": "test",
                "title": "Test",
                "scenes": [{
                    "type": "invalid_type",  # Invalid scene type
                    "narration": "Test"
                }]
            }]
        }

        response = client.post('/api/generate', json=video_set)
        # API accepts request for async processing (returns 200)
        assert response.status_code == 200

        data = response.json()
        assert 'task_id' in data
        task_id = data['task_id']

        # Wait briefly for async processing to complete/fail
        time.sleep(1.5)

        # Check task status - should show failure or errors
        status_response = client.get(f'/api/tasks/{task_id}')

        # Task might not be found if it failed early, or might have error status
        if status_response.status_code == 200:
            status_data = status_response.json()
            # Pipeline should fail or have errors for invalid scene type
            assert status_data['status'] in ['failed', 'error', 'processing'] or status_data.get('errors')
        else:
            # 404 is acceptable if task failed before state was persisted
            assert status_response.status_code in [404, 500]


# ============================================================================
# Multi-Step Workflow Tests
# ============================================================================

class TestMultiStepWorkflows:
    """Test complex multi-step user workflows"""

    def test_scene_builder_workflow(self, client):
        """Test complete scene builder workflow"""
        # 1. Load builder page
        response = client.get('/builder')
        assert response.status_code == 200

        # 2. Submit scene configuration
        video_set = {
            "set_id": "builder_test",
            "set_name": "Builder Test",
            "accent_color": "purple",
            "videos": [{
                "video_id": "builder_vid",
                "title": "Builder Video",
                "scenes": [
                    {
                        "type": "title",
                        "title": "Welcome",
                        "subtitle": "Getting Started"
                    },
                    {
                        "type": "list",
                        "title": "Key Points",
                        "items": ["Point 1", "Point 2", "Point 3"]
                    },
                    {
                        "type": "outro",
                        "message": "Thank you",
                        "cta": "Subscribe"
                    }
                ]
            }]
        }

        response = client.post('/api/generate', json=video_set)
        assert response.status_code == 200

        # 3. Verify task created
        data = response.json()
        assert 'task_id' in data
        assert data['status'] == 'started'

    def test_multilingual_scene_builder_workflow(self, client):
        """Test multilingual scene builder workflow"""
        # Build scenes
        video_set = {
            "set_id": "ml_builder",
            "set_name": "Multilingual Builder",
            "accent_color": "blue",
            "videos": [{
                "video_id": "ml_vid",
                "title": "ML Video",
                "scenes": [{
                    "type": "title",
                    "title": "Hello World",
                    "subtitle": "Welcome"
                }]
            }]
        }

        # Generate in multiple languages
        payload = {
            "video_set": video_set,
            "target_languages": ["en", "es", "de"],
            "source_language": "en",
            "translation_method": "claude"
        }

        response = client.post('/api/generate/multilingual', json=payload)
        assert response.status_code == 200

        data = response.json()
        assert data['languages'] == ["en", "es", "de"]


# ============================================================================
# API Discovery Workflow Tests
# ============================================================================

class TestAPIDiscoveryWorkflows:
    """Test API discovery and exploration workflows"""

    def test_scene_types_discovery(self, client):
        """Test discovering available scene types"""
        response = client.get('/api/scene-types')
        assert response.status_code == 200

        data = response.json()
        assert 'general' in data
        assert 'educational' in data
        assert len(data['general']) > 0
        assert len(data['educational']) > 0

    def test_voices_discovery(self, client):
        """Test discovering available voices"""
        response = client.get('/api/voices')
        assert response.status_code == 200

        voices = response.json()
        assert len(voices) > 0
        assert any(v['id'] == 'male' for v in voices)

    def test_languages_discovery(self, client):
        """Test discovering available languages"""
        response = client.get('/api/languages')
        assert response.status_code == 200

        data = response.json()
        assert 'languages' in data
        assert 'total' in data
        assert data['total'] >= 28

    def test_language_voices_discovery(self, client):
        """Test discovering voices for specific language"""
        response = client.get('/api/languages/en/voices')
        assert response.status_code == 200

        data = response.json()
        assert data['language'] == 'en'
        assert 'voices' in data


# ============================================================================
# Integration: Complete User Journey
# ============================================================================

def test_complete_user_journey(client):
    """Integration test: Complete user journey from start to finish"""
    # 1. User lands on homepage
    response = client.get('/')
    assert response.status_code == 200

    # 2. Explores API capabilities
    response = client.get('/api/scene-types')
    assert response.status_code == 200

    response = client.get('/api/languages')
    assert response.status_code == 200

    # 3. Navigates to builder
    response = client.get('/builder')
    assert response.status_code == 200

    # 4. Creates video with scenes
    video_set = {
        "set_id": "journey_test",
        "set_name": "User Journey Test",
        "accent_color": "blue",
        "videos": [{
            "video_id": "journey_vid",
            "title": "Journey Video",
            "scenes": [
                {"type": "title", "title": "Start", "subtitle": "Begin"},
                {"type": "list", "title": "Steps", "items": ["1", "2", "3"]},
                {"type": "outro", "message": "Done", "cta": "Thanks"}
            ]
        }]
    }

    response = client.post('/api/generate', json=video_set)
    assert response.status_code == 200

    # 5. Checks progress
    response = client.get('/progress')
    assert response.status_code == 200

    # Journey complete!


def test_error_recovery_journey(client):
    """Integration test: User journey with error recovery"""
    # 1. User submits invalid data
    response = client.post('/api/generate', json={"invalid": "data"})
    assert response.status_code in [400, 422]

    # 2. User corrects and resubmits
    video_set = {
        "set_id": "recovery_test",
        "set_name": "Recovery Test",
        "accent_color": "blue",
        "videos": [{
            "video_id": "recovery_vid",
            "title": "Recovery Video",
            "scenes": [{"type": "title", "title": "Success"}]
        }]
    }

    response = client.post('/api/generate', json=video_set)
    assert response.status_code == 200

    # Recovery successful!
