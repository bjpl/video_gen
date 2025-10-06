"""
Web UI Integration Tests
Tests the FastAPI Web UI with unified pipeline integration
Uses pytest fixtures for clean, compatible testing
"""
import pytest
import json
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def client():
    """Create test client using pytest fixture pattern"""
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as c:
        yield c


# ============================================================================
# UI Page Tests - Verify all templates load
# ============================================================================

def test_index_page_loads(client):
    """Test main index page loads successfully"""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_builder_page_loads(client):
    """Test visual builder page loads"""
    response = client.get("/builder")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_multilingual_page_loads(client):
    """Test multilingual interface loads"""
    response = client.get("/multilingual")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_progress_page_loads(client):
    """Test progress tracking page loads"""
    response = client.get("/progress")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_create_page_loads(client):
    """Test unified creation page loads"""
    response = client.get("/create")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


# ============================================================================
# API Endpoint Tests - Pipeline Integration
# ============================================================================

def test_health_endpoint(client):
    """Test health check returns pipeline status"""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["pipeline"] == "unified"
    assert data["version"] == "2.0.0"
    assert "features" in data
    assert data["features"]["state_persistence"] == True


def test_scene_types_endpoint(client):
    """Test scene types endpoint"""
    response = client.get("/api/scene-types")
    assert response.status_code == 200
    data = response.json()
    assert "general" in data
    assert "educational" in data
    assert len(data["general"]) == 6
    assert len(data["educational"]) == 6


def test_voices_endpoint(client):
    """Test voices endpoint"""
    response = client.get("/api/voices")
    assert response.status_code == 200
    voices = response.json()
    assert len(voices) == 4
    assert any(v["id"] == "male" for v in voices)


def test_colors_endpoint(client):
    """Test colors endpoint"""
    response = client.get("/api/colors")
    assert response.status_code == 200
    colors = response.json()
    assert "blue" in colors
    assert len(colors) == 6


def test_languages_endpoint(client):
    """Test languages endpoint returns 28+ languages"""
    response = client.get("/api/languages")
    assert response.status_code == 200
    data = response.json()
    assert "languages" in data
    assert data["total"] >= 28
    assert len(data["languages"]) >= 28


def test_language_voices_endpoint(client):
    """Test getting voices for specific language"""
    response = client.get("/api/languages/en/voices")
    assert response.status_code == 200
    data = response.json()
    assert data["language"] == "en"
    assert "voices" in data


def test_language_voices_not_found(client):
    """Test error handling for unsupported language"""
    response = client.get("/api/languages/invalid/voices")
    assert response.status_code == 404


# ============================================================================
# Pipeline Integration Tests
# ============================================================================

def test_parse_document_endpoint(client):
    """Test document parsing uses pipeline"""
    response = client.post(
        "/api/parse/document",
        json={
            "content": "# Test Document\n\nTest content here.",
            "voice": "male",
            "accent_color": "blue"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "task_id" in data
    assert data["status"] == "started"
    assert "doc_" in data["task_id"]


def test_parse_youtube_endpoint(client):
    """Test YouTube parsing uses pipeline"""
    response = client.post(
        "/api/parse/youtube",
        json={
            "url": "https://youtube.com/watch?v=test123",
            "duration": 60,
            "accent_color": "purple"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "task_id" in data
    assert data["status"] == "started"
    assert "yt_" in data["task_id"]


def test_generate_videos_endpoint(client):
    """Test video generation uses pipeline"""
    video_set = {
        "set_id": "test",
        "set_name": "Test Set",
        "videos": [
            {
                "video_id": "test_vid",
                "title": "Test Video",
                "scenes": [
                    {
                        "type": "title",
                        "narration": "Test narration"
                    }
                ]
            }
        ],
        "accent_color": "blue"
    }

    response = client.post(
        "/api/generate",
        json=video_set
    )
    assert response.status_code == 200
    data = response.json()
    assert "task_id" in data
    assert data["status"] == "started"


def test_multilingual_generation_endpoint(client):
    """Test multilingual generation uses pipeline"""
    request_data = {
        "video_set": {
            "set_id": "test_ml",
            "set_name": "Test Multilingual",
            "videos": [
                {
                    "video_id": "test",
                    "title": "Test",
                    "scenes": [{"type": "title", "narration": "Hello"}]
                }
            ],
            "accent_color": "blue"
        },
        "target_languages": ["en", "es", "fr"],
        "source_language": "en",
        "translation_method": "claude"
    }

    response = client.post(
        "/api/generate/multilingual",
        json=request_data
    )
    assert response.status_code == 200
    data = response.json()
    assert "task_id" in data
    assert data["languages"] == ["en", "es", "fr"]


# ============================================================================
# Error Handling Tests
# ============================================================================

def test_invalid_document_input(client):
    """Test error handling for invalid document input"""
    response = client.post(
        "/api/parse/document",
        json={"content": ""}  # Empty content
    )
    # Should handle gracefully (either 400 or process empty)
    assert response.status_code in [200, 400, 422]


def test_invalid_youtube_url(client):
    """Test error handling for invalid YouTube URL"""
    response = client.post(
        "/api/parse/youtube",
        json={"url": "not-a-url"}
    )
    # Should handle gracefully
    assert response.status_code in [200, 400, 422]


# ============================================================================
# Backward Compatibility Tests
# ============================================================================

def test_api_response_format_compatibility(client):
    """Verify API responses match expected format for templates"""
    response = client.post(
        "/api/parse/document",
        json={"content": "Test", "voice": "male", "accent_color": "blue"}
    )

    assert response.status_code == 200
    data = response.json()

    # Verify response has expected fields for HTMX templates
    assert "task_id" in data
    assert "status" in data
    assert "message" in data


def test_all_endpoints_return_json(client):
    """Verify all API endpoints return valid JSON"""
    endpoints = [
        ("/api/health", "get"),
        ("/api/scene-types", "get"),
        ("/api/voices", "get"),
        ("/api/colors", "get"),
        ("/api/languages", "get"),
    ]

    for endpoint, method in endpoints:
        if method == "get":
            response = client.get(endpoint)
        else:
            response = client.post(endpoint)

        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"
        # Verify it's valid JSON
        json_data = response.json()
        assert json_data is not None


# ============================================================================
# Integration Summary Test
# ============================================================================

def test_web_ui_integration_summary(client):
    """Summary test validating key integration points"""
    # Verify all pages load
    assert client.get("/").status_code == 200
    assert client.get("/builder").status_code == 200
    assert client.get("/multilingual").status_code == 200

    # Verify API works
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/languages").status_code == 200

    # Verify pipeline integration
    health = client.get("/api/health").json()
    assert health["pipeline"] == "unified"
    assert health["features"]["state_persistence"] == True
    assert health["features"]["auto_resume"] == True
