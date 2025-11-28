"""
Test suite for FastAPI endpoints in video_gen UI.

Priority: CRITICAL
Coverage Target: 90% of all API endpoints
Focus: The bug we found (content vs. path) and preventing similar issues
"""

import pytest
import json
from pathlib import Path
from io import BytesIO
from unittest.mock import patch, MagicMock
from fastapi import status


class TestDocumentEndpoints:
    """Tests for document parsing and upload endpoints."""

    @pytest.mark.critical
    def test_document_content_vs_path_bug(self, authenticated_client, sample_markdown):
        """
        TEST THE EXACT BUG WE FOUND!
        Document parser expects file path but receives content directly.
        This test ensures we never have this issue again.
        """
        # This is what the UI sends (content, not path)
        response = authenticated_client.post(
            "/api/parse/document",
            json={
                "content": sample_markdown,  # Direct content, not file path!
                "title": "Test Document",
                "use_ai": False
            }
        )

        # The bug caused a 500 error - we should handle this gracefully
        assert response.status_code != 500, "Server error - content treated as path!"

        # Should either work or return a proper error
        if response.status_code == 200:
            data = response.json()
            assert "task_id" in data
            assert "message" in data
        else:
            # If it fails, should be a 400 with clear error message
            assert response.status_code == 400
            error = response.json()
            assert "detail" in error
            # Error message should be helpful, not a stack trace
            assert "file not found" not in error["detail"].lower()

    def test_document_upload_valid_markdown(self, authenticated_client):
        """Test uploading a valid markdown file."""
        files = {
            "file": ("test.md", b"# Test\n\nContent", "text/markdown")
        }
        response = authenticated_client.post("/api/upload/document", files=files)

        assert response.status_code == 200
        data = response.json()
        assert "success" in data
        assert "preview" in data or "content" in data

    def test_document_upload_invalid_format(self, authenticated_client):
        """Test rejection of unsupported file formats."""
        files = {
            "file": ("test.exe", b"MZ\x90\x00", "application/x-msdownload")
        }
        response = authenticated_client.post("/api/upload/document", files=files)

        assert response.status_code == 400
        error = response.json()
        assert "detail" in error
        assert "format" in error["detail"].lower() or "type" in error["detail"].lower()

    def test_document_upload_size_limit(self, authenticated_client):
        """Test file size limit enforcement."""
        # Create a 10MB file (assuming limit is lower)
        large_content = b"A" * (10 * 1024 * 1024)
        files = {
            "file": ("large.md", large_content, "text/markdown")
        }
        response = authenticated_client.post("/api/upload/document", files=files)

        # Should reject large files
        assert response.status_code in [400, 413]

    def test_document_preview(self, authenticated_client):
        """Test document preview endpoint."""
        response = authenticated_client.post(
            "/api/preview/document",
            json={
                "content": "# Title\n\n## Section\n\n- Item 1\n- Item 2",
                "format": "markdown"
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert "preview" in data or "scenes" in data


class TestVideoGenerationEndpoints:
    """Tests for video generation pipeline endpoints."""

    def test_generate_video_minimal_config(self, authenticated_client):
        """Test video generation with minimum required fields."""
        response = authenticated_client.post(
            "/api/generate",
            json={
                "input_type": "manual",
                "title": "Test Video",
                "scenes": [
                    {"type": "title", "title": "Test", "subtitle": "Demo"}
                ]
            }
        )

        assert response.status_code in [200, 202]  # Accepted for async
        data = response.json()
        assert "task_id" in data or "id" in data

    def test_generate_video_full_config(self, authenticated_client, sample_video_request):
        """Test video generation with all configuration options."""
        response = authenticated_client.post(
            "/api/generate",
            json=sample_video_request
        )

        assert response.status_code in [200, 202]
        data = response.json()
        assert "task_id" in data or "id" in data

    def test_generate_video_invalid_scene_type(self, authenticated_client):
        """Test rejection of invalid scene types."""
        response = authenticated_client.post(
            "/api/generate",
            json={
                "input_type": "manual",
                "title": "Test",
                "scenes": [
                    {"type": "invalid_type", "content": "test"}
                ]
            }
        )

        assert response.status_code == 400
        error = response.json()
        assert "scene" in error["detail"].lower() or "type" in error["detail"].lower()

    @pytest.mark.asyncio
    async def test_task_status_endpoint(self, authenticated_client):
        """Test task status checking."""
        # First create a task
        create_response = authenticated_client.post(
            "/api/generate",
            json={
                "input_type": "manual",
                "title": "Test",
                "scenes": [{"type": "title", "title": "Test", "subtitle": "Demo"}]
            }
        )

        if create_response.status_code in [200, 202]:
            data = create_response.json()
            task_id = data.get("task_id") or data.get("id")

            # Check task status
            status_response = authenticated_client.get(f"/api/tasks/{task_id}")
            assert status_response.status_code == 200

            status_data = status_response.json()
            assert "status" in status_data
            assert status_data["status"] in ["pending", "processing", "completed", "failed"]


class TestYouTubeEndpoints:
    """Tests for YouTube-related endpoints."""

    def test_youtube_validate_valid_url(self, authenticated_client):
        """Test YouTube URL validation with valid URL."""
        response = authenticated_client.post(
            "/api/youtube/validate",
            json={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data.get("valid") is True or "video_id" in data

    def test_youtube_validate_invalid_url(self, authenticated_client):
        """Test YouTube URL validation with invalid URL."""
        response = authenticated_client.post(
            "/api/youtube/validate",
            json={"url": "https://vimeo.com/123456"}
        )

        assert response.status_code == 400
        error = response.json()
        assert "youtube" in error["detail"].lower() or "invalid" in error["detail"].lower()

    def test_youtube_parse(self, authenticated_client):
        """Test YouTube video parsing."""
        response = authenticated_client.post(
            "/api/parse/youtube",
            json={
                "url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
                "target_duration": 60
            }
        )

        # Might fail if no internet or API issues
        if response.status_code == 200:
            data = response.json()
            assert "task_id" in data or "scenes" in data


class TestConfigurationEndpoints:
    """Tests for configuration and options endpoints."""

    def test_get_voices(self, client):
        """Test voice options endpoint."""
        response = client.get("/api/voices")

        assert response.status_code == 200
        voices = response.json()
        assert isinstance(voices, list)
        assert len(voices) > 0

        # Check voice structure
        for voice in voices:
            assert "id" in voice
            assert "name" in voice

    def test_get_colors(self, client):
        """Test accent colors endpoint."""
        response = client.get("/api/colors")

        assert response.status_code == 200
        colors = response.json()
        assert isinstance(colors, list)
        assert "blue" in colors
        assert "purple" in colors

    def test_get_languages(self, client):
        """Test languages endpoint."""
        response = client.get("/api/languages")

        assert response.status_code == 200
        languages = response.json()
        assert isinstance(languages, list) or isinstance(languages, dict)

    def test_get_scene_types(self, client):
        """Test scene types endpoint."""
        response = client.get("/api/scene-types")

        assert response.status_code == 200
        scene_types = response.json()
        assert isinstance(scene_types, list)
        assert "title" in scene_types
        assert "list" in scene_types
        assert "outro" in scene_types


class TestSecurityEndpoints:
    """Security-related endpoint tests."""

    def test_csrf_token_generation(self, client):
        """Test CSRF token generation."""
        response = client.get("/api/csrf-token")

        assert response.status_code == 200
        data = response.json()
        assert "token" in data
        assert len(data["token"]) > 20

    def test_post_without_csrf_fails(self, client):
        """Test that POST requests without CSRF token fail."""
        # Don't use authenticated_client here
        response = client.post(
            "/api/generate",
            json={"input_type": "manual", "title": "Test"}
        )

        # Should fail without CSRF token (unless disabled for testing)
        # Check if CSRF is enforced
        if "CSRF_DISABLED" not in os.environ:
            assert response.status_code in [401, 403]

    def test_malicious_input_sanitization(self, authenticated_client, malicious_payloads):
        """Test that malicious inputs are properly sanitized."""
        for payload_type, payload in malicious_payloads.items():
            if payload_type == "large_string":
                continue  # Skip large payload for this test

            response = authenticated_client.post(
                "/api/generate",
                json={
                    "input_type": "manual",
                    "title": payload,
                    "scenes": [{"type": "title", "title": payload, "subtitle": "test"}]
                }
            )

            # Should either sanitize or reject, never execute
            assert response.status_code in [200, 202, 400]

            # If accepted, check response doesn't contain raw payload
            if response.status_code in [200, 202]:
                data = json.dumps(response.json())
                assert "<script>" not in data
                assert "DROP TABLE" not in data


class TestErrorHandling:
    """Test error handling across all endpoints."""

    def test_404_for_unknown_endpoint(self, client):
        """Test 404 response for unknown endpoints."""
        response = client.get("/api/this-does-not-exist")
        assert response.status_code == 404

    def test_method_not_allowed(self, client):
        """Test 405 for wrong HTTP methods."""
        response = client.get("/api/generate")  # Should be POST
        assert response.status_code == 405

    def test_malformed_json(self, authenticated_client):
        """Test handling of malformed JSON."""
        response = authenticated_client.post(
            "/api/generate",
            data="not json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422  # Unprocessable entity

    def test_missing_required_fields(self, authenticated_client):
        """Test handling of missing required fields."""
        response = authenticated_client.post(
            "/api/generate",
            json={}  # Missing all required fields
        )

        assert response.status_code in [400, 422]
        error = response.json()
        assert "detail" in error


class TestProgressTracking:
    """Test real-time progress tracking endpoints."""

    def test_sse_endpoint_exists(self, authenticated_client):
        """Test that SSE endpoint for progress exists."""
        # Note: Testing SSE is complex, just verify endpoint exists
        response = authenticated_client.get(
            "/api/tasks/fake-task-id/stream",
            headers={"Accept": "text/event-stream"}
        )

        # Should return 404 for fake task, not 405
        assert response.status_code in [404, 200]


@pytest.mark.performance
class TestPerformance:
    """Performance-related tests for API endpoints."""

    def test_response_time_voices(self, client, timing):
        """Test that voice endpoint responds quickly."""
        timing.start()
        response = client.get("/api/voices")
        timing.stop()

        assert response.status_code == 200
        timing.assert_faster_than(0.5)  # Should respond in <500ms

    def test_concurrent_requests(self, authenticated_client):
        """Test handling of concurrent requests."""
        import concurrent.futures

        def make_request():
            return authenticated_client.get("/api/colors")

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # All requests should succeed
        for response in results:
            assert response.status_code == 200


# Run with: pytest tests/test_api_endpoints.py -v --cov=app.main