"""
E2E Test: Error Scenarios
=========================

End-to-end tests for error handling:
- Invalid file upload (wrong format)
- Invalid YouTube URL
- API timeout during generation
- Recovery after error
"""

import pytest
from pathlib import Path
from fastapi.testclient import TestClient
import sys
from io import BytesIO

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.main import app


@pytest.fixture
def client():
    """Create test client with CSRF disabled"""
    import os
    os.environ["CSRF_DISABLED"] = "true"
    with TestClient(app) as c:
        yield c
    os.environ.pop("CSRF_DISABLED", None)


class TestInvalidFileUpload:
    """E2E tests for invalid file uploads"""

    @pytest.mark.e2e
    @pytest.mark.error
    def test_reject_executable_file(self, client):
        """Test rejection of executable files"""
        files = {
            "file": ("malware.exe", BytesIO(b"MZ\x90\x00"), "application/x-msdownload")
        }
        response = client.post("/api/validate/document", files=files)
        assert response.status_code == 400

    @pytest.mark.e2e
    @pytest.mark.error
    def test_reject_empty_file(self, client):
        """Test rejection of empty files"""
        files = {
            "file": ("empty.md", BytesIO(b""), "text/markdown")
        }
        response = client.post("/api/validate/document", files=files)
        # API may return 400 or 200 with valid=False
        if response.status_code == 200:
            data = response.json()
            assert data.get("valid") is False or "error" in str(data).lower()
        else:
            assert response.status_code == 400


class TestInvalidYouTubeURL:
    """E2E tests for invalid YouTube URLs"""

    @pytest.mark.e2e
    @pytest.mark.error
    def test_reject_non_youtube_url(self, client):
        """Test rejection of non-YouTube URLs"""
        response = client.post(
            "/api/youtube/validate",
            json={"url": "https://vimeo.com/123456789"}
        )
        assert response.status_code == 200
        assert response.json().get("is_valid") is False


class TestRecoveryAfterError:
    """E2E tests for recovery after errors"""

    @pytest.mark.e2e
    @pytest.mark.error
    def test_can_retry_after_validation_error(self, client):
        """Test can retry validation after error"""
        files = {
            "file": ("invalid.exe", BytesIO(b"content"), "application/x-msdownload")
        }
        response1 = client.post("/api/validate/document", files=files)
        assert response1.status_code == 400

        files = {
            "file": ("valid.md", BytesIO(b"# Title\n\nContent"), "text/markdown")
        }
        response2 = client.post("/api/validate/document", files=files)
        assert response2.status_code == 200


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short', '-m', 'e2e and error'])
