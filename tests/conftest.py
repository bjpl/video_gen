"""
Pytest configuration and shared fixtures for video_gen UI tests.

This file provides:
- Test client setup for FastAPI
- Temporary directories for file operations
- Mock data generators
- Async test utilities
"""

import os
import sys

# CRITICAL: Set test environment variables BEFORE any app imports
# This prevents rate limiting and other production features in tests
os.environ["TESTING"] = "true"
os.environ["LOG_LEVEL"] = "DEBUG"
os.environ["RATE_LIMIT_ENABLED"] = "false"  # Disable rate limiting in tests

# CRITICAL: Apply nest_asyncio to fix event loop pollution in test suite
# This allows nested asyncio.run() calls which occur when:
# - Main tests use emit_sync() or state_manager's sync methods
# - Later unit tests use @pytest.mark.asyncio with pytest-asyncio's auto mode
# Without this patch, running the full suite fails with:
# "RuntimeError: This event loop is already running"
import nest_asyncio
nest_asyncio.apply()
# Don't use real API keys in tests
if "ANTHROPIC_API_KEY" in os.environ:
    del os.environ["ANTHROPIC_API_KEY"]

import pytest
import asyncio
import tempfile
import shutil
from pathlib import Path
from typing import Generator, AsyncGenerator

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fastapi.testclient import TestClient
from app.main import app
import json


# NOTE: Session-scoped event_loop fixture REMOVED (2024-12-24)
# Reason: Conflicts with pytest-asyncio's asyncio_mode=auto in pytest.ini
# The plugin automatically provides function-scoped event loops for async tests
# See: docs/planning/GOAP_PORTFOLIO_READINESS_PLAN.md for full analysis


@pytest.fixture
def client() -> Generator:
    """Create test client for FastAPI app."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def authenticated_client(client: TestClient) -> TestClient:
    """Create test client with CSRF token."""
    # Get CSRF token
    response = client.get("/api/csrf-token")
    token = response.json().get("token", "test-token")

    # Set token in headers
    client.headers["X-CSRF-Token"] = token
    return client


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create temporary directory for test files."""
    temp_path = Path(tempfile.mkdtemp(prefix="test_video_gen_"))
    yield temp_path
    # Cleanup
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def sample_markdown() -> str:
    """Sample markdown document for testing."""
    return """# Test Video

This is a test document for the video generation system.

## Features

- Bullet point 1
- Bullet point 2
- Bullet point 3

## Code Example

```python
def hello_world():
    print("Hello, World!")
```

## Conclusion

This concludes our test document.
"""


@pytest.fixture
def sample_yaml_config() -> dict:
    """Sample YAML configuration for video generation."""
    return {
        "video": {
            "id": "test_video",
            "title": "Test Video",
            "description": "Test video for automated testing",
            "accent_color": "blue",
            "voice": "male"
        },
        "scenes": [
            {
                "type": "title",
                "title": "Test Title",
                "subtitle": "Test Subtitle",
                "voice": "male"
            },
            {
                "type": "list",
                "header": "Test List",
                "items": ["Item 1", "Item 2", "Item 3"],
                "voice": "female"
            },
            {
                "type": "outro",
                "main_text": "Test Complete",
                "sub_text": "Thank you",
                "voice": "male"
            }
        ]
    }


@pytest.fixture
def sample_video_request() -> dict:
    """Sample video generation request."""
    return {
        "input_type": "manual",
        "title": "Test Video",
        "scenes": [
            {
                "type": "title",
                "title": "Test Title",
                "subtitle": "Test Subtitle"
            },
            {
                "type": "list",
                "header": "Test Items",
                "items": ["First", "Second", "Third"]
            }
        ],
        "voice": "male",
        "accent_color": "blue",
        "duration": 60
    }


@pytest.fixture
def sample_document_file(temp_dir: Path) -> Path:
    """Create a sample markdown file."""
    file_path = temp_dir / "test_document.md"
    file_path.write_text("""# Test Document

## Introduction
This is a test document.

## Main Content
- Point 1
- Point 2
- Point 3

## Conclusion
End of document.
""")
    return file_path


@pytest.fixture
def malicious_payloads() -> dict:
    """Common malicious payloads for security testing."""
    return {
        "xss": "<script>alert('XSS')</script>",
        "sql_injection": "'; DROP TABLE users; --",
        "path_traversal": "../../etc/passwd",
        "command_injection": "; rm -rf /",
        "xxe": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        "large_string": "A" * 1000000,  # 1MB string
        "null_byte": "test.pdf\x00.exe",
        "unicode": "test\u202e\u0000\ufff0"
    }


@pytest.fixture
def mock_pipeline_response() -> dict:
    """Mock response from video generation pipeline."""
    return {
        "task_id": "test_task_123",
        "status": "processing",
        "progress": 0.5,
        "message": "Generating video...",
        "stages": [
            {"name": "input", "status": "completed"},
            {"name": "parsing", "status": "completed"},
            {"name": "script", "status": "processing"},
            {"name": "audio", "status": "pending"},
            {"name": "video", "status": "pending"},
            {"name": "output", "status": "pending"}
        ]
    }


@pytest.fixture
async def async_client():
    """Async test client for FastAPI."""
    from httpx import AsyncClient
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


# Markers for test organization
pytest.mark.unit = pytest.mark.unit
pytest.mark.integration = pytest.mark.integration
pytest.mark.e2e = pytest.mark.e2e
pytest.mark.security = pytest.mark.security
pytest.mark.performance = pytest.mark.performance
pytest.mark.slow = pytest.mark.slow


# ============================================================================
# SERVER AVAILABILITY CHECK FOR BROWSER TESTS
# ============================================================================

def _is_server_running(host: str = "localhost", port: int = 8000) -> bool:
    """Check if the server is running by attempting a socket connection."""
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


@pytest.fixture(scope="session")
def _global_server_available():
    """Session-scoped check if the test server is available."""
    base_url = os.environ.get("TEST_BASE_URL", "http://localhost:8000")
    if "://" in base_url:
        url_part = base_url.split("://")[1]
    else:
        url_part = base_url
    if ":" in url_part:
        host, port_str = url_part.split(":")
        port = int(port_str.split("/")[0])
    else:
        host = url_part.split("/")[0]
        port = 80
    return _is_server_running(host, port)


@pytest.fixture(autouse=True)
def _skip_browser_tests_without_server(request, _global_server_available):
    """Auto-skip tests with browser/server markers when server is unavailable.

    This fixture runs for ALL tests and checks if the test has markers
    indicating it needs a running server (selenium, browser, e2e, server).
    If so and the server is not running, the test is skipped.
    """
    # Markers that indicate a test needs a running server
    server_markers = {"selenium", "browser", "e2e", "server"}
    test_markers = {marker.name for marker in request.node.iter_markers()}

    if test_markers & server_markers and not _global_server_available:
        pytest.skip("Test requires running server (start with: python -m app.main)")


# Test environment configuration
@pytest.fixture(scope="session", autouse=True)
def setup_test_env():
    """
    Test environment variables setup.

    Note: Environment variables are already set at module import time
    to ensure they're available before the FastAPI app initializes.
    This fixture is kept for cleanup purposes.
    """
    yield
    # Cleanup
    if "TESTING" in os.environ:
        del os.environ["TESTING"]
    if "RATE_LIMIT_ENABLED" in os.environ:
        del os.environ["RATE_LIMIT_ENABLED"]


# ============================================================================
# MOCKING FIXTURES FOR EXTERNAL APIS
# ============================================================================

@pytest.fixture
def mock_edge_tts(monkeypatch):
    """Mock edge_tts.Communicate to avoid network calls."""
    from unittest.mock import AsyncMock, MagicMock
    import wave
    import struct

    async def mock_save(audio_path: str):
        """Create a dummy audio file."""
        # Create a simple WAV file
        path = Path(audio_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Create a 1-second silent audio file
        sample_rate = 22050
        duration = 1  # 1 second
        num_samples = sample_rate * duration

        with wave.open(str(path), 'w') as wav_file:
            wav_file.setnchannels(1)  # Mono
            wav_file.setsampwidth(2)  # 2 bytes per sample
            wav_file.setframerate(sample_rate)

            # Write silent audio (all zeros)
            for _ in range(num_samples):
                wav_file.writeframes(struct.pack('h', 0))

    # Mock Communicate class
    mock_communicate = MagicMock()
    mock_communicate.save = AsyncMock(side_effect=mock_save)

    def mock_communicate_init(text, voice, rate="+0%", volume="+0%"):
        return mock_communicate

    # Patch edge_tts.Communicate
    import edge_tts
    monkeypatch.setattr(edge_tts, "Communicate", mock_communicate_init)

    return mock_communicate


@pytest.fixture
def auto_mock_edge_tts_for_e2e(monkeypatch):
    """Mock edge_tts for end-to-end tests to prevent network calls."""
    from unittest.mock import AsyncMock, MagicMock
    import wave
    import struct

    async def mock_save(audio_path: str):
        """Create a dummy audio file."""
        path = Path(audio_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Create a simple WAV file (MP3 would need external library)
        # We'll create WAV and rename to MP3 for simplicity
        sample_rate = 22050
        duration = 1
        num_samples = sample_rate * duration

        with wave.open(str(path).replace('.mp3', '.wav'), 'w') as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(sample_rate)
            for _ in range(num_samples):
                wav_file.writeframes(struct.pack('h', 0))

        # Rename to requested format
        wav_path = Path(str(path).replace('.mp3', '.wav'))
        if wav_path.exists() and str(path).endswith('.mp3'):
            wav_path.rename(path)

    mock_communicate = MagicMock()
    mock_communicate.save = AsyncMock(side_effect=mock_save)

    def mock_communicate_init(text, voice, rate="+0%", volume="+0%"):
        return mock_communicate

    try:
        import edge_tts
        monkeypatch.setattr(edge_tts, "Communicate", mock_communicate_init)
    except ImportError:
        pass  # edge_tts not installed, skip mocking

    return mock_communicate


@pytest.fixture
def mock_anthropic_api(monkeypatch):
    """Mock Anthropic API to avoid network calls and API costs."""
    from unittest.mock import MagicMock, Mock

    # Mock response
    mock_response = MagicMock()
    mock_response.content = [
        MagicMock(text="This is a mocked AI-enhanced narration response.")
    ]

    # Mock client
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_response

    # Mock Anthropic class
    def mock_anthropic_init(*args, **kwargs):
        return mock_client

    try:
        import anthropic
        monkeypatch.setattr(anthropic, "Anthropic", mock_anthropic_init)
    except ImportError:
        pass  # anthropic not installed, skip mocking


@pytest.fixture
def mock_ffmpeg_audio_duration(monkeypatch):
    """Mock ffmpeg to return audio duration without running actual ffmpeg."""
    from unittest.mock import MagicMock
    import subprocess

    def mock_subprocess_run(cmd, *args, **kwargs):
        """Mock subprocess.run for ffmpeg duration checks."""
        result = MagicMock()
        result.returncode = 0
        result.stderr = "Duration: 00:00:05.00, start: 0.000000, bitrate: 128 kb/s"
        result.stdout = ""
        return result

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)


@pytest.fixture(autouse=True)
def auto_mock_ffmpeg(monkeypatch):
    """Automatically mock ffmpeg for all tests."""
    from unittest.mock import MagicMock
    import subprocess

    original_run = subprocess.run

    def mock_subprocess_run(cmd, *args, **kwargs):
        """Mock subprocess.run for ffmpeg, pass through others."""
        if isinstance(cmd, list) and len(cmd) > 0:
            # Check if this is an ffmpeg call
            if 'ffmpeg' in str(cmd[0]).lower():
                result = MagicMock()
                result.returncode = 0
                result.stderr = "Duration: 00:00:05.00, start: 0.000000, bitrate: 128 kb/s"
                result.stdout = ""
                return result

        # Pass through non-ffmpeg calls
        return original_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)