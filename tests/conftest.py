"""
Pytest configuration and shared fixtures for video_gen UI tests.

This file provides:
- Test client setup for FastAPI
- Temporary directories for file operations
- Mock data generators
- Async test utilities
"""

import pytest
import asyncio
import tempfile
import shutil
from pathlib import Path
from typing import Generator, AsyncGenerator
import sys
import os

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fastapi.testclient import TestClient
from app.main import app
import json


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


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


# Test environment configuration
@pytest.fixture(scope="session", autouse=True)
def setup_test_env():
    """Setup test environment variables."""
    os.environ["TESTING"] = "true"
    os.environ["LOG_LEVEL"] = "DEBUG"
    # Don't use real API keys in tests
    if "ANTHROPIC_API_KEY" in os.environ:
        del os.environ["ANTHROPIC_API_KEY"]
    yield
    # Cleanup
    if "TESTING" in os.environ:
        del os.environ["TESTING"]