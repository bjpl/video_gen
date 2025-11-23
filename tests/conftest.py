"""
Pytest Configuration and Fixtures
==================================

Shared fixtures and configuration for all test suites.
"""

import pytest
import sys
import os
from pathlib import Path
from io import BytesIO

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Import FastAPI app
from app.main import app
from fastapi.testclient import TestClient


# ============================================================================
# Test Client Fixtures
# ============================================================================

@pytest.fixture(scope="session")
def app_instance():
    """Get the FastAPI application instance."""
    return app


@pytest.fixture
def client():
    """Create a test client with CSRF disabled for testing."""
    os.environ["CSRF_DISABLED"] = "true"
    with TestClient(app) as c:
        yield c
    os.environ.pop("CSRF_DISABLED", None)


@pytest.fixture
def authenticated_client():
    """Create a test client with authentication (if needed)."""
    os.environ["CSRF_DISABLED"] = "true"
    with TestClient(app) as c:
        # Add any auth headers here if needed
        yield c
    os.environ.pop("CSRF_DISABLED", None)


# ============================================================================
# HTML Parser Fixture
# ============================================================================

@pytest.fixture
def html_parser():
    """Helper to parse HTML responses."""
    from bs4 import BeautifulSoup

    def parse(response):
        return BeautifulSoup(response.content, 'html.parser')

    return parse


# ============================================================================
# Sample Data Fixtures
# ============================================================================

@pytest.fixture
def sample_markdown():
    """Sample markdown content for testing."""
    return b"""# Test Document

## Introduction

This is a test document for testing purposes.

- Point one
- Point two
- Point three

## Code Example

```python
def hello():
    print("Hello, World!")
```

## Conclusion

Thank you for reading.
"""


@pytest.fixture
def sample_markdown_file(sample_markdown):
    """Create a file-like object with markdown content."""
    return {
        "filename": "test_document.md",
        "content": sample_markdown,
        "content_type": "text/markdown"
    }


@pytest.fixture
def sample_large_markdown():
    """Generate large markdown content for performance testing."""
    content = b"# Large Document\n\n"
    for i in range(50):
        content += f"## Section {i+1}\n\nContent for section {i+1}.\n\n".encode()
        content += b"- Item 1\n- Item 2\n- Item 3\n\n"
    return content


# ============================================================================
# Selenium Browser Fixtures
# ============================================================================

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False


@pytest.fixture
def browser():
    """Create a headless Chrome browser for E2E tests."""
    if not SELENIUM_AVAILABLE:
        pytest.skip("Selenium not installed")

    options = ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--window-size=1920,1080')

    try:
        driver = webdriver.Chrome(options=options)
        driver.implicitly_wait(10)
        yield driver
    except Exception as e:
        pytest.skip(f"Chrome WebDriver not available: {e}")
    finally:
        if 'driver' in locals():
            driver.quit()


@pytest.fixture
def firefox_browser():
    """Create a headless Firefox browser for E2E tests."""
    if not SELENIUM_AVAILABLE:
        pytest.skip("Selenium not installed")

    options = FirefoxOptions()
    options.add_argument('--headless')

    try:
        driver = webdriver.Firefox(options=options)
        driver.implicitly_wait(10)
        yield driver
    except Exception as e:
        pytest.skip(f"Firefox WebDriver not available: {e}")
    finally:
        if 'driver' in locals():
            driver.quit()


@pytest.fixture
def app_url():
    """Base URL for the application."""
    return os.environ.get("TEST_APP_URL", "http://localhost:8000")


# ============================================================================
# Test Data Fixtures
# ============================================================================

@pytest.fixture
def valid_youtube_url():
    """A valid YouTube URL for testing."""
    return "https://www.youtube.com/watch?v=dQw4w9WgXcQ"


@pytest.fixture
def invalid_youtube_url():
    """An invalid YouTube URL for testing."""
    return "https://vimeo.com/123456789"


@pytest.fixture
def sample_video_set():
    """Sample video set configuration."""
    return {
        "set_id": "test_set",
        "set_name": "Test Video Set",
        "videos": [
            {
                "video_id": "test_video_1",
                "title": "Test Video",
                "scenes": [
                    {"type": "title", "title": "Welcome", "subtitle": "Test"},
                    {"type": "list", "items": ["Point 1", "Point 2"]},
                    {"type": "outro", "message": "Thank you"}
                ],
                "voice": "male"
            }
        ],
        "accent_color": "blue"
    }


# ============================================================================
# Pytest Configuration
# ============================================================================

def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "e2e: End-to-end tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "performance: Performance tests")
    config.addinivalue_line("markers", "accessibility: Accessibility tests")
    config.addinivalue_line("markers", "browser: Browser-based tests")
    config.addinivalue_line("markers", "chrome: Chrome-specific tests")
    config.addinivalue_line("markers", "firefox: Firefox-specific tests")
    config.addinivalue_line("markers", "mobile: Mobile browser tests")
    config.addinivalue_line("markers", "error: Error handling tests")
    config.addinivalue_line("markers", "security: Security tests")
    config.addinivalue_line("markers", "slow: Slow running tests")


def pytest_collection_modifyitems(config, items):
    """Modify test collection based on markers."""
    # Skip browser tests if Selenium not available
    if not SELENIUM_AVAILABLE:
        skip_selenium = pytest.mark.skip(reason="Selenium not installed")
        for item in items:
            if "browser" in item.keywords or "chrome" in item.keywords or "firefox" in item.keywords:
                item.add_marker(skip_selenium)


# ============================================================================
# Performance Testing Utilities
# ============================================================================

@pytest.fixture
def timing():
    """Utility for timing code execution."""
    import time

    class Timer:
        def __init__(self):
            self.start_time = None
            self.end_time = None

        def start(self):
            self.start_time = time.time()
            return self

        def stop(self):
            self.end_time = time.time()
            return self

        @property
        def duration(self):
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return None

        def assert_faster_than(self, seconds):
            assert self.duration is not None, "Timer not started/stopped"
            assert self.duration < seconds, f"Took {self.duration:.2f}s (limit: {seconds}s)"

    return Timer()


# ============================================================================
# Cleanup Fixtures
# ============================================================================

@pytest.fixture(autouse=True)
def cleanup_env():
    """Clean up environment variables after each test."""
    yield
    # Clean up any test environment variables
    for key in list(os.environ.keys()):
        if key.startswith("TEST_"):
            del os.environ[key]
