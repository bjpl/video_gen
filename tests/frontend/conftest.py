"""
Pytest configuration for frontend tests.

This module provides fixtures for browser testing.
Supports both Playwright and Selenium, with fallback if neither is available.
"""

import pytest
import os
import socket
import urllib.request
import urllib.error


def _is_server_running(host: str = "localhost", port: int = 8000, timeout: float = 2.0) -> bool:
    """Check if the server is running by attempting a connection."""
    try:
        # Try a simple socket connection first
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


@pytest.fixture(scope="session")
def server_available():
    """Check if the test server is available.

    Returns True if the server is running, False otherwise.
    This is a session-scoped fixture so the check only happens once.
    """
    base_url = os.environ.get("TEST_BASE_URL", "http://localhost:8000")

    # Parse host and port from base_url
    if "://" in base_url:
        url_part = base_url.split("://")[1]
    else:
        url_part = base_url

    if ":" in url_part:
        host, port_str = url_part.split(":")
        port = int(port_str.split("/")[0])  # Handle paths like :8000/api
    else:
        host = url_part.split("/")[0]
        port = 80

    return _is_server_running(host, port)


@pytest.fixture(autouse=True)
def skip_without_server(request, server_available):
    """Auto-skip tests marked with 'server', 'browser', or 'e2e' when server is not available.

    This fixture runs automatically for all tests in the frontend directory.
    It checks if the test has specific markers that require a running server,
    and skips the test if the server is not available.
    """
    # Check if test has markers that require a server
    server_markers = {"server", "browser", "e2e", "selenium", "api"}
    test_markers = {marker.name for marker in request.node.iter_markers()}

    # If the test has any server-requiring markers and server is not available, skip
    if test_markers & server_markers and not server_available:
        pytest.skip("Test requires running server (start with: python -m app.main)")

    # Also skip if this test uses page/browser fixtures but server isn't running
    fixture_names = getattr(request, 'fixturenames', [])
    browser_fixtures = {"page", "authenticated_page", "browser"}
    if browser_fixtures & set(fixture_names) and not server_available:
        pytest.skip("Browser test requires running server (start with: python -m app.main)")


# Try to import Playwright
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# Try to import Selenium
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False


@pytest.fixture(scope="session")
def browser():
    """Create a browser instance for the test session.

    Tries Playwright first, falls back to Selenium if available.
    """
    if PLAYWRIGHT_AVAILABLE:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            yield browser
            browser.close()
    elif SELENIUM_AVAILABLE:
        options = ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        try:
            driver = webdriver.Chrome(options=options)
            yield driver
            driver.quit()
        except Exception as e:
            pytest.skip(f"No browser driver available: {e}")
    else:
        pytest.skip("Neither Playwright nor Selenium is installed")


@pytest.fixture(scope="session")
def base_url():
    """Return the base URL for the test server.

    Override this in your local pytest.ini or via environment variable.
    """
    import os
    return os.environ.get("TEST_BASE_URL", "http://localhost:8000")


@pytest.fixture(scope="function")
def page(browser):
    """Create a new page for each test function.

    Works with Playwright browser. Skip if Playwright not available.
    """
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("Playwright not available for page fixture")

    context = browser.new_context(
        viewport={"width": 1280, "height": 720},
        ignore_https_errors=True
    )
    page = context.new_page()

    # Set default timeout
    page.set_default_timeout(10000)  # 10 seconds

    yield page

    context.close()


@pytest.fixture(scope="function")
def authenticated_page(browser, base_url):
    """Create a page with authentication (if needed)."""
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("Playwright not available for authenticated_page fixture")

    context = browser.new_context(
        viewport={"width": 1280, "height": 720},
        ignore_https_errors=True
    )
    page = context.new_page()
    page.set_default_timeout(10000)

    yield page

    context.close()


@pytest.fixture
def clear_storage(page):
    """Clear localStorage before test."""
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("Playwright not available")

    def _clear():
        page.evaluate("() => localStorage.clear()")
    return _clear


@pytest.fixture
def mock_api_responses(page):
    """Set up mock API responses for testing."""
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("Playwright not available")

    def _mock(endpoint: str, response: dict, status: int = 200):
        page.route(
            f"**/api/{endpoint}",
            lambda route: route.fulfill(
                status=status,
                content_type="application/json",
                body=str(response)
            )
        )
    return _mock


@pytest.fixture
def wait_for_alpine(page):
    """Wait for Alpine.js to initialize."""
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("Playwright not available")

    def _wait():
        page.wait_for_function(
            "window.Alpine && Alpine.store('appState')",
            timeout=10000
        )
    return _wait


@pytest.fixture
def wait_for_utilities(page):
    """Wait for all frontend utilities to initialize."""
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("Playwright not available")

    def _wait():
        page.wait_for_function(
            """
            window.Alpine &&
            Alpine.store('appState') &&
            window.eventBus &&
            window.storage &&
            window.api &&
            window.errorHandler
            """,
            timeout=10000
        )
    return _wait
