"""
Pytest configuration for frontend tests.

This module provides fixtures for browser testing.
Supports both Playwright and Selenium, with fallback if neither is available.
"""

import pytest
import os

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
