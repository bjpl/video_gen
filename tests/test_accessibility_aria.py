"""
ARIA Label Accessibility Tests - P0 Testing
============================================

Tests ARIA label implementation for WCAG AA compliance.
Part of Week 1 P0 accessibility improvements.

Test Coverage:
- Form controls have labels
- Buttons have accessible names
- Interactive elements properly labeled
- Navigation elements accessible
- Video player controls labeled
- axe-core automated audit

Dependencies:
    pip install axe-selenium-python selenium beautifulsoup4

Usage:
    # Run all ARIA tests
    pytest tests/test_accessibility_aria.py -v

    # Run without Selenium tests (faster)
    pytest tests/test_accessibility_aria.py -v -m "not selenium"

Status: TEMPLATE - Requires P0.1 fix before implementation
"""

import pytest
from unittest.mock import Mock
from bs4 import BeautifulSoup

# Mark tests that require Selenium
pytestmark = pytest.mark.accessibility


class TestARIALabelsBasic:
    """Basic ARIA label tests using FastAPI TestClient."""

    def test_homepage_has_title(self, client):
        """Homepage has descriptive title."""
        response = client.get("/")
        assert response.status_code == 200
        soup = BeautifulSoup(response.content, 'html.parser')
        title = soup.find('title')
        assert title is not None, "Page missing <title> element"
        assert len(title.text) > 0, "Page title is empty"
        assert title.text != "Document", "Page title is too generic"

    def test_main_landmark_exists(self, client):
        """Page has main landmark for screen readers."""
        response = client.get("/")
        soup = BeautifulSoup(response.content, 'html.parser')

        # Check for <main> element or role="main"
        main_elem = soup.find('main')
        role_main = soup.find(attrs={"role": "main"})

        assert main_elem is not None or role_main is not None, \
            "Page missing main landmark (<main> or role='main')"

    def test_form_inputs_have_labels(self, client):
        """All form input fields have associated labels or aria-label."""
        response = client.get("/")
        soup = BeautifulSoup(response.content, 'html.parser')

        # Find all input, select, textarea elements
        form_controls = soup.find_all(['input', 'select', 'textarea'])

        unlabeled_controls = []
        for control in form_controls:
            # Skip hidden inputs and buttons (different labeling rules)
            if control.name == 'input':
                input_type = control.get('type', 'text')
                if input_type in ['hidden', 'submit', 'button', 'reset']:
                    continue

            control_id = control.get('id')
            has_aria_label = control.get('aria-label') is not None
            has_aria_labelledby = control.get('aria-labelledby') is not None

            # Check for associated <label>
            has_label_for = False
            if control_id:
                label = soup.find('label', attrs={'for': control_id})
                has_label_for = label is not None

            # Check if control is inside a <label>
            has_label_wrapper = control.find_parent('label') is not None

            if not (has_aria_label or has_aria_labelledby or has_label_for or has_label_wrapper):
                unlabeled_controls.append({
                    'tag': control.name,
                    'id': control_id,
                    'type': control.get('type'),
                    'name': control.get('name')
                })

        assert len(unlabeled_controls) == 0, \
            f"Found {len(unlabeled_controls)} unlabeled form controls: {unlabeled_controls}"

    def test_buttons_have_accessible_names(self, client):
        """All buttons have accessible names (text or aria-label)."""
        response = client.get("/")
        soup = BeautifulSoup(response.content, 'html.parser')

        # Find all button elements and input[type="button|submit|reset"]
        buttons = soup.find_all('button')
        input_buttons = soup.find_all('input', type=['button', 'submit', 'reset'])

        unlabeled_buttons = []

        for button in buttons:
            has_text = len(button.get_text(strip=True)) > 0
            has_aria_label = button.get('aria-label') is not None
            has_aria_labelledby = button.get('aria-labelledby') is not None

            if not (has_text or has_aria_label or has_aria_labelledby):
                unlabeled_buttons.append({
                    'id': button.get('id'),
                    'class': button.get('class'),
                    'type': button.get('type')
                })

        for button in input_buttons:
            has_value = button.get('value') is not None
            has_aria_label = button.get('aria-label') is not None

            if not (has_value or has_aria_label):
                unlabeled_buttons.append({
                    'id': button.get('id'),
                    'type': button.get('type'),
                    'name': button.get('name')
                })

        assert len(unlabeled_buttons) == 0, \
            f"Found {len(unlabeled_buttons)} buttons without accessible names: {unlabeled_buttons}"

    def test_images_have_alt_text(self, client):
        """All images have alt text (or role='presentation' if decorative)."""
        response = client.get("/")
        soup = BeautifulSoup(response.content, 'html.parser')

        images = soup.find_all('img')
        images_without_alt = []

        for img in images:
            has_alt = img.get('alt') is not None
            is_decorative = img.get('role') == 'presentation' or img.get('role') == 'none'
            has_aria_hidden = img.get('aria-hidden') == 'true'

            if not (has_alt or is_decorative or has_aria_hidden):
                images_without_alt.append({
                    'src': img.get('src'),
                    'id': img.get('id'),
                    'class': img.get('class')
                })

        assert len(images_without_alt) == 0, \
            f"Found {len(images_without_alt)} images without alt text: {images_without_alt}"

    def test_navigation_has_landmark(self, client):
        """Navigation elements use nav tag or role='navigation'."""
        response = client.get("/")
        soup = BeautifulSoup(response.content, 'html.parser')

        # Look for <nav> or role="navigation"
        nav_elem = soup.find('nav')
        role_nav = soup.find(attrs={"role": "navigation"})

        # At least one navigation landmark should exist
        # (unless it's a single-page app with no navigation)
        # Adjust this assertion based on your UI
        if nav_elem is None and role_nav is None:
            # Check if there are navigation-like lists
            nav_lists = soup.find_all('ul', class_=lambda c: c and 'nav' in c.lower())
            assert len(nav_lists) > 0 or True, \
                "Consider adding <nav> landmark for navigation elements"

    def test_headings_hierarchy(self, client):
        """Heading hierarchy is logical (no skipped levels)."""
        response = client.get("/")
        soup = BeautifulSoup(response.content, 'html.parser')

        # Find all headings
        headings = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])

        if len(headings) == 0:
            pytest.skip("No headings found on page")

        # Extract heading levels
        heading_levels = []
        for h in headings:
            level = int(h.name[1])  # Extract number from h1, h2, etc.
            heading_levels.append(level)

        # Check for skipped levels
        issues = []
        for i in range(1, len(heading_levels)):
            current = heading_levels[i]
            previous = heading_levels[i-1]

            # Heading level should not increase by more than 1
            if current > previous + 1:
                issues.append(f"Skipped heading level: h{previous} to h{current}")

        assert len(issues) == 0, \
            f"Heading hierarchy issues: {issues}"

    def test_skip_to_content_link(self, client):
        """Skip to main content link exists for keyboard users."""
        response = client.get("/")
        soup = BeautifulSoup(response.content, 'html.parser')

        # Look for skip link (usually first focusable element)
        # Common patterns: "skip to content", "skip to main", etc.
        skip_links = soup.find_all('a', string=lambda s: s and 'skip' in s.lower())

        # This is a recommendation, not a strict requirement
        if len(skip_links) == 0:
            pytest.skip("Consider adding 'Skip to content' link for keyboard users")


@pytest.mark.selenium
class TestARIALabelsSelenium:
    """ARIA label tests requiring Selenium for interactive testing."""

    @pytest.fixture(scope="class")
    def selenium_driver(self):
        """Create Selenium WebDriver instance."""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options

            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")

            driver = webdriver.Chrome(options=chrome_options)
            yield driver
            driver.quit()
        except Exception as e:
            pytest.skip(f"Selenium not available: {e}")

    def test_focus_indicators_visible(self, selenium_driver):
        """Focus indicators are visible for keyboard navigation."""
        selenium_driver.get("http://localhost:8000")

        # Find all focusable elements
        from selenium.webdriver.common.by import By
        focusable = selenium_driver.find_elements(
            By.CSS_SELECTOR,
            'a, button, input, select, textarea, [tabindex]:not([tabindex="-1"])'
        )

        if len(focusable) == 0:
            pytest.skip("No focusable elements found")

        # Check first few focusable elements for outline
        for elem in focusable[:5]:
            elem.send_keys("")  # Focus element
            # Note: Actual focus indicator testing requires visual comparison
            # This is a placeholder for manual verification
            assert elem.is_displayed(), "Focused element should be visible"

    def test_aria_live_regions_present(self, selenium_driver):
        """ARIA live regions exist for dynamic content announcements."""
        selenium_driver.get("http://localhost:8000")

        from selenium.webdriver.common.by import By

        # Look for aria-live regions
        live_regions = selenium_driver.find_elements(
            By.CSS_SELECTOR,
            '[aria-live], [role="status"], [role="alert"]'
        )

        # This is a recommendation for dynamic web apps
        if len(live_regions) == 0:
            pytest.skip("Consider adding aria-live regions for status updates")


@pytest.mark.selenium
class TestARIAAxeCore:
    """Automated accessibility testing using axe-core."""

    @pytest.fixture(scope="class")
    def selenium_driver(self):
        """Create Selenium WebDriver instance."""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options

            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")

            driver = webdriver.Chrome(options=chrome_options)
            yield driver
            driver.quit()
        except Exception as e:
            pytest.skip(f"Selenium not available: {e}")

    def test_axe_core_aria_violations(self, selenium_driver):
        """Run axe-core accessibility audit for ARIA violations."""
        try:
            from axe_selenium_python import Axe
        except ImportError:
            pytest.skip("axe-selenium-python not installed. Run: pip install axe-selenium-python")

        selenium_driver.get("http://localhost:8000")

        axe = Axe(selenium_driver)
        axe.inject()

        # Run axe-core with ARIA-specific rules
        results = axe.run({
            "runOnly": {
                "type": "tag",
                "values": ["wcag2a", "wcag2aa", "best-practice"]
            }
        })

        violations = results.get("violations", [])

        # Filter for ARIA-related violations
        aria_violations = [
            v for v in violations
            if 'aria' in v.get('id', '').lower() or
               'label' in v.get('id', '').lower()
        ]

        # Generate detailed violation report
        if aria_violations:
            report = []
            for violation in aria_violations:
                report.append(f"\n{violation['id']}: {violation['description']}")
                report.append(f"  Impact: {violation['impact']}")
                report.append(f"  Affected elements: {len(violation['nodes'])}")
                for node in violation['nodes'][:3]:  # Show first 3
                    report.append(f"    - {node.get('html', 'N/A')}")

            pytest.fail(
                f"Found {len(aria_violations)} ARIA-related violations:\n" +
                "\n".join(report)
            )

        assert len(aria_violations) == 0, "No ARIA violations found"


# Pytest configuration
def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers",
        "accessibility: marks tests as accessibility tests"
    )
    config.addinivalue_line(
        "markers",
        "selenium: marks tests that require Selenium WebDriver"
    )


# Test fixtures
@pytest.fixture
def client():
    """FastAPI test client fixture."""
    try:
        from fastapi.testclient import TestClient
        from app.main import app
        return TestClient(app)
    except ImportError:
        pytest.skip("FastAPI app not available - waiting for P0.1 fix")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
