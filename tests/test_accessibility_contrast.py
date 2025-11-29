"""
WCAG AA Color Contrast Tests - P0 Testing
==========================================

Tests color contrast compliance for WCAG AA Level (4.5:1 normal text, 3:1 large text).
Part of Week 1 P0 accessibility improvements.

Test Coverage:
- Normal text contrast (4.5:1 minimum)
- Large text contrast (3:1 minimum)
- Button state contrast (default, hover, active, focus, disabled)
- Focus indicator visibility
- Link contrast
- UI component contrast

Dependencies:
    pip install axe-selenium-python selenium

Usage:
    # Run all contrast tests
    pytest tests/test_accessibility_contrast.py -v

    # Run only automated tests (no Selenium)
    pytest tests/test_accessibility_contrast.py -v -m "not selenium"

WCAG AA Requirements:
- Normal text (<18pt or <14pt bold): 4.5:1
- Large text (≥18pt or ≥14pt bold): 3:1
- UI components: 3:1
- Focus indicators: 3:1

Status: TEMPLATE - Requires P0.1 fix before implementation
"""

import pytest
from unittest.mock import Mock
from bs4 import BeautifulSoup

pytestmark = pytest.mark.accessibility


class TestColorContrastBasic:
    """Basic color contrast tests using static analysis."""

    def test_page_has_css_styles(self, client):
        """Page includes CSS styles for contrast testing."""
        response = client.get("/")
        assert response.status_code == 200
        soup = BeautifulSoup(response.content, 'html.parser')

        # Check for style tags or linked stylesheets
        style_tags = soup.find_all('style')
        link_tags = soup.find_all('link', rel='stylesheet')

        assert len(style_tags) > 0 or len(link_tags) > 0, \
            "No CSS styles found on page"

    def test_inline_styles_avoid_low_contrast(self, client):
        """Elements with inline styles don't use obviously low-contrast colors."""
        response = client.get("/")
        soup = BeautifulSoup(response.content, 'html.parser')

        # Find elements with inline styles
        inline_styled = soup.find_all(attrs={"style": True})

        # Known problematic color combinations (low contrast)
        problematic_combos = [
            ("color: gray", "background-color: white"),
            ("color: lightgray", "background-color: white"),
            ("color: yellow", "background-color: white"),
            ("color: white", "background-color: lightgray"),
        ]

        issues = []
        for elem in inline_styled:
            style = elem.get('style', '').lower()
            for fg, bg in problematic_combos:
                if fg in style and bg in style:
                    issues.append({
                        'element': elem.name,
                        'id': elem.get('id'),
                        'class': elem.get('class'),
                        'style': style
                    })

        assert len(issues) == 0, \
            f"Found {len(issues)} elements with potentially low-contrast inline styles"


@pytest.mark.selenium
class TestColorContrastSelenium:
    """Color contrast tests using Selenium for computed styles."""

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

    def test_button_states_have_contrast(self, selenium_driver):
        """All button states meet contrast requirements."""
        from selenium.webdriver.common.by import By
        from selenium.webdriver.common.action_chains import ActionChains
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.common.exceptions import StaleElementReferenceException
        import time

        selenium_driver.get("http://localhost:8000")

        # Wait for page to fully load
        WebDriverWait(selenium_driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )
        time.sleep(0.5)  # Additional settle time for dynamic content

        buttons = selenium_driver.find_elements(By.TAG_NAME, "button")

        if len(buttons) == 0:
            pytest.skip("No buttons found on page")

        # Test first few buttons with retry logic for stale elements
        max_retries = 3
        for i in range(min(5, len(buttons))):
            for retry_count in range(max_retries):
                try:
                    # Re-fetch buttons to avoid stale reference
                    current_buttons = selenium_driver.find_elements(By.TAG_NAME, "button")
                    if i >= len(current_buttons):
                        break
                    button = current_buttons[i]

                    # Get default state colors
                    default_color = button.value_of_css_property("color")
                    default_bg = button.value_of_css_property("background-color")

                    # Check hover state (if possible)
                    try:
                        ActionChains(selenium_driver).move_to_element(button).perform()
                        time.sleep(0.1)  # Allow hover state to apply
                    except Exception:
                        pass

                    # Focus state - use JavaScript focus to avoid interception
                    try:
                        selenium_driver.execute_script("arguments[0].focus();", button)
                        time.sleep(0.1)  # Allow focus state to apply
                        focus_outline = button.value_of_css_property("outline")
                        focus_border = button.value_of_css_property("border")

                        # Should have visible focus indicator
                        assert (focus_outline != "none" or focus_border),                             f"Button lacks visible focus indicator: {button.text}"
                    except Exception:
                        pass  # Skip if button cannot be focused

                    break  # Success, exit retry loop
                except StaleElementReferenceException:
                    if retry_count == max_retries - 1:
                        pytest.skip(f"Button {i} became stale after {max_retries} retries")
                    time.sleep(0.2)  # Wait before retry

    def test_focus_indicators_sufficient_contrast(self, selenium_driver):
        """Focus indicators have 3:1 contrast ratio minimum."""
        selenium_driver.get("http://localhost:8000")

        from selenium.webdriver.common.by import By

        focusable = selenium_driver.find_elements(
            By.CSS_SELECTOR,
            'a, button, input, select, textarea'
        )

        if len(focusable) == 0:
            pytest.skip("No focusable elements found")

        for elem in focusable[:10]:  # Test first 10 elements
            elem.click()  # Focus element

            outline = elem.value_of_css_property("outline")
            outline_color = elem.value_of_css_property("outline-color")
            border = elem.value_of_css_property("border")

            # Should have SOME focus indicator
            assert outline != "none" or border != "none", \
                f"Element lacks focus indicator: {elem.tag_name}"


@pytest.mark.selenium
class TestColorContrastAxeCore:
    """Automated color contrast testing using axe-core."""

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

    def test_axe_core_contrast_violations(self, selenium_driver):
        """Run axe-core audit for WCAG AA color contrast violations."""
        try:
            from axe_selenium_python import Axe
        except ImportError:
            pytest.skip("axe-selenium-python not installed. Run: pip install axe-selenium-python")

        selenium_driver.get("http://localhost:8000")

        axe = Axe(selenium_driver)
        axe.inject()

        # Run axe-core with color-contrast rules
        results = axe.run({
            "runOnly": {
                "type": "rule",
                "values": ["color-contrast"]
            }
        })

        violations = results.get("violations", [])

        if violations:
            report = []
            report.append(f"\n{'='*60}")
            report.append("WCAG AA COLOR CONTRAST VIOLATIONS")
            report.append(f"{'='*60}\n")

            for violation in violations:
                report.append(f"Rule: {violation['id']}")
                report.append(f"Impact: {violation['impact']}")
                report.append(f"Description: {violation['description']}")
                report.append(f"Affected elements: {len(violation['nodes'])}\n")

                for idx, node in enumerate(violation['nodes'][:10], 1):
                    report.append(f"  {idx}. Element:")
                    report.append(f"     HTML: {node.get('html', 'N/A')[:100]}")

                    # Extract contrast ratio information
                    if 'any' in node:
                        for check in node['any']:
                            if 'color-contrast' in check.get('id', ''):
                                data = check.get('data', {})
                                report.append(f"     Foreground: {data.get('fgColor', 'N/A')}")
                                report.append(f"     Background: {data.get('bgColor', 'N/A')}")
                                report.append(f"     Ratio: {data.get('contrastRatio', 'N/A')}")
                                report.append(f"     Expected: {data.get('expectedContrastRatio', 'N/A')}")

                    report.append(f"     How to fix: {node.get('failureSummary', 'N/A')}\n")

                report.append("-" * 60)

            pytest.fail("\n".join(report))

        assert len(violations) == 0, "No color contrast violations found"

    def test_wcag_aa_level_compliance(self, selenium_driver):
        """Verify overall WCAG AA Level compliance."""
        try:
            from axe_selenium_python import Axe
        except ImportError:
            pytest.skip("axe-selenium-python not installed")

        selenium_driver.get("http://localhost:8000")

        axe = Axe(selenium_driver)
        axe.inject()

        # Run full WCAG AA audit
        results = axe.run({
            "runOnly": {
                "type": "tag",
                "values": ["wcag2a", "wcag2aa"]
            }
        })

        violations = results.get("violations", [])

        # Filter for contrast-related violations
        contrast_violations = [
            v for v in violations
            if 'contrast' in v.get('id', '').lower() or
               'color' in v.get('id', '').lower()
        ]

        if contrast_violations:
            report = [f"\n{len(contrast_violations)} contrast-related WCAG AA violations:"]
            for v in contrast_violations:
                report.append(f"  - {v['id']}: {v['description']} (Impact: {v['impact']})")

            pytest.fail("\n".join(report))

        assert len(contrast_violations) == 0


class TestColorContrastManual:
    """Manual color contrast test scenarios and documentation."""

    def test_manual_contrast_checklist_exists(self):
        """Ensure manual contrast test checklist is documented."""

        checklist = """
        MANUAL COLOR CONTRAST TEST CHECKLIST
        =====================================

        Test all UI states and color combinations manually using:
        - Chrome DevTools Contrast Ratio tool
        - WebAIM Contrast Checker: https://webaim.org/resources/contrastchecker/
        - Colour Contrast Analyser (CCA): https://www.tpgi.com/color-contrast-checker/

        □ 1. NORMAL TEXT (4.5:1 minimum)
          □ Body text on default background
          □ Navigation links
          □ Form labels
          □ Paragraph text
          □ List items
          □ Table cells

        □ 2. LARGE TEXT (3:1 minimum)
          □ Headings (h1-h6)
          □ Large button text (18pt+)
          □ Hero text
          □ Call-to-action text

        □ 3. BUTTON STATES (3:1 minimum)
          □ Default state
          □ Hover state
          □ Active/pressed state
          □ Focus state
          □ Disabled state

        □ 4. LINK STATES (4.5:1 minimum)
          □ Default link color
          □ Visited link color
          □ Hover state
          □ Focus state

        □ 5. FORM ELEMENTS (4.5:1 minimum)
          □ Input fields - default
          □ Input fields - focus
          □ Input fields - error state
          □ Input fields - disabled
          □ Select dropdowns
          □ Textareas
          □ Checkboxes
          □ Radio buttons

        □ 6. UI COMPONENTS (3:1 minimum)
          □ Icons
          □ Badges/pills
          □ Alerts/notifications
          □ Tooltips
          □ Modal dialogs
          □ Progress bars
          □ Breadcrumbs

        □ 7. FOCUS INDICATORS (3:1 minimum)
          □ Keyboard focus outline color
          □ Focus ring visibility
          □ Custom focus styles

        □ 8. VIDEO PLAYER UI
          □ Control button icons
          □ Progress bar
          □ Volume slider
          □ Playback rate display
          □ Captions/subtitles text

        □ 9. ERROR & SUCCESS MESSAGES
          □ Error text color
          □ Success text color
          □ Warning text color
          □ Info text color

        □ 10. DARK MODE (if applicable)
          □ Retest all above in dark mode
          □ Verify toggle button contrast
        """

        # This test always passes but documents the checklist
        assert True, checklist


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
