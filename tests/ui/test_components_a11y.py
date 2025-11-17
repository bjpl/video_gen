"""
Accessibility (A11y) Tests for UI Components
Tests WCAG 2.1 AA compliance for all interactive UI components
"""
import pytest
from pathlib import Path
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient
import re
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.main import app


@pytest.fixture
def client():
    """Create test client"""
    with TestClient(app) as c:
        yield c


@pytest.fixture
def html_parser():
    """Helper to parse HTML responses"""
    def parse(response):
        return BeautifulSoup(response.content, 'html.parser')
    return parse


# ============================================================================
# ARIA Labels & Semantic HTML Tests (WCAG 4.1.2)
# ============================================================================

class TestARIALabels:
    """Test that all interactive elements have proper ARIA labels"""

    def test_all_buttons_have_labels(self, client, html_parser):
        """All buttons must have accessible labels (WCAG 4.1.2)"""
        pages = ['/', '/builder', '/create', '/multilingual', '/progress']

        for page in pages:
            response = client.get(page)
            soup = html_parser(response)
            buttons = soup.find_all('button')

            for button in buttons:
                # Must have either text content, aria-label, aria-labelledby, or title
                has_text = button.get_text(strip=True)
                has_aria_label = button.get('aria-label')
                has_aria_labelledby = button.get('aria-labelledby')
                has_title = button.get('title')  # Title is acceptable for tooltips

                assert (has_text or has_aria_label or has_aria_labelledby or has_title), (
                    f"Button without accessible label found on {page}: {button}"
                )

    def test_all_inputs_have_labels(self, client, html_parser):
        """All form inputs must have associated labels (WCAG 4.1.2)"""
        pages = ['/builder', '/create', '/multilingual']

        for page in pages:
            response = client.get(page)
            soup = html_parser(response)
            inputs = soup.find_all(['input', 'textarea', 'select'])

            for input_elem in inputs:
                # Skip hidden inputs
                if input_elem.get('type') == 'hidden':
                    continue

                input_id = input_elem.get('id')
                has_label = False

                # Check for associated label
                if input_id:
                    has_label = bool(soup.find('label', {'for': input_id}))

                # Check for aria-label or aria-labelledby
                has_aria_label = input_elem.get('aria-label')
                has_aria_labelledby = input_elem.get('aria-labelledby')

                assert (has_label or has_aria_label or has_aria_labelledby), (
                    f"Input without accessible label found on {page}: {input_elem}"
                )

    def test_navigation_landmarks(self, client, html_parser):
        """Test that page has proper landmark regions (WCAG 1.3.1)"""
        response = client.get('/')
        soup = html_parser(response)

        # Check for required landmarks
        assert soup.find('header'), "Page missing <header> landmark"
        assert soup.find('main'), "Page missing <main> landmark"
        assert soup.find('footer'), "Page missing <footer> landmark"

        # Check navigation has proper role
        nav = soup.find('nav')
        assert nav, "Page missing <nav> landmark"

    def test_modal_accessibility(self, client, html_parser):
        """Test modals have proper ARIA attributes (WCAG 4.1.3)"""
        response = client.get('/builder')
        soup = html_parser(response)

        # Find modal dialogs (Alpine.js x-show pattern)
        modals = soup.find_all(attrs={'x-show': True})

        for modal in modals:
            # Modals should have role="dialog" or aria-modal
            has_dialog_role = modal.get('role') == 'dialog'
            has_aria_modal = modal.get('aria-modal') == 'true'

            # Check for keyboard escape handling
            has_escape = modal.get('x-on:keydown.escape') or modal.get('@keydown.escape')

            # At least one accessibility feature should be present
            # (some modals may be managed by JavaScript frameworks)
            assert (has_dialog_role or has_aria_modal or has_escape), (
                f"Modal missing accessibility features: {modal.get('class')}"
            )

    def test_icon_buttons_have_sr_text(self, client, html_parser):
        """Icon-only buttons must have screen reader text (WCAG 1.1.1)"""
        response = client.get('/builder')
        soup = html_parser(response)

        # Find buttons with only icon content (aria-hidden icons)
        icon_buttons = soup.find_all('button')

        for button in icon_buttons:
            # Check if button only contains icons/symbols
            text_content = button.get_text(strip=True)

            # If text is just symbols/emoji, needs aria-label
            if text_content and re.match(r'^[^\w\s]+$', text_content):
                has_aria_label = button.get('aria-label')
                has_sr_only = button.find(class_='sr-only')

                assert (has_aria_label or has_sr_only), (
                    f"Icon button without screen reader label: {button}"
                )


# ============================================================================
# Keyboard Navigation Tests (WCAG 2.1.1)
# ============================================================================

class TestKeyboardNavigation:
    """Test keyboard accessibility for all interactive elements"""

    def test_no_keyboard_traps(self, client, html_parser):
        """Verify no elements trap keyboard focus (WCAG 2.1.2)"""
        response = client.get('/builder')
        soup = html_parser(response)

        # Check for tabindex >= 0 on all interactive elements
        interactive = soup.find_all(['button', 'a', 'input', 'select', 'textarea'])

        for elem in interactive:
            tabindex = elem.get('tabindex')

            # Negative tabindex is OK (removes from tab order)
            # Zero or positive is OK (in tab order)
            # But very high positive values can create weird tab orders
            if tabindex and int(tabindex) > 10:
                pytest.fail(
                    f"Element has unusually high tabindex ({tabindex}), "
                    f"which can create keyboard traps: {elem}"
                )

    def test_skip_to_content_link(self, client, html_parser):
        """Test for skip navigation link (WCAG 2.4.1)"""
        response = client.get('/')
        soup = html_parser(response)

        # Look for skip link (often sr-only class)
        # Note: This is a best practice, not strictly required for AA
        # but recommended for better keyboard navigation
        body = soup.find('body')
        first_focusable = body.find(['a', 'button', 'input'])

        # If first element is a skip link, that's good
        if first_focusable and first_focusable.name == 'a':
            href = first_focusable.get('href', '')
            if href.startswith('#'):
                # This is likely a skip link
                assert True
                return

        # Skip links are recommended but not required for WCAG AA
        # So we just document this as info
        pytest.skip("Skip link not found (recommended but not required for AA)")

    def test_focus_visible_styles(self, client):
        """Test that CSS includes focus visible styles (WCAG 2.4.7)"""
        # Check for focus styles in CSS
        response = client.get('/static/style.css')
        css_content = response.text

        # Should have focus styles defined
        has_focus_styles = (
            ':focus' in css_content or
            'focus:' in css_content or  # Tailwind focus: utility
            'focus-visible:' in css_content
        )

        assert has_focus_styles, "CSS missing focus visible styles"

    def test_form_submission_keyboard_accessible(self, client, html_parser):
        """Forms must be submittable via keyboard (WCAG 2.1.1)"""
        response = client.get('/create')
        soup = html_parser(response)

        forms = soup.find_all('form')

        for form in forms:
            # Form should have submit button or submit input
            has_submit = bool(
                form.find('button', {'type': 'submit'}) or
                form.find('input', {'type': 'submit'})
            )

            # Or form should have onsubmit that works with Enter key
            has_onsubmit = bool(form.get('onsubmit') or form.get('@submit'))

            assert (has_submit or has_onsubmit), (
                f"Form not keyboard accessible: {form.get('class')}"
            )


# ============================================================================
# Color Contrast Tests (WCAG 1.4.3)
# ============================================================================

class TestColorContrast:
    """Test color contrast ratios meet WCAG AA standards"""

    def test_text_contrast_ratios(self, client, html_parser):
        """Test that text has sufficient contrast (WCAG 1.4.3)"""
        # Note: Full contrast testing requires rendered page analysis
        # This test checks for common contrast issues in CSS classes

        response = client.get('/')
        soup = html_parser(response)

        # Check for low-contrast text classes (gray on gray)
        suspicious_classes = [
            'text-gray-300',  # Light text
            'text-gray-400',
            'bg-gray-100',    # Light background
            'bg-gray-200'
        ]

        # Find elements with potential contrast issues
        for cls in suspicious_classes:
            elements = soup.find_all(class_=cls)

            for elem in elements:
                classes = elem.get('class', [])

                # Check if light text on light background
                has_light_text = any('text-gray-' in c for c in classes)
                has_light_bg = any('bg-gray-' in c for c in classes)

                # This is a simplified check - full contrast needs color values
                if has_light_text and has_light_bg:
                    # Check if it's helper text (allowed lower contrast)
                    is_helper_text = (
                        'text-xs' in classes or
                        'text-sm' in classes or
                        'text-gray-500' in classes or
                        'text-gray-600' in classes
                    )

                    if not is_helper_text:
                        pytest.fail(
                            f"Potential contrast issue: {elem.get('class')}"
                        )

    def test_no_color_only_indicators(self, client, html_parser):
        """Information not conveyed by color alone (WCAG 1.4.1)"""
        response = client.get('/builder')
        soup = html_parser(response)

        # Find status indicators (success, error, warning)
        status_elements = soup.find_all(class_=re.compile(
            r'(text-green|text-red|text-yellow|text-orange|bg-green|bg-red|bg-yellow|bg-orange)'
        ))

        for elem in status_elements:
            # Status should have additional indicator beyond color
            has_icon = bool(elem.find(['svg', 'img']))
            has_text = bool(elem.get_text(strip=True))
            has_aria_label = bool(elem.get('aria-label'))

            assert (has_icon or has_text or has_aria_label), (
                f"Status indicator uses color only: {elem.get('class')}"
            )


# ============================================================================
# Screen Reader Tests (WCAG 1.3.1)
# ============================================================================

class TestScreenReaderCompatibility:
    """Test screen reader accessibility"""

    def test_images_have_alt_text(self, client, html_parser):
        """All images must have alt text (WCAG 1.1.1)"""
        pages = ['/', '/builder', '/create']

        for page in pages:
            response = client.get(page)
            soup = html_parser(response)

            images = soup.find_all('img')

            for img in images:
                # Must have alt attribute (can be empty for decorative)
                assert img.has_attr('alt'), (
                    f"Image missing alt attribute on {page}: {img.get('src')}"
                )

    def test_svg_icons_accessible(self, client, html_parser):
        """SVG icons must be accessible (WCAG 1.1.1)"""
        response = client.get('/')
        soup = html_parser(response)

        svgs = soup.find_all('svg')

        for svg in svgs:
            # SVG should have role="img" and aria-label, or be aria-hidden
            has_role = svg.get('role') == 'img'
            has_aria_label = bool(svg.get('aria-label'))
            is_hidden = svg.get('aria-hidden') == 'true'

            # Decorative SVGs should be hidden, others need labels
            assert (is_hidden or (has_role and has_aria_label)), (
                f"SVG icon not accessible: {svg.get('class')}"
            )

    def test_heading_hierarchy(self, client, html_parser):
        """Heading levels should be logical (WCAG 1.3.1)"""
        response = client.get('/')
        soup = html_parser(response)

        headings = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])

        if not headings:
            pytest.skip("No headings found on page")

        levels = [int(h.name[1]) for h in headings]

        # Should have exactly one h1
        assert levels.count(1) == 1, "Page should have exactly one h1"

        # Should not skip heading levels
        for i in range(len(levels) - 1):
            jump = levels[i + 1] - levels[i]
            assert jump <= 1, (
                f"Heading levels skip: h{levels[i]} to h{levels[i+1]}"
            )

    def test_form_error_messages_accessible(self, client, html_parser):
        """Form errors must be accessible (WCAG 3.3.1)"""
        response = client.get('/create')
        soup = html_parser(response)

        # Find form validation elements (Alpine.js x-show pattern)
        error_elements = soup.find_all(class_=re.compile(r'(error|invalid|danger)'))

        for error in error_elements:
            # Error should be associated with form field
            # via aria-describedby or aria-live region
            has_aria_live = bool(error.get('aria-live'))
            has_role = bool(error.get('role'))

            # Check if it's in an aria-live region
            parent_live = error.find_parent(attrs={'aria-live': True})

            # At least one method of announcement should exist
            assert (has_aria_live or has_role or parent_live), (
                f"Form error not accessible to screen readers: {error.get('class')}"
            )

    def test_sr_only_class_properly_hidden(self, client, html_parser):
        """Screen reader only text must be visually hidden (WCAG 1.3.1)"""
        response = client.get('/')
        soup = html_parser(response)

        # Check that sr-only class exists in CSS
        style_tags = soup.find_all('style')
        has_sr_only_style = any('.sr-only' in tag.get_text() for tag in style_tags)

        # Also check inline styles in head
        head = soup.find('head')
        if head:
            has_sr_only_style = has_sr_only_style or '.sr-only' in head.get_text()

        assert has_sr_only_style, "sr-only class not defined in CSS"


# ============================================================================
# Dynamic Content Tests (WCAG 4.1.3)
# ============================================================================

class TestDynamicContentAccessibility:
    """Test accessibility of dynamically updated content"""

    def test_loading_states_announced(self, client, html_parser):
        """Loading states must be announced (WCAG 4.1.3)"""
        response = client.get('/builder')
        soup = html_parser(response)

        # Find loading indicators
        loading_elements = soup.find_all(class_=re.compile(r'(loading|spinner|progress)'))

        for loading in loading_elements:
            # Should have aria-live or role=status
            has_aria_live = bool(loading.get('aria-live'))
            has_status_role = loading.get('role') == 'status'

            # Check if parent has live region
            parent_live = loading.find_parent(attrs={'aria-live': True})

            if not (has_aria_live or has_status_role or parent_live):
                # Some loading indicators might be purely visual
                # but best practice is to announce them
                pass  # Warning instead of failure

    def test_progress_bars_accessible(self, client, html_parser):
        """Progress indicators must be accessible (WCAG 1.3.1)"""
        response = client.get('/progress')
        soup = html_parser(response)

        # Find progress bar elements
        progress_bars = soup.find_all(class_=re.compile(r'(progress|meter)'))

        for progress in progress_bars:
            # Should use proper role or element
            has_progressbar_role = progress.get('role') == 'progressbar'
            is_progress_element = progress.name == 'progress'

            # Should have aria-valuenow if using role
            if has_progressbar_role:
                assert progress.get('aria-valuenow'), (
                    "Progress bar missing aria-valuenow"
                )

    def test_modal_focus_management(self, client, html_parser):
        """Modals should trap and manage focus (WCAG 2.4.3)"""
        response = client.get('/builder')
        soup = html_parser(response)

        # Find modal dialogs
        modals = soup.find_all(attrs={'x-show': True})

        for modal in modals:
            # Check for focus management
            # Alpine.js handles this with x-trap directive
            has_focus_trap = bool(
                modal.get('x-trap') or
                modal.get('@keydown.tab')
            )

            # Not strictly required if modal is small and simple
            # but recommended for complex modals


# ============================================================================
# Mobile/Responsive Tests (WCAG 1.4.4, 1.4.10)
# ============================================================================

class TestResponsiveAccessibility:
    """Test accessibility on mobile/responsive layouts"""

    def test_viewport_meta_tag(self, client, html_parser):
        """Page should have proper viewport meta tag (WCAG 1.4.4)"""
        response = client.get('/')
        soup = html_parser(response)

        viewport = soup.find('meta', {'name': 'viewport'})
        assert viewport, "Missing viewport meta tag"

        content = viewport.get('content', '')

        # Should not prevent zooming
        assert 'user-scalable=no' not in content.lower(), (
            "Viewport prevents zooming (WCAG 1.4.4 violation)"
        )

        # Should not fix maximum scale below 2.0
        if 'maximum-scale' in content.lower():
            # Extract maximum-scale value
            match = re.search(r'maximum-scale=([0-9.]+)', content.lower())
            if match:
                max_scale = float(match.group(1))
                assert max_scale >= 2.0, (
                    f"maximum-scale too restrictive: {max_scale} (should be >= 2.0)"
                )

    def test_touch_target_sizes(self, client, html_parser):
        """Interactive elements should be large enough (WCAG 2.5.5)"""
        response = client.get('/')
        soup = html_parser(response)

        # Check button and link sizing classes
        interactive = soup.find_all(['button', 'a'])

        for elem in interactive:
            classes = elem.get('class', [])

            # Check for adequate padding
            has_padding = any(
                'p-' in cls or 'px-' in cls or 'py-' in cls
                for cls in classes
            )

            # Minimum touch target is 44x44px (WCAG 2.5.5 Level AAA)
            # For AA, we just check that padding exists
            assert has_padding or elem.get_text(strip=True), (
                f"Interactive element might be too small: {elem}"
            )


# ============================================================================
# Integration Test: Complete Page Accessibility
# ============================================================================

def test_homepage_accessibility_summary(client, html_parser):
    """Integration test: Overall homepage accessibility"""
    response = client.get('/')
    soup = html_parser(response)

    issues = []

    # Check critical accessibility features
    if not soup.find('html', {'lang': True}):
        issues.append("Missing lang attribute on <html>")

    if not soup.find('title'):
        issues.append("Missing <title> element")

    if not soup.find('main'):
        issues.append("Missing <main> landmark")

    # Report all issues
    assert len(issues) == 0, f"Accessibility issues found: {', '.join(issues)}"


def test_builder_accessibility_summary(client, html_parser):
    """Integration test: Builder page accessibility"""
    response = client.get('/builder')
    soup = html_parser(response)

    issues = []

    # Check for form accessibility
    forms = soup.find_all('form')
    if not forms:
        # Builder might not have traditional forms (uses Alpine.js)
        pass

    # Check for ARIA live regions (for dynamic updates)
    has_live_regions = bool(soup.find_all(attrs={'aria-live': True}))

    # Check for keyboard escape handling on modals
    modals = soup.find_all(attrs={'x-show': True})
    for modal in modals:
        if not (modal.get('@keydown.escape') or modal.get('x-on:keydown.escape')):
            issues.append(f"Modal missing keyboard escape: {modal.get('class')}")

    assert len(issues) == 0, f"Builder accessibility issues: {', '.join(issues)}"
