# UI Test Suite - Quick Start Guide

## Running the Tests

### Run All UI Tests
```bash
pytest tests/ui/ -v
```

### Run Specific Test Suite
```bash
# Accessibility tests only
pytest tests/ui/test_components_a11y.py -v

# Workflow navigation tests
pytest tests/ui/test_workflow_navigation.py -v

# State management tests
pytest tests/ui/test_state_management.py -v
```

### Run Specific Test Class
```bash
pytest tests/ui/test_components_a11y.py::TestARIALabels -v
```

### Run Single Test
```bash
pytest tests/ui/test_components_a11y.py::TestARIALabels::test_all_buttons_have_labels -v
```

## Test Organization

```
tests/ui/
├── __init__.py
├── test_components_a11y.py      # WCAG 2.1 AA compliance tests (23 tests)
├── test_workflow_navigation.py   # User workflow and navigation tests (20 tests)
└── test_state_management.py      # Alpine.js state management tests (22 tests)
```

## Test Categories

### 1. Accessibility Tests (WCAG 2.1 AA)

**ARIA Labels & Semantic HTML:**
- `test_all_buttons_have_labels` - Verifies buttons have accessible labels
- `test_all_inputs_have_labels` - Verifies form inputs have labels
- `test_navigation_landmarks` - Checks for proper landmark regions
- `test_modal_accessibility` - Validates modal ARIA attributes
- `test_icon_buttons_have_sr_text` - Ensures icon buttons have screen reader text

**Keyboard Navigation:**
- `test_no_keyboard_traps` - Ensures no keyboard focus traps
- `test_skip_to_content_link` - Checks for skip navigation (optional)
- `test_focus_visible_styles` - Validates focus styles in CSS
- `test_form_submission_keyboard_accessible` - Verifies keyboard form submission

**Color Contrast:**
- `test_text_contrast_ratios` - Checks text contrast ratios
- `test_no_color_only_indicators` - Ensures status not conveyed by color alone

**Screen Reader:**
- `test_images_have_alt_text` - Validates image alt attributes
- `test_svg_icons_accessible` - Checks SVG accessibility
- `test_heading_hierarchy` - Validates heading structure
- `test_form_error_messages_accessible` - Ensures errors are announced
- `test_sr_only_class_properly_hidden` - Validates screen reader only styles

**Dynamic Content:**
- `test_loading_states_announced` - Checks loading state announcements
- `test_progress_bars_accessible` - Validates progress indicators
- `test_modal_focus_management` - Checks modal focus handling

**Responsive:**
- `test_viewport_meta_tag` - Validates viewport configuration
- `test_touch_target_sizes` - Checks touch target sizing

### 2. Workflow Navigation Tests

**Navigation Flows:**
- Homepage to Create workflow
- Homepage to Builder workflow
- All navigation links functionality
- Breadcrumb navigation

**Form Workflows:**
- Document parsing submission
- Video generation workflow
- Multilingual generation workflow

**Progress Tracking:**
- Progress page functionality
- Task status checking

**Error Recovery:**
- Invalid input handling
- Missing field validation
- Invalid data recovery

**Multi-Step Workflows:**
- Scene builder workflow
- Multilingual scene builder

**API Discovery:**
- Scene types discovery
- Voice discovery
- Language discovery
- Language-specific voices

### 3. State Management Tests

**Alpine.js Initialization:**
- Scene builder state setup
- x-cloak content flash prevention
- Multilingual state initialization

**Form State:**
- Video metadata binding
- Scene array management
- Dynamic form rendering

**Reactivity:**
- Multilingual toggle
- Scene count updates
- Button state management

**Progress & Error State:**
- Loading modal state
- Progress tracking structure
- Error handling
- Error modal state

**Data Transformation:**
- Scene data transformation
- Multilingual payload construction

**Component Interaction:**
- Modal state coordination
- Form validation state

**Performance:**
- Debounced input handling
- Lazy loading patterns

**Persistence:**
- Template saving state

## Dependencies

```bash
pip install pytest pytest-asyncio fastapi beautifulsoup4
```

## Configuration

Tests use `pytest.ini` configuration in project root:
```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
```

## Fixtures

**client** - FastAPI TestClient for API endpoint testing
```python
@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c
```

**html_parser** - BeautifulSoup4 HTML parser
```python
@pytest.fixture
def html_parser():
    def parse(response):
        return BeautifulSoup(response.content, 'html.parser')
    return parse
```

## Current Test Results (2025-11-17)

- **Total:** 65 tests
- **Passed:** 58 (89.2%)
- **Failed:** 7 (10.8%)
- **Skipped:** 1 (1.5%)

See `ACCESSIBILITY_TEST_REPORT.md` for detailed results and recommendations.

## Continuous Integration

To integrate into CI/CD:

```yaml
# .github/workflows/accessibility-tests.yml
name: Accessibility Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.12'
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
      - name: Run UI accessibility tests
        run: pytest tests/ui/ -v
```

## Reporting

Generate HTML report:
```bash
pytest tests/ui/ --html=report.html --self-contained-html
```

Generate coverage report:
```bash
pytest tests/ui/ --cov=app --cov-report=html
```

## Troubleshooting

### Tests fail with "No module named 'app'"
Solution: Ensure parent directory is in path (tests handle this automatically)

### Tests fail to start FastAPI app
Solution: Verify `app/main.py` exists and FastAPI is installed

### BeautifulSoup warnings
Solution: Install `lxml` parser: `pip install lxml`

## Adding New Tests

### Accessibility Test Template
```python
def test_new_accessibility_feature(self, client, html_parser):
    """Test description (WCAG X.X.X)"""
    response = client.get('/page')
    soup = html_parser(response)

    # Your test logic
    element = soup.find(...)
    assert condition, "Failure message"
```

### Workflow Test Template
```python
def test_new_workflow(self, client):
    """Test description"""
    # Step 1
    response = client.get('/start')
    assert response.status_code == 200

    # Step 2
    response = client.post('/api/endpoint', json={...})
    assert response.status_code == 200

    # Verify outcome
    data = response.json()
    assert 'expected_field' in data
```

## Resources

- **WCAG 2.1 Guidelines:** https://www.w3.org/WAI/WCAG21/quickref/
- **ARIA Practices:** https://www.w3.org/WAI/ARIA/apg/
- **Alpine.js Docs:** https://alpinejs.dev/
- **FastAPI Testing:** https://fastapi.tiangolo.com/tutorial/testing/
