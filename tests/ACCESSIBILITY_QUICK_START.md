# Accessibility Testing - Quick Start Guide
**Video Gen Project | WCAG AA Compliance Testing**

---

## 🚀 Quick Run Commands

### Run All Accessibility Tests (No Selenium)
```bash
pytest -m "accessibility and not selenium" -v
```

### Run ARIA Label Tests
```bash
pytest tests/test_accessibility_aria.py -v
```

### Run Color Contrast Tests
```bash
pytest tests/test_accessibility_contrast.py -v
```

### Run With Selenium (After Installation)
```bash
# Install dependencies first
pip install selenium axe-selenium-python

# Run all accessibility tests
pytest -m accessibility -v
```

---

## 📋 Test Status

### ✅ Working Tests (No Dependencies)
- **test_accessibility_aria.py**: 7 tests PASSING
  - Homepage title ✅
  - Main landmark ✅
  - Form labels ✅
  - Button names ✅
  - Image alt text ✅
  - Navigation landmark ✅
  - Heading hierarchy ✅

### ⏭️ Ready Tests (Requires Selenium)
- **test_accessibility_aria.py**: 4 tests (Selenium)
  - Focus indicators
  - ARIA live regions
  - axe-core ARIA audit

- **test_accessibility_contrast.py**: 5 tests (Selenium)
  - Button state contrast
  - Focus indicator contrast
  - axe-core contrast audit
  - WCAG AA compliance

---

## 🔧 Setup Instructions

### 1. Basic Setup (Already Done)
```bash
# Accessibility markers registered in pytest.ini ✅
# Test files created ✅
# Ready to run basic tests ✅
```

### 2. Selenium Setup (For Advanced Tests)
```bash
# Install Selenium WebDriver
pip install selenium

# Install axe-core integration
pip install axe-selenium-python

# Install ChromeDriver (Ubuntu/Debian)
sudo apt-get install chromium-chromedriver

# Or download from: https://chromedriver.chromium.org/
```

### 3. Manual Testing Tools (Optional)
```bash
# NVDA Screen Reader (Windows)
# Download: https://www.nvaccess.org/download/

# Colour Contrast Analyser
# Download: https://www.tpgi.com/color-contrast-checker/

# Chrome DevTools (Built-in)
# Open: F12 → Accessibility Panel
```

---

## 📊 Current Test Results

```
========================= 7 passed, 4 skipped =========================

PASSED (Basic Tests):
✅ Homepage has descriptive title
✅ Page has main landmark
✅ Form inputs are properly labeled
✅ Buttons have accessible names
✅ Images have alt text
✅ Navigation has landmark
✅ Heading hierarchy is logical

SKIPPED (Selenium Tests):
⏭️ Focus indicators visible (needs Selenium)
⏭️ ARIA live regions present (needs Selenium)
⏭️ axe-core ARIA violations (needs axe-selenium-python)
⏭️ axe-core contrast violations (needs axe-selenium-python)
```

---

## 📖 Documentation Files

### Test Plan & Strategy
- **TEST_PLAN_P0_P1.md** - Comprehensive P0/P1 testing strategy
- **P0_TESTING_RESULTS.md** - Session summary and results

### Test Suites
- **test_accessibility_aria.py** - ARIA label compliance tests
- **test_accessibility_contrast.py** - WCAG AA color contrast tests

### Manual Testing
- **SCREEN_READER_TEST_SCENARIOS.md** - 10 screen reader scenarios
  - NVDA, JAWS, VoiceOver instructions
  - Step-by-step testing procedures
  - Expected announcements
  - Keyboard shortcuts

---

## 🎯 Next Steps

### Week 1 - P0 Testing (Current)
1. ✅ Create test infrastructure
2. ⏭️ Install Selenium dependencies
3. ⏭️ Run Selenium-based tests
4. ⏭️ Perform manual screen reader testing
5. ⏭️ Document accessibility issues found

### Week 2 - P1 Testing
1. Performance testing
2. Cross-browser testing
3. Security testing
4. CI/CD integration

---

## 🐛 Known Issues

### Critical (P0) - RESOLVED ✅
- **Translation Stage Import**: Fixed by making googletrans optional
- **Test Collection**: Now working (874 tests)

### To Investigate (Week 1)
- ARIA labels for video player controls
- Color contrast ratios (automated check pending)
- Focus indicators visibility
- ARIA live regions for status updates

---

## 💡 Tips

### Running Specific Test Classes
```bash
# Run only ARIA basic tests
pytest tests/test_accessibility_aria.py::TestARIALabelsBasic -v

# Run only Selenium tests
pytest tests/test_accessibility_aria.py::TestARIALabelsSelenium -v

# Run only axe-core tests
pytest tests/test_accessibility_aria.py::TestARIAAxeCore -v
```

### Debugging Failed Tests
```bash
# Show full output
pytest tests/test_accessibility_aria.py -v -s

# Stop on first failure
pytest tests/test_accessibility_aria.py -x

# Show local variables on failure
pytest tests/test_accessibility_aria.py -l
```

### Generating Reports
```bash
# HTML report
pytest -m accessibility --html=report.html

# Coverage report
pytest -m accessibility --cov=app --cov-report=html

# JUnit XML (for CI/CD)
pytest -m accessibility --junit-xml=accessibility-results.xml
```

---

## 📞 Support

### Documentation
- WCAG 2.1 AA: https://www.w3.org/WAI/WCAG21/quickref/?levels=a,aa
- ARIA Practices: https://www.w3.org/WAI/ARIA/apg/
- WebAIM Resources: https://webaim.org/articles/

### Testing Tools
- axe DevTools: https://www.deque.com/axe/devtools/
- WAVE Browser Extension: https://wave.webaim.org/extension/
- Lighthouse (Chrome): Built into DevTools

---

*Quick Start Version: 1.0*
*Last Updated: 2025-11-17*
*Maintained by: Tester Agent (Hive Mind)*
