# Comprehensive Test Plan - P0 Fixes and P1 Improvements
**Video Gen Project | Week 1-2 Testing Strategy**
*Created: 2025-11-17*
*Tester Agent: Hive Mind Swarm*

---

## Executive Summary

### Critical Findings (PRE-TESTING)

**🚨 BLOCKER ISSUE IDENTIFIED:**
- **File:** `video_gen/stages/translation_stage.py:16`
- **Issue:** Hard import of `googletrans` module which is not in `requirements.txt`
- **Impact:** **ALL 9 test modules fail to collect** (837 tests blocked)
- **Root Cause:** googletrans was removed from requirements (line 49-50) due to dependency conflicts, but code still imports it
- **Priority:** **P0 CRITICAL** - Must be fixed before any testing can proceed

**Affected Test Files:**
1. `scripts/test_restored_prompts.py`
2. `test_api_example.py`
3. `tests/test_api_validation.py`
4. `tests/test_end_to_end.py`
5. `tests/test_final_integration.py`
6. `tests/test_integration.py`
7. `tests/test_integration_comprehensive.py`
8. `tests/test_pipeline.py`
9. `tests/test_stages_coverage.py`

**Recommended Fix:**
```python
# translation_stage.py line 16
# BEFORE (broken):
from googletrans import Translator

# AFTER (safe):
try:
    from googletrans import Translator
    GOOGLE_TRANSLATE_AVAILABLE = True
except ImportError:
    GOOGLE_TRANSLATE_AVAILABLE = False
    Translator = None  # type: ignore
```

---

## Test Environment Status

### Current State
- **Total Tests Collected:** 750 tests (when working)
- **Collection Errors:** 9 modules (all tests blocked)
- **Test Coverage (Last Known):** 79% (475 passing tests)
- **Pytest Version:** 8.4.2
- **Python Version:** 3.12.3

### Test Infrastructure
- ✅ pytest.ini configured with markers (slow, unit, integration, api, server)
- ✅ Coverage configuration in place
- ✅ Asyncio mode: strict
- ✅ Test timeout: 10 seconds default
- ⚠️ Missing conftest.py (common fixtures may be missing)
- ❌ Test collection blocked by import error

---

## P0 Testing Tasks (Week 1)

### P0.1: Fix Translation Stage Import (BLOCKER)
**Priority:** CRITICAL
**Estimated Time:** 30 minutes
**Status:** Not Started

**Test Strategy:**
1. Verify fix allows test collection to succeed
2. Test Translation Stage with Claude API only (primary path)
3. Test graceful degradation when googletrans unavailable
4. Verify all 9 previously failing modules collect successfully

**Test Cases:**
- [ ] Test collection succeeds for all modules
- [ ] Translation Stage initializes without googletrans installed
- [ ] Claude API translation works (with valid API key)
- [ ] Appropriate warning logged when Google Translate unavailable
- [ ] Fallback behavior documented

**Success Criteria:**
- All 750+ tests can be collected without errors
- Translation Stage functional with Claude API only
- No runtime errors when googletrans not installed

---

### P0.2: ARIA Label Implementation Testing
**Priority:** HIGH
**Estimated Time:** 2 hours
**Status:** Blocked (waiting for P0.1 fix)

**Scope:**
- Web UI accessibility labels
- Form controls and interactive elements
- Navigation components
- Video player controls

**Test Strategy:**
1. **Automated Testing (axe-core):**
   - Install axe-core for Python/pytest
   - Create accessibility test suite
   - Check all interactive elements have ARIA labels
   - Validate label descriptiveness

2. **Manual Testing:**
   - Screen reader verification (NVDA/JAWS simulation)
   - Keyboard navigation flow
   - Focus management

**Test Cases:**
```python
# tests/test_accessibility_aria.py
import pytest
from axe_selenium_python import Axe

class TestARIALabels:
    """Test ARIA label implementation for WCAG AA compliance."""

    def test_form_controls_have_labels(self, client):
        """All form controls must have associated labels or aria-label."""
        response = client.get("/")
        # Check input fields have aria-label or associated <label>

    def test_buttons_have_accessible_names(self, client):
        """All buttons must have accessible names."""
        response = client.get("/")
        # Verify button elements have text or aria-label

    def test_interactive_elements_labeled(self, client):
        """Interactive elements have descriptive labels."""
        # Test video controls, navigation, etc.

    def test_axe_core_aria_violations(self, selenium_driver):
        """Run axe-core accessibility audit for ARIA issues."""
        selenium_driver.get("http://localhost:8000")
        axe = Axe(selenium_driver)
        axe.inject()
        results = axe.run()
        assert len(results["violations"]) == 0, f"ARIA violations: {results['violations']}"
```

**Success Criteria:**
- Zero ARIA-related axe-core violations
- All interactive elements have labels
- Labels are descriptive (not generic like "button" or "input")
- Manual screen reader testing passes

---

### P0.3: WCAG AA Color Contrast Verification
**Priority:** HIGH
**Estimated Time:** 3 hours (includes axe-core setup)
**Status:** Blocked (waiting for P0.1 fix)

**Scope:**
- All text on colored backgrounds
- Button states (default, hover, active, disabled)
- Focus indicators
- Video player UI

**Test Strategy:**
1. **Automated Testing (axe-core):**
   - Color contrast ratio checks (4.5:1 for normal text, 3:1 for large text)
   - All UI states (default, hover, active, focus, disabled)

2. **Manual Verification:**
   - Visual inspection with contrast analyzer tools
   - Test with different color schemes/themes
   - Verify against WCAG AA Level guidelines

**Test Cases:**
```python
# tests/test_accessibility_contrast.py
import pytest
from axe_selenium_python import Axe

class TestColorContrast:
    """Test WCAG AA color contrast requirements."""

    def test_normal_text_contrast_ratio(self, selenium_driver):
        """Normal text must have 4.5:1 contrast ratio minimum."""
        selenium_driver.get("http://localhost:8000")
        axe = Axe(selenium_driver)
        results = axe.run({"wcagLevel": "AA", "rules": ["color-contrast"]})
        violations = results.get("violations", [])
        assert len(violations) == 0, f"Contrast violations: {violations}"

    def test_large_text_contrast_ratio(self, selenium_driver):
        """Large text must have 3:1 contrast ratio minimum."""
        # Test headings, large UI text

    def test_button_states_contrast(self, client):
        """All button states meet contrast requirements."""
        # Test default, hover, active, focus, disabled states

    def test_focus_indicators_visible(self, selenium_driver):
        """Focus indicators have sufficient contrast."""
        # Test keyboard focus visibility
```

**Success Criteria:**
- Zero color-contrast violations in axe-core
- All text meets WCAG AA requirements (4.5:1 or 3:1)
- Focus indicators clearly visible
- All button states meet contrast requirements

---

### P0.4: Screen Reader Test Scenarios
**Priority:** MEDIUM
**Estimated Time:** 4 hours
**Status:** Blocked (waiting for P0.1 fix)

**Scope:**
- Page structure and landmarks
- Heading hierarchy
- Form navigation
- Video player accessibility
- Error message announcements

**Test Strategy:**
1. **Simulated Screen Reader Testing:**
   - Use accessibility tree inspection
   - Verify semantic HTML structure
   - Test ARIA live regions

2. **Documentation:**
   - Create screen reader test scenarios
   - Document expected behavior
   - Provide manual testing checklist

**Test Scenarios:**
```markdown
# Screen Reader Test Scenarios

## Scenario 1: New User Creating First Video
1. Navigate to homepage with screen reader
2. Expected: Site title, main navigation announced
3. Tab to "Create Video" button
4. Expected: Button purpose clearly announced
5. Activate button, form appears
6. Expected: Form purpose and fields announced in order
7. Fill in required fields
8. Expected: Field labels and validation messages announced
9. Submit form
10. Expected: Success/error message announced via ARIA live region

## Scenario 2: Video Player Interaction
1. Navigate to video page
2. Expected: Video title, description announced
3. Tab to player controls
4. Expected: Each control announced with state (play/pause, muted/unmuted)
5. Use spacebar to play/pause
6. Expected: State change announced

## Scenario 3: Error Handling
1. Submit form with missing required fields
2. Expected: Error summary announced
3. Focus moves to first error
4. Expected: Field label + error message announced
5. Correct error and resubmit
6. Expected: Success message announced
```

**Test Cases:**
```python
# tests/test_screen_reader_support.py
import pytest

class TestScreenReaderSupport:
    """Test screen reader compatibility and announcements."""

    def test_page_has_main_landmark(self, client):
        """Page has main landmark for screen readers."""
        response = client.get("/")
        assert b'<main' in response.content or b'role="main"' in response.content

    def test_heading_hierarchy_correct(self, client):
        """Headings follow proper hierarchy (h1, h2, h3)."""
        response = client.get("/")
        # Parse and verify h1 > h2 > h3 structure

    def test_skip_to_content_link(self, client):
        """Skip to main content link present for screen readers."""
        response = client.get("/")
        # Verify skip link exists and works

    def test_aria_live_regions_for_status(self, selenium_driver):
        """Status messages use ARIA live regions."""
        # Test that success/error messages are announced

    def test_form_errors_announced(self, selenium_driver):
        """Form validation errors properly announced."""
        # Submit invalid form, check aria-invalid and aria-describedby
```

**Success Criteria:**
- Semantic HTML structure (landmarks, headings)
- All interactive elements keyboard accessible
- ARIA live regions for dynamic content
- Comprehensive test scenario documentation
- Manual testing checklist provided

---

### P0.5: Translation Stage Implementation Tests
**Priority:** HIGH
**Estimated Time:** 4 hours
**Status:** Blocked (waiting for P0.1 fix)

**Scope:**
- Translation Stage initialization
- Claude API translation
- Google Translate fallback (if available)
- Batch translation
- Language code mapping
- Error handling

**Test Strategy:**
1. Unit tests for Translation Stage class
2. Integration tests with real API (mocked for CI)
3. Test all supported languages
4. Test error conditions and fallbacks

**Test Cases:**
```python
# tests/test_translation_stage.py
import pytest
from unittest.mock import Mock, patch
from video_gen.stages.translation_stage import TranslationStage

class TestTranslationStage:
    """Test Translation Stage functionality."""

    @pytest.fixture
    def translation_stage(self):
        """Create Translation Stage instance."""
        return TranslationStage()

    def test_initialization_without_googletrans(self, translation_stage):
        """Stage initializes successfully without googletrans."""
        assert translation_stage is not None
        assert translation_stage.name == "translation"

    def test_initialization_with_claude_api(self, monkeypatch):
        """Stage initializes Claude client with API key."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        stage = TranslationStage()
        assert stage.claude_client is not None

    def test_initialization_without_claude_api(self, monkeypatch):
        """Stage handles missing Claude API key gracefully."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        stage = TranslationStage()
        assert stage.claude_client is None

    @pytest.mark.asyncio
    async def test_translate_with_claude_api(self, translation_stage):
        """Translation works with Claude API."""
        with patch.object(translation_stage, 'claude_client') as mock_client:
            mock_response = Mock()
            mock_response.content = [Mock(text="Hola mundo")]
            mock_client.messages.create.return_value = mock_response

            result = await translation_stage._translate_text(
                "Hello world", "en", "es"
            )
            assert result == "Hola mundo"

    @pytest.mark.asyncio
    async def test_translate_fallback_when_claude_fails(self, translation_stage):
        """Falls back to Google Translate when Claude fails."""
        translation_stage.claude_client = Mock()
        translation_stage.claude_client.messages.create.side_effect = Exception("API Error")

        # If googletrans available, should fallback
        if hasattr(translation_stage, 'google_translator'):
            with patch.object(translation_stage.google_translator, 'translate') as mock_trans:
                mock_result = Mock(text="Hola mundo")
                mock_trans.return_value = mock_result

                result = await translation_stage._translate_text(
                    "Hello world", "en", "es"
                )
                assert result == "Hola mundo"
        else:
            # Should return original text
            result = await translation_stage._translate_text(
                "Hello world", "en", "es"
            )
            assert result == "Hello world"

    @pytest.mark.asyncio
    async def test_translate_video_config(self, translation_stage):
        """Translates complete video configuration."""
        # Test with mock VideoConfig
        pass

    @pytest.mark.asyncio
    async def test_translate_scene(self, translation_stage):
        """Translates individual scene."""
        # Test scene translation
        pass

    @pytest.mark.asyncio
    async def test_translate_visual_content(self, translation_stage):
        """Translates visual content based on scene type."""
        # Test different scene types
        pass

    def test_supported_languages(self, translation_stage):
        """Verify all 28+ supported languages map correctly."""
        lang_codes = [
            "en", "es", "fr", "de", "it", "pt", "nl", "ru",
            "ja", "zh", "ko", "ar", "hi", "tr", "pl", "sv"
        ]
        # Test language code mapping

    @pytest.mark.asyncio
    async def test_execute_translation_stage(self, translation_stage):
        """Full stage execution with multiple languages."""
        context = {
            "video_config": Mock(),
            "target_languages": ["es", "fr"],
            "source_language": "en"
        }
        result = await translation_stage.execute(context)
        assert result.success is True
        assert "translated_configs" in result.artifacts
```

**Success Criteria:**
- Translation Stage works without googletrans
- Claude API translation tested
- Fallback logic tested
- All 28+ languages supported
- Error handling comprehensive
- >85% code coverage for translation_stage.py

---

### P0.6: Voice per Language Feature Validation
**Priority:** MEDIUM
**Estimated Time:** 3 hours
**Status:** Blocked (waiting for P0.1 fix)

**Scope:**
- Voice selection per language
- Voice configuration validation
- edge-tts integration
- Voice preview functionality

**Test Cases:**
```python
# tests/test_voice_per_language.py
import pytest
from video_gen.config import VideoConfig

class TestVoicePerLanguage:
    """Test voice-per-language feature."""

    def test_different_voices_per_language(self):
        """Can specify different voice for each language."""
        config = {
            "voices": {
                "en": "en-US-ChristopherNeural",
                "es": "es-ES-AlvaroNeural",
                "fr": "fr-FR-HenriNeural"
            }
        }
        # Verify voice assignment works

    def test_voice_validation(self):
        """Invalid voice names are rejected."""
        # Test with invalid voice

    def test_voice_preview(self):
        """Voice preview generates correct audio sample."""
        # Test preview functionality

    def test_default_voice_fallback(self):
        """Falls back to default voice if language-specific not provided."""
        # Test fallback logic
```

**Success Criteria:**
- Voice can be set per language
- Invalid voices rejected with clear error
- Voice preview works for all supported voices
- Default fallback logic tested

---

### P0.7: Batch Video Count Behavior Testing
**Priority:** LOW
**Estimated Time:** 2 hours
**Status:** Blocked (waiting for P0.1 fix)

**Scope:**
- Batch processing logic
- Video counting accuracy
- Progress reporting
- Resource management

**Test Cases:**
```python
# tests/test_batch_processing.py
import pytest

class TestBatchProcessing:
    """Test batch video generation."""

    @pytest.mark.asyncio
    async def test_batch_count_accurate(self):
        """Batch processing reports correct video count."""
        # Generate batch of 5 videos
        # Verify count matches expected

    @pytest.mark.asyncio
    async def test_batch_progress_reporting(self):
        """Progress updates accurately during batch processing."""
        # Monitor progress callbacks

    @pytest.mark.asyncio
    async def test_batch_error_handling(self):
        """Batch processing handles individual failures gracefully."""
        # Test with one failing video in batch

    @pytest.mark.asyncio
    async def test_batch_resource_cleanup(self):
        """Resources cleaned up after batch processing."""
        # Verify no resource leaks
```

**Success Criteria:**
- Accurate video count in batches
- Progress reporting works correctly
- Individual failures don't crash batch
- No resource leaks

---

## P1 Testing Strategies (Week 2)

### P1.1: Advanced Accessibility Testing
- Keyboard-only navigation testing
- Focus trap prevention
- Skip link functionality
- ARIA live region testing
- High contrast mode compatibility

### P1.2: Performance Testing
- Video generation benchmarks
- API response time testing
- Memory usage profiling
- Concurrent request handling

### P1.3: Integration Testing Expansion
- End-to-end video generation workflows
- Multi-language video generation
- API integration testing
- UI-to-backend integration

### P1.4: Security Testing
- Input validation and sanitization
- API authentication testing
- Rate limiting verification
- XSS prevention testing
- SQL injection prevention (if applicable)

### P1.5: Browser Compatibility Testing
- Cross-browser accessibility testing
- CSS compatibility verification
- JavaScript functionality across browsers
- Responsive design testing

---

## Testing Tools and Dependencies

### Required Installations
```bash
# Accessibility testing
pip install axe-selenium-python
pip install selenium

# HTML parsing for tests
pip install beautifulsoup4
pip install lxml

# Mocking and fixtures
pip install pytest-mock
pip install responses
```

### CI/CD Integration
- Run accessibility tests in CI pipeline
- Fail builds on WCAG AA violations
- Generate accessibility reports
- Track accessibility metrics over time

---

## Test Coverage Goals

### Current Coverage: 79% (475 tests)
### Week 1 Goal: 85% (550+ tests)
### Week 2 Goal: 90% (650+ tests)

**Priority Coverage Areas:**
1. Translation Stage: 85%+ (currently 0% - blocked)
2. Accessibility features: 90%+
3. Voice management: 80%+
4. Batch processing: 85%+
5. API endpoints: 95%+

---

## Risk Assessment

### High Risk Areas
1. **Translation Stage Import Issue:** Blocks ALL testing - CRITICAL
2. **Accessibility Compliance:** Legal and usability risk
3. **API Integration:** Claude API dependency
4. **Browser Compatibility:** User experience impact

### Mitigation Strategies
1. Fix import issue immediately (P0.1)
2. Automated accessibility testing in CI
3. Mock API calls for testing
4. Cross-browser test suite

---

## Success Metrics

### Definition of Done - P0
- [ ] All test modules collect successfully (no import errors)
- [ ] Zero WCAG AA violations (axe-core)
- [ ] All ARIA labels implemented and tested
- [ ] Translation Stage 85%+ coverage
- [ ] Voice per language feature 80%+ coverage
- [ ] Batch processing tests pass
- [ ] Screen reader test scenarios documented

### Definition of Done - P1
- [ ] 90%+ overall test coverage
- [ ] Performance benchmarks established
- [ ] Security tests implemented
- [ ] Cross-browser tests passing
- [ ] Integration tests comprehensive

---

## Timeline

### Week 1 (Nov 17-23, 2025)
- **Day 1:** Fix P0.1 blocker (import issue) ✅ URGENT
- **Day 1-2:** P0.2 ARIA labels testing
- **Day 2-3:** P0.3 Color contrast verification
- **Day 3-4:** P0.4 Screen reader scenarios
- **Day 4-5:** P0.5 Translation Stage tests
- **Day 5:** P0.6 Voice per language tests
- **Day 5:** P0.7 Batch processing tests

### Week 2 (Nov 24-30, 2025)
- **Day 1-2:** P1.1 Advanced accessibility
- **Day 2-3:** P1.2 Performance testing
- **Day 3-4:** P1.3 Integration expansion
- **Day 4-5:** P1.4 Security testing
- **Day 5:** P1.5 Browser compatibility

---

## Deliverables

### Week 1
1. ✅ This test plan document
2. Translation Stage import fix (P0.1)
3. Accessibility test suite (P0.2, P0.3)
4. Screen reader test scenarios (P0.4)
5. Translation Stage test suite (P0.5)
6. Voice feature tests (P0.6)
7. Batch processing tests (P0.7)
8. Test results report

### Week 2
1. P1 test suites (5 areas)
2. Performance benchmarks
3. Security audit report
4. Browser compatibility matrix
5. Final test coverage report
6. CI/CD integration guide

---

## Notes and Observations

### Critical Finding Summary
The Translation Stage implementation has a **critical import bug** that prevents any tests from running. This was introduced when `googletrans` was removed from requirements.txt due to dependency conflicts, but the code still has a hard import.

**Impact:**
- 9 test modules cannot be collected
- 837 tests are blocked
- No testing can proceed until this is fixed

**Coordination Note:**
This finding has been stored in swarm memory at:
- Key: `swarm/tester/critical-bug-translation-import`
- Namespace: `coordination`
- Coder agent should be notified immediately

**Recommended Immediate Action:**
1. Coder agent fixes import to be optional
2. Tester validates fix allows collection
3. Proceed with P0 testing tasks

---

*Test Plan Author: Tester Agent (Hive Mind Swarm)*
*Next Update: After P0.1 fix completion*
