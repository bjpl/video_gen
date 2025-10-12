# UI/API Alignment - Comprehensive QA Test Plan

**Project:** video_gen - Professional Video Generation System
**Date:** October 11, 2025
**QA Agent:** Testing & Validation Specialist
**Scope:** Complete validation of UI/API feature parity
**Gap Analysis Source:** `docs/UI_API_GAP_ANALYSIS.md`

---

## Executive Summary

This test plan validates the alignment between the **Programmatic API** (full-featured, 12 scene types) and the **Web UI** (Quick Start, Builder, Multilingual pages). Current feature parity is estimated at **60%** based on gap analysis. This test plan will validate all features, identify remaining gaps, and provide recommendations for achieving **90%+ parity**.

---

## Test Environment

- **API Version:** Production-ready (79% test coverage, 475 passing tests)
- **UI Stack:** Flask + Alpine.js + Tailwind CSS
- **Test Framework:** pytest
- **Test Coverage Target:** All UI features mapped to API equivalents

---

## 1. Scene Type Coverage Testing

### 1.1 Quick Start Scene Type Support

**Expected:** 0/12 scene types (by design - uses document/YAML parsing)

**Test Cases:**
- [ ] QS-01: Verify Quick Start has NO scene type selection UI
- [ ] QS-02: Confirm document parsing generates appropriate scene types
- [ ] QS-03: Validate YAML input can specify all 12 scene types
- [ ] QS-04: Verify YouTube transcription generates basic scenes
- [ ] QS-05: Confirm AI enhancement affects scene generation

**Pass Criteria:** Quick Start correctly generates scenes via backend parsers, no direct scene editing (by design)

---

### 1.2 Builder Scene Type Support

**Expected:** 12/12 scene types have buttons, 6/12 have complete forms

**Test Cases:**
- [ ] BD-01: Verify all 12 scene type buttons are present
- [ ] BD-02: Test complete forms: title, command, list, outro, quiz
- [ ] BD-03: Test partial forms: learning_objectives, exercise, problem, solution, checkpoint
- [ ] BD-04: Verify missing forms: code_comparison, quote
- [ ] BD-05: Test scene type switching (changing type after creation)
- [ ] BD-06: Validate scene deletion works for all types

**Gap Identification:**
- **HIGH PRIORITY:** code_comparison, quote forms completely missing
- **MEDIUM PRIORITY:** Partial forms lack scene-specific fields

---

## 2. Scene-Specific Parameter Testing

### 2.1 Title Scene (✅ Complete)

**API Parameters:** `title`, `subtitle` (optional)

**Test Cases:**
- [ ] TS-01: Required `title` field validation
- [ ] TS-02: Optional `subtitle` field behavior
- [ ] TS-03: Max length validation (if any)
- [ ] TS-04: Special character handling
- [ ] TS-05: Unicode/emoji support

**Expected Result:** ✅ Perfect API/UI alignment

---

### 2.2 Command Scene (✅ Mostly Complete)

**API Parameters:** `header`, `label`, `commands[]` (max 8)

**UI Implementation:** `header`, `description` (maps to label), `commands`

**Test Cases:**
- [ ] CS-01: Verify all three fields present in UI
- [ ] CS-02: Test multi-line commands input
- [ ] CS-03: Validate max 8 commands constraint
- [ ] CS-04: Check label vs description naming mismatch
- [ ] CS-05: Test command line splitting logic

**Gap:** Label/description naming inconsistency, no max constraint UI

---

### 2.3 List Scene (✅ Adequate)

**API Parameters:** `header`, `description`, `items[]`

**Test Cases:**
- [ ] LS-01: Verify header field (required in API)
- [ ] LS-02: Test description field (should be required, UI shows optional)
- [ ] LS-03: Validate items parsing (one per line)
- [ ] LS-04: Test List[dict] format support (items with descriptions)
- [ ] LS-05: Check max items constraint

**Gap:** Description marked optional but API requires it, no List[dict] support

---

### 2.4 Outro Scene (✅ Perfect)

**API Parameters:** `message`, `cta` (optional)

**Test Cases:**
- [ ] OS-01: Verify message field (required)
- [ ] OS-02: Validate optional CTA field
- [ ] OS-03: Test rendering without CTA
- [ ] OS-04: Check character limits

**Expected Result:** ✅ Perfect alignment

---

### 2.5 Code Comparison Scene (❌ Missing Form)

**API Parameters:** `before_code[]`, `after_code[]`, `before_label`, `after_label`

**Test Cases:**
- [ ] CC-01: Verify add button exists
- [ ] CC-02: **CRITICAL:** Confirm form is missing
- [ ] CC-03: Test workaround (can users hack it?)
- [ ] CC-04: Validate API still works programmatically

**Gap:** **HIGH PRIORITY** - Complete scene form missing from UI

---

### 2.6 Quote Scene (❌ Missing Form)

**API Parameters:** `quote_text`, `attribution` (optional)

**Test Cases:**
- [ ] QU-01: Verify add button exists
- [ ] QU-02: **CRITICAL:** Confirm form is missing
- [ ] QU-03: Test if generic fields can substitute
- [ ] QU-04: Validate API functionality

**Gap:** **HIGH PRIORITY** - Complete scene form missing

---

### 2.7 Learning Objectives Scene (⚠️ Partial)

**API Parameters:** `title`, `objectives[]` (max 5)

**UI Implementation:** Generic `title` + `content` textarea

**Test Cases:**
- [ ] LO-01: Verify title field present
- [ ] LO-02: Test content textarea (should be objectives)
- [ ] LO-03: Check max 5 objectives constraint in UI
- [ ] LO-04: Validate one-per-line parsing
- [ ] LO-05: Test objectives vs generic content confusion

**Gap:** Generic implementation, no max 5 constraint, unclear purpose

---

### 2.8 Quiz Scene (✅ Good)

**API Parameters:** `question`, `options[]` (max 4), `correct_index`

**UI Implementation:** `question`, `options` (textarea), `answer` (string)

**Test Cases:**
- [ ] QZ-01: Verify question field
- [ ] QZ-02: Test options input (one per line)
- [ ] QZ-03: Validate answer field (should be index, not string?)
- [ ] QZ-04: Check max 4 options constraint
- [ ] QZ-05: Test answer validation logic

**Gap:** Minor - `answer` string vs `correct_index` integer mismatch

---

### 2.9 Exercise Scene (⚠️ Partial)

**API Parameters:** `title`, `instructions`, `hints[]` (max 3)

**UI Implementation:** `title`, `content` (no hints field)

**Test Cases:**
- [ ] EX-01: Verify title field
- [ ] EX-02: **CRITICAL:** Check for hints field (expected missing)
- [ ] EX-03: Test instructions via content field
- [ ] EX-04: Validate max 3 hints constraint (N/A if missing)

**Gap:** **MEDIUM PRIORITY** - Missing hints field, no max 3 constraint

---

### 2.10 Problem Scene (⚠️ Partial)

**API Parameters:** `title`, `problem_text`, `difficulty` (easy/medium/hard)

**UI Implementation:** `title`, `content` (no difficulty)

**Test Cases:**
- [ ] PR-01: Verify title field
- [ ] PR-02: **CRITICAL:** Check for difficulty dropdown (expected missing)
- [ ] PR-03: Test problem_text via content field
- [ ] PR-04: Validate difficulty affects color coding in API
- [ ] PR-05: Check if difficulty can be inferred from content

**Gap:** **MEDIUM PRIORITY** - Missing difficulty selector, no color-coding

---

### 2.11 Solution Scene (⚠️ Partial)

**API Parameters:** `code[]`, `explanation`

**UI Implementation:** Generic `title`, `content` (no separation)

**Test Cases:**
- [ ] SO-01: **CRITICAL:** Check for separate code field (expected missing)
- [ ] SO-02: **CRITICAL:** Check for explanation field (expected missing)
- [ ] SO-03: Test combined content workaround
- [ ] SO-04: Validate multi-line code input
- [ ] SO-05: Check syntax highlighting hint

**Gap:** **MEDIUM PRIORITY** - No code/explanation separation, no syntax hint

---

### 2.12 Checkpoint Scene (⚠️ Partial)

**API Parameters:** `learned_topics[]` (max 6), `next_topics[]` (max 6)

**UI Implementation:** Generic `title`, `content` (no two-column structure)

**Test Cases:**
- [ ] CP-01: **CRITICAL:** Check for learned_topics field (expected missing)
- [ ] CP-02: **CRITICAL:** Check for next_topics field (expected missing)
- [ ] CP-03: Test generic content as workaround
- [ ] CP-04: Validate max 6 per column constraint
- [ ] CP-05: Check if two-column rendering works in output

**Gap:** **MEDIUM PRIORITY** - No left/right split, unclear checkpoint purpose

---

## 3. Voice Configuration Testing

### 3.1 Voice Options

**API:** 4 voices (male, male_warm, female, female_friendly)

**Test Cases:**
- [ ] VC-01: Verify all 4 voices available in Quick Start
- [ ] VC-02: Verify all 4 voices available in Builder
- [ ] VC-03: Verify all 4 voices available in Multilingual page
- [ ] VC-04: Test voice preview functionality (🔊 buttons)
- [ ] VC-05: Validate voice metadata (name, gender, tone)

**Expected Result:** ✅ All voices present in all UI pages

---

### 3.2 Voice Rotation Patterns

**API:** Supports single, alternating, full rotation patterns

**Test Cases:**
- [ ] VR-01: Test single voice selection (all scenes same voice)
- [ ] VR-02: Test multi-voice tracks (2 voices alternating)
- [ ] VR-03: Test 3+ voices (full rotation)
- [ ] VR-04: **CRITICAL:** Check for rotation explanation in UI
- [ ] VR-05: Validate rotation preview/visualization
- [ ] VR-06: Test per-scene voice override in Builder

**Gap:** **MEDIUM PRIORITY** - Rotation pattern not explained to users

---

### 3.3 Per-Scene Voice Override

**API:** `SceneConfig(voice="female")` overrides default

**Test Cases:**
- [ ] PV-01: Verify per-scene voice dropdown in Builder
- [ ] PV-02: Test voice override behavior
- [ ] PV-03: Validate override persists across saves
- [ ] PV-04: **CRITICAL:** Check Quick Start for per-scene override (expected missing)

**Gap:** Quick Start has no per-scene editing

---

## 4. Color Options Testing

### 4.1 Color Availability

**API:** 6 colors (blue, orange, purple, green, pink, cyan)

**Test Cases:**
- [ ] CL-01: Verify all 6 colors in Quick Start
- [ ] CL-02: Verify all 6 colors in Builder
- [ ] CL-03: Verify all 6 colors in Multilingual page
- [ ] CL-04: Test color preview/visualization
- [ ] CL-05: Validate color application in generated videos

**Expected Result:** ✅ All colors present

---

### 4.2 Color Psychology Guide

**API Docs:** Color psychology + "best for" recommendations

**Test Cases:**
- [ ] CP-01: **CRITICAL:** Check for tooltips on color buttons (expected missing)
- [ ] CP-02: Validate tooltip content (psychology + use cases)
- [ ] CP-03: Test tooltip visibility/accessibility
- [ ] CP-04: Check for link to full color guide

**Gap:** **LOW PRIORITY** - Educational context missing, functionality complete

---

## 5. Duration Controls Testing

### 5.1 Global Duration

**UI Only:** Quick Start has global duration slider (30s-300s)

**Test Cases:**
- [ ] GD-01: Verify global duration slider in Quick Start
- [ ] GD-02: Test min (30s) and max (300s) bounds
- [ ] GD-03: Validate per-video override
- [ ] GD-04: **CRITICAL:** Check Builder for global duration (expected missing)

**Gap:** Builder has no global duration control

---

### 5.2 Per-Scene Min/Max Duration

**API:** `min_duration`, `max_duration` per scene (defaults: 3.0s, 15.0s)

**Test Cases:**
- [ ] SD-01: **CRITICAL:** Check Quick Start for scene duration (expected missing)
- [ ] SD-02: **CRITICAL:** Check Builder for scene duration (expected missing)
- [ ] SD-03: Validate API defaults (3.0s min, 15.0s max)
- [ ] SD-04: Test duration logic explanation in UI
- [ ] SD-05: Validate audio-based duration adjustment

**Gap:** **HIGH PRIORITY** - Scene-level duration control completely missing

---

## 6. Multilingual Testing

### 6.1 Language Support

**API:** 28+ languages with auto-translation

**Test Cases:**
- [ ] ML-01: Verify 28+ languages in Quick Start
- [ ] ML-02: Verify 28+ languages in Multilingual page
- [ ] ML-03: Test language selection (single + multiple)
- [ ] ML-04: Validate translation method selection (Claude vs Google)
- [ ] ML-05: Test language presets (EN+ES, European, Asian, Global)

**Expected Result:** ✅ Complete language coverage

---

### 6.2 Voice Per Language

**API:** Each language can have different voice

**Test Cases:**
- [ ] VL-01: Verify voice selection per language
- [ ] VL-02: Test voice recommendations per language
- [ ] VL-03: Validate voice-language pairing saves correctly
- [ ] VL-04: Test multi-language voice rotation

**Expected Result:** ✅ Full support in UI

---

### 6.3 Video Set × Languages

**API:** M videos × N languages = M×N outputs

**Test Cases:**
- [ ] VS-01: Test single video → multiple languages
- [ ] VS-02: **CRITICAL:** Test video set → multiple languages (may be limited)
- [ ] VS-03: Validate output file structure
- [ ] VS-04: Check Builder multilingual integration (expected missing)

**Gap:** Builder has no multilingual options

---

## 7. AI Narration Toggle Testing

### 7.1 Toggle Presence & Clarity

**API:** `use_ai_narration=True` (opt-in, costs ~$0.03/video)

**Test Cases:**
- [ ] AI-01: Verify AI toggle in Quick Start
- [ ] AI-02: **CRITICAL:** Check AI toggle in Builder (expected missing)
- [ ] AI-03: Validate toggle label clarity ("AI-Enhanced Narration" vs actual behavior)
- [ ] AI-04: Test cost information display
- [ ] AI-05: Check API key requirement notice

**Gap:** **MEDIUM PRIORITY** - Misleading label, no cost info, Builder missing

---

### 7.2 AI Enhancement Behavior

**Test Cases:**
- [ ] AB-01: Test AI ON vs OFF narration quality
- [ ] AB-02: Validate 3-5s per scene processing time
- [ ] AB-03: Test fallback when API key missing
- [ ] AB-04: Validate template narration (default)
- [ ] AB-05: Compare AI-enhanced vs template narration

---

## 8. End-to-End Workflow Testing

### 8.1 Quick Start Workflows

**Test Cases:**
- [ ] QW-01: Manual title → auto-generate scenes → video
- [ ] QW-02: Document upload → parse → video
- [ ] QW-03: YouTube URL → transcribe → video
- [ ] QW-04: YAML upload → validate → video
- [ ] QW-05: Multilingual expansion (1 video → N languages)
- [ ] QW-06: AI enhancement ON workflow
- [ ] QW-07: Multi-voice track workflow

---

### 8.2 Builder Workflows

**Test Cases:**
- [ ] BW-01: Create video from scratch (all 12 scene types)
- [ ] BW-02: Edit scene (change type, content, voice)
- [ ] BW-03: Delete scenes and reorder
- [ ] BW-04: Save and resume editing
- [ ] BW-05: Generate video from builder
- [ ] BW-06: Test validation errors (missing fields)

---

### 8.3 Multilingual Page Workflows

**Test Cases:**
- [ ] MW-01: Source language selection
- [ ] MW-02: Multiple target languages
- [ ] MW-03: Voice per language configuration
- [ ] MW-04: Translation method selection
- [ ] MW-05: Quick presets usage
- [ ] MW-06: Generate multilingual video set

---

## 9. UI vs API Output Comparison

### 9.1 Identical Input Testing

**Approach:** Create same video via UI and programmatic API, compare outputs

**Test Cases:**
- [ ] CP-01: Simple 3-scene video (title, list, outro)
- [ ] CP-02: Complex educational video (all scene types)
- [ ] CP-03: Multilingual video (EN + ES + FR)
- [ ] CP-04: Multi-voice video (2-4 voices)
- [ ] CP-05: AI-enhanced video
- [ ] CP-06: Custom duration video

**Validation:**
- Video duration matches
- Audio narration matches (voice, content, timing)
- Visual content matches (scenes, colors, text)
- File structure matches

---

## 10. Regression Testing

### 10.1 Existing Test Suite

**Test Cases:**
- [ ] RT-01: Run full test suite (`pytest tests/ -m "not slow"`)
- [ ] RT-02: Validate 475 passing tests remain green
- [ ] RT-03: Check for new failures
- [ ] RT-04: Verify 79% coverage maintained/improved
- [ ] RT-05: Test slow tests separately

---

### 10.2 Web UI Integration Tests

**Test Cases:**
- [ ] WI-01: All pages load (`test_web_ui_integration.py`)
- [ ] WI-02: All API endpoints respond correctly
- [ ] WI-03: JSON response format validation
- [ ] WI-04: Error handling tests
- [ ] WI-05: Edge case validation

---

## 11. Issue Documentation

### 11.1 Bug Tracking

For each failed test:
- **Issue ID:** Unique identifier
- **Severity:** Critical / High / Medium / Low
- **Category:** Missing Feature / Incorrect Behavior / UX Issue
- **Description:** What's wrong
- **Expected:** What should happen (per API)
- **Actual:** What actually happens
- **Reproduction:** Steps to reproduce
- **Recommendation:** Suggested fix (reference gap analysis)

---

### 11.2 Gap Confirmation

Validate gap analysis findings:
- ✅ Confirm identified gaps
- ❌ Refute incorrect gaps
- ⚠️ Partial gaps (more nuanced than binary)
- 🆕 New gaps discovered during testing

---

## 12. Test Execution Plan

### Phase 1: Automated Testing (30 minutes)
1. Run existing test suite
2. Execute web UI integration tests
3. Validate API endpoints
4. Check test coverage

### Phase 2: Manual UI Testing (60 minutes)
1. Scene type coverage (Builder + Quick Start)
2. Scene-specific parameters (all 12 types)
3. Voice configuration and rotation
4. Color options and psychology
5. Duration controls
6. Multilingual features
7. AI narration toggle

### Phase 3: End-to-End Testing (45 minutes)
1. Quick Start workflows (4 input methods)
2. Builder workflows (create, edit, generate)
3. Multilingual page workflows
4. UI vs API output comparison

### Phase 4: Documentation (30 minutes)
1. Compile test results
2. Document all issues found
3. Create test report
4. Store results in memory
5. Generate recommendations

**Total Estimated Time:** 2.5-3 hours

---

## 13. Pass/Fail Criteria

### Overall Success Criteria

**Test Suite:**
- ✅ All existing tests pass (475/475)
- ✅ No regressions introduced
- ✅ Coverage maintained at 79%+

**UI/API Alignment:**
- ✅ All 12 scene types accessible (buttons present)
- ⚠️ At least 8/12 scene types have complete forms (currently 6/12)
- ⚠️ Voice rotation pattern explained somewhere in UI
- ⚠️ Scene min/max duration in at least one UI page
- ✅ All 6 colors available
- ✅ All 28+ languages available
- ✅ AI narration toggle present and functional

**Feature Parity Target:**
- Current: ~60%
- After improvements: >80%
- Ideal: 90%+

---

## 14. Deliverables

1. **Test Execution Report** (`tests/qa_test_results.md`)
   - All test case results (pass/fail/skip)
   - Issue log with severity ratings
   - Screenshots/evidence for failures

2. **Gap Validation Report** (`tests/qa_gap_validation.md`)
   - Confirmation of gap analysis findings
   - New gaps discovered
   - Updated feature parity score

3. **Recommendations Report** (`tests/qa_recommendations.md`)
   - Prioritized fix list
   - Implementation guidance
   - Estimated effort for each fix

4. **Memory Store Updates**
   - Test results stored in swarm memory
   - Coordination with other agents
   - Session metrics and logs

---

## Test Plan Approval

**Created By:** QA Testing Agent
**Date:** October 11, 2025
**Status:** Ready for Execution
**Estimated Completion:** 2.5-3 hours

---

**Next Steps:**
1. Execute Phase 1 (Automated Testing)
2. Execute Phase 2 (Manual UI Testing)
3. Execute Phase 3 (E2E Testing)
4. Compile and deliver test reports
