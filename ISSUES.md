# Project Issues & Backlog

**Project:** video_gen - Professional Video Generation System
**Last Updated:** October 9, 2025
**Issue Tracker Created:** As part of Plan A technical debt reduction

---

## 🔴 High Priority

### #1: Web UI Testing (0% Coverage)
**Status:** Open
**Priority:** HIGH (if deploying Web UI)
**Effort:** 2-3 days
**Category:** Testing

**Description:**
Web UI has zero automated test coverage. Integration tests fail due to TestClient compatibility issues.

**Tasks:**
- [ ] Fix TestClient compatibility issue (httpx version)
- [ ] Add 50+ endpoint tests for FastAPI routes
- [ ] Add UI component tests
- [ ] Create integration test suite for complete workflows

**Blocking:** Web UI deployment

**References:**
- `docs/PRODUCTION_READINESS.md` - Documents 0% coverage
- `tests/test_integration.py` - Contains failing TestClient tests

---

### #2: Remaining Skipped Tests (112 legitimate + others)
**Status:** Open
**Priority:** MEDIUM
**Effort:** Variable
**Category:** Testing

**Description:**
120 skipped tests remain (down from 128). Most are legitimate (slow/server tests), but some categories need attention.

**Breakdown:**
- ✅ ~90 tests: Legitimate (slow/server tests) - Keep as-is
- ⚠️ ~20 tests: Need review or minor fixes
- ⚠️ ~10 tests: Integration tests requiring server setup

**Tasks:**
- [ ] Review remaining skipped tests individually
- [ ] Create server test infrastructure for integration tests
- [ ] Document skip reasons for all tests
- [ ] Target: Reduce to <60 skipped tests (10%)

**References:**
- `docs/testing/SKIPPED_TESTS_ANALYSIS.md` - Full analysis

---

## 🟡 Medium Priority

### #3: Deprecated app/input_adapters Module - Test Migration Required
**Status:** Open (Blocked - requires test migration)
**Priority:** MEDIUM
**Effort:** 2-3 days (not 2-3 hours - API is completely different)
**Category:** Technical Debt

**Description:**
The `app/input_adapters/` module was deprecated on Oct 6, 2025, but cannot be removed yet because 116 test references depend on it.

**Discovery (Oct 9):**
- Attempted automatic migration - FAILED
- Canonical adapters have different API:
  - Deprecated: `.parse()` (sync) → VideoSet
  - Canonical: `.adapt()` (async) → InputAdapterResult
- Helper functions missing in canonical (create_title_scene, etc.)
- Tests would need complete rewrite, not just import changes

**Tasks:**
- [x] Add deprecation warnings (Oct 9)
- [ ] Create API compatibility layer OR
- [ ] Rewrite 116 test instances to use new adapter API
- [ ] Verify all tests pass with canonical adapters
- [ ] Remove deprecated directory

**Current Workaround:**
- Deprecation warning added to `app/input_adapters/__init__.py`
- Tests continue using deprecated API
- New code should use `video_gen.input_adapters`

**References:**
- `app/input_adapters/DEPRECATED.md` - Migration guide
- Test files affected: 13 files, 116 instances

---

### #4: Low Coverage Areas (AI Components) - ✅ COMPLETED Oct 9
**Status:** ✅ COMPLETED
**Priority:** MEDIUM
**Effort:** 2-3 hours (ACTUAL: 2 hours via agent)
**Category:** Testing

**Description:**
AI narration components had lower test coverage than rest of system.

**Coverage:**
- Before: `ai_enhancer.py` (39%), `narration.py` (37%)
- After: `ai_enhancer.py` (93%), `narration.py` (100%)
- **Overall script_generator module: 95%** ✅

**Completed:**
- [x] Added tests for AI prompt generation
- [x] Added tests for error handling and fallbacks
- [x] Added tests for edge cases (validation, metrics, etc.)
- [x] Exceeded target (95% vs 60-65% target)

**Tests Added:** 43 comprehensive tests in `tests/test_ai_components.py`
- AIUsageMetrics class (10 tests)
- AIScriptEnhancer initialization (3 tests)
- Validation logic (8 tests)
- Enhancement with mocked API (7 tests)
- NarrationGenerator (12 tests)
- Not-implemented methods (2 tests)
- Backward compatibility (1 test)

**All 43 tests passing** ✅

**Completed:** October 9, 2025 (via parallel agent)
**Moved to:** Recently Completed section

---

### #5: Configuration Consolidation
**Status:** Open
**Priority:** LOW-MEDIUM
**Effort:** 1-2 days
**Category:** Architecture

**Description:**
Legacy config files exist alongside new consolidated `shared/config.py`.

**Tasks:**
- [ ] Identify all config duplication
- [ ] Migrate remaining legacy config usage
- [ ] Remove old config files
- [ ] Document configuration patterns

**References:**
- `docs/architecture/ARCHITECTURE_ANALYSIS.md` - Notes config duplication

---

## 🟢 Low Priority / Future Enhancements

### #6: YouTube Search Feature
**Status:** Open
**Priority:** LOW
**Effort:** 2-3 hours
**Category:** Feature

**Description:**
TODO in `app/utils.py:103` for YouTube search functionality.

**Tasks:**
- [ ] Design YouTube search API
- [ ] Implement search by keywords
- [ ] Add batch video download
- [ ] Write tests

**Note:** Feature not currently used; low priority unless user need identified.

---

### #7: Multilingual Template TODO
**Status:** Open
**Priority:** LOW
**Effort:** 1 hour
**Category:** Feature

**Description:**
TODO in `app/templates/multilingual.html:91` to get videos from builder.

**Tasks:**
- [ ] Implement video list population
- [ ] Test in Web UI
- [ ] Update templates

**Note:** Part of broader Web UI work (see #1).

---

### #8: Large File Refactoring (Optional)
**Status:** Open
**Priority:** LOW
**Effort:** 2-3 days
**Category:** Code Quality

**Description:**
Two files exceed recommended 500-line limit.

**Files:**
- `video_gen/video_generator/unified.py` (623 lines)
- `video_gen/input_adapters/document.py` (594 lines)

**Tasks:**
- [ ] Split video_generator/unified.py into modules
- [ ] Split input_adapters/document.py into modules
- [ ] Maintain API compatibility
- [ ] Update tests

**Note:** Both files are complex but functional; refactoring is optional cleanup.

---

## ✅ Recently Completed

### ✅ #DONE-1: Dead Code Removal
**Completed:** October 9, 2025
**Commits:** 0cd52694
**Part of:** Plan A - Test Debt Reduction

**Description:**
Removed 3 files with 0% test coverage (237 lines total).

**Files Removed:**
- `app/main_backup.py` (143 lines)
- `app/unified_api.py` (80 lines)
- `video_gen/output_handler/exporter.py` (14 lines)

---

### ✅ #DONE-2: Empty Stub Test Removal
**Completed:** October 9, 2025
**Commits:** 3ea6600d
**Part of:** Plan A - Test Debt Reduction

**Description:**
Removed 8 empty test stubs from previous refactoring.

**Tests Removed:**
- `test_auto_orchestrator.py`: 3 tests
- `test_input_adapters_integration.py`: 5 tests

**Impact:** Skip rate reduced from 20.9% → 19.6% (128 → 120 skipped tests)

---

### ✅ #DONE-3: H2 Document Splitting Fix
**Completed:** October 6, 2025
**Commits:** Multiple

**Description:**
Fixed H2 splitting feature that was broken during refactoring.

**Status:** Now working, test passing (`test_split_by_h2_headings`)

---

### ✅ #DONE-4: CRITICAL - Shell Injection Vulnerability (RCE)
**Completed:** October 9, 2025
**Commits:** 3ad98618
**Part of:** Systematic Review - Security Fixes

**Description:**
Fixed critical remote code execution vulnerability in CLI script.

**Problem:** `os.system()` with user input allowed arbitrary command execution
**Attack Example:** `--youtube "test; rm -rf /"`

**Fix:**
- Replaced `os.system()` with `subprocess.run()` using list args
- All 3 instances in `scripts/create_video.py` fixed

**Impact:** CRITICAL security vulnerability eliminated

---

### ✅ #DONE-5: CRITICAL - Path Traversal Vulnerability
**Completed:** October 9, 2025
**Commits:** 31a16f33
**Part of:** Security Hardening Sprint

**Description:**
Fixed critical path traversal vulnerability allowing arbitrary file read.

**Problem:** No validation of file paths - could read any file on system
**Attack Example:** `--document "../../../../../etc/passwd"`

**Fix:**
- Added path resolution and validation in `document.py:133-151`
- Validates paths are within project bounds using `Path.relative_to()`
- 10MB file size limit enforced

**Impact:** Arbitrary file read attacks blocked

---

### ✅ #DONE-6: CRITICAL - SSRF Vulnerability
**Completed:** October 9, 2025
**Commits:** 31a16f33
**Part of:** Security Hardening Sprint

**Description:**
Fixed Server-Side Request Forgery vulnerability.

**Problem:** No validation of URLs - could scan internal network
**Attack Example:** `--document "http://192.168.1.1/admin"`

**Fix:**
- Added IP address validation in `document.py:94-103`
- Blocks localhost, private IP ranges (127.x, 192.168.x, 10.x, 172.16.x, 169.254.x)
- Only allows public URLs

**Impact:** Internal network scanning attacks blocked

---

### ✅ #DONE-7: Input Validation & DoS Protection
**Completed:** October 9, 2025
**Commits:** 31a16f33
**Part of:** Security Hardening Sprint

**Description:**
Implemented comprehensive input validation to prevent DoS attacks.

**Limits Added:**
- SceneConfig: scene_id (200 chars), narration (50K chars)
- VideoConfig: title (500 chars), description (5K chars), max scenes (100)
- File size: 10MB for both files and URLs
- Duration bounds: 0-300 seconds

**Implementation:**
- `models.py:31-58` - SceneConfig validation
- `models.py:96-124` - VideoConfig validation

**Impact:** DoS via oversized inputs prevented

---

### ✅ #DONE-8: AI Enhancement Implementation (Plan B)
**Completed:** October 9, 2025
**Commits:** 41ffa107
**Part of:** Plan B - AI Enhancement Sprint

**Description:**
Implemented 5 major AI enhancements for better narration quality.

**Features Added:**
1. Scene-position awareness (AI knows opening vs closing vs middle)
2. Cost tracking (AIUsageMetrics class with token counting)
3. Quality validation (prevents bad AI outputs)
4. Enhanced prompts (9 scene types, position-specific guidance)
5. Metrics integration (stage logs costs and success rates)

**Code Added:** +171 lines

---

### ✅ #DONE-9: AI Bug Fixes (Found in Systematic Review)
**Completed:** October 9, 2025
**Commits:** 3ad98618
**Part of:** Systematic Review - Bug Fixes

**Description:**
Fixed 3 bugs found during systematic review of AI implementation.

**Bugs Fixed:**
1. Context attribute bug (`parsed_content` → `visual_content`)
2. Over-aggressive markdown validation (rejected parentheses)
3. Metrics counting logic flaw (recorded success before validation)

**Impact:** AI enhancement quality significantly improved

---

### ✅ #DONE-10: Security Test Suite
**Completed:** October 9, 2025
**Commits:** 31a16f33
**Part of:** Security Hardening Sprint

**Description:**
Created comprehensive security test suite.

**Tests Added:** 34 tests (all passing)
- Path traversal protection (5 tests)
- SSRF protection (5 tests)
- Input validation (10 tests)
- DoS protection (4 tests)
- File size limits (2 tests)
- Shell injection verification (2 tests)
- Input sanitization (3 tests)
- Security defaults (3 tests)

**File:** `tests/test_security.py` (598 lines)

---

## 📊 Issue Statistics

**Total Open Issues:** 8
**By Priority:**
- 🔴 High: 2
- 🟡 Medium: 3
- 🟢 Low: 3

**By Category:**
- Testing: 3
- Technical Debt: 2
- Features: 2
- Architecture: 1

**Recently Completed:** 11 (8 completed today!)

**Completion Rate (Oct 9):** 11 completed vs 7 remaining = 61% of total issues resolved

---

## 📝 Issue Management

### How to Add Issues

Issues can be added to this file following this template:

```markdown
### #N: Issue Title
**Status:** Open/In Progress/Blocked
**Priority:** HIGH/MEDIUM/LOW
**Effort:** Time estimate
**Category:** Testing/Feature/Bug/Tech Debt/etc

**Description:**
[Detailed description]

**Tasks:**
- [ ] Task 1
- [ ] Task 2

**References:**
- Link to related docs/code

**Blocking:** What this blocks (if applicable)
```

### Priority Guidelines

- **HIGH:** Blocks deployment or core functionality
- **MEDIUM:** Important but not blocking
- **LOW:** Nice to have, future enhancement

### Effort Estimates

- **< 1 hour:** Quick fix
- **1-3 hours:** Small task
- **1 day:** Medium task
- **2-3 days:** Large task
- **1+ weeks:** Epic (should be broken down)

---

## 🎯 Recommended Next Actions

Based on current project state:

**This Week:**
1. Consider Web UI testing if planning to deploy UI (#1)
2. Review remaining skipped tests (#2)
3. Remove deprecated module if ready (#3)

**This Month:**
4. Increase AI component coverage (#4)
5. Configuration consolidation (#5)

**Future:**
6. Large file refactoring when convenient (#8)
7. YouTube search if user need arises (#6)

---

## 📈 Progress Tracking

**Test Debt Reduction Progress:**
- ✅ Dead code removed: 237 lines
- ✅ Empty tests removed: 8 tests
- 🎯 Target: Skip rate <10% (currently 19.6%)
- 🎯 Target: Coverage >85% (currently 79%)

**Technical Debt Score:**
- Previous: 3.5/10
- Current: 3.0/10 (improved with recent cleanup)
- Target: <2.0/10

---

**Issue Tracker Established:** October 9, 2025
**Next Review:** Weekly or as needed
**Maintained By:** Project team

*This tracker was created as part of the Plan A+B technical debt reduction and enhancement sprint.*
