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

### #3: Deprecated app/input_adapters Module
**Status:** Open
**Priority:** MEDIUM
**Effort:** 2-3 hours
**Category:** Technical Debt

**Description:**
The `app/input_adapters/` module was deprecated on Oct 6, 2025. Migration guide exists, but old code still present.

**Tasks:**
- [ ] Verify all references updated to `video_gen/input_adapters/`
- [ ] Remove deprecated `app/input_adapters/` directory
- [ ] Update any remaining documentation references
- [ ] Create deprecation warning for users

**References:**
- `app/input_adapters/DEPRECATED.md` - Migration guide

---

### #4: Low Coverage Areas (AI Components)
**Status:** Open
**Priority:** MEDIUM
**Effort:** 2-3 hours
**Category:** Testing

**Description:**
AI narration components have lower test coverage than rest of system.

**Coverage:**
- `video_gen/script_generator/ai_enhancer.py`: 39%
- `video_gen/script_generator/narration.py`: 37%

**Tasks:**
- [ ] Add tests for AI prompt generation
- [ ] Add tests for error handling and fallbacks
- [ ] Add tests for edge cases (empty input, special characters)
- [ ] Target: Increase to 60-65% coverage

**Note:** Some low coverage is acceptable for AI code (hard to unit test API calls)

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

**Recently Completed:** 3

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
