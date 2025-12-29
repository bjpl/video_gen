# GOAP Plan Summary - Technical Debt Remediation
## Quick Reference Guide

**Date:** 2025-12-28 (Updated)
**Previous Session:** 2025-12-23 (Portfolio Readiness)
**Status:** ANALYSIS COMPLETE - READY FOR EXECUTION
**Critical Path:** 6 priority actions (24-32 hours estimated)

---

## Problem Statement

**Previous Issue (RESOLVED):** Session-scoped `event_loop` fixture conflict - Fixed with nest_asyncio.apply()

**Current Technical Debt Analysis (2025-12-28):**
- Overall Quality Score: 7.5/10
- Tests Passing: 1800+ (79% coverage)
- Critical Issues: 3 categories requiring attention
- Total Remediation Estimate: 24-32 hours

**Impact:** Code maintainability, potential silent failures from bare excepts, large file complexity.

---

## Technical Debt Summary

### CRITICAL (Address First - 16 hours)

| Issue | Files | Est. Time |
|-------|-------|-----------|
| Bare except handlers (13 instances) | parser.py, document.py, yaml_file.py, output_stage.py | 4h |
| Large file: document.py (1211 lines) | video_gen/input_adapters/document.py | 6h |
| Large file: yaml_file.py (1181 lines) | video_gen/input_adapters/yaml_file.py | 6h |

### MEDIUM (Next Sprint - 6 hours)

| Issue | Description | Est. Time |
|-------|-------------|-----------|
| Outdated dependencies | 28 packages need updates (anthropic, aiohttp, etc.) | 2h |
| Duplicate adapter code | compat.py (491 lines) duplicates other adapters | 4h |

### LOW (Backlog - 7 hours)

| Issue | Description | Est. Time |
|-------|-------------|-----------|
| Print statements | 1,125 occurrences (mostly in scripts) | 6h |
| Missing pyproject.toml | Modern Python packaging standard | 1h |

---

## GOAP Action Sequence (6 Priority Actions)

```
1. FIX_BARE_EXCEPTS (4h) → Replace 13 bare except handlers with specific exceptions
   Files: parser.py:152,177,195, document.py:323, yaml_file.py:262, output_stage.py:401,406

2. REFACTOR_DOCUMENT_ADAPTER (6h) → Split 1211-line file into focused modules
   Target: <500 lines per file, extract PDF/DOCX handlers, AI enhancement module

3. REFACTOR_YAML_ADAPTER (6h) → Split 1181-line file into focused modules
   Target: <500 lines per file, extract schema validation, template engine

4. UPDATE_DEPENDENCIES (2h) → Update 28 outdated packages
   Priority: anthropic (0.71→0.75), aiohttp, attrs, click

5. REMOVE_COMPAT_DUPLICATION (4h) → Consolidate adapter code
   File: compat.py (491 lines) → Remove or merge with main adapters

6. VALIDATE_AND_DOCUMENT (2h) → Run tests, update patterns
   Verify: All tests pass, coverage maintained, AgentDB updated
```

**Total Estimated Time:** 24 hours (minimum) to 32 hours (with contingency)

---

## Success Criteria

1. ✅ Zero bare except handlers in core modules
2. ✅ All files under 500 lines (or justified exception documented)
3. ✅ Dependencies updated to latest stable versions
4. ✅ No duplicate adapter code
5. ✅ Test pass rate maintained ≥ 95%
6. ✅ Code coverage maintained at 79%+
7. ✅ AgentDB patterns updated with learnings

## Positive Findings (No Action Needed)

- ✅ **Security**: No hardcoded secrets, no vulnerabilities found
- ✅ **Logging**: 234 consistent logging calls across 22 files
- ✅ **Type Hints**: Well-implemented throughout codebase
- ✅ **Tests**: 1800+ passing (79% coverage)
- ✅ **Event Loops**: Previously resolved with nest_asyncio.apply()

---

## Risk Assessment

| Risk | Level | Mitigation |
|------|-------|------------|
| Fixture removal breaks other tests | Medium | Check all fixture dependencies first |
| async_client depends on event_loop | Medium | Test immediately after change |
| CI behaves differently | Low | Test in CI early (Action 7) |
| 95% pass rate not achieved | Low | Comprehensive analysis and fixes |

---

## Implementation Code

**Change Required:**

```python
# tests/conftest.py lines 39-44 (REMOVE):

# @pytest.fixture(scope="session")
# def event_loop():
#     """Create event loop for async tests."""
#     loop = asyncio.get_event_loop_policy().new_event_loop()
#     yield loop
#     loop.close()
#
# Note: Removed to prevent conflict with pytest-asyncio's asyncio_mode=auto
# The plugin automatically provides function-scoped event loops for async tests
```

**No Other Changes Required** (unless validation reveals issues)

---

## Testing Commands

```bash
# Validate async tests
pytest tests/ -k "async" -v

# Run fast tests
pytest tests/ -m "not slow" -v

# Full test suite with coverage
pytest tests/ --cov=video_gen --cov=app --cov-report=html -v

# CI/CD simulation
pytest tests/ --tb=short -v
```

---

## Git Workflow

```bash
# Create feature branch
git checkout -b fix/pytest-asyncio-event-loop-conflict

# Make changes
# Edit tests/conftest.py

# Commit
git add tests/conftest.py
git commit -m "fix: Remove session-scoped event_loop fixture conflicting with asyncio_mode=auto"

# Push and create PR
git push -u origin fix/pytest-asyncio-event-loop-conflict
gh pr create --title "Fix pytest-asyncio event loop conflict" --body "..."

# After CI green, merge
git checkout main
git merge fix/pytest-asyncio-event-loop-conflict
git push origin main
```

---

## Key Insights

### pytest-asyncio 0.23.4 Behavior

**With `asyncio_mode=auto`:**
- Automatically detects async test functions
- Provides function-scoped event loop per test
- Manages event loop lifecycle automatically
- Manual event_loop fixtures are unnecessary and conflict

**Best Practice:**
> "When using auto mode, you don't need to provide your own event_loop fixture. The plugin will automatically create and manage event loops for async tests."

### Why This Conflict Occurred

1. **Session-scoped fixture** creates ONE event loop for entire test session
2. **pytest-asyncio auto mode** tries to create function-scoped loops per test
3. **Result:** RuntimeError when pytest-asyncio tries to run event loop that's already running

### Prevention for Future

- When using `asyncio_mode=auto`, don't create event_loop fixtures
- If manual control needed, set `asyncio_mode=strict` and manage loops explicitly
- Always check pytest-asyncio documentation for version-specific behavior

---

## SPARC Integration Points

### Specification (Actions 1-2)
- Requirements analysis
- Success criteria definition
- State mapping

### Pseudocode (Action 2)
- Solution algorithm design
- Test strategy planning

### Architecture (Action 3)
- Test fixture architecture
- CI/CD integration

### Refinement (Actions 4-6)
- TDD validation
- Iterative improvement

### Completion (Actions 7-9)
- Production deployment
- Documentation
- Pattern storage

---

## Memory Patterns to Store

**Pattern 1: pytest-asyncio Configuration**
```yaml
pattern: pytest_asyncio_configuration
context: Modern pytest-asyncio (0.23.x+) configuration
solution:
  - Use asyncio_mode=auto in pytest.ini
  - Do NOT create manual event_loop fixtures
  - Plugin handles all event loop management
  - Function-scoped loops per test (clean isolation)
```

**Pattern 2: Event Loop Conflict Resolution**
```yaml
pattern: event_loop_conflict_resolution
symptoms:
  - RuntimeError: "This event loop is already running"
  - Async tests failing with event loop errors
  - Session-scoped vs function-scoped conflict
diagnosis:
  - Check for manual event_loop fixtures in conftest.py
  - Verify asyncio_mode setting in pytest.ini
  - Identify scope conflicts (session vs function)
solution:
  - Remove manual event_loop fixture
  - Trust pytest-asyncio auto mode
  - Validate with async test subset first
```

**Pattern 3: GOAP Planning for Test Infrastructure**
```yaml
pattern: goap_test_infrastructure_planning
approach:
  - World state modeling (current vs desired)
  - Action sequence with preconditions/effects
  - Dependency graph (parallel vs sequential)
  - Risk assessment per action
  - Success criteria metrics
  - Heuristic cost estimation
benefits:
  - Systematic problem-solving
  - Clear success criteria
  - Measurable progress
  - Risk mitigation strategies
  - Time estimation accuracy
```

---

## Next Steps

1. **Review this plan** with stakeholders (if applicable)
2. **Execute Action 1** (Analyze Conflict) - 30 minutes
3. **Proceed sequentially** through critical path
4. **Monitor at each validation point** (Actions 4, 5, 7)
5. **Document completion** (Action 9)

---

## References

- Full GOAP Plan: `docs/planning/GOAP_PORTFOLIO_READINESS_PLAN.md`
- pytest-asyncio docs: https://pytest-asyncio.readthedocs.io/
- Current test config: `tests/conftest.py`, `pytest.ini`
- CI/CD workflows: `.github/workflows/`

---

**Plan Status:** ✅ READY FOR EXECUTION
**Estimated Completion:** Within 1 working day
**Risk Level:** LOW (well-understood problem, clear solution)
**Deployment Blocker:** YES (P0 priority)

---

*Generated: 2025-12-23*
*Planning Methodology: Goal-Oriented Action Planning (GOAP) with SPARC Integration*
