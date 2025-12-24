# GOAP Plan Summary - Portfolio Readiness
## Quick Reference Guide

**Date:** 2025-12-23
**Status:** PLANNING COMPLETE
**Critical Path:** 9 actions (4.5-12.5 hours estimated)

---

## Problem Statement

**Critical Issue:** Session-scoped `event_loop` fixture in `tests/conftest.py` (lines 39-44) conflicts with `asyncio_mode=auto` in `pytest.ini`, causing RuntimeError in async tests.

**Impact:** Test infrastructure unstable, deployment blocked, portfolio presentation delayed.

---

## Solution Summary

**Recommended Fix:** Remove the session-scoped event_loop fixture from tests/conftest.py

**Rationale:**
- pytest-asyncio 0.23.4 with `asyncio_mode=auto` automatically provides function-scoped event loops
- Manual session-scoped fixture is redundant and conflicts with auto mode
- Aligns with modern pytest-asyncio best practices

---

## Critical Path (9 Actions)

```
1. ANALYZE_CONFLICT (30 min) → Understand pytest-asyncio behavior
2. DESIGN_SOLUTION (20 min) → Choose optimal fix approach
3. IMPLEMENT_FIX (15 min) → Remove conflicting fixture
4. VALIDATE_ASYNC (30 min) → Test async tests specifically
5. RUN_FULL_SUITE (60 min) → Comprehensive testing
6. FIX_CRITICAL (variable) → Address any remaining issues (conditional)
7. UPDATE_CI_CD (50 min) → Verify pipeline green
8. MERGE_DEPLOY (30 min) → Production deployment
9. DOCUMENT (45 min) → Store patterns and lessons
```

**Total Time:** 4.5 hours (best case) to 12.5 hours (worst case)

---

## Success Criteria

1. ✅ Test pass rate ≥ 95%
2. ✅ Zero RuntimeError: "event loop already running"
3. ✅ All 2,151 tests executable
4. ✅ CI/CD pipeline green
5. ✅ Production deployed and verified
6. ✅ Documentation complete
7. ✅ Code coverage maintained at 79%+

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
