# Goal-Oriented Action Planning (GOAP) - Portfolio Readiness
## video_gen Project Full Production Deployment

**Date:** 2025-12-23
**Status:** PLANNING PHASE
**Priority:** P0 - CRITICAL
**Planning Methodology:** GOAP with SPARC Integration

---

## Executive Summary

This GOAP plan provides a systematic approach to achieve full portfolio readiness for the video_gen project. The critical path focuses on resolving test infrastructure issues related to pytest-asyncio event loop configuration conflicts.

**Current State Assessment:**
- Architecture: 9/10 (excellent, production-ready)
- Code Quality: 8.5/10 (excellent, minor issues)
- Production Readiness: 8.5/10 (approved with issues)
- Documentation: 9/10 (266 files, comprehensive)
- Test Infrastructure: 6/10 (CRITICAL - configuration conflict)

**Goal State:**
- Test Infrastructure: 10/10 (all tests passing, stable)
- Test Pass Rate: 95%+ (currently unclear due to event loop errors)
- Production Deployment: Ready (blocked by test failures)
- Portfolio Presentation: Complete (deployment-verified)

---

## GOAP Analysis

### 1. Goal Definition

**Primary Goal:** Achieve Portfolio-Ready Production Deployment

**Success Criteria:**
1. All tests passing with 95%+ pass rate
2. No event loop conflicts in test execution
3. Test infrastructure stable and maintainable
4. CI/CD pipeline green on all branches
5. Production deployment verified and documented
6. Memory patterns stored for future learning
7. Zero critical or high-severity issues

**Measurable Outcomes:**
- Test pass rate: Target 95%+ (from unknown current state)
- Test execution time: <5 minutes for fast suite
- Code coverage: Maintain 79%+ (current level)
- Zero RuntimeError exceptions in test runs
- All 2151 tests executable without configuration errors

---

### 2. World State Analysis

#### Current State (S₀)

```python
current_state = {
    # Test Infrastructure
    "test_configuration": {
        "pytest_asyncio_mode": "auto",  # In pytest.ini line 43
        "event_loop_fixture": "session-scoped",  # In conftest.py lines 39-44
        "asyncio_plugin": "pytest-asyncio==0.23.4",
        "total_tests": 2151,
        "test_collection": "successful",
        "conflict_detected": True  # CRITICAL ISSUE
    },

    # Issue Details
    "identified_problems": {
        "root_cause": "session-scoped event_loop fixture conflicts with asyncio_mode=auto",
        "error_type": "RuntimeError: This event loop is already running",
        "affected_tests": "async tests (584 collected with 'async' keyword)",
        "impact": "test infrastructure unstable, deployment blocked"
    },

    # Project Health
    "codebase_status": {
        "architecture_score": 9.0,
        "code_quality": 8.5,
        "documentation": 9.0,
        "core_functionality": "working",
        "core_tests": "passing (81/81 renderer tests confirmed)",
        "async_tests": "failing/unknown due to fixture conflict"
    },

    # Dependencies
    "external_dependencies": {
        "pytest": "7.4.4",
        "pytest_asyncio": "0.23.4",
        "python": "3.10.11",
        "platform": "win32",
        "plugins": ["anyio", "dash", "Faker", "asyncio", "cov", "timeout", "xdist"]
    },

    # Knowledge State
    "known_patterns": {
        "event_loop_handling": "documented in ADR_001",
        "nested_loops": "handled via ThreadPoolExecutor in code",
        "test_fixtures": "comprehensive mock fixtures exist",
        "ci_cd": "GitHub Actions workflows configured"
    }
}
```

#### Desired State (S*)

```python
goal_state = {
    # Test Infrastructure
    "test_configuration": {
        "pytest_asyncio_mode": "auto",  # Keep modern approach
        "event_loop_fixture": "removed or function-scoped",  # FIX: Remove conflict
        "asyncio_plugin": "pytest-asyncio==0.23.4",
        "total_tests": 2151,
        "test_pass_rate": 0.95,  # 95%+ passing
        "conflict_detected": False  # RESOLVED
    },

    # Issue Resolution
    "problems_resolved": {
        "root_cause": "fixed - removed conflicting fixture",
        "error_type": "none",
        "affected_tests": "all async tests passing",
        "impact": "test infrastructure stable, deployment unblocked"
    },

    # Production Ready
    "deployment_status": {
        "ci_cd_green": True,
        "production_verified": True,
        "documentation_complete": True,
        "portfolio_ready": True
    },

    # Learning State
    "memory_patterns": {
        "test_fixes_stored": True,
        "goap_plan_documented": True,
        "lessons_learned_captured": True,
        "future_reference_available": True
    }
}
```

---

### 3. Action Sequence with Preconditions & Effects

#### Action 1: ANALYZE_PYTEST_ASYNCIO_CONFLICT

**Description:** Deep analysis of pytest-asyncio configuration and fixture conflict

**Preconditions:**
- Access to tests/conftest.py
- Access to pytest.ini
- pytest-asyncio documentation available
- Understanding of event loop lifecycle

**Actions:**
1. Read pytest-asyncio 0.23.4 changelog and documentation
2. Analyze conftest.py event_loop fixture (lines 39-44)
3. Understand asyncio_mode=auto behavior
4. Identify exact conflict mechanism
5. Document findings

**Effects:**
- `conflict_mechanism_understood = True`
- `solution_approaches_identified = [approach1, approach2, approach3]`
- `risk_assessment_complete = True`

**Estimated Time:** 30 minutes
**Complexity:** Medium (requires documentation research)
**Risk:** Low (read-only analysis)

---

#### Action 2: DESIGN_TEST_FIXTURE_SOLUTION

**Description:** Design the optimal solution for event loop fixture configuration

**Preconditions:**
- `conflict_mechanism_understood = True`
- Solution approaches identified
- Test structure analyzed

**Actions:**
1. Evaluate solution options:
   - **Option A:** Remove session-scoped event_loop fixture entirely (recommended)
   - **Option B:** Change to function-scoped event_loop fixture
   - **Option C:** Disable asyncio_mode=auto and manage manually
2. Choose optimal solution based on:
   - Compatibility with pytest-asyncio 0.23.4
   - Minimal code changes required
   - Maintainability
   - Industry best practices
3. Design test fixture changes
4. Plan validation strategy

**Effects:**
- `solution_selected = "Option A: Remove conflicting fixture"`
- `implementation_plan_created = True`
- `test_strategy_defined = True`

**Estimated Time:** 20 minutes
**Complexity:** Medium (requires architectural decision)
**Risk:** Low (design phase, no code changes)

**Recommended Solution:**
According to pytest-asyncio 0.23.4 documentation, `asyncio_mode=auto` automatically provides event loop fixtures for each test. The session-scoped event_loop fixture in conftest.py is redundant and conflicts with this modern approach.

---

#### Action 3: IMPLEMENT_FIXTURE_FIX

**Description:** Implement the selected solution in test configuration

**Preconditions:**
- `solution_selected = True`
- `implementation_plan_created = True`
- Git branch created for changes
- Backup of current configuration

**Actions:**
1. Create git feature branch: `fix/pytest-asyncio-event-loop-conflict`
2. Edit tests/conftest.py:
   - Remove or comment out event_loop fixture (lines 39-44)
   - Add documentation comment explaining why
3. Verify pytest.ini configuration:
   - Confirm asyncio_mode=auto is present
   - Add any additional markers if needed
4. Update any tests that explicitly used event_loop fixture
5. Run local test validation

**Effects:**
- `conflicting_fixture_removed = True`
- `tests_updated = True`
- `local_validation_started = True`

**Estimated Time:** 15 minutes
**Complexity:** Low (simple configuration change)
**Risk:** Medium (could break tests if async_client fixture depends on it)

**Code Change:**
```python
# tests/conftest.py lines 39-44 (REMOVE or COMMENT):
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

---

#### Action 4: VALIDATE_ASYNC_TESTS

**Description:** Validate that async tests now execute without event loop errors

**Preconditions:**
- `conflicting_fixture_removed = True`
- Test environment configured
- pytest-asyncio plugin active

**Actions:**
1. Run async test subset:
   ```bash
   pytest tests/ -k "async" -v
   ```
2. Check for RuntimeError exceptions
3. Verify async_client fixture still works (line 214-218 in conftest.py)
4. Test edge_tts mocking (uses AsyncMock)
5. Run full test suite on fast tests:
   ```bash
   pytest tests/ -m "not slow" -v
   ```
6. Analyze pass/fail rate
7. Document any remaining failures

**Effects:**
- `async_tests_passing = True/False`
- `pass_rate_measured = X%`
- `remaining_issues_identified = [...]`

**Estimated Time:** 10 minutes (execution) + 20 minutes (analysis)
**Complexity:** Low (automated testing)
**Risk:** Low (read-only validation)

**Success Criteria:**
- Zero RuntimeError: "This event loop is already running"
- async_client fixture functional
- edge_tts mocking works
- Pass rate ≥ 95%

---

#### Action 5: RUN_COMPREHENSIVE_TEST_SUITE

**Description:** Execute full test suite including slow tests

**Preconditions:**
- `async_tests_passing = True`
- Basic validation complete
- CI environment available

**Actions:**
1. Run complete test suite:
   ```bash
   pytest tests/ --cov=video_gen --cov=app --cov-report=html -v
   ```
2. Include slow tests:
   ```bash
   pytest tests/ -m "slow" -v
   ```
3. Run E2E tests:
   ```bash
   pytest tests/e2e/ -v
   ```
4. Run browser tests (if Selenium available):
   ```bash
   pytest tests/frontend/ -v
   ```
5. Generate coverage report
6. Analyze all failures
7. Categorize issues (critical, high, medium, low)

**Effects:**
- `full_suite_pass_rate = X%`
- `coverage_maintained = True/False`
- `critical_issues = [...]`
- `deployment_blocker_count = N`

**Estimated Time:** 30 minutes (execution) + 30 minutes (analysis)
**Complexity:** Low (automated testing)
**Risk:** Low (validation phase)

---

#### Action 6: FIX_REMAINING_CRITICAL_ISSUES

**Description:** Address any critical or high-severity issues found in comprehensive testing

**Preconditions:**
- `full_suite_pass_rate < 0.95` OR `deployment_blocker_count > 0`
- Issues categorized and prioritized
- Root causes identified

**Actions:**
1. For each critical issue:
   - Analyze root cause
   - Design minimal fix
   - Implement fix
   - Validate fix with targeted test
   - Re-run affected test suite
2. Update documentation if needed
3. Ensure no regressions introduced

**Effects:**
- `critical_issues = []`
- `pass_rate_improved = True`
- `deployment_blockers = 0`

**Estimated Time:** Variable (2-8 hours depending on issues found)
**Complexity:** Variable (depends on issue complexity)
**Risk:** Medium (code changes required)

**Note:** This action may not be needed if Action 4 and 5 show 95%+ pass rate.

---

#### Action 7: UPDATE_CI_CD_PIPELINE

**Description:** Ensure CI/CD pipeline runs updated test suite successfully

**Preconditions:**
- Local tests passing at 95%+ rate
- Fixture changes committed to feature branch
- GitHub Actions workflows exist

**Actions:**
1. Push feature branch to GitHub
2. Monitor CI/CD workflow execution:
   - Check .github/workflows/test-*.yml
   - Verify all jobs pass (test-fast, test-full, deploy-production)
3. Review CI/CD logs for any environment-specific issues
4. Fix any CI-specific failures (e.g., missing dependencies)
5. Ensure coverage reports generated
6. Verify deployment workflows ready

**Effects:**
- `ci_cd_green = True`
- `all_workflows_passing = True`
- `deployment_pipeline_ready = True`

**Estimated Time:** 20 minutes (monitoring) + 30 minutes (fixes if needed)
**Complexity:** Low (infrastructure validation)
**Risk:** Low (CI environment well-configured)

---

#### Action 8: MERGE_AND_DEPLOY

**Description:** Merge fix to main branch and execute production deployment

**Preconditions:**
- `ci_cd_green = True`
- `pass_rate ≥ 0.95`
- `deployment_blockers = 0`
- Code review completed (if team process requires)

**Actions:**
1. Create pull request: fix/pytest-asyncio-event-loop-conflict → main
2. Review changes one final time
3. Merge to main branch
4. Monitor main branch CI/CD
5. Execute production deployment (if auto-deploy not enabled)
6. Verify deployment health:
   - Application starts successfully
   - API endpoints responsive
   - No runtime errors in logs
7. Smoke test critical functionality

**Effects:**
- `fix_merged = True`
- `production_deployed = True`
- `deployment_verified = True`

**Estimated Time:** 30 minutes
**Complexity:** Low (standard deployment process)
**Risk:** Low (comprehensive testing completed)

---

#### Action 9: DOCUMENT_AND_STORE_PATTERNS

**Description:** Document the fix and store patterns for future learning

**Preconditions:**
- `production_deployed = True`
- `deployment_verified = True`
- Solution proven successful

**Actions:**
1. Create completion report in docs/planning/:
   - GOAP_PORTFOLIO_READINESS_COMPLETION.md
   - Include: problem, solution, results, lessons learned
2. Update relevant documentation:
   - docs/testing/TEST_INFRASTRUCTURE.md (if exists)
   - README.md test instructions
   - CONTRIBUTING.md (if exists)
3. Store patterns in memory for future reference:
   - pytest-asyncio best practices
   - Event loop fixture patterns
   - GOAP planning methodology
4. Update daily log: daily_logs/2025-12-23.md
5. Create portfolio presentation notes

**Effects:**
- `documentation_complete = True`
- `memory_patterns_stored = True`
- `portfolio_ready = True`
- `lessons_learned_captured = True`

**Estimated Time:** 45 minutes
**Complexity:** Low (documentation)
**Risk:** None

---

### 4. Dependency Graph

```
Dependency Graph (CRITICAL PATH in bold):

**Action 1: ANALYZE_PYTEST_ASYNCIO_CONFLICT**
    ↓
**Action 2: DESIGN_TEST_FIXTURE_SOLUTION**
    ↓
**Action 3: IMPLEMENT_FIXTURE_FIX**
    ↓
**Action 4: VALIDATE_ASYNC_TESTS**
    ↓
**Action 5: RUN_COMPREHENSIVE_TEST_SUITE**
    ↓
Action 6: FIX_REMAINING_CRITICAL_ISSUES (conditional)
    ↓
**Action 7: UPDATE_CI_CD_PIPELINE**
    ↓
**Action 8: MERGE_AND_DEPLOY**
    ↓
**Action 9: DOCUMENT_AND_STORE_PATTERNS**


Parallel Opportunities:
- None (sequential critical path required for this fix)

Conditional Actions:
- Action 6 only if pass_rate < 95% or critical issues found
```

---

### 5. Complexity and Risk Assessment

#### Action Complexity Matrix

| Action | Complexity | Estimated Time | Risk Level | Impact if Failed |
|--------|-----------|----------------|------------|------------------|
| 1. Analyze Conflict | Medium | 30 min | Low | Delayed understanding, wrong fix |
| 2. Design Solution | Medium | 20 min | Low | Suboptimal solution chosen |
| 3. Implement Fix | Low | 15 min | Medium | Tests still broken |
| 4. Validate Async Tests | Low | 30 min | Low | Issues not caught early |
| 5. Run Full Suite | Low | 60 min | Low | Unknown issues remain |
| 6. Fix Critical Issues | Variable | 2-8 hrs | Medium | Deployment blocked |
| 7. Update CI/CD | Low | 50 min | Low | Deployment pipeline broken |
| 8. Merge & Deploy | Low | 30 min | Low | Production issues |
| 9. Document Patterns | Low | 45 min | None | Lost learning opportunity |

**Total Estimated Time (Best Case):** 4.5 hours
**Total Estimated Time (With Action 6):** 6.5-12.5 hours
**Critical Path Length:** 9 actions (8 if Action 6 not needed)

#### Risk Mitigation Strategies

**Risk 1: Fixture removal breaks other tests**
- **Mitigation:** Carefully check all uses of event_loop fixture before removal
- **Contingency:** Revert change, use function-scoped fixture instead

**Risk 2: async_client fixture depends on session event_loop**
- **Mitigation:** Test async_client fixture immediately after change
- **Contingency:** Update async_client to use auto-provided event loop

**Risk 3: CI/CD environment behaves differently than local**
- **Mitigation:** Test in CI early (Action 7)
- **Contingency:** Add CI-specific configuration if needed

**Risk 4: 95% pass rate not achieved after fix**
- **Mitigation:** Comprehensive analysis in Action 5
- **Contingency:** Execute Action 6 to address remaining issues

**Risk 5: Production deployment fails**
- **Mitigation:** Smoke tests and health checks in Action 8
- **Contingency:** Rollback procedure, investigate logs

---

### 6. Success Metrics

#### Primary Metrics

1. **Test Pass Rate:** ≥ 95%
   - Current: Unknown (blocked by event loop error)
   - Target: ≥ 95%
   - Measurement: `pytest --tb=short -v | grep "passed"`

2. **Event Loop Errors:** 0
   - Current: RuntimeError present
   - Target: 0 RuntimeError exceptions
   - Measurement: `pytest -v 2>&1 | grep "RuntimeError.*event loop"`

3. **Test Suite Execution:** Complete
   - Current: 2151 tests collected, execution blocked
   - Target: All tests execute, results clear
   - Measurement: `pytest --co -q | grep "test session"`

4. **CI/CD Pipeline:** Green
   - Current: Unknown
   - Target: All workflows passing
   - Measurement: GitHub Actions status badges

5. **Code Coverage:** ≥ 79%
   - Current: 79%
   - Target: Maintain or improve
   - Measurement: `pytest --cov-report=term | grep "TOTAL"`

#### Secondary Metrics

6. **Deployment Status:** Successful
   - Target: Production deployed and verified
   - Measurement: Manual deployment verification

7. **Documentation:** Complete
   - Target: Fix documented, patterns stored
   - Measurement: Completion report exists

8. **Time to Resolution:** < 12 hours
   - Target: Fix implemented and deployed within 1 working day
   - Measurement: From planning to deployment time

---

### 7. GOAP Planning Metadata

#### World State Variables

```python
# Binary State Variables
binary_vars = [
    "conflict_mechanism_understood",
    "solution_selected",
    "implementation_plan_created",
    "conflicting_fixture_removed",
    "tests_updated",
    "async_tests_passing",
    "ci_cd_green",
    "fix_merged",
    "production_deployed",
    "deployment_verified",
    "documentation_complete",
    "memory_patterns_stored",
    "portfolio_ready"
]

# Numeric State Variables
numeric_vars = {
    "pass_rate": (0.0, 1.0),  # 0-100%
    "test_execution_time": (0, 3600),  # seconds
    "code_coverage": (0.0, 1.0),  # 0-100%
    "deployment_blocker_count": (0, 100),  # count
    "critical_issue_count": (0, 100),  # count
}

# List State Variables
list_vars = [
    "solution_approaches_identified",
    "remaining_issues_identified",
    "critical_issues",
]
```

#### Action Costs

```python
action_costs = {
    "ANALYZE_PYTEST_ASYNCIO_CONFLICT": {
        "time": 30,  # minutes
        "cognitive_load": "medium",
        "risk": "low",
        "reversibility": "full"
    },
    "DESIGN_TEST_FIXTURE_SOLUTION": {
        "time": 20,
        "cognitive_load": "medium",
        "risk": "low",
        "reversibility": "full"
    },
    "IMPLEMENT_FIXTURE_FIX": {
        "time": 15,
        "cognitive_load": "low",
        "risk": "medium",
        "reversibility": "full (via git)"
    },
    "VALIDATE_ASYNC_TESTS": {
        "time": 30,
        "cognitive_load": "low",
        "risk": "low",
        "reversibility": "n/a (read-only)"
    },
    "RUN_COMPREHENSIVE_TEST_SUITE": {
        "time": 60,
        "cognitive_load": "low",
        "risk": "low",
        "reversibility": "n/a (read-only)"
    },
    "FIX_REMAINING_CRITICAL_ISSUES": {
        "time": 240,  # variable, worst case
        "cognitive_load": "high",
        "risk": "medium",
        "reversibility": "full (via git)"
    },
    "UPDATE_CI_CD_PIPELINE": {
        "time": 50,
        "cognitive_load": "low",
        "risk": "low",
        "reversibility": "full"
    },
    "MERGE_AND_DEPLOY": {
        "time": 30,
        "cognitive_load": "low",
        "risk": "low",
        "reversibility": "partial (rollback possible)"
    },
    "DOCUMENT_AND_STORE_PATTERNS": {
        "time": 45,
        "cognitive_load": "low",
        "risk": "none",
        "reversibility": "n/a"
    }
}
```

#### Heuristic Function (A* Search)

```python
def heuristic(state):
    """
    Estimate cost to reach goal from current state.
    Uses Manhattan distance in state space.
    """
    h = 0

    # Critical binary variables not yet true
    if not state.conflict_mechanism_understood:
        h += 30  # Action 1
    if not state.solution_selected:
        h += 20  # Action 2
    if not state.conflicting_fixture_removed:
        h += 15  # Action 3
    if not state.async_tests_passing:
        h += 30  # Action 4
    if state.pass_rate < 0.95:
        h += 60 + 240  # Action 5 + potential Action 6
    if not state.ci_cd_green:
        h += 50  # Action 7
    if not state.production_deployed:
        h += 30  # Action 8
    if not state.documentation_complete:
        h += 45  # Action 9

    # Add cost for critical issues
    h += state.critical_issue_count * 30  # Each issue ~30 min

    # Add cost for deployment blockers
    h += state.deployment_blocker_count * 60  # Each blocker ~60 min

    return h
```

---

## Implementation Notes

### pytest-asyncio Documentation Reference

**Version:** 0.23.4
**Key Behavior:** `asyncio_mode = auto`

When `asyncio_mode=auto` is set, pytest-asyncio automatically:
1. Detects async test functions
2. Provides a function-scoped event loop for each async test
3. Handles event loop lifecycle automatically
4. Makes manual event_loop fixtures unnecessary and conflicting

**From pytest-asyncio docs:**
> "When using auto mode, you don't need to provide your own event_loop fixture. The plugin will automatically create and manage event loops for async tests."

**Conflict Explanation:**
The session-scoped event_loop fixture in tests/conftest.py creates a single event loop for the entire test session. This conflicts with pytest-asyncio's auto mode, which tries to create function-scoped event loops. The result is the RuntimeError: "This event loop is already running."

### Alternative Solutions Considered

**Option A: Remove session-scoped event_loop fixture (RECOMMENDED)**
- Pros: Aligns with pytest-asyncio best practices, simplest solution
- Cons: None identified
- Implementation: Delete lines 39-44 in tests/conftest.py

**Option B: Change to function-scoped event_loop fixture**
- Pros: Maintains explicit control
- Cons: Still potentially conflicts with auto mode, redundant
- Implementation: Change scope from "session" to "function"

**Option C: Disable asyncio_mode=auto**
- Pros: Full manual control
- Cons: More complex, goes against modern pytest-asyncio patterns
- Implementation: Remove line from pytest.ini, manage loops manually

**Selected: Option A** - Simplest, most maintainable, follows best practices.

---

## Execution Checklist

### Pre-Implementation
- [ ] Review this GOAP plan
- [ ] Confirm pytest-asyncio version (0.23.4)
- [ ] Backup current test configuration
- [ ] Create git feature branch

### Implementation Phase
- [ ] Action 1: ANALYZE_PYTEST_ASYNCIO_CONFLICT
- [ ] Action 2: DESIGN_TEST_FIXTURE_SOLUTION
- [ ] Action 3: IMPLEMENT_FIXTURE_FIX
- [ ] Action 4: VALIDATE_ASYNC_TESTS
- [ ] Action 5: RUN_COMPREHENSIVE_TEST_SUITE
- [ ] Action 6: FIX_REMAINING_CRITICAL_ISSUES (if needed)
- [ ] Action 7: UPDATE_CI_CD_PIPELINE
- [ ] Action 8: MERGE_AND_DEPLOY
- [ ] Action 9: DOCUMENT_AND_STORE_PATTERNS

### Validation Phase
- [ ] Test pass rate ≥ 95%
- [ ] Zero event loop RuntimeErrors
- [ ] CI/CD pipeline green
- [ ] Production deployment successful
- [ ] Documentation complete

### Completion Phase
- [ ] Completion report written
- [ ] Memory patterns stored
- [ ] Daily log updated
- [ ] Portfolio presentation ready

---

## SPARC Integration

This GOAP plan can be enhanced with SPARC methodology:

### Specification Phase (Action 1-2)
- Analyze requirements (current issue)
- Define success criteria (test infrastructure goals)
- Map current to desired state

### Pseudocode Phase (Action 2)
- Design solution algorithm
- Plan test validation strategy
- Outline fix implementation

### Architecture Phase (Action 3)
- Design test fixture changes
- Plan CI/CD integration
- Structure validation approach

### Refinement Phase (Action 4-6)
- TDD approach to validation
- Iterative testing and fixing
- Continuous improvement

### Completion Phase (Action 7-9)
- Integration with CI/CD
- Production deployment
- Documentation and learning capture

---

## Appendix: Test Infrastructure Details

### Current Test Structure
- Total tests: 2,151
- Test categories:
  - Unit tests (fast)
  - Integration tests
  - E2E tests (slow)
  - Browser tests (Selenium)
  - Performance tests
  - Accessibility tests
  - Security tests

### Test Fixtures (tests/conftest.py)
- `event_loop` (session-scoped) - **TO BE REMOVED**
- `client` - FastAPI TestClient
- `authenticated_client` - With CSRF token
- `async_client` - AsyncClient for FastAPI
- `temp_dir` - Temporary file directory
- Mock fixtures: edge_tts, anthropic, ffmpeg
- Sample data fixtures

### pytest Configuration (pytest.ini)
- Test discovery patterns
- Markers for test organization
- asyncio_mode = auto
- Timeout settings (120s)
- Coverage configuration

### CI/CD Workflows
- `.github/workflows/test-fast.yml`
- `.github/workflows/test-full.yml`
- `.github/workflows/deploy-production.yml`

---

## Contact & Support

**Planning Document Version:** 1.0
**Last Updated:** 2025-12-23
**Next Review:** After Action 5 completion

For questions or updates to this plan, see:
- Daily logs: `daily_logs/2025-12-23.md`
- Architecture docs: `docs/architecture/`
- Test documentation: `docs/testing/` (to be created)

---

**End of GOAP Planning Document**
