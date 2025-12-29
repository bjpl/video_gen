# GOAP Visual Roadmap - Portfolio Readiness
## Test Infrastructure Fix to Production Deployment

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     PORTFOLIO READINESS GOAP PLAN                       │
│                                                                         │
│  Current State: Test infrastructure broken (event loop conflict)       │
│  Goal State: Production deployed, portfolio ready, 95%+ tests passing  │
│  Critical Path: 9 actions, 4.5-12.5 hours                             │
└─────────────────────────────────────────────────────────────────────────┘

╔═══════════════════════════════════════════════════════════════════════╗
║                          WORLD STATE MODEL                            ║
╚═══════════════════════════════════════════════════════════════════════╝

CURRENT STATE (S₀):                     DESIRED STATE (S*):
┌──────────────────────────┐           ┌──────────────────────────┐
│ test_infrastructure: 6/10│           │ test_infrastructure: 10/10│
│ event_loop_conflict: YES │  ──────>  │ event_loop_conflict: NO  │
│ tests_passing: UNKNOWN   │           │ tests_passing: 95%+      │
│ deployment_ready: NO     │           │ deployment_ready: YES    │
│ portfolio_ready: NO      │           │ portfolio_ready: YES     │
└──────────────────────────┘           └──────────────────────────┘

╔═══════════════════════════════════════════════════════════════════════╗
║                        CRITICAL PATH (9 ACTIONS)                      ║
╚═══════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────────┐
│ ACTION 1: ANALYZE_PYTEST_ASYNCIO_CONFLICT                           │
├─────────────────────────────────────────────────────────────────────┤
│ Duration: 30 min │ Complexity: Medium │ Risk: Low                  │
│                                                                     │
│ Preconditions:                                                      │
│  • Access to conftest.py and pytest.ini                           │
│  • pytest-asyncio documentation available                          │
│                                                                     │
│ Actions:                                                            │
│  1. Read pytest-asyncio 0.23.4 documentation                       │
│  2. Analyze event_loop fixture (conftest.py lines 39-44)          │
│  3. Understand asyncio_mode=auto behavior                          │
│  4. Identify conflict mechanism                                    │
│                                                                     │
│ Effects:                                                            │
│  ✓ conflict_mechanism_understood = True                            │
│  ✓ solution_approaches_identified = [A, B, C]                      │
└─────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│ ACTION 2: DESIGN_TEST_FIXTURE_SOLUTION                              │
├─────────────────────────────────────────────────────────────────────┤
│ Duration: 20 min │ Complexity: Medium │ Risk: Low                  │
│                                                                     │
│ Preconditions:                                                      │
│  • conflict_mechanism_understood = True                            │
│  • Solution approaches identified                                  │
│                                                                     │
│ Evaluate Options:                                                   │
│  Option A: Remove session-scoped fixture (RECOMMENDED) ⭐          │
│  Option B: Change to function-scoped fixture                       │
│  Option C: Disable asyncio_mode=auto                               │
│                                                                     │
│ Effects:                                                            │
│  ✓ solution_selected = "Option A"                                  │
│  ✓ implementation_plan_created = True                              │
└─────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│ ACTION 3: IMPLEMENT_FIXTURE_FIX                                     │
├─────────────────────────────────────────────────────────────────────┤
│ Duration: 15 min │ Complexity: Low │ Risk: Medium                  │
│                                                                     │
│ Preconditions:                                                      │
│  • solution_selected = True                                        │
│  • Git feature branch created                                      │
│                                                                     │
│ Implementation:                                                     │
│  1. git checkout -b fix/pytest-asyncio-event-loop-conflict        │
│  2. Edit tests/conftest.py (remove lines 39-44)                   │
│  3. Add documentation comment explaining change                    │
│  4. Verify pytest.ini has asyncio_mode=auto                        │
│                                                                     │
│ Code Change:                                                        │
│  # Remove session-scoped event_loop fixture                        │
│  # (conflicts with asyncio_mode=auto)                              │
│                                                                     │
│ Effects:                                                            │
│  ✓ conflicting_fixture_removed = True                              │
│  ✓ tests_updated = True                                            │
└─────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│ ACTION 4: VALIDATE_ASYNC_TESTS                                      │
├─────────────────────────────────────────────────────────────────────┤
│ Duration: 30 min │ Complexity: Low │ Risk: Low                     │
│                                                                     │
│ Preconditions:                                                      │
│  • conflicting_fixture_removed = True                              │
│  • Test environment configured                                     │
│                                                                     │
│ Validation Commands:                                                │
│  pytest tests/ -k "async" -v                                       │
│  pytest tests/ -m "not slow" -v                                    │
│                                                                     │
│ Success Criteria:                                                   │
│  • Zero RuntimeError: "event loop already running"                 │
│  • async_client fixture functional                                 │
│  • edge_tts mocking works (AsyncMock tests pass)                  │
│                                                                     │
│ Effects:                                                            │
│  ✓ async_tests_passing = True/False                                │
│  ✓ initial_pass_rate_measured = X%                                 │
└─────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│ ACTION 5: RUN_COMPREHENSIVE_TEST_SUITE                              │
├─────────────────────────────────────────────────────────────────────┤
│ Duration: 60 min │ Complexity: Low │ Risk: Low                     │
│                                                                     │
│ Preconditions:                                                      │
│  • async_tests_passing = True                                      │
│  • Basic validation complete                                       │
│                                                                     │
│ Test Suites to Run:                                                 │
│  • Full suite: pytest tests/ -v                                    │
│  • With coverage: --cov=video_gen --cov=app                        │
│  • Slow tests: pytest tests/ -m "slow" -v                          │
│  • E2E tests: pytest tests/e2e/ -v                                 │
│  • Browser tests: pytest tests/frontend/ -v                        │
│                                                                     │
│ Metrics to Capture:                                                 │
│  • Total pass rate (target: ≥95%)                                  │
│  • Code coverage (maintain ≥79%)                                   │
│  • Critical issue count                                            │
│  • Deployment blocker count                                        │
│                                                                     │
│ Effects:                                                            │
│  ✓ full_suite_pass_rate = X%                                       │
│  ✓ coverage_maintained = True/False                                │
│  ✓ critical_issues = [...]                                         │
└─────────────────────────────────────────────────────────────────────┘
                                ↓
                     ┌──────────────────┐
                     │  DECISION POINT  │
                     │ Pass Rate ≥ 95%? │
                     └──────────────────┘
                      ↓                ↓
                    YES               NO
                      ↓                ↓
                 [Skip Action 6]  [Execute Action 6]
                      ↓                ↓
                      └────────┬───────┘
                               ↓
┌─────────────────────────────────────────────────────────────────────┐
│ ACTION 6: FIX_REMAINING_CRITICAL_ISSUES (CONDITIONAL)               │
├─────────────────────────────────────────────────────────────────────┤
│ Duration: 2-8 hrs │ Complexity: Variable │ Risk: Medium            │
│                                                                     │
│ Triggered When:                                                     │
│  • full_suite_pass_rate < 0.95  OR                                 │
│  • deployment_blocker_count > 0                                    │
│                                                                     │
│ Process:                                                            │
│  For each critical issue:                                          │
│   1. Analyze root cause                                            │
│   2. Design minimal fix                                            │
│   3. Implement fix                                                 │
│   4. Validate with targeted tests                                  │
│   5. Re-run affected test suite                                    │
│   6. Ensure no regressions                                         │
│                                                                     │
│ Effects:                                                            │
│  ✓ critical_issues = []                                            │
│  ✓ deployment_blockers = 0                                         │
│  ✓ pass_rate ≥ 0.95                                                │
└─────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│ ACTION 7: UPDATE_CI_CD_PIPELINE                                     │
├─────────────────────────────────────────────────────────────────────┤
│ Duration: 50 min │ Complexity: Low │ Risk: Low                     │
│                                                                     │
│ Preconditions:                                                      │
│  • Local tests passing at ≥95%                                     │
│  • Fixture changes committed                                       │
│                                                                     │
│ Actions:                                                            │
│  1. Push feature branch to GitHub                                  │
│  2. Monitor CI/CD workflows:                                        │
│     • .github/workflows/test-fast.yml                              │
│     • .github/workflows/test-full.yml                              │
│     • .github/workflows/deploy-production.yml                      │
│  3. Review CI logs for environment-specific issues                 │
│  4. Fix any CI-specific failures                                   │
│  5. Verify coverage reports generated                              │
│                                                                     │
│ Success Criteria:                                                   │
│  • All GitHub Actions workflows pass (green checkmarks)            │
│  • Coverage reports generated and uploaded                         │
│  • No CI-specific test failures                                    │
│                                                                     │
│ Effects:                                                            │
│  ✓ ci_cd_green = True                                              │
│  ✓ all_workflows_passing = True                                    │
│  ✓ deployment_pipeline_ready = True                                │
└─────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│ ACTION 8: MERGE_AND_DEPLOY                                          │
├─────────────────────────────────────────────────────────────────────┤
│ Duration: 30 min │ Complexity: Low │ Risk: Low                     │
│                                                                     │
│ Preconditions:                                                      │
│  • ci_cd_green = True                                              │
│  • pass_rate ≥ 0.95                                                │
│  • deployment_blockers = 0                                         │
│                                                                     │
│ Deployment Process:                                                 │
│  1. Create pull request to main branch                             │
│  2. Review changes (code review if team process)                   │
│  3. Merge to main branch                                           │
│  4. Monitor main branch CI/CD                                      │
│  5. Execute production deployment                                  │
│  6. Verify deployment health:                                      │
│     • Application starts successfully                              │
│     • API endpoints responsive                                     │
│     • No runtime errors in logs                                    │
│  7. Smoke test critical functionality                              │
│                                                                     │
│ Rollback Plan:                                                      │
│  • If deployment fails: revert merge, investigate logs            │
│  • If tests fail in production: rollback to previous version      │
│                                                                     │
│ Effects:                                                            │
│  ✓ fix_merged = True                                               │
│  ✓ production_deployed = True                                      │
│  ✓ deployment_verified = True                                      │
└─────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│ ACTION 9: DOCUMENT_AND_STORE_PATTERNS                               │
├─────────────────────────────────────────────────────────────────────┤
│ Duration: 45 min │ Complexity: Low │ Risk: None                    │
│                                                                     │
│ Preconditions:                                                      │
│  • production_deployed = True                                      │
│  • deployment_verified = True                                      │
│                                                                     │
│ Documentation Tasks:                                                │
│  1. Create completion report:                                      │
│     docs/planning/GOAP_PORTFOLIO_READINESS_COMPLETION.md          │
│  2. Update project documentation:                                  │
│     • README.md (test instructions)                                │
│     • docs/testing/TEST_INFRASTRUCTURE.md                          │
│  3. Store memory patterns:                                         │
│     • pytest-asyncio best practices                                │
│     • Event loop fixture patterns                                  │
│     • GOAP planning methodology                                    │
│  4. Update daily log: daily_logs/2025-12-23.md                    │
│  5. Create portfolio presentation notes                            │
│                                                                     │
│ Memory Patterns to Store:                                           │
│  • pytest_asyncio_configuration                                    │
│  • event_loop_conflict_resolution                                  │
│  • goap_test_infrastructure_planning                               │
│                                                                     │
│ Effects:                                                            │
│  ✓ documentation_complete = True                                   │
│  ✓ memory_patterns_stored = True                                   │
│  ✓ portfolio_ready = True                                          │
│  ✓ lessons_learned_captured = True                                 │
└─────────────────────────────────────────────────────────────────────┘
                                ↓
                   ┌──────────────────────┐
                   │  GOAL STATE ACHIEVED │
                   │  Portfolio Ready! 🎉 │
                   └──────────────────────┘

╔═══════════════════════════════════════════════════════════════════════╗
║                          SUCCESS METRICS                              ║
╚═══════════════════════════════════════════════════════════════════════╝

┌──────────────────────────┬──────────┬──────────┬─────────────────┐
│ Metric                   │ Current  │ Target   │ Status          │
├──────────────────────────┼──────────┼──────────┼─────────────────┤
│ Test Pass Rate           │ Unknown  │ ≥95%     │ 🔴 Blocked      │
│ Event Loop Errors        │ Present  │ 0        │ 🔴 Critical     │
│ Test Suite Execution     │ Blocked  │ Complete │ 🔴 Blocked      │
│ CI/CD Pipeline           │ Unknown  │ Green    │ 🟡 Pending      │
│ Code Coverage            │ 79%      │ ≥79%     │ 🟢 Maintained   │
│ Deployment Status        │ Blocked  │ Success  │ 🔴 Blocked      │
│ Documentation            │ 9/10     │ Complete │ 🟢 Excellent    │
│ Portfolio Readiness      │ No       │ Yes      │ 🔴 Blocked      │
└──────────────────────────┴──────────┴──────────┴─────────────────┘

Legend: 🟢 Good | 🟡 In Progress | 🔴 Needs Action

╔═══════════════════════════════════════════════════════════════════════╗
║                        TIME & COMPLEXITY MATRIX                       ║
╚═══════════════════════════════════════════════════════════════════════╝

┌────────────┬──────────┬────────────┬──────────┬─────────────────┐
│ Action     │ Duration │ Complexity │ Risk     │ Dependencies    │
├────────────┼──────────┼────────────┼──────────┼─────────────────┤
│ Action 1   │  30 min  │ Medium     │ Low      │ None            │
│ Action 2   │  20 min  │ Medium     │ Low      │ Action 1        │
│ Action 3   │  15 min  │ Low        │ Medium   │ Action 2        │
│ Action 4   │  30 min  │ Low        │ Low      │ Action 3        │
│ Action 5   │  60 min  │ Low        │ Low      │ Action 4        │
│ Action 6   │ 0-8 hrs  │ Variable   │ Medium   │ Action 5 (cond) │
│ Action 7   │  50 min  │ Low        │ Low      │ Action 5/6      │
│ Action 8   │  30 min  │ Low        │ Low      │ Action 7        │
│ Action 9   │  45 min  │ Low        │ None     │ Action 8        │
├────────────┼──────────┼────────────┼──────────┼─────────────────┤
│ TOTAL      │ 4.5-12.5h│ Low-Med    │ Low      │ Sequential      │
└────────────┴──────────┴────────────┴──────────┴─────────────────┘

╔═══════════════════════════════════════════════════════════════════════╗
║                           RISK MITIGATION                             ║
╚═══════════════════════════════════════════════════════════════════════╝

Risk 1: Fixture removal breaks other tests
├─ Mitigation: Check all fixture dependencies before removal
└─ Contingency: Revert and use function-scoped fixture instead

Risk 2: async_client fixture depends on session event_loop
├─ Mitigation: Test async_client immediately after change
└─ Contingency: Update async_client to use auto-provided loop

Risk 3: CI/CD environment behaves differently
├─ Mitigation: Test in CI early (Action 7)
└─ Contingency: Add CI-specific configuration

Risk 4: 95% pass rate not achieved
├─ Mitigation: Comprehensive analysis in Action 5
└─ Contingency: Execute Action 6 for remaining issues

Risk 5: Production deployment fails
├─ Mitigation: Smoke tests and health checks
└─ Contingency: Rollback procedure available

╔═══════════════════════════════════════════════════════════════════════╗
║                      QUICK COMMAND REFERENCE                          ║
╚═══════════════════════════════════════════════════════════════════════╝

Git Workflow:
  git checkout -b fix/pytest-asyncio-event-loop-conflict
  # Make changes
  git add tests/conftest.py
  git commit -m "fix: Remove session-scoped event_loop fixture"
  git push -u origin fix/pytest-asyncio-event-loop-conflict

Testing Commands:
  pytest tests/ -k "async" -v              # Async tests only
  pytest tests/ -m "not slow" -v           # Fast tests
  pytest tests/ --cov=video_gen --cov=app  # With coverage
  pytest tests/e2e/ -v                     # E2E tests

CI/CD Monitoring:
  gh workflow view test-fast
  gh workflow view test-full
  gh run list --branch fix/pytest-asyncio-event-loop-conflict

╔═══════════════════════════════════════════════════════════════════════╗
║                            NEXT STEPS                                 ║
╚═══════════════════════════════════════════════════════════════════════╝

1. ✅ Review GOAP plan (COMPLETE - you are here)
2. ⬜ Execute Action 1: Analyze Conflict (30 min)
3. ⬜ Execute Action 2: Design Solution (20 min)
4. ⬜ Execute Action 3: Implement Fix (15 min)
5. ⬜ Execute Action 4: Validate Async Tests (30 min)
6. ⬜ Execute Action 5: Run Full Suite (60 min)
7. ⬜ Execute Action 6: Fix Critical Issues (if needed)
8. ⬜ Execute Action 7: Update CI/CD (50 min)
9. ⬜ Execute Action 8: Merge & Deploy (30 min)
10. ⬜ Execute Action 9: Document & Store Patterns (45 min)

╔═══════════════════════════════════════════════════════════════════════╗
║                         PLAN STATUS                                   ║
╚═══════════════════════════════════════════════════════════════════════╝

Status: ✅ READY FOR EXECUTION
Estimated Completion: Within 1 working day
Risk Level: LOW (well-understood problem, clear solution)
Deployment Blocker: YES (P0 priority)

Generated: 2025-12-23
Planning Methodology: GOAP with SPARC Integration
Full Plan: docs/planning/GOAP_PORTFOLIO_READINESS_PLAN.md
```
