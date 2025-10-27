# Test Skip Documentation

**Status:** Complete
**Date:** October 16, 2025
**Total Skipped Tests:** 180
**Related:** Plan D.6 - Test Skip Reason Documentation

## Executive Summary

This document provides comprehensive documentation for all 180 skipped tests in the video_gen project. Each skip has been categorized, justified, and assigned a priority for potential enablement.

**Key Findings:**
- **68 tests (38%)**: Adapter architecture migration (ADR_001) - Will be enabled after compatibility layer
- **55 tests (31%)**: Feature not yet implemented - Require significant development work
- **32 tests (18%)**: Conditional tests - Skip based on environment/file availability
- **18 tests (10%)**: Web server required - Integration tests needing running API
- **7 tests (4%)**: Performance/profiling tests - Run manually or in CI only

**Recommendation:** Focus on ADR_001 adapter migration first (68 tests), then evaluate feature implementation priorities.

---

## Skip Categories

### Category 1: Adapter Architecture Migration (68 tests)

**Status:** Temporary - Will be enabled after ADR_001 implementation
**Priority:** High
**Estimated Effort:** 12-15 days (per ADR_001)
**Target Date:** November 2025

**Rationale:**
The project underwent an architectural consolidation where the deprecated `app/input_adapters` module was replaced by the canonical `video_gen/input_adapters` module with an async API. These tests validate the old synchronous API and will be migrated via a compatibility layer.

**Tests Affected:**

1. **Examples Module Tests (8 tests)** - `test_adapters_coverage.py::TestExamplesAdapter`
   - `test_example_document_adapter` - Examples module removed in consolidation
   - `test_example_yaml_adapter` - Examples module removed in consolidation
   - `test_example_programmatic_adapter` - Examples module removed in consolidation
   - `test_example_factory_pattern` - Examples module removed in consolidation
   - `test_example_export_workflow` - Examples module removed in consolidation
   - `test_example_custom_adapter` - Examples module removed in consolidation
   - `test_run_all_examples_success` - Examples module removed in consolidation
   - `test_run_all_examples_error_handling` - Examples module removed in consolidation
   - **Skip Reason:** "app.input_adapters.examples module removed in adapter consolidation"
   - **Reference:** docs/architecture/ADR_001_INPUT_ADAPTER_CONSOLIDATION.md

2. **Private Method Tests (15 tests)** - `test_adapters_coverage.py::TestYouTubeAdapterCoverage`
   - `test_extract_video_id_from_url` - Private method removed
   - `test_analyze_transcript_empty` - Private method removed
   - `test_analyze_transcript_with_pauses` - Private method removed
   - `test_analyze_transcript_error_handling` - Private method removed
   - `test_extract_key_segments_empty` - Private method removed
   - `test_extract_key_segments_with_data` - Private method removed
   - `test_has_commands_detection` - Private method removed
   - `test_extract_commands_from_text` - Private method removed
   - `test_extract_key_points` - Private method removed
   - `test_summarize_text` - Private method removed
   - `test_convert_to_scenes_with_commands` - Private method removed
   - `test_convert_to_scenes_with_lists` - Private method removed
   - `test_parse_without_api` - Migrated to new adapter
   - `test_parse_invalid_video_id` - Migrated to new adapter
   - `test_fetch_transcript_error` - Migrated to new adapter
   - **Skip Reason:** "Private method removed - see ADR_001_INPUT_ADAPTER_CONSOLIDATION"
   - **Note:** These tests validated internal implementation details. New architecture uses different internal structure.

3. **ProgrammaticAdapter Tests (4 tests)** - `test_adapters_coverage.py::TestProgrammaticAdapterCoverage`
   - `test_parse_from_file` - API changed, no longer accepts file paths
   - `test_parse_file_missing_builder` - API changed
   - `test_parse_builder_direct` - Method removed
   - `test_convert_builder_to_videoset` - Internal method removed
   - **Skip Reason:** "ProgrammaticAdapter doesn't support file paths - only accepts VideoSet/dict/VideoConfig"
   - **Migration Path:** Update tests to use new dict/VideoConfig API

4. **Helper Function Tests (6 tests)** - `test_adapters_coverage.py::TestProgrammaticHelperFunctions`
   - `test_create_title_scene_minimal` - Helper removed
   - `test_create_title_scene_with_narration` - Helper removed
   - `test_create_command_scene` - Helper removed
   - `test_create_list_scene` - Helper removed
   - `test_create_outro_scene` - Helper removed
   - `test_helper_functions_with_kwargs` - Helper removed
   - **Skip Reason:** "Helper functions removed in refactor - use SceneConfig directly"
   - **Migration Path:** Replace with SceneConfig model instantiation

5. **WizardAdapter Tests (5 tests)** - `test_adapters_coverage.py::TestWizardAdapterCoverage`
   - `test_parse_raises_not_implemented` - API changed
   - `test_parse_with_options` - API changed
   - `test_parse_wizard_data_minimal` - Method removed
   - `test_parse_wizard_data_full` - Method removed
   - `test_parse_wizard_data_defaults` - Method removed
   - **Skip Reason:** "WizardAdapter.parse() requires source argument" / "parse_wizard_data() method removed"
   - **Migration Path:** Update to new adapter API

6. **Integration Tests (4 tests)** - `test_adapters_coverage.py::TestAdapterIntegration`
   - `test_create_and_export_workflow` - Deprecated helper functions
   - `test_youtube_adapter_initialization` - Constructor changed
   - `test_scene_helper_functions_coverage` - Helper functions removed
   - **Skip Reason:** Various - see inline comments
   - **Migration Path:** Update to use new APIs

7. **Deprecated API Tests (12 tests)** - `test_input_adapters.py`
   - `test_create_scene` - Method removed, use SceneConfig
   - `test_extract_video_id` - Private method removed
   - `test_has_commands` - Private method removed
   - `test_yaml_parsing` - Not implemented in async refactor
   - `test_yaml_adapter_constructor` - Constructor changed
   - `test_create_from_dict` - Method removed, use parse()
   - `test_get_adapter_max_scenes` - Parameter moved to parse()
   - `test_videoset_config` - Class removed
   - `test_export_to_yaml` - Method removed
   - **Skip Reason:** "Deprecated API: [specific method/class] removed/changed in async refactor"
   - **Migration Path:** Update to canonical API patterns

8. **Export Functionality Tests (3 tests)** - Various files
   - Tests for `export_to_yaml()` method
   - **Skip Reason:** "export_to_yaml() method removed from VideoSet - needs new export functionality"
   - **Migration Path:** Implement new export system or use VideoSet.model_dump()

**Enablement Roadmap:**
1. ✅ Phase 1: Implement compatibility layer (Days 1-2)
2. ⏳ Phase 2: Migrate tests in batches (Days 3-10)
3. ⏳ Phase 3: Remove compatibility layer (Days 11-12)
4. ⏳ Phase 4: Full async migration (Days 13-15)

**References:**
- docs/architecture/ADR_001_INPUT_ADAPTER_CONSOLIDATION.md
- docs/reports/analysis/TESTCLIENT_COMPATIBILITY_REPORT.md

---

### Category 2: Feature Not Yet Implemented (55 tests)

**Status:** Permanent until feature development
**Priority:** Variable (see subcategories)
**Estimated Effort:** 40-80 hours per feature area

**Rationale:**
These tests validate functionality that is planned but not yet implemented. They serve as specification tests and should be enabled as features are built.

#### 2.1 Audio/TTS Generation (12 tests)
**Priority:** Low (TTS library integration not critical path)
**Effort:** 20-30 hours

- `test_generators.py` - TTS implementation tests (3 tests)
  - "Requires TTS implementation"
  - "Requires TTS engine with multi-language support"
- `test_generators.py` - Audio generation tests (3 tests)
  - "Requires audio generation implementation"
  - "Requires audio conversion implementation"
- `test_generators.py` - Audio processing tests (6 tests)
  - "Requires audio processing implementation"
  - "Requires audio mixing implementation"
  - "Requires audio generator"
  - "Requires duration estimation implementation"

**Decision:** Keep skipped until TTS library integration is prioritized.

#### 2.2 Video Rendering Features (18 tests)
**Priority:** Medium (some features desired for v2.0)
**Effort:** 40-60 hours

- **Transitions** (2 tests)
  - "Requires transition implementation"
  - "Requires transition system"

- **Scene Renderers** (4 tests)
  - "Requires scene renderer"
  - "Requires scene renderer implementation"
  - "Requires code renderer"
  - "Requires bullet list renderer"
  - "Requires quote renderer"

- **Composition** (4 tests)
  - "Requires composition system"
  - "Requires overlay system"
  - "Requires image composition"

- **A/V Sync** (2 tests)
  - "Requires A/V sync implementation"
  - "Requires A/V integration"
  - "Requires sync implementation"

- **Advanced Features** (6 tests)
  - "Requires subtitle implementation"
  - "Requires animation implementation"
  - "Requires color theming"
  - "Requires font handling"

**Decision:** Evaluate which features are needed for v2.0, enable tests incrementally.

#### 2.3 Pipeline & Stage System (13 tests)
**Priority:** Low (current pipeline works well)
**Effort:** 30-40 hours

- **Stage Implementation** (4 tests)
  - "Requires stage implementation"
  - "Requires stage execution"
  - "Requires stage configuration system"
  - "Requires scene processing"

- **Full Pipeline** (9 tests)
  - "Requires full pipeline"
  - "Requires full pipeline setup"
  - "Requires full pipeline with large video"
  - "Requires full pipeline implementation"
  - "Requires full pipeline execution"
  - "Requires full pipeline and state persistence"
  - "Requires full pipeline - 5 minute max expected"

**Decision:** Keep skipped unless major pipeline refactor planned.

#### 2.4 Performance & Optimization (8 tests)
**Priority:** Low (current performance acceptable)
**Effort:** 20-30 hours

- **GPU Support** (2 tests)
  - "Requires GPU encoding setup"
  - "Requires GPU support"

- **Parallelization** (2 tests)
  - "Requires parallel rendering"
  - "Requires parallel pipeline"

- **Caching** (3 tests)
  - "Requires cache system"
  - "Requires cache implementation"
  - "Requires cache metrics"

- **Memory** (1 test)
  - "Requires memory optimization"

**Decision:** Implement only if performance issues arise.

#### 2.5 Resource Management (4 tests)
**Priority:** Low
**Effort:** 10-15 hours

- "Requires resource manager"
- "Requires resource management implementation"
- "Requires asset management"
- "Requires file validation tools"

**Decision:** Keep skipped unless resource management becomes critical.

---

### Category 3: Conditional Tests (32 tests)

**Status:** Permanent - Environmental dependency
**Priority:** Low (tests work when conditions met)
**Estimated Effort:** 0 hours (no code changes needed)

**Rationale:**
These tests skip based on runtime conditions (file existence, module availability, API keys). They work correctly when conditions are met.

#### 3.1 File Existence (5 tests)
- `test_document_adapter_enhanced.py`:
  - `test_internet_guide_readme` - Skips if README not found
  - `test_vol1_core_infrastructure` - Skips if Volume 1 not found
  - `test_multiple_volumes` - Skips if test files missing
- **Skip Pattern:**
  ```python
  if not readme_path.exists():
      pytest.skip(f"README not found at {readme_path}")
  ```
- **Status:** CORRECT - Tests validate real file handling

#### 3.2 Module Availability (20 tests)
- `test_input_adapters_integration.py`:
  - `test_wizard_adapter` - "WizardAdapter not available"
- `test_pipeline_integration.py` (12 tests):
  - "comparison_scenes module not available" (12 tests)
  - "checkpoint_scenes module not available" (8 tests)
- **Skip Pattern:**
  ```python
  try:
      from video_gen.stages import VideoGenerationStage
  except ImportError:
      pytest.skip("VideoGenerationStage not available")
  ```
- **Status:** CORRECT - Graceful degradation for optional modules

#### 3.3 API Keys (2 tests)
- `test_adapters_coverage.py`:
  - `test_youtube_parsing` - "YouTube API not available"
  - `test_youtube_integration` - "Requires YouTube API key"
- **Skip Pattern:**
  ```python
  if not config.get_api_key("youtube"):
      pytest.skip("YouTube API not available")
  ```
- **Status:** CORRECT - Don't fail tests when API unavailable

#### 3.4 Network Tests (5 tests)
- Various files:
  - "Requires network and YouTube API" (2 tests)
  - "Network test - run manually" (1 test)
  - "Network test - requires live YouTube video" (1 test)
  - "Network simulation test" (1 test)
- **Status:** CORRECT - Network tests should be opt-in

**Enablement Strategy:**
- These tests should remain skipped in standard test runs
- Enable via pytest markers for specific test scenarios:
  ```bash
  pytest -m "network"  # Run network tests
  pytest -m "requires_files"  # Run file-dependent tests
  ```

---

### Category 4: Web Server Required (18 tests)

**Status:** Permanent - Integration tests
**Priority:** Low (not blocking core functionality)
**Estimated Effort:** 0 hours (tests work when server running)

**Rationale:**
These tests validate the web API and require a running web server. They work correctly when the server is running.

**Tests Affected:**
- `test_api_voice_arrays.py` (5 tests):
  - `test_video_with_voice_array` - "Requires running web server"
  - `test_multilingual_with_language_voices` - "Requires running web server"
  - `test_backward_compatibility` - "Requires running web server"
  - `test_scene_content_richness` - "Requires running web server"
  - Additional web API tests (1 test)

- `test_integration.py` (13 tests):
  - Various integration tests requiring web server

**Skip Pattern:**
```python
@pytest.mark.skip(reason="Requires running web server")
def test_api_endpoint():
    # Test code
```

**Enablement Strategy:**
1. Run web server in CI/CD pipeline
2. Enable tests in integration test suite
3. Use pytest markers:
   ```bash
   pytest -m "integration"  # Run integration tests
   pytest -m "requires_server"  # Run server-dependent tests
   ```

**Status:** CORRECT - Integration tests should be separate from unit tests

---

### Category 5: Performance & Profiling Tests (7 tests)

**Status:** Permanent - Manual/CI only
**Priority:** Low (run on-demand)
**Estimated Effort:** 0 hours (tests work when profiling enabled)

**Rationale:**
These tests perform profiling or performance analysis and are expensive to run. They should be opt-in via markers.

**Tests Affected:**
- `test_performance.py`:
  - `test_cpu_profiling` - "Requires CPU profiling"
  - `test_memory_profiling` - "Requires memory profiling"
  - `test_io_profiling` - "Requires I/O profiling"
  - `test_network_profiling` - "Requires network profiling"
  - `test_profiling_tools` - "Requires profiling tools" (3 tests)
  - `test_memory_monitoring` - "Requires memory monitoring"

**Skip Pattern:**
```python
@pytest.mark.slow
@pytest.mark.skip(reason="Requires profiling tools")
def test_performance_metrics():
    # Profiling code
```

**Enablement Strategy:**
```bash
pytest -m "slow"  # Run slow/profiling tests
pytest -m "profiling"  # Run profiling tests specifically
```

**Status:** CORRECT - Expensive tests should be opt-in

---

## Skip Reason Matrix

| Category | Count | % | Status | Priority | Effort | Target |
|----------|-------|---|--------|----------|--------|--------|
| Adapter Migration (ADR_001) | 68 | 38% | Temporary | High | 12-15 days | Nov 2025 |
| Feature Not Implemented | 55 | 31% | Permanent* | Variable | 40-80h per area | TBD |
| Conditional (Environment) | 32 | 18% | Permanent | Low | 0h | N/A |
| Web Server Required | 18 | 10% | Permanent | Low | 0h | N/A |
| Performance/Profiling | 7 | 4% | Permanent | Low | 0h | N/A |
| **Total** | **180** | **100%** | - | - | - | - |

**Legend:**
- *Permanent*: Until feature developed or architectural decision made
- *Temporary*: Will be enabled after planned work

---

## Recommendations

### Immediate Actions (Week 1-2)
1. ✅ **Document all skip reasons** (This document) - COMPLETE
2. ⏳ **Implement ADR_001 compatibility layer** - Enable 68 tests
3. ⏳ **Add pytest markers** for conditional tests:
   ```python
   @pytest.mark.network
   @pytest.mark.requires_files
   @pytest.mark.integration
   @pytest.mark.profiling
   ```

### Short-term Actions (Month 1)
4. ⏳ **Migrate adapter tests** (68 tests) - 12-15 days
5. ⏳ **Evaluate feature priorities** - Decide which of 55 feature tests to enable
6. ⏳ **CI/CD integration** - Run integration tests in pipeline

### Long-term Actions (Quarter 1)
7. ⏳ **Feature development** - Implement priority features (TTS, transitions, etc.)
8. ⏳ **Performance optimization** - Enable profiling tests when optimizing
9. ⏳ **Test coverage improvement** - Target 85%+ coverage

---

## Test Quality Standards

### Acceptable Skip Reasons

✅ **GOOD:**
- "Requires running web server" - Integration test, architectural
- "YouTube API not available" - Conditional on environment
- "Private method removed - see ADR_001" - Architectural change with documentation
- "Requires TTS implementation" - Feature not yet developed
- "Requires profiling tools" - Expensive test, opt-in

✅ **GOOD (with conditions):**
- "Requires full pipeline setup" - OK if pipeline is genuinely incomplete
- "Network test - run manually" - OK if network calls are expensive

❌ **BAD:**
- "Test broken" - Fix or delete test
- "TODO" - Not informative
- "Skipping for now" - Vague, no rationale
- No skip reason - Must have reason

### Skip Comment Standards

Every skip must include:
1. **Reason:** Clear explanation why skipped
2. **Reference:** Link to ADR, issue, or documentation (if applicable)
3. **Condition:** What needs to happen to enable test (if temporary)

**Example:**
```python
@pytest.mark.skip(
    reason="Private method _extract_video_id() removed in adapter consolidation. "
           "See ADR_001_INPUT_ADAPTER_CONSOLIDATION.md. "
           "Will be enabled after compatibility layer implementation (Nov 2025)."
)
def test_extract_video_id():
    # Test code
```

---

## Pytest Marker Strategy

### Recommended Markers

Add to `pytest.ini`:
```ini
[pytest]
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
    network: marks tests requiring network access
    integration: marks tests requiring web server or full system
    requires_files: marks tests requiring specific files to exist
    profiling: marks tests that perform performance profiling
    adapter_migration: marks tests awaiting ADR_001 completion
```

### Usage Examples

```bash
# Run only fast unit tests (default)
pytest -m "not slow and not network and not integration"

# Run all tests including slow ones
pytest -m ""

# Run only integration tests
pytest -m "integration"

# Run network tests
pytest -m "network"

# Run profiling tests
pytest -m "profiling"

# Run tests awaiting adapter migration
pytest -m "adapter_migration"
```

---

## Future Maintenance

### When Adding New Skipped Tests

1. **Document why:** Use clear, specific skip reason
2. **Reference:** Link to ADR, issue, or documentation
3. **Categorize:** Add to appropriate category in this document
4. **Add marker:** Use pytest marker for filtering
5. **Set priority:** Decide if temporary or permanent

### When Enabling Skipped Tests

1. **Verify reason resolved:** Check that condition for skip no longer applies
2. **Remove skip decorator:** Delete `@pytest.mark.skip` line
3. **Update test if needed:** Adapt to new API/architecture
4. **Run test:** Verify it passes
5. **Update this doc:** Remove from skip count

### Quarterly Review

- Review all "Permanent" skips - still valid?
- Check "Temporary" skips - can any be enabled?
- Update effort estimates based on team velocity
- Reprioritize based on product roadmap

---

## Summary Statistics

```
Total Tests: 817
Passing: 637 (78%)
Skipped: 180 (22%)

Skipped Breakdown:
├── Adapter Migration (38%): 68 tests - HIGH PRIORITY
├── Feature Not Implemented (31%): 55 tests - VARIABLE PRIORITY
├── Conditional (18%): 32 tests - CORRECT AS-IS
├── Web Server Required (10%): 18 tests - CORRECT AS-IS
└── Performance/Profiling (4%): 7 tests - CORRECT AS-IS

Actionable (can be enabled soon): 68 tests (38%)
Permanent (correct as-is): 57 tests (32%)
Feature-dependent (requires development): 55 tests (31%)
```

---

## Related Documents

- [ADR_001_INPUT_ADAPTER_CONSOLIDATION.md](../architecture/ADR_001_INPUT_ADAPTER_CONSOLIDATION.md)
- [TESTCLIENT_COMPATIBILITY_REPORT.md](../reports/analysis/TESTCLIENT_COMPATIBILITY_REPORT.md)
- [TESTING_STRATEGY.md](TESTING_STRATEGY.md)
- [TEST_EXECUTION_GUIDE.md](TEST_EXECUTION_GUIDE.md)
- [SKIPPED_TESTS_ANALYSIS.md](SKIPPED_TESTS_ANALYSIS.md) - If exists

---

**Document Version:** 1.0
**Last Updated:** October 16, 2025
**Next Review:** November 16, 2025
**Owner:** QA/Testing Team
