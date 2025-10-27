# ADR-004: Testing Strategy and Organization

**Status:** Accepted
**Date:** 2025-10-16
**Deciders:** Development Team
**Technical Story:** Test Suite Architecture and Philosophy

## Context and Problem Statement

The video_gen project started as a rapid prototype with minimal testing. As features grew, testing became critical but challenging:

**Initial Testing Challenges:**
1. Mix of synchronous and asynchronous code
2. External dependencies (FFmpeg, Edge TTS, Anthropic API)
3. Slow integration tests blocking development
4. Inconsistent test organization
5. Low coverage (< 50%) in critical modules
6. Flaky tests due to timing issues
7. No clear guidance on test types or markers

**Test Suite Requirements:**
- Fast unit tests (< 1s total)
- Comprehensive coverage (> 75% target, 90%+ for core)
- Reliable async testing
- Isolated tests (no inter-test dependencies)
- Clear organization and discovery
- Mock external dependencies appropriately
- Support for slow integration tests (opt-in)

**Key Questions:**
- How to handle async/await in tests?
- When to mock vs. use real implementations?
- How to organize 475+ tests?
- How to skip slow tests in CI/local development?
- What coverage targets for different modules?

## Decision

**Implement multi-tier testing strategy with clear markers and organization:**

### Test Organization Philosophy

**Three Test Tiers:**

1. **Unit Tests** (`@pytest.mark.unit` or default)
   - Fast (< 0.1s per test)
   - Isolated (no external dependencies)
   - Test single functions/classes
   - Mock all I/O operations
   - Run on every commit

2. **Integration Tests** (`@pytest.mark.integration`)
   - Moderate speed (< 2s per test)
   - Test component interactions
   - May use real file I/O, but local only
   - Mock external APIs
   - Run before merge

3. **Slow Tests** (`@pytest.mark.slow`)
   - Slow (> 5s per test)
   - End-to-end workflows
   - May involve real video generation
   - Full pipeline tests
   - Run on demand / in CI only

### Test Patterns

**Async Testing Pattern:**
```python
# Use pytest-asyncio for async tests
@pytest.mark.asyncio
async def test_async_function():
    result = await some_async_function()
    assert result is not None
```

**Sync Wrapper Testing Pattern:**
```python
# For compatibility layers
def test_sync_wrapper_of_async():
    # Uses asyncio.run() internally
    adapter = CompatAdapter(AsyncAdapter())
    result = adapter.parse('input.md')  # Blocks until complete
    assert isinstance(result, VideoSet)
```

**Mock External Dependencies:**
```python
# Mock Anthropic API
@pytest.fixture
def mock_anthropic(monkeypatch):
    mock_client = MagicMock()
    mock_client.messages.create.return_value = MagicMock(
        content=[MagicMock(text="Enhanced narration")],
        usage=MagicMock(input_tokens=100, output_tokens=50)
    )
    monkeypatch.setattr('anthropic.Anthropic', lambda **kwargs: mock_client)
    return mock_client
```

**Parametrized Tests for Comprehensive Coverage:**
```python
@pytest.mark.parametrize("color", [
    ACCENT_BLUE, ACCENT_GREEN, ACCENT_ORANGE,
    ACCENT_PURPLE, ACCENT_PINK, ACCENT_CYAN
])
def test_renderer_with_all_colors(color):
    start, end = create_title_keyframes("Title", "Subtitle", color)
    assert start.size == (WIDTH, HEIGHT)
```

### Test Configuration

**pytest.ini Settings:**
```ini
[pytest]
markers =
    slow: marks tests as slow (integration tests, e2e tests)
    unit: marks tests as unit tests (fast, isolated)
    integration: marks tests as integration tests
    api: marks tests that require API server running
    server: marks tests that require web server running

addopts =
    -v
    --strict-markers
    --tb=short
    --disable-warnings
    -p no:warnings

timeout = 10  # Individual test timeout
asyncio_mode = strict
```

**Default Test Run** (excludes slow tests):
```bash
pytest tests/ -m "not slow" -q
# Runs 475 tests in ~30 seconds
```

**Full Test Run** (includes slow tests):
```bash
pytest tests/ -v
# Runs 475+ tests in ~5 minutes
```

## Alternatives Considered

### Alternative 1: Synchronous-Only Testing
**Approach:** Convert all async code to sync for testing

**Pros:**
- Simpler test code
- No async complexity

**Cons:**
- ❌ Doesn't match production code (async)
- ❌ Hides async bugs
- ❌ Can't test async performance
- ❌ Requires sync wrappers everywhere

**Decision:** Rejected - Must test code as it runs in production

### Alternative 2: Integration Tests Only
**Approach:** Skip unit tests, only test full workflows

**Pros:**
- Fewer tests to write
- Tests "real" behavior

**Cons:**
- ❌ Slow feedback loop (5+ minutes)
- ❌ Hard to debug failures
- ❌ Brittle (many failure points)
- ❌ Poor isolation
- ❌ Expensive to run on CI

**Decision:** Rejected - Need fast unit tests for development

### Alternative 3: Mock Everything
**Approach:** Mock all dependencies including file I/O

**Pros:**
- Very fast tests
- Complete isolation

**Cons:**
- ❌ Tests mock behavior, not real behavior
- ❌ Brittle (breaks on implementation changes)
- ❌ Doesn't catch integration bugs
- ❌ High maintenance burden

**Decision:** Rejected - Need balance of mocking and real code

### Alternative 4: No Test Markers (Run All Tests Every Time)
**Approach:** No `@pytest.mark.slow`, run everything always

**Pros:**
- Simple - no marker management
- Always comprehensive

**Cons:**
- ❌ Slow local development (5+ min per run)
- ❌ Developers skip tests to save time
- ❌ CI takes too long
- ❌ Can't optimize test runs

**Decision:** Rejected - Need fast default runs

### Alternative 5: Separate Test Suites (Different Directories)
**Approach:** `tests/unit/`, `tests/integration/`, `tests/e2e/`

**Pros:**
- Clear separation
- Can run by directory

**Cons:**
- ❌ Confusing where to put new tests
- ❌ Duplication across directories
- ❌ Less flexible than markers
- ❌ Harder to reorganize

**Decision:** Rejected - Markers provide better flexibility

## Decision Outcome

**Chosen: Multi-tier testing with pytest markers and async support**

### Rationale

1. **Fast Feedback**: Default run completes in < 30s
   - Developers run tests frequently
   - Quick iteration cycles
   - Catches bugs early

2. **Comprehensive Coverage**: 79% overall, 100% for critical modules
   - Unit tests: renderers, adapters, utilities
   - Integration tests: pipeline stages, full workflows
   - Slow tests: end-to-end video generation

3. **Clear Organization**: Markers indicate test type
   - Easy to filter tests
   - Self-documenting
   - Flexible reorganization

4. **Async Support**: Tests match production code
   - pytest-asyncio handles async/await
   - Catches async bugs
   - Tests actual performance characteristics

5. **Appropriate Mocking**: Balance of isolation and realism
   - Mock external APIs (Anthropic, YouTube)
   - Use real file I/O (tempfiles, cleanup)
   - Real PIL/Pillow rendering
   - Real FFmpeg (in integration tests only)

### Positive Consequences

✅ **Fast development** - 30s test runs enable TDD
✅ **High coverage** - 79% overall (475 passing tests)
✅ **100% coverage** - Renderer system (142 tests)
✅ **Reliable** - Proper async testing, no flaky tests
✅ **Organized** - Clear test types and markers
✅ **CI-friendly** - Fast default runs, comprehensive CI runs
✅ **Debuggable** - Isolated failures, clear error messages
✅ **Maintainable** - Consistent patterns, good fixtures

### Negative Consequences

⚠️ **Marker discipline required** - Developers must use correct markers
   - *Mitigation*: Linting checks for marker usage

⚠️ **Async complexity** - pytest-asyncio adds learning curve
   - *Mitigation*: Clear examples in docs, templates

⚠️ **Test duplication** - Some tests exist at multiple levels
   - *Mitigation*: Acceptable trade-off for comprehensive coverage

⚠️ **Mock maintenance** - Mocks must stay in sync with APIs
   - *Mitigation*: Regular integration test runs catch mismatches

### Neutral Consequences

🔹 **128 skipped tests** - Intentionally skipped for valid reasons (see SKIPPED_TESTS_ANALYSIS.md)
🔹 **Coverage gaps** - Some legacy code not yet tested
🔹 **CI time** - Full suite takes 5 minutes (acceptable)

## Implementation Details

### Test File Organization

```
tests/
├── test_renderers.py              # Renderer unit tests (142 tests, 100% coverage)
├── test_input_adapters.py         # Adapter unit tests (85 tests)
├── test_compat_layer.py           # Compatibility tests (47 tests)
├── test_pipeline_stages.py        # Pipeline integration tests (35 tests)
├── test_ai_components.py          # AI enhancement tests (mock API)
├── test_integration.py            # Integration tests (@pytest.mark.integration)
├── test_end_to_end.py             # E2E tests (@pytest.mark.slow)
├── test_performance.py            # Performance tests (@pytest.mark.slow)
└── conftest.py                    # Shared fixtures
```

### Fixture Philosophy

**Shared Fixtures** (conftest.py):
```python
@pytest.fixture
def temp_markdown_file():
    """Create temporary markdown file for testing."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
        f.write("# Test Content\n\nTest body")
        yield f.name
    Path(f.name).unlink()

@pytest.fixture
def mock_config():
    """Mock configuration for testing."""
    config = MagicMock()
    config.video_width = 1920
    config.video_height = 1080
    config.video_fps = 30
    return config

@pytest.fixture
def sample_video_set():
    """Create sample VideoSet for testing."""
    return VideoSet(
        videos=[
            VideoConfig(
                title="Test Video",
                scenes=[
                    {"type": "title", "title": "Test", "subtitle": "Test"}
                ]
            )
        ]
    )
```

**Test-Specific Fixtures** (in test file):
```python
@pytest.fixture
def renderer_test_data():
    """Fixture specific to renderer tests."""
    return {
        'title': 'Test Title',
        'subtitle': 'Test Subtitle',
        'colors': [ACCENT_BLUE, ACCENT_GREEN]
    }
```

### Coverage Targets by Module

**Critical Modules** (90-100% required):
- ✅ `video_gen/renderers/` - 100%
- ✅ `video_gen/shared/models.py` - 95%
- ✅ `video_gen/shared/config.py` - 92%
- ⚠️ `video_gen/input_adapters/` - 85% (target: 90%)
- ⚠️ `video_gen/pipeline/` - 78% (target: 85%)

**Important Modules** (75-90% target):
- ✅ `video_gen/script_generator/` - 82%
- ✅ `video_gen/audio_generator/` - 79%
- ⚠️ `video_gen/utilities/` - 68% (target: 75%)

**Legacy/Deprecated** (< 50% acceptable):
- `app/input_adapters/` - 35% (being phased out)
- `app/old_pipeline/` - 20% (deprecated)

### Test Patterns and Examples

**1. Basic Unit Test (Sync)**
```python
def test_ease_out_cubic():
    """Test easing function produces correct values."""
    assert ease_out_cubic(0.0) == 0.0
    assert ease_out_cubic(1.0) == 1.0
    assert 0.0 < ease_out_cubic(0.5) < 1.0
```

**2. Async Unit Test**
```python
@pytest.mark.asyncio
async def test_document_adapter():
    """Test document adapter parses markdown."""
    adapter = DocumentAdapter()
    result = await adapter.adapt('test.md')

    assert result.success
    assert result.video_set is not None
    assert len(result.video_set.videos) > 0
```

**3. Parametrized Test**
```python
@pytest.mark.parametrize("scene_type,expected_keys", [
    ("title", ["title", "subtitle"]),
    ("list", ["title", "items"]),
    ("command", ["title", "subtitle", "commands"])
])
def test_scene_structure(scene_type, expected_keys):
    """Test all scene types have required keys."""
    scene = create_scene(scene_type)
    for key in expected_keys:
        assert key in scene
```

**4. Mock External API**
```python
@pytest.mark.asyncio
async def test_ai_enhancement_with_mock(monkeypatch):
    """Test AI enhancement with mocked API."""
    mock_response = MagicMock(
        content=[MagicMock(text="Enhanced text")],
        usage=MagicMock(input_tokens=50, output_tokens=30)
    )

    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_response

    monkeypatch.setattr('anthropic.Anthropic', lambda **k: mock_client)

    enhancer = AIScriptEnhancer(api_key="test-key")
    result = await enhancer.enhance_script("Original text")

    assert result == "Enhanced text"
    assert enhancer.metrics.total_api_calls == 1
```

**5. Integration Test (Slow)**
```python
@pytest.mark.slow
@pytest.mark.integration
def test_full_video_generation():
    """Test complete pipeline from markdown to video."""
    input_file = 'test.md'
    output_file = 'output/test.mp4'

    # Run full pipeline
    generate_video(input_file, output_file)

    # Verify output exists and is valid video
    assert Path(output_file).exists()
    assert Path(output_file).stat().st_size > 100_000  # > 100KB

    # Cleanup
    Path(output_file).unlink()
```

**6. Exception Testing**
```python
def test_adapter_raises_on_invalid_input():
    """Test adapter raises appropriate exception."""
    adapter = DocumentAdapter()

    with pytest.raises(FileNotFoundError):
        asyncio.run(adapter.adapt('nonexistent.md'))

def test_enhancement_fallback_on_api_error():
    """Test enhancement falls back gracefully."""
    enhancer = AIScriptEnhancer(api_key="invalid")
    original = "Test narration"

    # Should not raise, should return original
    result = asyncio.run(enhancer.enhance_script(original))
    assert result == original
```

### Skipped Tests Strategy

**Why Skip Tests?**
1. **Feature not yet implemented** (intentional)
2. **External dependency unavailable** (optional feature)
3. **Platform-specific** (Windows-only, etc.)
4. **Known bug** (tracked in ISSUES.md)

**Proper Skip Usage:**
```python
@pytest.mark.skip(reason="Feature not implemented yet - see ISSUES.md #42")
def test_future_feature():
    """Test future translation feature."""
    pass

@pytest.mark.skipif(not has_ffmpeg(), reason="FFmpeg not installed")
def test_video_composition():
    """Test video composition with FFmpeg."""
    pass
```

**Documented in:** `docs/testing/SKIPPED_TESTS_ANALYSIS.md`

### Running Tests

**Common Commands:**

```bash
# Fast unit tests (default) - 30s
pytest tests/ -m "not slow" -q

# Specific module
pytest tests/test_renderers.py -v

# With coverage
pytest --cov=video_gen --cov=app --cov-report=html

# Slow tests only
pytest tests/ -m slow -v

# Integration tests
pytest tests/ -m integration -v

# Specific test
pytest tests/test_renderers.py::test_create_title_keyframes -v

# Watch mode (with pytest-watch)
ptw tests/ -- -m "not slow"
```

## Performance Metrics

**Test Suite Performance** (as of Oct 16, 2025):

**Fast Tests** (default `-m "not slow"`):
- Tests run: 475
- Duration: 28.4s
- Success rate: 100%
- Coverage: 79% (with fast tests)

**Full Tests** (no markers):
- Tests run: 509
- Duration: 4m 52s
- Success rate: 99.8% (1 expected failure)
- Coverage: 82% (with slow tests)

**Coverage by Module Type:**
- Renderers: 100% (142 tests)
- Input Adapters: 85% (132 tests)
- Pipeline: 78% (86 tests)
- Utilities: 68% (58 tests)
- Scripts: 42% (not critical)

**Test Distribution:**
- Unit tests: 392 (82%)
- Integration tests: 67 (14%)
- Slow E2E tests: 16 (3%)
- Skipped: 128 (intentional)

## Compliance and Validation

### CI/CD Integration

**GitHub Actions Workflow:**
```yaml
- name: Run fast tests
  run: pytest tests/ -m "not slow" -v --cov=video_gen

- name: Run full tests (scheduled)
  if: github.event_name == 'schedule'
  run: pytest tests/ -v --cov=video_gen --cov-report=xml

- name: Upload coverage
  uses: codecov/codecov-action@v3
```

### Coverage Requirements

**Pre-commit Hook** (enforced):
```bash
# Don't commit if coverage drops below 75%
pytest --cov=video_gen --cov-fail-under=75
```

**PR Requirements**:
- Fast tests must pass
- New code must have tests
- Coverage must not decrease

**Release Requirements**:
- All tests (including slow) must pass
- Coverage must be ≥ 79%
- No new skipped tests without documentation

## Related Decisions

- **ADR-001**: Input Adapter Consolidation (async testing patterns)
- **ADR-002**: Modular Renderer System (renderer test organization)
- **ADR-003**: AI Integration Strategy (mocking external APIs)
- **ADR-005**: Configuration System (config test fixtures)

## Links and References

- [TESTING_GUIDE.md](../testing/TESTING_GUIDE.md) - Complete testing guide
- [SKIPPED_TESTS_ANALYSIS.md](../testing/SKIPPED_TESTS_ANALYSIS.md) - Skipped tests documentation
- [pytest.ini](../../pytest.ini) - Test configuration
- [tests/conftest.py](../../tests/conftest.py) - Shared fixtures
- [pytest documentation](https://docs.pytest.org/)
- [pytest-asyncio](https://pytest-asyncio.readthedocs.io/)

## Follow-Up Actions

- [x] Achieve 75% overall coverage (completed Oct 6, 79% achieved)
- [x] 100% coverage for renderer system (completed Oct 6)
- [x] Document skipped tests (completed Oct 11)
- [ ] Improve adapter coverage to 90%
- [ ] Add mutation testing (detect weak tests)
- [ ] Create test templates for common patterns
- [ ] Add visual regression tests for renderers
- [ ] Implement contract testing for API

---

**Template Version:** ADR 1.0
**Next Review Date:** 2026-01-16 (3 months)
