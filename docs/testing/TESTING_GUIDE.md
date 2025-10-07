# Testing Guide - Video Generation System

## Overview

This guide covers the comprehensive test suite for the video generation system, including test organization, running tests, writing new tests, and understanding coverage metrics.

## Test Structure

```
tests/
├── __init__.py
├── test_input_adapters.py        # Input adapter tests (existing)
├── test_quick_win_validation.py  # Auto-orchestrator tests
├── test_pipeline_integration.py  # End-to-end integration tests
├── test_generators.py            # Audio/video generator tests
├── test_performance.py           # Performance benchmarks
├── test_integration.py           # Legacy integration tests
└── test_pipeline.py              # Pipeline-specific tests
```

## Running Tests

### All Tests
```bash
# Run complete test suite
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=video_gen --cov-report=html --cov-report=term

# Run with detailed output
pytest tests/ -vv --tb=long
```

### Specific Test Suites
```bash
# Quick Win validation tests
pytest tests/test_quick_win_validation.py -v

# Integration tests only
pytest tests/test_pipeline_integration.py -v

# Performance benchmarks
pytest tests/test_performance.py -v

# Generator tests
pytest tests/test_generators.py -v
```

### By Test Category
```bash
# Unit tests (fast)
pytest tests/ -m "not integration and not performance" -v

# Integration tests (slower)
pytest tests/ -m integration -v

# Performance tests
pytest tests/ -m performance -v
```

### Specific Test Functions
```bash
# Single test function
pytest tests/test_quick_win_validation.py::TestAutoOrchestratorDocumentInput::test_simple_markdown_parsing -v

# Test class
pytest tests/test_quick_win_validation.py::TestAutoOrchestratorDocumentInput -v

# Pattern matching
pytest tests/ -k "document" -v
```

## Test Categories

### 1. Unit Tests
**Purpose:** Test individual components in isolation
**Speed:** Fast (<1s each)
**Coverage:** Functions, classes, methods

**Examples:**
- Input adapter parsing
- Scene creation helpers
- Validation functions
- Utility functions

### 2. Integration Tests
**Purpose:** Test component interactions
**Speed:** Medium (1-10s each)
**Coverage:** Multi-stage workflows

**Examples:**
- Document → YAML conversion
- YAML → Script generation
- Audio generation with timing
- Complete pipeline execution

### 3. End-to-End Tests
**Purpose:** Test complete user workflows
**Speed:** Slow (10s-5min each)
**Coverage:** Full pipeline scenarios

**Examples:**
- Document to video (complete)
- YouTube to video (complete)
- Batch processing multiple videos
- Error recovery and resume

### 4. Performance Tests
**Purpose:** Benchmark and prevent regressions
**Speed:** Variable
**Coverage:** Time, memory, throughput

**Examples:**
- Parse time benchmarks
- Memory usage tracking
- Concurrent execution speedup
- Scalability tests

### 5. Validation Tests
**Purpose:** Verify output correctness
**Speed:** Medium
**Coverage:** Output quality

**Examples:**
- YAML structure validation
- Audio timing accuracy
- Video quality checks
- File integrity validation

## Coverage Goals

### Overall Coverage Targets
- **Overall:** >80%
- **Core Pipeline:** >90%
- **Input Adapters:** >85%
- **Generators:** >80%
- **Utilities:** >75%

### Critical Path Coverage
These modules require highest coverage:
- `video_gen/pipeline/orchestrator.py` - 95%+
- `video_gen/input_adapters/*.py` - 90%+
- `video_gen/audio_generator/unified.py` - 85%+
- `video_gen/video_generator/unified.py` - 85%+

### Viewing Coverage Reports
```bash
# Generate HTML report
pytest tests/ --cov=video_gen --cov-report=html

# Open in browser
open htmlcov/index.html

# Terminal report
pytest tests/ --cov=video_gen --cov-report=term-missing
```

## Writing New Tests

### Test Structure
```python
"""
Module docstring explaining what's being tested
"""

import pytest
from pathlib import Path
import tempfile


class TestFeatureName:
    """Test specific feature functionality"""

    @pytest.fixture
    def sample_data(self):
        """Create test data"""
        # Setup
        data = create_test_data()
        yield data
        # Teardown (optional)

    def test_basic_functionality(self, sample_data):
        """Test basic use case"""
        # Arrange
        input_data = sample_data

        # Act
        result = function_under_test(input_data)

        # Assert
        assert result is not None
        assert result.property == expected_value

    def test_edge_case(self):
        """Test edge case behavior"""
        # Test boundary conditions
        pass

    def test_error_handling(self):
        """Test error scenarios"""
        with pytest.raises(ExpectedException):
            function_that_should_fail()
```

### Best Practices

#### 1. Use Fixtures for Test Data
```python
@pytest.fixture
def sample_markdown():
    """Create temporary markdown file"""
    content = "# Test\n\nContent"
    with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
        f.write(content)
        yield f.name
    # Cleanup happens automatically
```

#### 2. Test One Thing Per Test
```python
# Good
def test_parse_returns_video_set():
    result = adapter.parse(file)
    assert isinstance(result, VideoSet)

def test_parse_extracts_title():
    result = adapter.parse(file)
    assert result.videos[0].title == 'Expected Title'

# Bad
def test_parse():
    result = adapter.parse(file)
    assert isinstance(result, VideoSet)
    assert result.videos[0].title == 'Expected Title'
    assert len(result.videos[0].scenes) > 0
```

#### 3. Use Descriptive Names
```python
# Good
def test_parse_empty_document_raises_error():
    pass

def test_concurrent_parsing_improves_performance():
    pass

# Bad
def test_parse():
    pass

def test_performance():
    pass
```

#### 4. Test Error Conditions
```python
def test_invalid_input_raises_value_error():
    with pytest.raises(ValueError, match="Invalid input"):
        function_under_test(invalid_input)

def test_missing_file_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        adapter.parse('/nonexistent/file.md')
```

#### 5. Use Parametrize for Similar Tests
```python
@pytest.mark.parametrize("voice,expected_engine", [
    ('male', 'en-US-GuyNeural'),
    ('female', 'en-US-JennyNeural'),
    ('male_warm', 'en-US-EricNeural'),
])
def test_voice_mapping(voice, expected_engine):
    engine = get_tts_engine(voice)
    assert engine == expected_engine
```

#### 6. Mock External Dependencies
```python
from unittest.mock import Mock, patch

@patch('requests.get')
def test_fetch_github_readme(mock_get):
    mock_get.return_value = Mock(text="# README")

    result = fetch_github_readme('https://example.com')

    assert result == "# README"
    mock_get.assert_called_once()
```

### Async Tests
```python
import pytest

@pytest.mark.asyncio
async def test_async_audio_generation():
    """Test async audio generation"""
    generator = AudioGenerator()

    result = await generator.generate_audio("Test text")

    assert result is not None
```

## Test Markers

Define custom markers in `pytest.ini`:
```ini
[pytest]
markers =
    integration: Integration tests (slower)
    performance: Performance benchmarks
    network: Tests requiring network access
    slow: Tests that take >5 seconds
```

Use markers:
```python
@pytest.mark.integration
def test_complete_pipeline():
    pass

@pytest.mark.performance
def test_parse_performance():
    pass

@pytest.mark.network
def test_fetch_url():
    pass
```

Run specific markers:
```bash
pytest -m integration
pytest -m "not network"
pytest -m "integration and not slow"
```

## Continuous Integration

### Pre-commit Hooks
```bash
# Install pre-commit
pip install pre-commit

# Setup hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

### CI Pipeline
```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.10'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run tests
        run: pytest tests/ --cov=video_gen --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v2
```

## Debugging Failed Tests

### Verbose Output
```bash
# Show print statements
pytest tests/ -v -s

# Show full error traceback
pytest tests/ --tb=long

# Drop into debugger on failure
pytest tests/ --pdb
```

### Isolate Failing Test
```bash
# Run only failed tests from last run
pytest --lf

# Run failed first, then rest
pytest --ff

# Stop on first failure
pytest -x
```

### Debug Specific Test
```python
def test_feature():
    import pdb; pdb.set_trace()  # Breakpoint
    result = function_under_test()
    assert result is not None
```

## Performance Testing

### Time Measurement
```python
import time

def test_performance():
    start = time.time()
    function_under_test()
    duration = time.time() - start

    assert duration < 5.0  # Should complete in <5s
```

### Memory Profiling
```python
import psutil
import os

def test_memory_usage():
    process = psutil.Process(os.getpid())
    initial_memory = process.memory_info().rss / 1024 / 1024  # MB

    function_under_test()

    peak_memory = process.memory_info().rss / 1024 / 1024
    memory_used = peak_memory - initial_memory

    assert memory_used < 100  # Should use <100MB
```

## Common Patterns

### Testing File Operations
```python
import tempfile
from pathlib import Path

def test_file_output():
    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = Path(tmpdir) / "output.txt"

        function_that_creates_file(output_file)

        assert output_file.exists()
        assert output_file.read_text() == "expected content"
    # Files cleaned up automatically
```

### Testing Exceptions
```python
def test_exception_handling():
    with pytest.raises(ValueError) as exc_info:
        function_that_should_fail()

    assert "expected error message" in str(exc_info.value)
```

### Testing Warnings
```python
import warnings

def test_deprecation_warning():
    with warnings.catch_warnings(record=True) as w:
        function_that_warns()

        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
```

## Gap Analysis

### Finding Untested Code
```bash
# Show uncovered lines
pytest tests/ --cov=video_gen --cov-report=term-missing

# Generate annotated source files
pytest tests/ --cov=video_gen --cov-report=annotate
```

### Adding Tests for Gaps
1. Review coverage report
2. Identify critical uncovered code
3. Write tests for high-priority gaps
4. Repeat until coverage goals met

## Resources

### Documentation
- [pytest Documentation](https://docs.pytest.org/)
- [pytest-cov](https://pytest-cov.readthedocs.io/)
- [pytest-asyncio](https://pytest-asyncio.readthedocs.io/)

### Tools
- pytest - Test framework
- pytest-cov - Coverage plugin
- pytest-xdist - Parallel execution
- pytest-mock - Mocking utilities

## Troubleshooting

### Common Issues

**Issue: Tests pass locally but fail in CI**
- Solution: Check for environment-specific dependencies
- Ensure all test dependencies in requirements.txt

**Issue: Flaky tests (intermittent failures)**
- Solution: Fix race conditions, add timeouts, use explicit waits
- Mark as flaky: `@pytest.mark.flaky(reruns=3)`

**Issue: Tests too slow**
- Solution: Use mocks for expensive operations
- Run in parallel: `pytest -n auto`
- Mark slow tests: `@pytest.mark.slow`

**Issue: Import errors in tests**
- Solution: Ensure proper PYTHONPATH
- Use `sys.path.insert(0, ...)` if needed
- Install package in editable mode: `pip install -e .`

## Next Steps

1. **Achieve 80% Coverage** - Run coverage report and add tests for gaps
2. **Setup CI/CD** - Automate test execution on commits
3. **Performance Baselines** - Establish and track performance metrics
4. **Integration Testing** - Test complete workflows end-to-end
5. **Load Testing** - Test system under concurrent load
