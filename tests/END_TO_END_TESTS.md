# End-to-End Testing Documentation

## Overview

The end-to-end tests in `test_end_to_end.py` test the complete video generation pipeline from input to final video output. These tests verify that all stages work together correctly.

## Network Requirements

**IMPORTANT**: End-to-end tests require network access to:
- **edge_tts API**: For text-to-speech audio generation
- **Anthropic API** (optional): For AI-enhanced narration

Due to these external dependencies, e2e tests are **skipped by default** in CI/CD and local development to:
1. Prevent network-dependent test failures
2. Avoid API rate limiting and costs
3. Enable fast offline development
4. Ensure deterministic test results

## Running End-to-End Tests

### Option 1: Environment Variable
```bash
NETWORK_TESTS=1 pytest tests/test_end_to_end.py -v
```

### Option 2: Command Line Flag
```bash
pytest tests/test_end_to_end.py --run-network-tests -v
```

### Run All Tests Including E2E
```bash
NETWORK_TESTS=1 pytest tests/ -v
```

## Test Coverage

While e2e tests are skipped by default, test coverage remains high (79%+) through:

1. **Unit Tests**: Individual component testing with full mocking
2. **Integration Tests**: Stage integration with mocked external APIs
3. **Smoke Tests**: Quick validation that pipeline stages load correctly

The `test_quick_integration_smoke_test()` function provides a lightweight e2e validation without network calls.

## Mocking Strategy

For tests that need to avoid network calls, use these patterns:

### Mock edge_tts
```python
from unittest.mock import AsyncMock, MagicMock, patch

@patch('edge_tts.Communicate')
async def test_with_mock_tts(mock_communicate):
    mock_comm = MagicMock()
    mock_comm.save = AsyncMock(side_effect=create_dummy_audio)
    mock_communicate.return_value = mock_comm
    # Your test code here
```

### Mock ffmpeg
```python
@patch('subprocess.run')
def test_with_mock_ffmpeg(mock_run):
    def mock_ffmpeg(cmd, *args, **kwargs):
        if 'ffmpeg' in str(cmd[0]).lower():
            result = MagicMock()
            result.stderr = "Duration: 00:00:05.00"
            return result
        return subprocess.run(cmd, *args, **kwargs)

    mock_run.side_effect = mock_ffmpeg
    # Your test code here
```

## CI/CD Integration

In CI/CD pipelines, e2e tests are skipped unless:
- `NETWORK_TESTS=1` environment variable is set
- Running in a designated integration testing environment with API access

## Troubleshooting

### Tests Hang or Timeout
- Ensure you're not running e2e tests accidentally (check for NETWORK_TESTS env var)
- Verify network connectivity if intentionally running e2e tests
- Check API rate limits if tests fail intermittently

### API Key Issues
- Anthropic API failures are non-fatal; the system falls back to original narration
- edge_tts failures will cause test failures (required for audio generation)

### Mock Issues in Other Tests
- If other tests accidentally trigger network calls, add proper mocking
- See `tests/test_audio_stage_comprehensive.py` for examples of proper audio mocking
- Use `conftest.py` fixtures for shared mocking setup

## Best Practices

1. **Keep e2e tests minimal**: They're slow and network-dependent
2. **Prefer integration tests**: Test stage interactions with mocked external APIs
3. **Use smoke tests**: Quick validation without external dependencies
4. **Mock aggressively**: Only hit real APIs in designated e2e test runs
5. **Document network requirements**: Clearly mark tests that need network access

## Related Files

- `tests/test_end_to_end.py` - End-to-end test suite
- `tests/conftest.py` - Shared test fixtures and mocking utilities
- `tests/test_audio_stage_comprehensive.py` - Example of proper audio mocking
- `pytest.ini` - Pytest configuration including markers

## Future Improvements

- [ ] Add VCR.py for recording/replaying network interactions
- [ ] Create dedicated integration test environment with API access
- [ ] Implement mock API server for edge_tts to enable offline e2e testing
- [ ] Add performance benchmarks to e2e tests
- [ ] Create test data fixtures for consistent e2e test results
