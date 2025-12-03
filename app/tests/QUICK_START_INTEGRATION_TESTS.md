# Quick Start: Integration Tests

## TL;DR

```bash
# Run critical bug tests (fast, <3 seconds)
pytest app/tests/test_integration.py::TestDocumentParserBugFix -v

# Run all fast tests (skip slow SSE/concurrent tests)
pytest app/tests/test_integration.py -k "not concurrent and not SSE and not streaming" -v

# Run complete document workflow tests
pytest app/tests/test_integration.py::TestCompleteDocumentWorkflow -v

# Run all tests (may timeout on some async tests)
pytest app/tests/test_integration.py -v
```

## What These Tests Do

### 1. Critical Bug Fix Validation ⭐
**Bug:** Document parser expects file path but receives content.

**Tests:** `TestDocumentParserBugFix`
- ✅ Verifies path (not content) is passed to pipeline
- ✅ Validates absolute path usage
- ✅ Prevents regression

**Run Time:** 2 seconds

### 2. Complete User Journey
**Tests:** `TestCompleteDocumentWorkflow`
- Upload document → Parse → Generate → Status check
- Document validation
- Preview generation

**Run Time:** 2-3 seconds

### 3. Pipeline Integration
**Tests:** `TestPipelineStageTransitions`
- Stage progression
- Error propagation
- Status mapping

**Run Time:** 3 seconds

### 4. Security & File Safety
**Tests:** `TestFileSystemOperations`
- File upload validation
- Path traversal prevention
- Extension filtering
- Filename sanitization

**Run Time:** 3 seconds

## Test Categories

### Fast Tests (<5 seconds each)
- ✅ Document workflow
- ✅ Pipeline transitions
- ✅ File system operations
- ✅ Error recovery
- ✅ CSRF protection
- ✅ Multi-language
- ✅ Scene types
- ✅ Input type inference

### May Timeout (async/streaming)
- ⚠️ SSE progress streaming
- ⚠️ Concurrent uploads
- ⚠️ Some CSRF tests

## Common Commands

```bash
# Run only fast, reliable tests
pytest app/tests/test_integration.py -k "not concurrent and not SSE" -v

# Run with coverage
pytest app/tests/test_integration.py --cov=app --cov-report=html

# Run specific test
pytest app/tests/test_integration.py::TestDocumentParserBugFix::test_document_upload_passes_file_path_not_content -v

# Run with detailed output
pytest app/tests/test_integration.py -vv --tb=short

# Run in parallel (if pytest-xdist installed)
pytest app/tests/test_integration.py -n auto
```

## Test Output

### Success Example
```
app/tests/test_integration.py::TestDocumentParserBugFix::test_document_upload_passes_file_path_not_content PASSED
app/tests/test_integration.py::TestDocumentParserBugFix::test_document_parse_endpoint_receives_path PASSED

============================== 2 passed in 2.08s ===============================
```

### Failure Example (if bug returns)
```
FAILED app/tests/test_integration.py::TestDocumentParserBugFix::test_document_upload_passes_file_path_not_content
AssertionError: assert False
 +  where False = isinstance('# Complete Python Tutorial\n\n...', Path)
E   Expected file path but got markdown content!
```

## Troubleshooting

### Tests Timeout
**Solution:** Run fast tests only
```bash
pytest app/tests/test_integration.py -k "not concurrent and not SSE" -v --timeout=30
```

### Import Errors
**Solution:** Run from project root
```bash
cd /path/to/video_gen
pytest app/tests/test_integration.py -v
```

### Mock Not Working
**Solution:** Check patch target
```python
# Correct
with patch('app.main.get_pipeline') as mock:

# Wrong
with patch('main.get_pipeline') as mock:
```

## Key Test Files

- **Test Suite:** `app/tests/test_integration.py` (954 lines)
- **Test Config:** `app/tests/conftest.py` (shared fixtures)
- **Summary:** `app/tests/TEST_INTEGRATION_SUMMARY.md`
- **This Guide:** `app/tests/QUICK_START_INTEGRATION_TESTS.md`

## Integration with CI/CD

### GitHub Actions Example
```yaml
- name: Run Integration Tests
  run: |
    pytest app/tests/test_integration.py -k "not concurrent and not SSE" -v --junit-xml=junit.xml
  timeout-minutes: 5

- name: Run Critical Bug Tests
  run: |
    pytest app/tests/test_integration.py::TestDocumentParserBugFix -v
  timeout-minutes: 2
```

### GitLab CI Example
```yaml
integration_tests:
  script:
    - pytest app/tests/test_integration.py -k "not concurrent and not SSE" -v
  timeout: 5m
```

## Test Statistics

- **Total Tests:** 27
- **Fast Tests:** ~21 (run in <5 seconds each)
- **Slow Tests:** ~6 (may timeout in CI)
- **Critical Tests:** 2 (document parser bug)
- **Total Lines:** 954
- **Coverage:** API endpoints, pipeline, security, multi-language

## Need Help?

1. **Read the summary:** `TEST_INTEGRATION_SUMMARY.md`
2. **Check test file:** Comments explain each test
3. **Run with verbose:** `-vv` flag shows detailed output
4. **Check fixtures:** `conftest.py` has test utilities

## Best Practices

1. ✅ Run critical tests before committing
2. ✅ Run fast tests in CI/CD
3. ✅ Review failures carefully (they catch real bugs!)
4. ✅ Update tests when API changes
5. ✅ Add new tests for new features

---

**Quick Win:** Run the critical bug tests now!
```bash
pytest app/tests/test_integration.py::TestDocumentParserBugFix -v
```

Should complete in 2 seconds with 2 PASSED. ✅
