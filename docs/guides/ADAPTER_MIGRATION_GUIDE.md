# Input Adapter Migration Guide

**Status:** Active
**Version:** 1.0
**Last Updated:** 2025-10-16
**Related:** [ADR_001_INPUT_ADAPTER_CONSOLIDATION](../architecture/ADR_001_INPUT_ADAPTER_CONSOLIDATION.md)

---

## Executive Summary

This guide provides step-by-step instructions for migrating from the deprecated `app.input_adapters` API to the canonical `video_gen.input_adapters` API using the compatibility layer.

**Migration Phases:**
1. **Phase 1:** Use compatibility layer (zero breaking changes)
2. **Phase 2:** Adopt async/await patterns (better performance)
3. **Phase 3:** Use InputAdapterResult (better error handling)

**Time Estimate:** 5-10 minutes per test file

---

## Table of Contents

- [Quick Start](#quick-start)
- [API Differences](#api-differences)
- [Phase 1: Compatibility Layer](#phase-1-compatibility-layer-drop-in-replacement)
- [Phase 2: Async Migration](#phase-2-async-migration)
- [Phase 3: Full Migration](#phase-3-full-migration-to-inputadapterresult)
- [Common Patterns](#common-migration-patterns)
- [Troubleshooting](#troubleshooting)
- [Testing](#testing)
- [Best Practices](#best-practices)

---

## Quick Start

### For Impatient Developers (30 seconds)

**Step 1:** Change your import (that's it!)

```python
# OLD (deprecated)
from app.input_adapters import DocumentAdapter

# NEW (compatibility layer - no other changes needed)
from video_gen.input_adapters.compat import DocumentAdapter
```

Your code works exactly the same. You'll see a deprecation warning. Done!

**Step 2 (optional):** Run tests to verify nothing broke:

```bash
pytest tests/your_test_file.py -v
```

---

## API Differences

### Deprecated API (`app.input_adapters`)

```python
# Synchronous, simple
adapter = DocumentAdapter()
video_set = adapter.parse('document.md')  # Returns VideoSet or raises exception
```

**Characteristics:**
- ✅ Simple synchronous API
- ✅ Direct VideoSet return
- ✅ Exception-based error handling
- ❌ Blocks on I/O operations
- ❌ Less structured error reporting

### Canonical API (`video_gen.input_adapters`)

```python
# Asynchronous, structured
adapter = DocumentAdapter()
result = await adapter.adapt('document.md')  # Returns InputAdapterResult

if result.success:
    video_set = result.video_set
else:
    print(f"Error: {result.error}")
```

**Characteristics:**
- ✅ Modern async/await pattern
- ✅ Non-blocking I/O
- ✅ Structured error reporting
- ✅ Rich metadata
- ❌ Requires async context
- ❌ More verbose

---

## Phase 1: Compatibility Layer (Drop-in Replacement)

**Goal:** Zero breaking changes, instant migration
**Time:** 30 seconds per file
**Deprecation Warnings:** Yes

### Step-by-Step Instructions

#### 1. Update Import Statement

```python
# Before
from app.input_adapters import DocumentAdapter, YouTubeAdapter, YAMLAdapter

# After
from video_gen.input_adapters.compat import DocumentAdapter, YouTubeAdapter, YAMLAdapter
```

That's it! All your existing code continues to work.

#### 2. Run Tests

```bash
pytest tests/your_test.py -v
```

You'll see deprecation warnings, but tests should pass.

#### 3. Verify Behavior

```python
# All these still work exactly the same
adapter = DocumentAdapter(test_mode=True)
video_set = adapter.parse('document.md')
video_set = adapter.parse('document.md', set_name="Custom Name")

# Exception handling still works
try:
    video_set = adapter.parse('/nonexistent.md')
except ValueError as e:
    print(f"Error: {e}")
```

### Complete Before/After Example

```python
# ============================================
# BEFORE (deprecated app.input_adapters)
# ============================================
import pytest
from app.input_adapters import DocumentAdapter
from app.models import VideoSet

def test_document_parsing():
    adapter = DocumentAdapter()
    video_set = adapter.parse('README.md')

    assert isinstance(video_set, VideoSet)
    assert len(video_set.videos) > 0

def test_error_handling():
    adapter = DocumentAdapter()
    with pytest.raises(ValueError):
        adapter.parse('/nonexistent.md')

# ============================================
# AFTER (compatibility layer - ONLY IMPORT CHANGED)
# ============================================
import pytest
from video_gen.input_adapters.compat import DocumentAdapter  # <- Only this changed
from video_gen.shared.models import VideoSet  # <- Updated model import

def test_document_parsing():
    adapter = DocumentAdapter()
    video_set = adapter.parse('README.md')  # <- Same code

    assert isinstance(video_set, VideoSet)
    assert len(video_set.videos) > 0

def test_error_handling():
    adapter = DocumentAdapter()
    with pytest.raises(ValueError):
        adapter.parse('/nonexistent.md')  # <- Same code
```

**What Changed:**
- ✅ Import path only
- ✅ Model import path
- ❌ No logic changes
- ❌ No API changes

---

## Phase 2: Async Migration

**Goal:** Adopt async/await for better performance
**Time:** 5 minutes per file
**Deprecation Warnings:** No

### Step-by-Step Instructions

#### 1. Update Import to Canonical Adapter

```python
# From compatibility layer
from video_gen.input_adapters.compat import DocumentAdapter

# To canonical async adapter
from video_gen.input_adapters import DocumentAdapter
```

#### 2. Make Test Functions Async

```python
# Before (sync)
def test_document_parsing():
    adapter = DocumentAdapter()
    video_set = adapter.parse('document.md')

# After (async)
import pytest

@pytest.mark.asyncio
async def test_document_parsing():
    adapter = DocumentAdapter(test_mode=True)
    result = await adapter.adapt('document.md')
    video_set = result.video_set
```

#### 3. Handle InputAdapterResult

```python
# Extract VideoSet from result
result = await adapter.adapt('document.md')

if result.success:
    video_set = result.video_set
else:
    pytest.fail(f"Adapter failed: {result.error}")
```

### Complete Before/After Example

```python
# ============================================
# BEFORE (compatibility layer sync)
# ============================================
import pytest
from video_gen.input_adapters.compat import DocumentAdapter
from video_gen.shared.models import VideoSet

def test_document_parsing():
    adapter = DocumentAdapter(test_mode=True)
    video_set = adapter.parse('README.md')

    assert isinstance(video_set, VideoSet)
    assert len(video_set.videos) > 0
    assert video_set.videos[0].title != ""

# ============================================
# AFTER (canonical async)
# ============================================
import pytest
from video_gen.input_adapters import DocumentAdapter
from video_gen.shared.models import VideoSet

@pytest.mark.asyncio
async def test_document_parsing():
    adapter = DocumentAdapter(test_mode=True)
    result = await adapter.adapt('README.md')

    assert result.success, f"Adapter failed: {result.error}"
    video_set = result.video_set

    assert isinstance(video_set, VideoSet)
    assert len(video_set.videos) > 0
    assert video_set.videos[0].title != ""
```

**What Changed:**
- ✅ Import from canonical module
- ✅ Added `@pytest.mark.asyncio`
- ✅ Made function `async`
- ✅ Changed `.parse()` → `await .adapt()`
- ✅ Extract `video_set` from `result`

---

## Phase 3: Full Migration to InputAdapterResult

**Goal:** Leverage structured error handling
**Time:** 10 minutes per file
**Best Practices:** Modern error handling

### Step-by-Step Instructions

#### 1. Use InputAdapterResult Properly

```python
from video_gen.input_adapters import DocumentAdapter
from video_gen.input_adapters.base import InputAdapterResult

@pytest.mark.asyncio
async def test_with_result_handling():
    adapter = DocumentAdapter(test_mode=True)
    result = await adapter.adapt('document.md')

    # Check success first
    assert result.success, f"Failed: {result.error}"

    # Access metadata
    assert 'adapter_type' in result.metadata

    # Use video_set
    video_set = result.video_set
    assert video_set is not None
```

#### 2. Better Error Handling

```python
@pytest.mark.asyncio
async def test_error_scenarios():
    adapter = DocumentAdapter()

    # Test non-existent file
    result = await adapter.adapt('/nonexistent.md')
    assert not result.success
    assert result.error is not None
    assert 'not found' in result.error.lower()

    # Test invalid format
    result = await adapter.adapt('invalid_format.xyz')
    assert not result.success
    assert result.video_set is None
```

#### 3. Use Metadata

```python
@pytest.mark.asyncio
async def test_with_metadata():
    adapter = DocumentAdapter(test_mode=True)
    result = await adapter.adapt('document.md')

    if result.success:
        # Access rich metadata
        print(f"Adapter: {result.metadata.get('adapter_type')}")
        print(f"Source: {result.metadata.get('source_path')}")
        print(f"Processed: {result.metadata.get('timestamp')}")
```

### Complete Before/After Example

```python
# ============================================
# BEFORE (exception-based error handling)
# ============================================
import pytest
from video_gen.input_adapters.compat import DocumentAdapter

def test_error_handling():
    adapter = DocumentAdapter()

    # Test success case
    try:
        video_set = adapter.parse('valid.md')
        assert video_set is not None
    except ValueError as e:
        pytest.fail(f"Should have succeeded: {e}")

    # Test failure case
    with pytest.raises(ValueError) as excinfo:
        adapter.parse('/nonexistent.md')
    assert "not found" in str(excinfo.value).lower()

# ============================================
# AFTER (result-based error handling)
# ============================================
import pytest
from video_gen.input_adapters import DocumentAdapter

@pytest.mark.asyncio
async def test_error_handling():
    adapter = DocumentAdapter(test_mode=True)

    # Test success case
    result = await adapter.adapt('valid.md')
    assert result.success, f"Should succeed: {result.error}"
    assert result.video_set is not None
    assert result.error is None

    # Test failure case
    result = await adapter.adapt('/nonexistent.md')
    assert not result.success
    assert result.error is not None
    assert "not found" in result.error.lower()
    assert result.video_set is None
```

**Benefits:**
- ✅ No exception handling needed
- ✅ Clear success/failure status
- ✅ Rich error messages
- ✅ Additional metadata
- ✅ Easier to test error conditions

---

## Common Migration Patterns

### Pattern 1: Simple Parse

```python
# Old
video_set = adapter.parse('file.md')

# New (compat)
video_set = adapter.parse('file.md')  # Same!

# New (async)
result = await adapter.adapt('file.md')
video_set = result.video_set
```

### Pattern 2: Parse with Options

```python
# Old
video_set = adapter.parse('file.md', set_name="Custom", language="es")

# New (compat)
video_set = adapter.parse('file.md', set_name="Custom", language="es")  # Same!

# New (async)
result = await adapter.adapt('file.md', set_name="Custom", language="es")
video_set = result.video_set
```

### Pattern 3: Error Handling

```python
# Old (exceptions)
try:
    video_set = adapter.parse('file.md')
except ValueError as e:
    print(f"Error: {e}")

# New (compat - still exceptions)
try:
    video_set = adapter.parse('file.md')
except ValueError as e:
    print(f"Error: {e}")

# New (async - result pattern)
result = await adapter.adapt('file.md')
if not result.success:
    print(f"Error: {result.error}")
```

### Pattern 4: Multiple Adapters

```python
# Old
from app.input_adapters import DocumentAdapter, YouTubeAdapter, YAMLAdapter

doc = DocumentAdapter()
yt = YouTubeAdapter()
yaml = YAMLAdapter()

# New (compat)
from video_gen.input_adapters.compat import DocumentAdapter, YouTubeAdapter, YAMLAdapter

doc = DocumentAdapter()
yt = YouTubeAdapter()
yaml = YAMLAdapter()

# New (async)
from video_gen.input_adapters import DocumentAdapter, YouTubeAdapter, YAMLFileAdapter

doc = DocumentAdapter(test_mode=True)
yt = YouTubeAdapter()
yaml = YAMLFileAdapter(test_mode=True)
```

### Pattern 5: Parameterized Tests

```python
# Old
@pytest.mark.parametrize("source", ['file1.md', 'file2.md'])
def test_multiple(source):
    adapter = DocumentAdapter()
    video_set = adapter.parse(source)
    assert video_set is not None

# New (compat)
@pytest.mark.parametrize("source", ['file1.md', 'file2.md'])
def test_multiple(source):
    adapter = DocumentAdapter(test_mode=True)
    video_set = adapter.parse(source)
    assert video_set is not None

# New (async)
@pytest.mark.asyncio
@pytest.mark.parametrize("source", ['file1.md', 'file2.md'])
async def test_multiple(source):
    adapter = DocumentAdapter(test_mode=True)
    result = await adapter.adapt(source)
    assert result.success
    assert result.video_set is not None
```

---

## Troubleshooting

### Issue 1: "asyncio.run() cannot be called from a running event loop"

**Symptom:** Error when using compatibility layer in async context

**Solution:** The compatibility layer handles this automatically. If you see this error, you're mixing sync and async incorrectly.

```python
# Don't do this
@pytest.mark.asyncio
async def test_mixed():
    from video_gen.input_adapters.compat import DocumentAdapter
    adapter = DocumentAdapter()
    video_set = adapter.parse('file.md')  # Will cause event loop error

# Do this instead
@pytest.mark.asyncio
async def test_correct():
    from video_gen.input_adapters import DocumentAdapter
    adapter = DocumentAdapter(test_mode=True)
    result = await adapter.adapt('file.md')
    video_set = result.video_set
```

### Issue 2: "module 'app.input_adapters' has no attribute 'DocumentAdapter'"

**Symptom:** Import error for deprecated module

**Solution:** The `app/input_adapters/` directory has been removed. Use compatibility layer.

```python
# Don't do this
from app.input_adapters import DocumentAdapter  # Module doesn't exist!

# Do this
from video_gen.input_adapters.compat import DocumentAdapter  # Works!
```

### Issue 3: Deprecation Warnings Everywhere

**Symptom:** Lots of deprecation warnings in test output

**Solution:** This is intentional! Warnings tell you what to migrate. You can:

**Option A:** Suppress warnings temporarily
```python
import warnings
warnings.filterwarnings('ignore', category=DeprecationWarning)
```

**Option B:** Migrate to async API (removes warnings)
```python
from video_gen.input_adapters import DocumentAdapter  # No warnings!
```

### Issue 4: Tests Fail After Migration

**Symptom:** Tests that passed before now fail

**Solution:** Check these common issues:

1. **Model imports:** Update to `video_gen.shared.models`
2. **Test mode:** Add `test_mode=True` parameter
3. **Async markers:** Add `@pytest.mark.asyncio`
4. **Result extraction:** Get `video_set` from `result.video_set`

```python
# Check all these
from video_gen.shared.models import VideoSet  # ✓ Correct import
adapter = DocumentAdapter(test_mode=True)  # ✓ Test mode enabled

@pytest.mark.asyncio  # ✓ Async marker
async def test_it():  # ✓ Async function
    result = await adapter.adapt('file.md')  # ✓ Await adapt()
    video_set = result.video_set  # ✓ Extract from result
```

---

## Testing

### Run Compatibility Layer Tests

```bash
# Test compat layer itself
pytest tests/test_compat_layer.py -v

# Test your migrated code
pytest tests/your_test.py -v

# Test everything
pytest tests/ -v
```

### Verify Migration Success

```bash
# No errors
pytest tests/ --tb=short

# No deprecation warnings (after full async migration)
pytest tests/ -W error::DeprecationWarning

# Coverage maintained
pytest tests/ --cov=video_gen --cov-report=term-missing
```

---

## Best Practices

### DO ✅

1. **Start with compatibility layer** - zero risk, instant migration
2. **Migrate in small batches** - 10-20 tests at a time
3. **Test after each batch** - catch issues early
4. **Use test_mode=True** - bypass external dependencies
5. **Add async markers** - `@pytest.mark.asyncio` for async tests
6. **Extract video_set** - always check `result.success` first
7. **Keep models updated** - import from `video_gen.shared.models`

### DON'T ❌

1. **Don't skip compatibility layer** - trying to jump straight to async is error-prone
2. **Don't migrate everything at once** - too risky
3. **Don't ignore deprecation warnings** - they guide your migration
4. **Don't mix sync and async** - choose one pattern per file
5. **Don't forget test_mode** - tests will hit real APIs otherwise
6. **Don't ignore result.success** - always check before using video_set

---

## Migration Checklist

### Phase 1: Compatibility Layer (Per File)

- [ ] Update import to `video_gen.input_adapters.compat`
- [ ] Update model imports to `video_gen.shared.models`
- [ ] Run tests - verify they pass
- [ ] Note deprecation warnings
- [ ] Commit changes

### Phase 2: Async Migration (Per File)

- [ ] Update import to `video_gen.input_adapters`
- [ ] Add `@pytest.mark.asyncio` to test functions
- [ ] Change `def test_x():` → `async def test_x():`
- [ ] Change `.parse()` → `await .adapt()`
- [ ] Extract `video_set` from `result.video_set`
- [ ] Add `test_mode=True` parameter
- [ ] Run tests - verify they pass
- [ ] Verify no deprecation warnings
- [ ] Commit changes

### Phase 3: Full Migration (Per File)

- [ ] Check `result.success` before using `video_set`
- [ ] Use `result.error` for error messages
- [ ] Access `result.metadata` for additional info
- [ ] Remove exception handling (use result pattern)
- [ ] Run tests - verify they pass
- [ ] Update documentation
- [ ] Commit changes

---

## Support

### Need Help?

1. **Check examples:** See `tests/test_compat_layer.py` for working examples
2. **Read ADR:** [ADR_001_INPUT_ADAPTER_CONSOLIDATION](../architecture/ADR_001_INPUT_ADAPTER_CONSOLIDATION.md)
3. **Check troubleshooting:** See above section
4. **Ask questions:** File an issue with your specific case

### Quick Reference

| Task | Command |
|------|---------|
| Run compat tests | `pytest tests/test_compat_layer.py -v` |
| Check coverage | `pytest --cov=video_gen.input_adapters --cov-report=html` |
| Find deprecated imports | `grep -r "from app.input_adapters" tests/` |
| Suppress warnings | `pytest -W ignore::DeprecationWarning` |

---

**Last Updated:** 2025-10-16
**Version:** 1.0
**Status:** Active

