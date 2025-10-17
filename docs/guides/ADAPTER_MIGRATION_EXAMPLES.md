# Input Adapter Migration - Real-World Examples

**Version:** 1.0
**Last Updated:** 2025-10-16
**Related:** [ADAPTER_MIGRATION_GUIDE.md](./ADAPTER_MIGRATION_GUIDE.md)

---

## Overview

This document provides complete before/after examples from real test files in the video_gen project, showing actual migration paths.

---

## Example 1: Simple Document Test

### Before (Deprecated API)

```python
# tests/test_document_adapter.py
"""Tests for document adapter"""
import pytest
from pathlib import Path
from app.input_adapters import DocumentAdapter
from app.models import VideoSet

class TestDocumentAdapter:
    """Test document adapter functionality"""

    def test_parse_markdown_file(self, tmp_path):
        """Should parse markdown file into VideoSet"""
        # Create test markdown
        test_file = tmp_path / "test.md"
        test_file.write_text("""
# Introduction to Python

Python is a high-level programming language.

## Why Python?

- Easy to learn
- Versatile
- Large community

## Basic Syntax

Variables are easy to declare.
""")

        # Parse document
        adapter = DocumentAdapter()
        video_set = adapter.parse(str(test_file))

        # Verify structure
        assert isinstance(video_set, VideoSet)
        assert len(video_set.videos) == 1

        video = video_set.videos[0]
        assert video.title == "Introduction to Python"
        assert len(video.scenes) >= 3

    def test_parse_nonexistent_file(self):
        """Should raise error for nonexistent file"""
        adapter = DocumentAdapter()

        with pytest.raises(ValueError) as excinfo:
            adapter.parse("/path/to/nonexistent.md")

        assert "not found" in str(excinfo.value).lower()

    def test_parse_with_options(self, tmp_path):
        """Should accept parsing options"""
        test_file = tmp_path / "simple.md"
        test_file.write_text("# Simple Doc\n\nContent here.")

        adapter = DocumentAdapter()
        video_set = adapter.parse(
            str(test_file),
            set_name="Custom Set",
            language="es"
        )

        assert video_set.name == "Custom Set"
```

### After Phase 1 (Compatibility Layer)

```python
# tests/test_document_adapter.py
"""Tests for document adapter"""
import pytest
from pathlib import Path
from video_gen.input_adapters.compat import DocumentAdapter  # <- ONLY CHANGE
from video_gen.shared.models import VideoSet  # <- Updated import

class TestDocumentAdapter:
    """Test document adapter functionality"""

    def test_parse_markdown_file(self, tmp_path):
        """Should parse markdown file into VideoSet"""
        # Create test markdown
        test_file = tmp_path / "test.md"
        test_file.write_text("""
# Introduction to Python

Python is a high-level programming language.

## Why Python?

- Easy to learn
- Versatile
- Large community

## Basic Syntax

Variables are easy to declare.
""")

        # Parse document
        adapter = DocumentAdapter(test_mode=True)  # <- Added test_mode
        video_set = adapter.parse(str(test_file))  # <- Same code

        # Verify structure
        assert isinstance(video_set, VideoSet)
        assert len(video_set.videos) == 1

        video = video_set.videos[0]
        assert video.title == "Introduction to Python"
        assert len(video.scenes) >= 3

    def test_parse_nonexistent_file(self):
        """Should raise error for nonexistent file"""
        adapter = DocumentAdapter(test_mode=True)  # <- Added test_mode

        with pytest.raises(ValueError) as excinfo:
            adapter.parse("/path/to/nonexistent.md")  # <- Same code

        assert "not found" in str(excinfo.value).lower()

    def test_parse_with_options(self, tmp_path):
        """Should accept parsing options"""
        test_file = tmp_path / "simple.md"
        test_file.write_text("# Simple Doc\n\nContent here.")

        adapter = DocumentAdapter(test_mode=True)  # <- Added test_mode
        video_set = adapter.parse(
            str(test_file),
            set_name="Custom Set",
            language="es"
        )  # <- Same code

        assert video_set.name == "Custom Set"
```

**Changes Made:**
- ✅ Import path: `app.input_adapters` → `video_gen.input_adapters.compat`
- ✅ Model import: `app.models` → `video_gen.shared.models`
- ✅ Added `test_mode=True` parameter
- ❌ No other logic changes

### After Phase 2 (Async Migration)

```python
# tests/test_document_adapter.py
"""Tests for document adapter"""
import pytest
from pathlib import Path
from video_gen.input_adapters import DocumentAdapter  # <- Canonical import
from video_gen.shared.models import VideoSet

class TestDocumentAdapter:
    """Test document adapter functionality"""

    @pytest.mark.asyncio  # <- Added async marker
    async def test_parse_markdown_file(self, tmp_path):  # <- Made async
        """Should parse markdown file into VideoSet"""
        # Create test markdown
        test_file = tmp_path / "test.md"
        test_file.write_text("""
# Introduction to Python

Python is a high-level programming language.

## Why Python?

- Easy to learn
- Versatile
- Large community

## Basic Syntax

Variables are easy to declare.
""")

        # Parse document
        adapter = DocumentAdapter(test_mode=True)
        result = await adapter.adapt(str(test_file))  # <- Changed to adapt()

        # Extract VideoSet
        assert result.success, f"Adapter failed: {result.error}"
        video_set = result.video_set  # <- Extract from result

        # Verify structure
        assert isinstance(video_set, VideoSet)
        assert len(video_set.videos) == 1

        video = video_set.videos[0]
        assert video.title == "Introduction to Python"
        assert len(video.scenes) >= 3

    @pytest.mark.asyncio  # <- Added async marker
    async def test_parse_nonexistent_file(self):  # <- Made async
        """Should return failure for nonexistent file"""
        adapter = DocumentAdapter(test_mode=True)

        result = await adapter.adapt("/path/to/nonexistent.md")  # <- Changed to adapt()

        # Check result instead of exception
        assert not result.success
        assert result.error is not None
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio  # <- Added async marker
    async def test_parse_with_options(self, tmp_path):  # <- Made async
        """Should accept parsing options"""
        test_file = tmp_path / "simple.md"
        test_file.write_text("# Simple Doc\n\nContent here.")

        adapter = DocumentAdapter(test_mode=True)
        result = await adapter.adapt(
            str(test_file),
            set_name="Custom Set",
            language="es"
        )  # <- Changed to adapt()

        assert result.success
        video_set = result.video_set  # <- Extract from result
        assert video_set.name == "Custom Set"
```

**Changes Made:**
- ✅ Import: `compat` → canonical `video_gen.input_adapters`
- ✅ Added `@pytest.mark.asyncio` decorators
- ✅ Made functions `async`
- ✅ Changed `.parse()` → `await .adapt()`
- ✅ Extract `video_set` from `result`
- ✅ Changed exception handling to result checking

---

## Example 2: Parameterized Tests

### Before (Deprecated API)

```python
# tests/test_multiple_adapters.py
import pytest
from app.input_adapters import DocumentAdapter, YAMLAdapter

class TestMultipleFormats:
    """Test different input formats"""

    @pytest.mark.parametrize("filename,adapter_class", [
        ("test1.md", DocumentAdapter),
        ("test2.md", DocumentAdapter),
        ("test3.yaml", YAMLAdapter),
        ("test4.yaml", YAMLAdapter),
    ])
    def test_parse_multiple_files(self, tmp_path, filename, adapter_class):
        """Should parse different file types"""
        # Create test file
        test_file = tmp_path / filename
        if filename.endswith('.md'):
            test_file.write_text("# Test\n\nContent")
        else:
            test_file.write_text("videos:\n  - title: Test\n    scenes: []")

        # Parse with appropriate adapter
        adapter = adapter_class()
        video_set = adapter.parse(str(test_file))

        assert video_set is not None
        assert len(video_set.videos) > 0
```

### After Phase 2 (Async Migration)

```python
# tests/test_multiple_adapters.py
import pytest
from video_gen.input_adapters import DocumentAdapter, YAMLFileAdapter as YAMLAdapter

class TestMultipleFormats:
    """Test different input formats"""

    @pytest.mark.asyncio  # <- Added async marker
    @pytest.mark.parametrize("filename,adapter_class", [
        ("test1.md", DocumentAdapter),
        ("test2.md", DocumentAdapter),
        ("test3.yaml", YAMLAdapter),
        ("test4.yaml", YAMLAdapter),
    ])
    async def test_parse_multiple_files(self, tmp_path, filename, adapter_class):  # <- Made async
        """Should parse different file types"""
        # Create test file
        test_file = tmp_path / filename
        if filename.endswith('.md'):
            test_file.write_text("# Test\n\nContent")
        else:
            test_file.write_text("videos:\n  - title: Test\n    scenes: []")

        # Parse with appropriate adapter
        adapter = adapter_class(test_mode=True)
        result = await adapter.adapt(str(test_file))  # <- Changed to adapt()

        assert result.success, f"Failed: {result.error}"
        video_set = result.video_set  # <- Extract from result
        assert video_set is not None
        assert len(video_set.videos) > 0
```

---

## Example 3: Fixture-Based Tests

### Before (Deprecated API)

```python
# tests/test_with_fixtures.py
import pytest
from pathlib import Path
from app.input_adapters import DocumentAdapter

@pytest.fixture
def sample_document(tmp_path):
    """Create sample markdown document"""
    doc = tmp_path / "sample.md"
    doc.write_text("""
# Machine Learning Basics

Introduction to ML concepts.

## Supervised Learning

Training with labeled data.

## Unsupervised Learning

Finding patterns in unlabeled data.
""")
    return doc

@pytest.fixture
def adapter():
    """Create document adapter"""
    return DocumentAdapter()

class TestWithFixtures:
    """Tests using pytest fixtures"""

    def test_parse_with_fixture(self, adapter, sample_document):
        """Should parse document from fixture"""
        video_set = adapter.parse(str(sample_document))

        assert video_set.videos[0].title == "Machine Learning Basics"
        assert len(video_set.videos[0].scenes) >= 2

    def test_multiple_parses(self, adapter, sample_document):
        """Should handle multiple parses"""
        video_set1 = adapter.parse(str(sample_document))
        video_set2 = adapter.parse(str(sample_document))

        assert video_set1.videos[0].title == video_set2.videos[0].title
```

### After Phase 2 (Async Migration)

```python
# tests/test_with_fixtures.py
import pytest
from pathlib import Path
from video_gen.input_adapters import DocumentAdapter

@pytest.fixture
def sample_document(tmp_path):
    """Create sample markdown document"""
    doc = tmp_path / "sample.md"
    doc.write_text("""
# Machine Learning Basics

Introduction to ML concepts.

## Supervised Learning

Training with labeled data.

## Unsupervised Learning

Finding patterns in unlabeled data.
""")
    return doc

@pytest.fixture
def adapter():
    """Create document adapter"""
    return DocumentAdapter(test_mode=True)  # <- Added test_mode

class TestWithFixtures:
    """Tests using pytest fixtures"""

    @pytest.mark.asyncio  # <- Added async marker
    async def test_parse_with_fixture(self, adapter, sample_document):  # <- Made async
        """Should parse document from fixture"""
        result = await adapter.adapt(str(sample_document))  # <- Changed to adapt()

        assert result.success
        video_set = result.video_set  # <- Extract from result
        assert video_set.videos[0].title == "Machine Learning Basics"
        assert len(video_set.videos[0].scenes) >= 2

    @pytest.mark.asyncio  # <- Added async marker
    async def test_multiple_parses(self, adapter, sample_document):  # <- Made async
        """Should handle multiple parses"""
        result1 = await adapter.adapt(str(sample_document))  # <- Changed to adapt()
        result2 = await adapter.adapt(str(sample_document))

        assert result1.success and result2.success
        video_set1 = result1.video_set  # <- Extract from result
        video_set2 = result2.video_set

        assert video_set1.videos[0].title == video_set2.videos[0].title
```

---

## Example 4: Complex Error Handling

### Before (Deprecated API)

```python
# tests/test_error_scenarios.py
import pytest
from app.input_adapters import DocumentAdapter

class TestErrorHandling:
    """Test error scenarios"""

    def test_empty_file(self, tmp_path):
        """Should handle empty file"""
        empty_file = tmp_path / "empty.md"
        empty_file.write_text("")

        adapter = DocumentAdapter()

        with pytest.raises(ValueError) as exc:
            adapter.parse(str(empty_file))

        assert "empty" in str(exc.value).lower()

    def test_invalid_markdown(self, tmp_path):
        """Should handle invalid markdown"""
        bad_file = tmp_path / "bad.md"
        bad_file.write_text("Just some text with no structure")

        adapter = DocumentAdapter()

        try:
            video_set = adapter.parse(str(bad_file))
            # Might succeed with minimal structure
            assert video_set is not None
        except ValueError as e:
            # Or might fail - both are acceptable
            assert "structure" in str(e).lower()

    def test_file_permissions(self, tmp_path):
        """Should handle permission errors"""
        import os

        protected_file = tmp_path / "protected.md"
        protected_file.write_text("# Test")
        os.chmod(protected_file, 0o000)

        adapter = DocumentAdapter()

        try:
            with pytest.raises((ValueError, PermissionError)):
                adapter.parse(str(protected_file))
        finally:
            os.chmod(protected_file, 0o644)
```

### After Phase 2 (Async Migration)

```python
# tests/test_error_scenarios.py
import pytest
from video_gen.input_adapters import DocumentAdapter

class TestErrorHandling:
    """Test error scenarios"""

    @pytest.mark.asyncio
    async def test_empty_file(self, tmp_path):
        """Should handle empty file"""
        empty_file = tmp_path / "empty.md"
        empty_file.write_text("")

        adapter = DocumentAdapter(test_mode=True)
        result = await adapter.adapt(str(empty_file))

        # Check result instead of exception
        assert not result.success
        assert result.error is not None
        assert "empty" in result.error.lower()

    @pytest.mark.asyncio
    async def test_invalid_markdown(self, tmp_path):
        """Should handle invalid markdown"""
        bad_file = tmp_path / "bad.md"
        bad_file.write_text("Just some text with no structure")

        adapter = DocumentAdapter(test_mode=True)
        result = await adapter.adapt(str(bad_file))

        # Both success and failure are acceptable
        if result.success:
            assert result.video_set is not None
        else:
            assert "structure" in result.error.lower()

    @pytest.mark.asyncio
    async def test_file_permissions(self, tmp_path):
        """Should handle permission errors"""
        import os

        protected_file = tmp_path / "protected.md"
        protected_file.write_text("# Test")
        os.chmod(protected_file, 0o000)

        adapter = DocumentAdapter(test_mode=True)

        try:
            result = await adapter.adapt(str(protected_file))

            # Should report permission error
            assert not result.success
            assert result.error is not None
        finally:
            os.chmod(protected_file, 0o644)
```

---

## Example 5: Integration Tests

### Before (Deprecated API)

```python
# tests/test_end_to_end.py
import pytest
from pathlib import Path
from app.input_adapters import DocumentAdapter
from app.services.video_service import VideoService

class TestEndToEnd:
    """End-to-end workflow tests"""

    def test_full_pipeline(self, tmp_path):
        """Test complete pipeline from document to video"""
        # 1. Create input document
        doc = tmp_path / "tutorial.md"
        doc.write_text("""
# Web Development Tutorial

Learn to build websites.

## HTML Basics

Structure your content.

## CSS Styling

Make it beautiful.
""")

        # 2. Parse document
        adapter = DocumentAdapter()
        video_set = adapter.parse(str(doc))

        assert video_set is not None
        assert len(video_set.videos) == 1

        # 3. Process with video service
        service = VideoService()
        video_config = video_set.videos[0]

        # Verify configuration
        assert video_config.title == "Web Development Tutorial"
        assert len(video_config.scenes) >= 2

        # 4. Generate (mock for test)
        # output = service.generate(video_config)
        # assert output.exists()
```

### After Phase 2 (Async Migration)

```python
# tests/test_end_to_end.py
import pytest
from pathlib import Path
from video_gen.input_adapters import DocumentAdapter
from app.services.video_service import VideoService

class TestEndToEnd:
    """End-to-end workflow tests"""

    @pytest.mark.asyncio
    async def test_full_pipeline(self, tmp_path):
        """Test complete pipeline from document to video"""
        # 1. Create input document
        doc = tmp_path / "tutorial.md"
        doc.write_text("""
# Web Development Tutorial

Learn to build websites.

## HTML Basics

Structure your content.

## CSS Styling

Make it beautiful.
""")

        # 2. Parse document
        adapter = DocumentAdapter(test_mode=True)
        result = await adapter.adapt(str(doc))

        assert result.success, f"Parse failed: {result.error}"
        video_set = result.video_set
        assert video_set is not None
        assert len(video_set.videos) == 1

        # 3. Process with video service
        service = VideoService()
        video_config = video_set.videos[0]

        # Verify configuration
        assert video_config.title == "Web Development Tutorial"
        assert len(video_config.scenes) >= 2

        # 4. Generate (mock for test)
        # output = await service.generate_async(video_config)
        # assert output.exists()
```

---

## Summary of Changes

### Phase 1 (Compatibility Layer)

| Aspect | Change | Difficulty |
|--------|--------|-----------|
| Imports | `app.input_adapters` → `video_gen.input_adapters.compat` | Trivial |
| Models | `app.models` → `video_gen.shared.models` | Trivial |
| Parameters | Add `test_mode=True` | Trivial |
| Logic | None | N/A |
| Time | 30 seconds per file | Very Easy |

### Phase 2 (Async Migration)

| Aspect | Change | Difficulty |
|--------|--------|-----------|
| Imports | Remove `.compat` | Trivial |
| Decorators | Add `@pytest.mark.asyncio` | Easy |
| Functions | Add `async` keyword | Easy |
| Method calls | `.parse()` → `await .adapt()` | Easy |
| Result handling | Extract from `result` | Moderate |
| Error handling | Exceptions → result checking | Moderate |
| Time | 5-10 minutes per file | Moderate |

---

**See Also:**
- [ADAPTER_MIGRATION_GUIDE.md](./ADAPTER_MIGRATION_GUIDE.md) - Complete guide
- [ADR_001_INPUT_ADAPTER_CONSOLIDATION.md](../architecture/ADR_001_INPUT_ADAPTER_CONSOLIDATION.md) - Architecture decision
- `tests/test_compat_layer.py` - Compatibility layer tests
