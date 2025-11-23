"""
Tests for Input Adapter Compatibility Layer
============================================

Validates that the compatibility layer correctly wraps async adapters
and provides backward-compatible synchronous .parse() API.
"""

import pytest
import warnings
from pathlib import Path
import tempfile

from video_gen.input_adapters.compat import (
    CompatAdapter,
    DocumentAdapter,
    YouTubeAdapter,
    YAMLAdapter,
    ProgrammaticAdapter,
)
from video_gen.shared.models import VideoSet


class TestCompatAdapter:
    """Test core CompatAdapter wrapper functionality"""

    def test_compat_adapter_wraps_async(self):
        """CompatAdapter should wrap async adapter"""
        from video_gen.input_adapters import DocumentAdapter as AsyncDoc
        async_adapter = AsyncDoc(test_mode=True)
        compat = CompatAdapter(async_adapter)

        assert compat._adapter is async_adapter
        assert not compat._warned  # Warning flag starts False

    def test_compat_adapter_emits_deprecation_warning(self):
        """CompatAdapter.parse() should emit deprecation warning"""
        from video_gen.input_adapters import DocumentAdapter as AsyncDoc

        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write("# Test Document\n\nSimple content.")
            test_file = f.name

        try:
            compat = CompatAdapter(AsyncDoc(test_mode=True))

            # Should emit DeprecationWarning on first call
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                video_set = compat.parse(test_file)

                assert len(w) == 1
                assert issubclass(w[0].category, DeprecationWarning)
                assert "deprecated" in str(w[0].message).lower()
                assert compat._warned  # Flag set after first warning

            # Second call should not emit warning (flag set)
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                video_set = compat.parse(test_file)
                assert len(w) == 0  # No second warning

        finally:
            Path(test_file).unlink()

    def test_compat_adapter_returns_video_set(self):
        """CompatAdapter.parse() should return VideoSet"""
        from video_gen.input_adapters import DocumentAdapter as AsyncDoc

        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write("# Test\n\nContent")
            test_file = f.name

        try:
            compat = CompatAdapter(AsyncDoc(test_mode=True))

            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                result = compat.parse(test_file)

            assert isinstance(result, VideoSet)
            # VideoSet structure varies - just check it's valid
            assert result is not None

        finally:
            Path(test_file).unlink()

    def test_compat_adapter_raises_on_failure(self):
        """CompatAdapter should raise ValueError on adapter failure"""
        from video_gen.input_adapters import DocumentAdapter as AsyncDoc

        compat = CompatAdapter(AsyncDoc())

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with pytest.raises(ValueError, match="Adapter failed"):
                # Non-existent file should cause failure
                compat.parse("/nonexistent/file.md")


class TestDocumentAdapterCompat:
    """Test DocumentAdapter compatibility wrapper"""

    def test_document_adapter_initialization(self):
        """DocumentAdapter should initialize with async adapter"""
        adapter = DocumentAdapter(test_mode=True)
        assert isinstance(adapter, CompatAdapter)
        assert adapter._adapter.__class__.__name__ == "DocumentAdapter"

    def test_document_adapter_parse_method(self):
        """DocumentAdapter.parse() should work like deprecated API"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write("# Test Document\n\n## Section 1\n\nContent here.")
            test_file = f.name

        try:
            adapter = DocumentAdapter(test_mode=True)

            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                video_set = adapter.parse(test_file)

            assert isinstance(video_set, VideoSet)
            # VideoSet structure - just verify it's valid
            assert video_set is not None

        finally:
            Path(test_file).unlink()


class TestYouTubeAdapterCompat:
    """Test YouTubeAdapter compatibility wrapper"""

    def test_youtube_adapter_initialization(self):
        """YouTubeAdapter should initialize with async adapter"""
        adapter = YouTubeAdapter(test_mode=True)
        assert isinstance(adapter, CompatAdapter)
        assert adapter._adapter.__class__.__name__ == "YouTubeAdapter"


class TestYAMLAdapterCompat:
    """Test YAMLAdapter compatibility wrapper"""

    def test_yaml_adapter_initialization(self):
        """YAMLAdapter should initialize with async adapter"""
        adapter = YAMLAdapter(test_mode=True)
        assert isinstance(adapter, CompatAdapter)
        assert adapter._adapter.__class__.__name__ == "YAMLFileAdapter"


class TestProgrammaticAdapterCompat:
    """Test ProgrammaticAdapter compatibility wrapper"""

    def test_programmatic_adapter_initialization(self):
        """ProgrammaticAdapter should initialize with async adapter"""
        adapter = ProgrammaticAdapter(test_mode=True)
        assert isinstance(adapter, CompatAdapter)
        assert adapter._adapter.__class__.__name__ == "ProgrammaticAdapter"


class TestBackwardCompatibility:
    """Test that compat layer matches deprecated API behavior"""

    def test_same_method_signature(self):
        """Compat parse() should have same signature as deprecated"""
        adapter = DocumentAdapter(test_mode=True)

        # Should accept source and **options like deprecated API
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write("# Test\n\nContent")
            test_file = f.name

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")

                # Test with just source
                result1 = adapter.parse(test_file)
                assert isinstance(result1, VideoSet)

                # Test with options (like deprecated API)
                result2 = adapter.parse(test_file, set_name="custom_name")
                assert isinstance(result2, VideoSet)

        finally:
            Path(test_file).unlink()

    def test_exception_on_failure(self):
        """Should raise exceptions like deprecated API (not return Result)"""
        adapter = DocumentAdapter(test_mode=True)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")

            # Deprecated API raised exceptions, not Result objects
            with pytest.raises((ValueError, FileNotFoundError)):
                adapter.parse("/nonexistent/file.md")


class TestMigrationPath:
    """Test migration scenarios from deprecated to canonical"""

    def test_can_use_compat_layer_as_drop_in(self):
        """Can replace 'from app.input_adapters' with 'from compat'"""
        # This is what migration looks like:
        # OLD: from video_gen.input_adapters.compat import DocumentAdapter
        # NEW: from video_gen.input_adapters.compat import DocumentAdapter

        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write("# Migration Test\n\nContent")
            test_file = f.name

        try:
            # Code looks identical to deprecated usage
            from video_gen.input_adapters.compat import DocumentAdapter

            adapter = DocumentAdapter(test_mode=True)
            video_set = adapter.parse(test_file)

            assert isinstance(video_set, VideoSet)

        finally:
            Path(test_file).unlink()

    @pytest.mark.asyncio
    async def test_can_migrate_to_full_async(self):
        """After compat, can migrate to full async API"""
        # This is the final migration target:
        # from video_gen.input_adapters import DocumentAdapter
        # result = await adapter.adapt(source)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write("# Async Test\n\nContent")
            test_file = f.name

        try:
            from video_gen.input_adapters import DocumentAdapter

            adapter = DocumentAdapter(test_mode=True)
            result = await adapter.adapt(test_file)

            assert result.success
            assert isinstance(result.video_set, VideoSet)

        finally:
            Path(test_file).unlink()
