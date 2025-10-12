"""Tests for YAMLFileAdapter - Phase 1: Core validation and reading.

Tests cover:
- Security validation (path traversal, system dirs, file size)
- YAML file reading with safe parsing
- Format detection (single video vs video set)
- Error handling
"""

import pytest
import tempfile
from pathlib import Path
import yaml

from video_gen.input_adapters.yaml_file import YAMLFileAdapter
from video_gen.input_adapters.base import InputAdapterResult


@pytest.fixture
def adapter():
    """Create adapter instance with test mode enabled."""
    return YAMLFileAdapter(test_mode=True)


@pytest.fixture
def temp_yaml_file():
    """Create a temporary YAML file for testing."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml_data = {
            "video_id": "test_video",
            "title": "Test Video",
            "scenes": [
                {
                    "scene_id": "scene_1",
                    "scene_type": "title",
                    "narration": "Test narration",
                    "visual_content": {"title": "Test"}
                }
            ]
        }
        yaml.dump(yaml_data, f)
        temp_path = Path(f.name)

    yield temp_path

    # Cleanup
    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def temp_video_set_file():
    """Create a temporary YAML file with video set format."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml_data = {
            "set_id": "test_set",
            "name": "Test Set",
            "videos": [
                {
                    "video_id": "video_1",
                    "title": "Video 1",
                    "scenes": [
                        {
                            "scene_id": "scene_1",
                            "scene_type": "title",
                            "narration": "Test",
                            "visual_content": {"title": "Test"}
                        }
                    ]
                }
            ]
        }
        yaml.dump(yaml_data, f)
        temp_path = Path(f.name)

    yield temp_path

    # Cleanup
    if temp_path.exists():
        temp_path.unlink()


class TestSecurityValidation:
    """Test security features of YAML adapter."""

    @pytest.mark.asyncio
    async def test_system_directory_blocked(self, adapter):
        """Test that system directories are blocked."""
        system_paths = [
            "/etc/passwd",
            "/root/.ssh/id_rsa",
            "/sys/kernel/config",
            "/proc/version"
        ]

        for path in system_paths:
            with pytest.raises(ValueError, match="Access to system directories denied"):
                await adapter._read_yaml_file(path)

    @pytest.mark.asyncio
    async def test_file_size_limit(self, adapter):
        """Test that files exceeding size limit are rejected."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            # Create a file larger than 10MB
            large_content = "x" * (YAMLFileAdapter.MAX_FILE_SIZE + 1000)
            f.write(large_content)
            temp_path = Path(f.name)

        try:
            with pytest.raises(ValueError, match="File too large"):
                await adapter._read_yaml_file(temp_path)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    @pytest.mark.asyncio
    async def test_invalid_file_extension(self, adapter):
        """Test that non-YAML files are rejected."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("test content")
            temp_path = Path(f.name)

        try:
            with pytest.raises(ValueError, match="Invalid file extension"):
                await adapter._read_yaml_file(temp_path)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    @pytest.mark.asyncio
    async def test_nonexistent_file(self, adapter):
        """Test that nonexistent files raise error."""
        with pytest.raises(FileNotFoundError):
            await adapter._read_yaml_file("/tmp/nonexistent_file_12345.yaml")

    @pytest.mark.asyncio
    async def test_directory_not_file(self, adapter):
        """Test that directories are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(ValueError, match="Not a file"):
                await adapter._read_yaml_file(tmpdir)


class TestYAMLParsing:
    """Test YAML file reading and parsing."""

    @pytest.mark.asyncio
    async def test_read_valid_yaml(self, adapter, temp_yaml_file):
        """Test reading a valid YAML file."""
        yaml_data = await adapter._read_yaml_file(temp_yaml_file)

        assert isinstance(yaml_data, dict)
        assert yaml_data["video_id"] == "test_video"
        assert yaml_data["title"] == "Test Video"
        assert "scenes" in yaml_data

    @pytest.mark.asyncio
    async def test_safe_load_prevents_code_execution(self, adapter):
        """Test that yaml.safe_load prevents arbitrary code execution."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            # Try to inject Python code (should fail with safe_load)
            f.write("!!python/object/apply:os.system ['echo hacked']")
            temp_path = Path(f.name)

        try:
            with pytest.raises(ValueError, match="YAML parsing error"):
                await adapter._read_yaml_file(temp_path)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    @pytest.mark.asyncio
    async def test_invalid_yaml_syntax(self, adapter):
        """Test that invalid YAML syntax is caught."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("invalid: yaml: syntax: error:")
            temp_path = Path(f.name)

        try:
            with pytest.raises(ValueError, match="YAML parsing error"):
                await adapter._read_yaml_file(temp_path)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    @pytest.mark.asyncio
    async def test_non_dict_root(self, adapter):
        """Test that non-dictionary YAML root is rejected."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(["list", "of", "items"], f)
            temp_path = Path(f.name)

        try:
            with pytest.raises(ValueError, match="root must be a dictionary"):
                await adapter._read_yaml_file(temp_path)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    @pytest.mark.asyncio
    async def test_unicode_content(self, adapter):
        """Test that Unicode content is handled correctly."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False, encoding='utf-8') as f:
            yaml_data = {
                "video_id": "unicode_test",
                "title": "Test with Unicode: 你好世界 🎉",
                "scenes": []
            }
            yaml.dump(yaml_data, f, allow_unicode=True)
            temp_path = Path(f.name)

        try:
            result = await adapter._read_yaml_file(temp_path)
            assert "你好世界" in result["title"]
            assert "🎉" in result["title"]
        finally:
            if temp_path.exists():
                temp_path.unlink()


class TestFormatDetection:
    """Test format detection logic."""

    def test_detect_single_video_format(self, adapter):
        """Test detection of single video format."""
        yaml_data = {
            "video_id": "test",
            "scenes": []
        }
        format_type = adapter._detect_format(yaml_data)
        assert format_type == "single_video"

    def test_detect_video_set_format(self, adapter):
        """Test detection of video set format."""
        yaml_data = {
            "videos": [
                {"video_id": "v1", "scenes": []},
                {"video_id": "v2", "scenes": []}
            ]
        }
        format_type = adapter._detect_format(yaml_data)
        assert format_type == "video_set"

    def test_detect_unknown_format(self, adapter):
        """Test detection of unknown format."""
        yaml_data = {
            "some_other_key": "value"
        }
        format_type = adapter._detect_format(yaml_data)
        assert format_type == "unknown"

    def test_detect_format_with_scenes_only(self, adapter):
        """Test detection when only scenes are present."""
        yaml_data = {
            "scenes": [
                {"scene_id": "s1", "scene_type": "title"}
            ]
        }
        format_type = adapter._detect_format(yaml_data)
        assert format_type == "single_video"


class TestAdaptMethod:
    """Test the main adapt() method."""

    @pytest.mark.asyncio
    async def test_adapt_single_video(self, adapter, temp_yaml_file):
        """Test adapting a single video YAML file."""
        result = await adapter.adapt(temp_yaml_file)

        assert result.success
        assert result.video_set is not None
        assert len(result.video_set.videos) == 1
        assert result.video_set.videos[0].video_id == "test_video"
        assert result.metadata["format_type"] == "single_video"

    @pytest.mark.asyncio
    async def test_adapt_video_set(self, adapter, temp_video_set_file):
        """Test adapting a video set YAML file."""
        result = await adapter.adapt(temp_video_set_file)

        assert result.success
        assert result.video_set is not None
        assert result.video_set.set_id == "test_set"
        assert len(result.video_set.videos) >= 1
        assert result.metadata["format_type"] == "video_set"

    @pytest.mark.asyncio
    async def test_adapt_with_kwargs_override(self, adapter, temp_yaml_file):
        """Test that kwargs override YAML values."""
        result = await adapter.adapt(
            temp_yaml_file,
            accent_color="purple",
            voice="female"
        )

        assert result.success
        video = result.video_set.videos[0]
        assert video.accent_color == "purple"
        assert video.scenes[0].voice == "female"

    @pytest.mark.asyncio
    async def test_adapt_invalid_format(self, adapter):
        """Test adapting a file with unknown format."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({"unknown_key": "value"}, f)
            temp_path = Path(f.name)

        try:
            result = await adapter.adapt(temp_path)
            assert not result.success
            assert "Unrecognized YAML format" in result.error
        finally:
            if temp_path.exists():
                temp_path.unlink()

    @pytest.mark.asyncio
    async def test_adapt_nonexistent_file(self, adapter):
        """Test adapting a nonexistent file."""
        result = await adapter.adapt("/tmp/nonexistent_12345.yaml")

        assert not result.success
        assert "File not found" in result.error


class TestValidationMethods:
    """Test validation helper methods."""

    @pytest.mark.asyncio
    async def test_validate_source_valid(self, adapter, temp_yaml_file):
        """Test validation of valid YAML file."""
        is_valid = await adapter.validate_source(temp_yaml_file)
        assert is_valid

    @pytest.mark.asyncio
    async def test_validate_source_invalid_extension(self, adapter):
        """Test validation rejects non-YAML files."""
        with tempfile.NamedTemporaryFile(suffix='.txt') as f:
            is_valid = await adapter.validate_source(f.name)
            assert not is_valid

    @pytest.mark.asyncio
    async def test_validate_source_nonexistent(self, adapter):
        """Test validation of nonexistent file."""
        is_valid = await adapter.validate_source("/tmp/nonexistent.yaml")
        assert not is_valid

    def test_supports_format_yaml(self, adapter):
        """Test format support for .yaml extension."""
        assert adapter.supports_format(".yaml")
        assert adapter.supports_format(".yml")

    def test_supports_format_invalid(self, adapter):
        """Test format support rejects other extensions."""
        assert not adapter.supports_format(".txt")
        assert not adapter.supports_format(".json")
        assert not adapter.supports_format(".pdf")


class TestTestMode:
    """Test behavior with test_mode flag."""

    def test_test_mode_disabled_by_default(self):
        """Test that test_mode is disabled by default."""
        adapter = YAMLFileAdapter()
        assert not adapter.test_mode

    def test_test_mode_enabled(self):
        """Test that test_mode can be enabled."""
        adapter = YAMLFileAdapter(test_mode=True)
        assert adapter.test_mode

    @pytest.mark.asyncio
    async def test_test_mode_bypasses_project_root_check(self):
        """Test that test_mode allows files outside project root."""
        adapter = YAMLFileAdapter(test_mode=True)

        # Create temp file outside project
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({"video_id": "test", "scenes": []}, f)
            temp_path = Path(f.name)

        try:
            # Should work with test_mode=True
            yaml_data = await adapter._read_yaml_file(temp_path)
            assert yaml_data["video_id"] == "test"
        finally:
            if temp_path.exists():
                temp_path.unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
