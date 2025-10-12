"""
Comprehensive tests for YAML schema validation in YAMLFileAdapter.

Tests cover:
- Video set format validation
- Single video format validation
- Required field validation
- Type validation
- Constraint validation (lengths, ranges)
- Cross-field validation
- Error message quality
"""

import pytest
import tempfile
from pathlib import Path
from video_gen.input_adapters.yaml_file import YAMLFileAdapter


@pytest.fixture
def adapter():
    """Create adapter in test mode."""
    return YAMLFileAdapter(test_mode=True)


@pytest.fixture
def temp_yaml_file():
    """Create temporary YAML file for testing."""
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False, encoding='utf-8')
    yield temp_file
    temp_file.close()
    Path(temp_file.name).unlink(missing_ok=True)


class TestVideoSetValidation:
    """Test validation for video_set format."""

    @pytest.mark.asyncio
    async def test_valid_video_set(self, adapter, temp_yaml_file):
        """Test that valid video set passes validation."""
        yaml_content = """
set_id: test_set
name: Test Set
videos:
  - video_id: video_1
    title: Test Video
    scenes:
      - scene_id: scene_1
        scene_type: title
        narration: "Hello world"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is True
        assert result.error is None
        assert result.video_set is not None
        assert len(result.video_set.videos) == 1

    @pytest.mark.asyncio
    async def test_missing_videos_field(self, adapter, temp_yaml_file):
        """Test that missing 'videos' field is caught."""
        yaml_content = """
set_id: test_set
name: Test Set
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        # When neither 'videos' nor 'video_id'/'scenes' present, format is unknown
        assert "Unrecognized YAML format" in result.error

    @pytest.mark.asyncio
    async def test_videos_not_a_list(self, adapter, temp_yaml_file):
        """Test that videos must be a list."""
        yaml_content = """
set_id: test_set
videos: "not a list"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "must be a list" in result.error

    @pytest.mark.asyncio
    async def test_empty_videos_list(self, adapter, temp_yaml_file):
        """Test that empty videos list is caught."""
        yaml_content = """
set_id: test_set
videos: []
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "cannot be empty" in result.error

    @pytest.mark.asyncio
    async def test_too_many_videos(self, adapter, temp_yaml_file):
        """Test that >100 videos is caught."""
        # Generate 101 minimal videos
        videos = []
        for i in range(101):
            videos.append(f"""
  - video_id: video_{i}
    title: Video {i}
    scenes:
      - scene_id: scene_1
        scene_type: title
        narration: "Test"
""")

        yaml_content = f"""
set_id: test_set
videos:
{''.join(videos)}
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "Too many videos" in result.error
        assert "maximum 100" in result.error


class TestSingleVideoValidation:
    """Test validation for single_video format."""

    @pytest.mark.asyncio
    async def test_valid_single_video(self, adapter, temp_yaml_file):
        """Test that valid single video passes validation."""
        yaml_content = """
video_id: test_video
title: Test Video
description: A test video
scenes:
  - scene_id: scene_1
    scene_type: title
    narration: "Hello world"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is True
        assert result.error is None
        assert result.video_set is not None

    @pytest.mark.asyncio
    async def test_missing_video_id(self, adapter, temp_yaml_file):
        """Test that missing video_id is caught."""
        yaml_content = """
title: Test Video
scenes:
  - scene_id: scene_1
    scene_type: title
    narration: "Test"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "Missing required field 'video_id' or 'id'" in result.error

    @pytest.mark.asyncio
    async def test_missing_title(self, adapter, temp_yaml_file):
        """Test that missing title is caught."""
        yaml_content = """
video_id: test_video
scenes:
  - scene_id: scene_1
    scene_type: title
    narration: "Test"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "Missing required field 'title'" in result.error

    @pytest.mark.asyncio
    async def test_missing_scenes(self, adapter, temp_yaml_file):
        """Test that missing scenes is caught."""
        yaml_content = """
video_id: test_video
title: Test Video
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "Missing required field 'scenes'" in result.error


class TestVideoConfigValidation:
    """Test validation for video configuration fields."""

    @pytest.mark.asyncio
    async def test_video_id_wrong_type(self, adapter, temp_yaml_file):
        """Test that video_id must be string."""
        yaml_content = """
video_id: 123
title: Test Video
scenes:
  - scene_id: scene_1
    scene_type: title
    narration: "Test"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "video_id: Must be a string" in result.error

    @pytest.mark.asyncio
    async def test_video_id_too_long(self, adapter, temp_yaml_file):
        """Test that video_id max length is enforced."""
        long_id = "x" * 201
        yaml_content = f"""
video_id: {long_id}
title: Test Video
scenes:
  - scene_id: scene_1
    scene_type: title
    narration: "Test"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "video_id: Too long" in result.error
        assert "max 200" in result.error

    @pytest.mark.asyncio
    async def test_title_wrong_type(self, adapter, temp_yaml_file):
        """Test that title must be string."""
        yaml_content = """
video_id: test_video
title: 123
scenes:
  - scene_id: scene_1
    scene_type: title
    narration: "Test"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "title: Must be a string" in result.error

    @pytest.mark.asyncio
    async def test_title_too_long(self, adapter, temp_yaml_file):
        """Test that title max length is enforced."""
        long_title = "x" * 501
        yaml_content = f"""
video_id: test_video
title: {long_title}
scenes:
  - scene_id: scene_1
    scene_type: title
    narration: "Test"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "title: Too long" in result.error
        assert "max 500" in result.error

    @pytest.mark.asyncio
    async def test_description_wrong_type(self, adapter, temp_yaml_file):
        """Test that description must be string if present."""
        yaml_content = """
video_id: test_video
title: Test Video
description: 123
scenes:
  - scene_id: scene_1
    scene_type: title
    narration: "Test"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "description: Must be a string" in result.error

    @pytest.mark.asyncio
    async def test_voices_wrong_type(self, adapter, temp_yaml_file):
        """Test that voices must be list if present."""
        yaml_content = """
video_id: test_video
title: Test Video
voices: "male"
scenes:
  - scene_id: scene_1
    scene_type: title
    narration: "Test"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "voices: Must be a list" in result.error

    @pytest.mark.asyncio
    async def test_voice_wrong_type(self, adapter, temp_yaml_file):
        """Test that voice must be string if present."""
        yaml_content = """
video_id: test_video
title: Test Video
voice: 123
scenes:
  - scene_id: scene_1
    scene_type: title
    narration: "Test"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "voice: Must be a string" in result.error


class TestSceneValidation:
    """Test validation for scene configuration fields."""

    @pytest.mark.asyncio
    async def test_scenes_not_a_list(self, adapter, temp_yaml_file):
        """Test that scenes must be a list."""
        yaml_content = """
video_id: test_video
title: Test Video
scenes: "not a list"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "scenes: Must be a list" in result.error

    @pytest.mark.asyncio
    async def test_empty_scenes_list(self, adapter, temp_yaml_file):
        """Test that scenes cannot be empty."""
        yaml_content = """
video_id: test_video
title: Test Video
scenes: []
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "scenes: Cannot be empty" in result.error

    @pytest.mark.asyncio
    async def test_missing_scene_id(self, adapter, temp_yaml_file):
        """Test that scene_id is required."""
        yaml_content = """
video_id: test_video
title: Test Video
scenes:
  - scene_type: title
    narration: "Test"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "Missing required field 'scene_id'" in result.error

    @pytest.mark.asyncio
    async def test_missing_scene_type(self, adapter, temp_yaml_file):
        """Test that scene_type is required."""
        yaml_content = """
video_id: test_video
title: Test Video
scenes:
  - scene_id: scene_1
    narration: "Test"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "Missing required field 'scene_type' or 'type'" in result.error

    @pytest.mark.asyncio
    async def test_invalid_scene_type(self, adapter, temp_yaml_file):
        """Test that invalid scene_type is caught."""
        yaml_content = """
video_id: test_video
title: Test Video
scenes:
  - scene_id: scene_1
    scene_type: invalid_type
    narration: "Test"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "Invalid type 'invalid_type'" in result.error
        assert "Must be one of:" in result.error

    @pytest.mark.asyncio
    async def test_missing_narration(self, adapter, temp_yaml_file):
        """Test that narration is required."""
        yaml_content = """
video_id: test_video
title: Test Video
scenes:
  - scene_id: scene_1
    scene_type: title
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "Missing required field 'narration'" in result.error

    @pytest.mark.asyncio
    async def test_narration_wrong_type(self, adapter, temp_yaml_file):
        """Test that narration must be string."""
        yaml_content = """
video_id: test_video
title: Test Video
scenes:
  - scene_id: scene_1
    scene_type: title
    narration: 123
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "narration: Must be a string" in result.error

    @pytest.mark.asyncio
    async def test_narration_too_long(self, adapter, temp_yaml_file):
        """Test that narration max length is enforced."""
        long_narration = "x" * 50001
        yaml_content = f"""
video_id: test_video
title: Test Video
scenes:
  - scene_id: scene_1
    scene_type: title
    narration: "{long_narration}"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "narration: Too long" in result.error
        assert "max 50000" in result.error

    @pytest.mark.asyncio
    async def test_visual_content_wrong_type(self, adapter, temp_yaml_file):
        """Test that visual_content must be dict if present."""
        yaml_content = """
video_id: test_video
title: Test Video
scenes:
  - scene_id: scene_1
    scene_type: title
    narration: "Test"
    visual_content: "not a dict"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "visual_content: Must be a dictionary" in result.error

    @pytest.mark.asyncio
    async def test_min_duration_wrong_type(self, adapter, temp_yaml_file):
        """Test that min_duration must be number."""
        yaml_content = """
video_id: test_video
title: Test Video
scenes:
  - scene_id: scene_1
    scene_type: title
    narration: "Test"
    min_duration: "not a number"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "min_duration: Must be a number" in result.error

    @pytest.mark.asyncio
    async def test_min_duration_out_of_range(self, adapter, temp_yaml_file):
        """Test that min_duration range is enforced."""
        yaml_content = """
video_id: test_video
title: Test Video
scenes:
  - scene_id: scene_1
    scene_type: title
    narration: "Test"
    min_duration: 400
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "min_duration: Out of range" in result.error
        assert "must be 0-300" in result.error

    @pytest.mark.asyncio
    async def test_max_duration_out_of_range(self, adapter, temp_yaml_file):
        """Test that max_duration range is enforced."""
        yaml_content = """
video_id: test_video
title: Test Video
scenes:
  - scene_id: scene_1
    scene_type: title
    narration: "Test"
    max_duration: -5
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "max_duration: Out of range" in result.error

    @pytest.mark.asyncio
    async def test_min_greater_than_max_duration(self, adapter, temp_yaml_file):
        """Test cross-field validation: min_duration <= max_duration."""
        yaml_content = """
video_id: test_video
title: Test Video
scenes:
  - scene_id: scene_1
    scene_type: title
    narration: "Test"
    min_duration: 10
    max_duration: 5
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        assert "min_duration (10) cannot be greater than max_duration (5)" in result.error


class TestMultipleErrors:
    """Test that multiple validation errors are reported together."""

    @pytest.mark.asyncio
    async def test_multiple_errors_reported(self, adapter, temp_yaml_file):
        """Test that all validation errors are reported at once."""
        yaml_content = """
video_id: test_video
scenes:
  - scene_type: invalid_type
    narration: 123
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        # Should contain multiple errors
        assert "Missing required field 'title'" in result.error
        assert "Missing required field 'scene_id'" in result.error
        assert "Invalid type 'invalid_type'" in result.error
        assert "narration: Must be a string" in result.error

    @pytest.mark.asyncio
    async def test_error_context_in_video_set(self, adapter, temp_yaml_file):
        """Test that errors include context for video_set format."""
        yaml_content = """
videos:
  - video_id: video_1
    scenes:
      - scene_id: scene_1
        scene_type: title
        narration: "Test"
  - video_id: video_2
    title: Video 2
    scenes: []
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is False
        # Should show which video has errors
        assert "videos[0]" in result.error
        assert "videos[1]" in result.error


class TestBackwardCompatibility:
    """Test validation with backward-compatible field names."""

    @pytest.mark.asyncio
    async def test_id_instead_of_video_id(self, adapter, temp_yaml_file):
        """Test that 'id' works as alternative to 'video_id'."""
        yaml_content = """
id: test_video
title: Test Video
scenes:
  - scene_id: scene_1
    scene_type: title
    narration: "Test"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_type_instead_of_scene_type(self, adapter, temp_yaml_file):
        """Test that 'type' works as alternative to 'scene_type'."""
        yaml_content = """
video_id: test_video
title: Test Video
scenes:
  - scene_id: scene_1
    type: title
    narration: "Test"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is True


class TestValidSceneTypes:
    """Test all valid scene types are accepted."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("scene_type", [
        "title", "command", "list", "outro", "code_comparison", "quote",
        "learning_objectives", "problem", "solution", "checkpoint", "quiz", "exercise"
    ])
    async def test_valid_scene_types(self, adapter, temp_yaml_file, scene_type):
        """Test that all documented scene types are valid."""
        yaml_content = f"""
video_id: test_video
title: Test Video
scenes:
  - scene_id: scene_1
    scene_type: {scene_type}
    narration: "Test narration"
"""
        temp_yaml_file.write(yaml_content)
        temp_yaml_file.flush()

        result = await adapter.adapt(temp_yaml_file.name)
        assert result.success is True, f"Valid scene_type '{scene_type}' should be accepted"
