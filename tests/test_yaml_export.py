"""Tests for YAML export functionality.

This module tests the export_to_yaml() method and related helpers
to ensure VideoSet objects can be properly converted back to YAML format.
"""

import pytest
import yaml
from pathlib import Path
from video_gen.input_adapters.yaml_file import YAMLFileAdapter
from video_gen.shared.models import VideoSet, VideoConfig, SceneConfig


@pytest.fixture
def yaml_adapter():
    """Create a YAMLFileAdapter instance for testing."""
    return YAMLFileAdapter(test_mode=True)


@pytest.fixture
def sample_scene():
    """Create a sample SceneConfig for testing."""
    return SceneConfig(
        scene_id="scene_1",
        scene_type="title",
        narration="Welcome to the test video",
        visual_content={
            "title": "Test Video",
            "subtitle": "Testing YAML Export"
        },
        voice="male",
        min_duration=3.0,
        max_duration=15.0
    )


@pytest.fixture
def sample_video(sample_scene):
    """Create a sample VideoConfig for testing."""
    return VideoConfig(
        video_id="test_video",
        title="Test Video",
        description="A test video for YAML export",
        scenes=[sample_scene],
        accent_color="blue",
        voices=["male"]
    )


@pytest.fixture
def sample_video_set(sample_video):
    """Create a sample VideoSet for testing."""
    return VideoSet(
        set_id="test_set",
        name="Test Video Set",
        description="A test video set",
        videos=[sample_video],
        metadata={"test": "data"}
    )


class TestSceneConfigToYAML:
    """Tests for _scene_config_to_yaml() helper method."""

    def test_scene_to_yaml_basic(self, yaml_adapter, sample_scene):
        """Test converting a basic scene to YAML dict."""
        result = yaml_adapter._scene_config_to_yaml(sample_scene)

        assert result["scene_id"] == "scene_1"
        assert result["scene_type"] == "title"
        assert result["narration"] == "Welcome to the test video"
        assert result["visual_content"]["title"] == "Test Video"
        assert result["visual_content"]["subtitle"] == "Testing YAML Export"

    def test_scene_to_yaml_default_voice_omitted(self, yaml_adapter):
        """Test that default voice 'male' is omitted from export."""
        scene = SceneConfig(
            scene_id="scene_1",
            scene_type="title",
            narration="Test",
            visual_content={"title": "Test"},
            voice="male"  # Default
        )
        result = yaml_adapter._scene_config_to_yaml(scene)
        assert "voice" not in result

    def test_scene_to_yaml_non_default_voice_included(self, yaml_adapter):
        """Test that non-default voice is included in export."""
        scene = SceneConfig(
            scene_id="scene_1",
            scene_type="title",
            narration="Test",
            visual_content={"title": "Test"},
            voice="female"  # Non-default
        )
        result = yaml_adapter._scene_config_to_yaml(scene)
        assert result["voice"] == "female"

    def test_scene_to_yaml_default_durations_omitted(self, yaml_adapter):
        """Test that default durations are omitted from export."""
        scene = SceneConfig(
            scene_id="scene_1",
            scene_type="title",
            narration="Test",
            visual_content={"title": "Test"},
            min_duration=3.0,  # Default
            max_duration=15.0  # Default
        )
        result = yaml_adapter._scene_config_to_yaml(scene)
        assert "min_duration" not in result
        assert "max_duration" not in result

    def test_scene_to_yaml_non_default_durations_included(self, yaml_adapter):
        """Test that non-default durations are included in export."""
        scene = SceneConfig(
            scene_id="scene_1",
            scene_type="title",
            narration="Test",
            visual_content={"title": "Test"},
            min_duration=5.0,  # Non-default
            max_duration=20.0  # Non-default
        )
        result = yaml_adapter._scene_config_to_yaml(scene)
        assert result["min_duration"] == 5.0
        assert result["max_duration"] == 20.0


class TestVideoConfigToYAML:
    """Tests for _video_config_to_yaml() helper method."""

    def test_video_to_yaml_basic(self, yaml_adapter, sample_video):
        """Test converting a basic video to YAML dict."""
        result = yaml_adapter._video_config_to_yaml(sample_video)

        assert result["video_id"] == "test_video"
        assert result["title"] == "Test Video"
        assert result["description"] == "A test video for YAML export"
        assert result["accent_color"] == "blue"
        assert len(result["scenes"]) == 1

    def test_video_to_yaml_single_voice(self, yaml_adapter):
        """Test that single voice is exported as string, not list."""
        scene = SceneConfig(
            scene_id="scene_1",
            scene_type="title",
            narration="Test",
            visual_content={"title": "Test"}
        )
        video = VideoConfig(
            video_id="test",
            title="Test",
            description="Test",
            scenes=[scene],
            voices=["male"]
        )
        result = yaml_adapter._video_config_to_yaml(video)
        assert result["voice"] == "male"
        assert "voices" not in result

    def test_video_to_yaml_multiple_voices(self, yaml_adapter):
        """Test that multiple voices are exported as list."""
        scene = SceneConfig(
            scene_id="scene_1",
            scene_type="title",
            narration="Test",
            visual_content={"title": "Test"}
        )
        video = VideoConfig(
            video_id="test",
            title="Test",
            description="Test",
            scenes=[scene],
            voices=["male", "female"]
        )
        result = yaml_adapter._video_config_to_yaml(video)
        assert result["voices"] == ["male", "female"]
        assert "voice" not in result

    def test_video_to_yaml_with_scenes(self, yaml_adapter, sample_video):
        """Test that scenes are properly converted."""
        result = yaml_adapter._video_config_to_yaml(sample_video)

        assert len(result["scenes"]) == 1
        scene = result["scenes"][0]
        assert scene["scene_id"] == "scene_1"
        assert scene["scene_type"] == "title"
        assert scene["narration"] == "Welcome to the test video"


class TestVideoSetToYAML:
    """Tests for _video_set_to_yaml() helper method."""

    def test_video_set_to_yaml_basic(self, yaml_adapter, sample_video_set):
        """Test converting a basic video set to YAML dict."""
        result = yaml_adapter._video_set_to_yaml(sample_video_set)

        assert result["set_id"] == "test_set"
        assert result["name"] == "Test Video Set"
        assert result["description"] == "A test video set"
        assert len(result["videos"]) == 1

    def test_video_set_to_yaml_metadata_filtered(self, yaml_adapter):
        """Test that runtime metadata is filtered out."""
        video_set = VideoSet(
            set_id="test",
            name="Test",
            description="Test",
            videos=[],
            metadata={
                "test": "data",
                "source": "should_be_filtered",
                "videos_generated": "should_be_filtered",
                "generation_timestamp": "should_be_filtered"
            }
        )
        # Add a dummy video to avoid empty videos error
        video_set.videos.append(
            VideoConfig(
                video_id="dummy",
                title="Dummy",
                description="Dummy",
                scenes=[
                    SceneConfig(
                        scene_id="scene_1",
                        scene_type="title",
                        narration="Test",
                        visual_content={"title": "Test"}
                    )
                ]
            )
        )
        result = yaml_adapter._video_set_to_yaml(video_set)

        assert "metadata" in result
        assert result["metadata"]["test"] == "data"
        assert "source" not in result["metadata"]
        assert "videos_generated" not in result["metadata"]
        assert "generation_timestamp" not in result["metadata"]

    def test_video_set_to_yaml_multiple_videos(self, yaml_adapter, sample_video):
        """Test converting video set with multiple videos."""
        video_set = VideoSet(
            set_id="test",
            name="Test",
            description="Test",
            videos=[sample_video, sample_video]
        )
        result = yaml_adapter._video_set_to_yaml(video_set)
        assert len(result["videos"]) == 2


class TestExportToYAML:
    """Tests for export_to_yaml() main method."""

    def test_export_video_set_format(self, yaml_adapter, sample_video_set, tmp_path):
        """Test exporting in video_set format."""
        output_path = tmp_path / "test_output.yaml"
        success = yaml_adapter.export_to_yaml(sample_video_set, output_path, format_type="video_set")

        assert success is True
        assert output_path.exists()

        # Verify YAML structure
        with open(output_path, 'r') as f:
            data = yaml.safe_load(f)

        assert data["set_id"] == "test_set"
        assert data["name"] == "Test Video Set"
        assert "videos" in data
        assert len(data["videos"]) == 1

    def test_export_single_video_format(self, yaml_adapter, sample_video_set, tmp_path):
        """Test exporting in single_video format."""
        output_path = tmp_path / "test_output.yaml"
        success = yaml_adapter.export_to_yaml(sample_video_set, output_path, format_type="single_video")

        assert success is True
        assert output_path.exists()

        # Verify YAML structure
        with open(output_path, 'r') as f:
            data = yaml.safe_load(f)

        assert data["video_id"] == "test_video"
        assert data["title"] == "Test Video"
        assert "scenes" in data
        assert len(data["scenes"]) == 1

    def test_export_creates_directories(self, yaml_adapter, sample_video_set, tmp_path):
        """Test that export creates parent directories if needed."""
        output_path = tmp_path / "subdir" / "nested" / "test.yaml"
        success = yaml_adapter.export_to_yaml(sample_video_set, output_path)

        assert success is True
        assert output_path.exists()
        assert output_path.parent.exists()

    def test_export_invalid_format_type(self, yaml_adapter, sample_video_set, tmp_path):
        """Test that invalid format_type raises ValueError."""
        output_path = tmp_path / "test.yaml"
        with pytest.raises(ValueError, match="Invalid format_type"):
            yaml_adapter.export_to_yaml(sample_video_set, output_path, format_type="invalid")

    def test_export_empty_video_set(self, yaml_adapter, tmp_path):
        """Test that empty VideoSet raises ValueError."""
        video_set = VideoSet(set_id="empty", name="Empty", videos=[])
        output_path = tmp_path / "test.yaml"
        with pytest.raises(ValueError, match="Cannot export empty VideoSet"):
            yaml_adapter.export_to_yaml(video_set, output_path)

    def test_export_multiple_videos_single_format_error(self, yaml_adapter, sample_video, tmp_path):
        """Test that multiple videos can't be exported as single_video format."""
        video_set = VideoSet(
            set_id="test",
            name="Test",
            videos=[sample_video, sample_video]
        )
        output_path = tmp_path / "test.yaml"
        with pytest.raises(ValueError, match="Cannot export 2 videos as 'single_video' format"):
            yaml_adapter.export_to_yaml(video_set, output_path, format_type="single_video")


class TestRoundTripConversion:
    """Tests for round-trip conversion (import → export → import)."""

    @pytest.mark.asyncio
    async def test_round_trip_video_set_format(self, yaml_adapter, sample_video_set, tmp_path):
        """Test round-trip conversion for video_set format."""
        # Export
        export_path = tmp_path / "export.yaml"
        yaml_adapter.export_to_yaml(sample_video_set, export_path, format_type="video_set")

        # Import back
        result = await yaml_adapter.adapt(export_path)

        assert result.success is True
        assert result.video_set.set_id == sample_video_set.set_id
        assert result.video_set.name == sample_video_set.name
        assert len(result.video_set.videos) == len(sample_video_set.videos)

        # Compare video details
        original_video = sample_video_set.videos[0]
        imported_video = result.video_set.videos[0]
        assert imported_video.video_id == original_video.video_id
        assert imported_video.title == original_video.title
        assert imported_video.description == original_video.description
        assert imported_video.accent_color == original_video.accent_color

        # Compare scene details
        assert len(imported_video.scenes) == len(original_video.scenes)
        original_scene = original_video.scenes[0]
        imported_scene = imported_video.scenes[0]
        assert imported_scene.scene_id == original_scene.scene_id
        assert imported_scene.scene_type == original_scene.scene_type
        assert imported_scene.narration == original_scene.narration

    @pytest.mark.asyncio
    async def test_round_trip_single_video_format(self, yaml_adapter, sample_video_set, tmp_path):
        """Test round-trip conversion for single_video format."""
        # Export
        export_path = tmp_path / "export.yaml"
        yaml_adapter.export_to_yaml(sample_video_set, export_path, format_type="single_video")

        # Import back
        result = await yaml_adapter.adapt(export_path)

        assert result.success is True
        assert len(result.video_set.videos) == 1

        # Compare video details
        original_video = sample_video_set.videos[0]
        imported_video = result.video_set.videos[0]
        assert imported_video.video_id == original_video.video_id
        assert imported_video.title == original_video.title
        assert imported_video.description == original_video.description

    @pytest.mark.asyncio
    async def test_round_trip_preserves_special_characters(self, yaml_adapter, tmp_path):
        """Test that special characters are preserved in round-trip."""
        # Create video set with special characters
        scene = SceneConfig(
            scene_id="scene_1",
            scene_type="title",
            narration="Test with quotes: \"Hello\" and 'world'",
            visual_content={
                "title": "Test: Special & Characters",
                "subtitle": "With 日本語 and émojis 🎉"
            }
        )
        video = VideoConfig(
            video_id="test",
            title="Test: Special Characters",
            description="Description with\nmultiple\nlines",
            scenes=[scene]
        )
        video_set = VideoSet(
            set_id="test",
            name="Test",
            videos=[video]
        )

        # Export
        export_path = tmp_path / "export.yaml"
        yaml_adapter.export_to_yaml(video_set, export_path)

        # Import back
        result = await yaml_adapter.adapt(export_path)

        assert result.success is True
        imported_scene = result.video_set.videos[0].scenes[0]
        assert "quotes: \"Hello\"" in imported_scene.narration
        assert "日本語" in imported_scene.visual_content["subtitle"]
        assert "🎉" in imported_scene.visual_content["subtitle"]


class TestYAMLOutputFormat:
    """Tests for YAML output formatting and readability."""

    def test_yaml_output_is_readable(self, yaml_adapter, sample_video_set, tmp_path):
        """Test that exported YAML is human-readable."""
        output_path = tmp_path / "test.yaml"
        yaml_adapter.export_to_yaml(sample_video_set, output_path)

        content = output_path.read_text()

        # Check that it's not using flow style (inline dicts/lists)
        assert "- {" not in content or content.count("- {") < 2  # Minimal flow style
        assert content.count("\n") > 10  # Multiple lines

        # Check key formatting
        assert "set_id:" in content
        assert "videos:" in content
        assert "scenes:" in content

    def test_yaml_unicode_support(self, yaml_adapter, tmp_path):
        """Test that Unicode characters are properly supported."""
        scene = SceneConfig(
            scene_id="scene_1",
            scene_type="title",
            narration="Test with Unicode: 日本語 français español",
            visual_content={"title": "Unicode Test 🎉"}
        )
        video = VideoConfig(
            video_id="test",
            title="Unicode Test",
            description="Test",
            scenes=[scene]
        )
        video_set = VideoSet(set_id="test", name="Test", videos=[video])

        output_path = tmp_path / "test.yaml"
        yaml_adapter.export_to_yaml(video_set, output_path)

        # Read back and verify
        with open(output_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        assert "日本語" in data["videos"][0]["scenes"][0]["narration"]
        assert "🎉" in data["videos"][0]["scenes"][0]["visual_content"]["title"]
