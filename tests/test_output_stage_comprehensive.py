"""
Comprehensive tests for OutputStage to achieve 80%+ coverage.

Tests cover:
- Complete video workflow (new template-based pipeline)
- Legacy workflow (scene video combination)
- Error handling (missing files, write errors, thumbnail failures)
- Edge cases (large videos, many scenes, special characters)
- Metadata generation
- Thumbnail generation with timeout
- File organization and cleanup
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock, mock_open
from pathlib import Path
import json

from video_gen.stages.output_stage import OutputStage
from video_gen.shared.models import VideoConfig, SceneConfig, InputConfig
from video_gen.shared.exceptions import StageError
from video_gen.pipeline.stage import StageResult


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def output_stage():
    """Create OutputStage instance."""
    return OutputStage()


@pytest.fixture
def mock_event_emitter():
    """Create mock event emitter."""
    emitter = Mock()
    emitter.emit = AsyncMock()
    return emitter


@pytest.fixture
def sample_video_config():
    """Create sample VideoConfig."""
    return VideoConfig(
        video_id="test-output-123",
        title="Test Output Video",
        description="Test output handling",
        total_duration=20.0,
        scenes=[
            SceneConfig(
                scene_id="scene1",
                scene_type="title",
                narration="Scene 1",
                visual_content={"title": "Scene 1"},
                final_duration=5.0
            ),
            SceneConfig(
                scene_id="scene2",
                scene_type="command",
                narration="Scene 2",
                visual_content={"command": "ls"},
                final_duration=7.0
            ),
            SceneConfig(
                scene_id="scene3",
                scene_type="outro",
                narration="Scene 3",
                visual_content={"message": "Thanks"},
                final_duration=8.0
            )
        ]
    )


# ============================================================================
# COMPLETE VIDEO WORKFLOW TESTS
# ============================================================================

class TestOutputStageCompleteVideo:
    """Test complete video workflow (new template-based pipeline)."""

    @pytest.mark.asyncio
    async def test_handle_complete_video_success(self, output_stage, sample_video_config, tmp_path):
        """Test successful complete video handling."""
        # Setup
        video_dir = tmp_path / "video"
        video_dir.mkdir()

        final_video = video_dir / "final.mp4"
        final_video.write_text("fake video content")

        timing_report = tmp_path / "timing.json"
        timing_report.write_text('{"video_id": "test"}')

        context = {
            "task_id": "task-complete",
            "video_config": sample_video_config,
            "final_video_path": final_video,
            "video_dir": video_dir,
            "timing_report": timing_report
        }

        with patch("video_gen.stages.output_stage.config") as mock_config:
            mock_config.output_dir = tmp_path / "output"
            mock_config.output_dir.mkdir()

            # Mock methods
            output_stage.emit_progress = AsyncMock()
            output_stage._generate_metadata = AsyncMock()
            output_stage._generate_thumbnail = AsyncMock()

            result = await output_stage.execute(context)

        assert result.success
        assert "final_video_path" in result.artifacts
        assert "output_dir" in result.artifacts
        assert "metadata_path" in result.artifacts
        assert "thumbnail_path" in result.artifacts
        assert result.metadata["workflow"] == "template-based"
        assert result.metadata["scene_count"] == 3

    @pytest.mark.asyncio
    async def test_complete_video_without_timing_report(self, output_stage, sample_video_config, tmp_path):
        """Test complete video handling without timing report."""
        video_dir = tmp_path / "video"
        video_dir.mkdir()

        final_video = video_dir / "final.mp4"
        final_video.write_text("fake video")

        context = {
            "task_id": "task-no-timing",
            "video_config": sample_video_config,
            "final_video_path": final_video,
            "video_dir": video_dir
            # No timing_report
        }

        with patch("video_gen.stages.output_stage.config") as mock_config:
            mock_config.output_dir = tmp_path / "output"
            mock_config.output_dir.mkdir()

            output_stage.emit_progress = AsyncMock()
            output_stage._generate_metadata = AsyncMock()
            output_stage._generate_thumbnail = AsyncMock()

            result = await output_stage.execute(context)

        assert result.success

    @pytest.mark.asyncio
    async def test_thumbnail_generation_timeout(self, output_stage, sample_video_config, tmp_path):
        """Test handling of thumbnail generation timeout."""
        video_dir = tmp_path / "video"
        video_dir.mkdir()

        final_video = video_dir / "final.mp4"
        final_video.write_text("fake video")

        context = {
            "task_id": "task-thumb-timeout",
            "video_config": sample_video_config,
            "final_video_path": final_video,
            "video_dir": video_dir
        }

        with patch("video_gen.stages.output_stage.config") as mock_config:
            mock_config.output_dir = tmp_path / "output"
            mock_config.output_dir.mkdir()

            output_stage.emit_progress = AsyncMock()
            output_stage._generate_metadata = AsyncMock()

            # Mock thumbnail generation to timeout
            async def timeout_mock(*args):
                await asyncio.sleep(35)  # Longer than 30s timeout

            output_stage._generate_thumbnail = timeout_mock

            result = await output_stage.execute(context)

        # Should succeed even with thumbnail timeout
        assert result.success


# ============================================================================
# LEGACY WORKFLOW TESTS
# ============================================================================

class TestOutputStageLegacyWorkflow:
    """Test legacy workflow (scene video combination)."""

    @pytest.mark.asyncio
    async def test_handle_scene_videos_success(self, output_stage, sample_video_config, tmp_path):
        """Test successful scene video combination."""
        video_dir = tmp_path / "video"
        video_dir.mkdir()

        # Create fake scene videos
        scene_videos = [
            video_dir / "scene1.mp4",
            video_dir / "scene2.mp4",
            video_dir / "scene3.mp4"
        ]
        for video in scene_videos:
            video.write_text("fake video content")

        context = {
            "task_id": "task-legacy",
            "video_config": sample_video_config,
            "scene_videos": scene_videos,
            "video_dir": video_dir
        }

        with patch("video_gen.stages.output_stage.config") as mock_config:
            output_dir = tmp_path / "output" / sample_video_config.video_id
            output_dir.mkdir(parents=True)
            mock_config.output_dir = tmp_path / "output"

            # Create the expected final video file
            final_video = output_dir / f"{sample_video_config.video_id}_final.mp4"
            final_video.write_text("combined video")

            output_stage.emit_progress = AsyncMock()
            output_stage._combine_videos_sync = Mock()
            output_stage._generate_metadata = AsyncMock()
            output_stage._generate_thumbnail = AsyncMock()

            result = await output_stage.execute(context)

        assert result.success
        assert result.metadata["workflow"] == "legacy-combined"
        assert output_stage._combine_videos_sync.called

    @pytest.mark.asyncio
    async def test_combine_videos_missing_file(self, output_stage, tmp_path):
        """Test error when scene video file is missing."""
        scene_videos = [
            tmp_path / "scene1.mp4",
            tmp_path / "nonexistent.mp4"  # Missing
        ]
        scene_videos[0].write_text("fake video")
        # scene_videos[1] doesn't exist

        output_path = tmp_path / "output.mp4"

        with pytest.raises(StageError) as exc_info:
            output_stage._combine_videos_sync(scene_videos, output_path)

        error_msg = str(exc_info.value).lower()
        assert "not found" in error_msg or "missing" in error_msg

    @pytest.mark.asyncio
    async def test_combine_videos_empty_file(self, output_stage, tmp_path):
        """Test error when scene video file is empty."""
        scene_videos = [
            tmp_path / "scene1.mp4",
            tmp_path / "empty.mp4"
        ]
        scene_videos[0].write_text("fake video")
        scene_videos[1].write_text("")  # Empty file

        output_path = tmp_path / "output.mp4"

        with pytest.raises(StageError) as exc_info:
            output_stage._combine_videos_sync(scene_videos, output_path)

        error_msg = str(exc_info.value).lower()
        assert "empty" in error_msg


# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

class TestOutputStageErrors:
    """Test error handling in OutputStage."""

    @pytest.mark.asyncio
    async def test_missing_video_artifacts(self, output_stage):
        """Test error when neither complete video nor scene videos present."""
        # Use a valid VideoConfig with at least one scene
        scene = SceneConfig(
            scene_id="scene1",
            scene_type="title",
            narration="Test",
            visual_content={"title": "Test"}
        )

        context = {
            "task_id": "task-missing",
            "video_config": VideoConfig(
                video_id="test",
                title="Test",
                description="Test",
                scenes=[scene]
            )
            # No final_video_path or scene_videos
        }

        with pytest.raises(StageError) as exc_info:
            await output_stage.execute(context)

        error_msg = str(exc_info.value).lower()
        assert "no video artifacts" in error_msg

    @pytest.mark.asyncio
    async def test_missing_required_context_complete_video(self, output_stage, tmp_path):
        """Test error when required context missing for complete video."""
        final_video = tmp_path / "final.mp4"
        final_video.write_text("video")

        context = {
            "task_id": "task-incomplete",
            "final_video_path": final_video
            # Missing video_config and video_dir
        }

        with pytest.raises(StageError) as exc_info:
            await output_stage.execute(context)

        assert "video_config" in str(exc_info.value).lower() or "video_dir" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_missing_required_context_scene_videos(self, output_stage, tmp_path):
        """Test error when required context missing for scene videos."""
        scene_videos = [tmp_path / "scene1.mp4"]
        scene_videos[0].write_text("video")

        context = {
            "task_id": "task-incomplete-legacy",
            "scene_videos": scene_videos
            # Missing video_config and video_dir
        }

        with pytest.raises(StageError) as exc_info:
            await output_stage.execute(context)

        error_msg = str(exc_info.value).lower()
        assert "video_config" in error_msg or "video_dir" in error_msg


# ============================================================================
# METADATA GENERATION TESTS
# ============================================================================

class TestOutputStageMetadata:
    """Test metadata generation."""

    @pytest.mark.asyncio
    async def test_generate_metadata_with_language(self, output_stage, sample_video_config, tmp_path):
        """Test metadata generation with language from input_config."""
        output_path = tmp_path / "metadata.json"

        input_config = InputConfig(
            input_type="document",
            source="test.md",
            languages=["es", "fr"]
        )

        context = {
            "task_id": "task-metadata-lang",
            "video_config": sample_video_config,
            "input_config": input_config
        }

        await output_stage._generate_metadata(sample_video_config, output_path, context)

        assert output_path.exists()

        with open(output_path) as f:
            metadata = json.load(f)

        assert metadata["video_id"] == "test-output-123"
        assert metadata["language"] == "es"
        assert metadata["scene_count"] == 3

    @pytest.mark.asyncio
    async def test_generate_metadata_default_language(self, output_stage, sample_video_config, tmp_path):
        """Test metadata generation with default language."""
        output_path = tmp_path / "metadata.json"

        context = {
            "task_id": "task-metadata-default"
            # No input_config
        }

        await output_stage._generate_metadata(sample_video_config, output_path, context)

        assert output_path.exists()

        with open(output_path) as f:
            metadata = json.load(f)

        assert metadata["language"] == "en"  # Default

    @pytest.mark.asyncio
    async def test_generate_metadata_includes_scenes(self, output_stage, sample_video_config, tmp_path):
        """Test that metadata includes scene information."""
        output_path = tmp_path / "metadata.json"

        context = {
            "task_id": "task-metadata-scenes"
        }

        await output_stage._generate_metadata(sample_video_config, output_path, context)

        with open(output_path) as f:
            metadata = json.load(f)

        assert "scenes" in metadata
        assert len(metadata["scenes"]) == 3

        scene1 = metadata["scenes"][0]
        assert scene1["scene_id"] == "scene1"
        assert scene1["type"] == "title"
        assert scene1["title"] == "Scene 1"
        assert scene1["duration"] == 5.0


# ============================================================================
# THUMBNAIL GENERATION TESTS
# ============================================================================

class TestOutputStageThumbnail:
    """Test thumbnail generation."""

    @pytest.mark.asyncio
    async def test_generate_thumbnail_success(self, output_stage, tmp_path):
        """Test successful thumbnail generation."""
        video_path = tmp_path / "video.mp4"
        video_path.write_text("fake video")

        thumbnail_path = tmp_path / "thumbnail.jpg"

        # Mock moviepy components
        mock_clip = MagicMock()
        mock_clip.duration = 10.0
        mock_frame = MagicMock()
        mock_clip.get_frame.return_value = mock_frame

        with patch("moviepy.VideoFileClip", return_value=mock_clip), \
             patch("matplotlib.pyplot.imsave") as mock_imsave, \
             patch("matplotlib.pyplot.close"):

            output_stage._generate_thumbnail_sync(video_path, thumbnail_path)

        mock_imsave.assert_called_once()
        mock_clip.get_frame.assert_called_once_with(5.0)  # Middle of video
        mock_clip.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_generate_thumbnail_failure_non_fatal(self, output_stage, tmp_path):
        """Test that thumbnail generation failure doesn't fail the stage."""
        video_path = tmp_path / "video.mp4"
        video_path.write_text("fake video")

        thumbnail_path = tmp_path / "thumbnail.jpg"

        with patch("moviepy.VideoFileClip", side_effect=Exception("Thumbnail error")):
            # Should not raise - thumbnail is optional
            output_stage._generate_thumbnail_sync(video_path, thumbnail_path)

        # No thumbnail created, but no exception raised


# ============================================================================
# EDGE CASES
# ============================================================================

class TestOutputStageEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_very_large_video(self, output_stage, tmp_path):
        """Test handling of very large video files."""
        video_dir = tmp_path / "video"
        video_dir.mkdir()

        final_video = video_dir / "large.mp4"
        # Simulate large file (write marker, not actual size)
        final_video.write_text("large video marker")

        # Create config with many scenes
        scenes = [
            SceneConfig(
                scene_id=f"scene{i}",
                scene_type="title",
                narration=f"Scene {i}",
                visual_content={"title": f"Scene {i}"},
                final_duration=5.0
            )
            for i in range(100)
        ]

        video_config = VideoConfig(
            video_id="test-large",
            title="Large Video",
            description="Test",
            total_duration=500.0,
            scenes=scenes
        )

        context = {
            "task_id": "task-large",
            "video_config": video_config,
            "final_video_path": final_video,
            "video_dir": video_dir
        }

        with patch("video_gen.stages.output_stage.config") as mock_config:
            mock_config.output_dir = tmp_path / "output"
            mock_config.output_dir.mkdir()

            output_stage.emit_progress = AsyncMock()
            output_stage._generate_metadata = AsyncMock()
            output_stage._generate_thumbnail = AsyncMock()

            result = await output_stage.execute(context)

        assert result.success
        assert result.metadata["scene_count"] == 100

    @pytest.mark.asyncio
    async def test_special_characters_in_video_id(self, output_stage, sample_video_config, tmp_path):
        """Test handling of special characters in video_id."""
        sample_video_config.video_id = "test-video_123!@#"

        video_dir = tmp_path / "video"
        video_dir.mkdir()

        final_video = video_dir / "final.mp4"
        final_video.write_text("video")

        context = {
            "task_id": "task-special",
            "video_config": sample_video_config,
            "final_video_path": final_video,
            "video_dir": video_dir
        }

        with patch("video_gen.stages.output_stage.config") as mock_config:
            mock_config.output_dir = tmp_path / "output"
            mock_config.output_dir.mkdir()

            output_stage.emit_progress = AsyncMock()
            output_stage._generate_metadata = AsyncMock()
            output_stage._generate_thumbnail = AsyncMock()

            result = await output_stage.execute(context)

        assert result.success

    @pytest.mark.asyncio
    async def test_unicode_in_metadata(self, output_stage, tmp_path):
        """Test handling of unicode in metadata."""
        video_config = VideoConfig(
            video_id="test-unicode",
            title="测试视频 🎬",
            description="日本語の説明",
            total_duration=10.0,
            scenes=[
                SceneConfig(
                    scene_id="scene1",
                    scene_type="title",
                    narration="こんにちは",
                    visual_content={"title": "你好"}
                )
            ]
        )

        output_path = tmp_path / "metadata.json"
        context = {"task_id": "task-unicode"}

        await output_stage._generate_metadata(video_config, output_path, context)

        with open(output_path, encoding="utf-8") as f:
            metadata = json.load(f)

        assert "测试视频" in metadata["title"]
        assert "日本語" in metadata["description"]

    @pytest.mark.asyncio
    async def test_video_file_already_in_output_location(self, output_stage, sample_video_config, tmp_path):
        """Test when video is already in final output location."""
        with patch("video_gen.stages.output_stage.config") as mock_config:
            output_dir = tmp_path / "output" / sample_video_config.video_id
            output_dir.mkdir(parents=True)

            # Video already in output location
            final_video = output_dir / f"{sample_video_config.video_id}_final.mp4"
            final_video.write_text("video")

            mock_config.output_dir = tmp_path / "output"

            context = {
                "task_id": "task-same-location",
                "video_config": sample_video_config,
                "final_video_path": final_video,
                "video_dir": output_dir
            }

            output_stage.emit_progress = AsyncMock()
            output_stage._generate_metadata = AsyncMock()
            output_stage._generate_thumbnail = AsyncMock()

            result = await output_stage.execute(context)

        assert result.success
        # File should not be copied (same location)


# ============================================================================
# PROGRESS EMISSION TESTS
# ============================================================================

class TestOutputStageProgress:
    """Test progress emission."""

    @pytest.mark.asyncio
    async def test_progress_emission_complete_video(self, mock_event_emitter, sample_video_config, tmp_path):
        """Test progress emission for complete video workflow."""
        output_stage = OutputStage(event_emitter=mock_event_emitter)

        video_dir = tmp_path / "video"
        video_dir.mkdir()

        final_video = video_dir / "final.mp4"
        final_video.write_text("video")

        context = {
            "task_id": "task-progress",
            "video_config": sample_video_config,
            "final_video_path": final_video,
            "video_dir": video_dir
        }

        with patch("video_gen.stages.output_stage.config") as mock_config:
            mock_config.output_dir = tmp_path / "output"
            mock_config.output_dir.mkdir()

            output_stage._generate_metadata = AsyncMock()
            output_stage._generate_thumbnail = AsyncMock()

            await output_stage.execute(context)

        # Verify multiple progress events
        assert mock_event_emitter.emit.call_count >= 4  # Multiple stages

    @pytest.mark.asyncio
    async def test_progress_emission_legacy_workflow(self, mock_event_emitter, sample_video_config, tmp_path):
        """Test progress emission for legacy workflow."""
        output_stage = OutputStage(event_emitter=mock_event_emitter)

        video_dir = tmp_path / "video"
        video_dir.mkdir()

        scene_videos = [video_dir / "scene1.mp4"]
        scene_videos[0].write_text("video")

        context = {
            "task_id": "task-progress-legacy",
            "video_config": sample_video_config,
            "scene_videos": scene_videos,
            "video_dir": video_dir
        }

        with patch("video_gen.stages.output_stage.config") as mock_config:
            output_dir = tmp_path / "output" / sample_video_config.video_id
            output_dir.mkdir(parents=True)
            mock_config.output_dir = tmp_path / "output"

            # Create expected final video file
            final_video = output_dir / f"{sample_video_config.video_id}_final.mp4"
            final_video.write_text("combined video")

            output_stage._combine_videos_sync = Mock()
            output_stage._generate_metadata = AsyncMock()
            output_stage._generate_thumbnail = AsyncMock()

            await output_stage.execute(context)

        # Verify progress events
        assert mock_event_emitter.emit.call_count >= 4
