"""
Comprehensive tests for pipeline stages to improve coverage.

Target modules:
- output_stage.py (95 missing lines, 16% coverage)
- audio_generation_stage.py (69 missing lines, 17% coverage)
- video_generation_stage.py (42 missing lines, 25% coverage)
- script_generation_stage.py (16 missing lines, 43% coverage)

This test file aims to add ~150-200 test lines to cover critical untested paths.
"""

import pytest
import asyncio
import json
import subprocess
from unittest.mock import Mock, AsyncMock, patch, MagicMock, mock_open
from pathlib import Path
from datetime import datetime

from video_gen.stages.output_stage import OutputStage
from video_gen.stages.audio_generation_stage import AudioGenerationStage
from video_gen.stages.video_generation_stage import VideoGenerationStage
from video_gen.stages.script_generation_stage import ScriptGenerationStage
from video_gen.shared.models import VideoConfig, Scene, InputConfig
from video_gen.shared.exceptions import StageError, AudioGenerationError, VideoGenerationError
from video_gen.pipeline.stage import StageResult


# ============================================================================
# OUTPUT STAGE TESTS (95 missing lines)
# ============================================================================

class TestOutputStageCompletVideo:
    """Test OutputStage._handle_complete_video workflow."""

    @pytest.fixture
    def output_stage(self):
        """Create OutputStage instance."""
        return OutputStage()

    @pytest.fixture
    def video_config(self):
        """Create VideoConfig with scenes."""
        return VideoConfig(
            video_id="test-video-123",
            title="Test Video",
            description="Test description",
            total_duration=15.0,
            scenes=[
                Scene(
                    scene_id="scene1",
                    scene_type="title",
                    narration="Welcome",
                    visual_content={"title": "Welcome"},
                    final_duration=5.0
                ),
                Scene(
                    scene_id="scene2",
                    scene_type="command",
                    narration="Run command",
                    visual_content={"command": "ls -la"},
                    final_duration=10.0
                )
            ]
        )

    @pytest.fixture
    def complete_video_context(self, video_config, tmp_path):
        """Create context for complete video workflow."""
        video_dir = tmp_path / "video"
        video_dir.mkdir()

        final_video = video_dir / "final.mp4"
        final_video.write_text("fake video content")

        timing_report = tmp_path / "timing.json"
        timing_report.write_text('{"video_id": "test-video-123"}')

        return {
            "task_id": "task-123",
            "video_config": video_config,
            "final_video_path": final_video,
            "video_dir": video_dir,
            "timing_report": timing_report
        }

    @pytest.mark.asyncio
    async def test_handle_complete_video_success(self, output_stage, complete_video_context, tmp_path):
        """Test successful complete video handling."""
        # Mock config.output_dir
        with patch("video_gen.stages.output_stage.config") as mock_config:
            mock_config.output_dir = tmp_path / "output"
            mock_config.output_dir.mkdir()

            # Mock progress emission
            output_stage.emit_progress = AsyncMock()

            # Mock metadata and thumbnail generation
            output_stage._generate_metadata = AsyncMock()
            output_stage._generate_thumbnail = AsyncMock()

            result = await output_stage._handle_complete_video(complete_video_context)

            assert result.success
            assert result.stage_name == "output_handling"
            assert "final_video_path" in result.artifacts
            assert "output_dir" in result.artifacts
            assert "metadata_path" in result.artifacts
            assert "thumbnail_path" in result.artifacts
            assert result.metadata["workflow"] == "template-based"
            assert result.metadata["scene_count"] == 2

            # Verify progress emissions
            assert output_stage.emit_progress.call_count >= 3

    @pytest.mark.asyncio
    async def test_handle_complete_video_copies_final_video(self, output_stage, complete_video_context, tmp_path):
        """Test final video is copied to output directory."""
        with patch("video_gen.stages.output_stage.config") as mock_config:
            mock_config.output_dir = tmp_path / "output"
            mock_config.output_dir.mkdir()

            output_stage.emit_progress = AsyncMock()
            output_stage._generate_metadata = AsyncMock()
            output_stage._generate_thumbnail = AsyncMock()

            result = await output_stage._handle_complete_video(complete_video_context)

            # Verify output video was created
            output_video = result.artifacts["final_video_path"]
            assert output_video.exists()
            assert output_video.stat().st_size > 0

    @pytest.mark.asyncio
    async def test_handle_complete_video_with_timing_report(self, output_stage, complete_video_context, tmp_path):
        """Test timing report is copied when present."""
        with patch("video_gen.stages.output_stage.config") as mock_config:
            mock_config.output_dir = tmp_path / "output"
            mock_config.output_dir.mkdir()

            output_stage.emit_progress = AsyncMock()
            output_stage._generate_metadata = AsyncMock()
            output_stage._generate_thumbnail = AsyncMock()

            result = await output_stage._handle_complete_video(complete_video_context)

            # Verify timing report was copied
            output_dir = result.artifacts["output_dir"]
            timing_file = output_dir / f"{complete_video_context['video_config'].video_id}_timing.json"
            assert timing_file.exists()

    @pytest.mark.asyncio
    async def test_handle_complete_video_creates_output_dir(self, output_stage, complete_video_context, tmp_path):
        """Test output directory is created if it doesn't exist."""
        with patch("video_gen.stages.output_stage.config") as mock_config:
            mock_config.output_dir = tmp_path / "output"

            output_stage.emit_progress = AsyncMock()
            output_stage._generate_metadata = AsyncMock()
            output_stage._generate_thumbnail = AsyncMock()

            result = await output_stage._handle_complete_video(complete_video_context)

            # Verify output directory was created
            assert result.artifacts["output_dir"].exists()
            assert result.artifacts["output_dir"].is_dir()


class TestOutputStageSceneVideos:
    """Test OutputStage._handle_scene_videos workflow."""

    @pytest.fixture
    def output_stage(self):
        """Create OutputStage instance."""
        return OutputStage()

    @pytest.fixture
    def scene_videos_context(self, video_config, tmp_path):
        """Create context for scene videos workflow."""
        video_dir = tmp_path / "video"
        video_dir.mkdir()

        # Create fake scene videos
        scene_videos = [
            video_dir / "scene1.mp4",
            video_dir / "scene2.mp4"
        ]
        for video in scene_videos:
            video.write_text("fake scene video")

        return {
            "task_id": "task-123",
            "video_config": video_config,
            "scene_videos": scene_videos,
            "video_dir": video_dir
        }

    @pytest.mark.asyncio
    async def test_handle_scene_videos_success(self, output_stage, tmp_path):
        """Test successful scene videos combination."""
        video_config = VideoConfig(
            video_id="test-123",
            title="Test",
            description="Test",
            total_duration=15.0,
            scenes=[
                Scene(scene_id="s1", scene_type="title", narration="Test", visual_content={}, final_duration=5.0),
                Scene(scene_id="s2", scene_type="command", narration="Test", visual_content={}, final_duration=10.0)
            ]
        )

        video_dir = tmp_path / "video"
        video_dir.mkdir()

        scene_videos = [
            video_dir / "scene1.mp4",
            video_dir / "scene2.mp4"
        ]
        for video in scene_videos:
            video.write_text("fake scene video")

        scene_videos_context = {
            "task_id": "task-123",
            "video_config": video_config,
            "scene_videos": scene_videos,
            "video_dir": video_dir
        }

        with patch("video_gen.stages.output_stage.config") as mock_config:
            mock_config.output_dir = tmp_path / "output"
            mock_config.output_dir.mkdir()

            output_stage.emit_progress = AsyncMock()

            # Mock _combine_videos to create the final video file
            async def mock_combine(scene_vids, output_path):
                output_path.write_text("fake final video")

            output_stage._combine_videos = AsyncMock(side_effect=mock_combine)
            output_stage._generate_metadata = AsyncMock()
            output_stage._generate_thumbnail = AsyncMock()

            result = await output_stage._handle_scene_videos(scene_videos_context)

            assert result.success
            assert result.metadata["workflow"] == "legacy-combined"
            assert result.metadata["scene_count"] == 2

            # Verify combine_videos was called
            output_stage._combine_videos.assert_called_once()

    @pytest.mark.asyncio
    async def test_combine_videos_validates_file_existence(self, output_stage, tmp_path):
        """Test _combine_videos validates all input files exist."""
        scene_videos = [
            tmp_path / "missing1.mp4",
            tmp_path / "missing2.mp4"
        ]
        output_path = tmp_path / "output.mp4"

        with pytest.raises(StageError, match="Scene video not found"):
            await output_stage._combine_videos(scene_videos, output_path)

    @pytest.mark.asyncio
    async def test_combine_videos_validates_file_size(self, output_stage, tmp_path):
        """Test _combine_videos rejects empty video files."""
        scene_videos = [
            tmp_path / "empty.mp4"
        ]
        # Create empty file
        scene_videos[0].write_text("")

        output_path = tmp_path / "output.mp4"

        with pytest.raises(StageError, match="Scene video is empty"):
            await output_stage._combine_videos(scene_videos, output_path)

    @pytest.mark.asyncio
    async def test_combine_videos_handles_load_failure(self, output_stage, tmp_path):
        """Test _combine_videos handles video loading errors."""
        scene_videos = [tmp_path / "video.mp4"]
        scene_videos[0].write_text("fake video")
        output_path = tmp_path / "output.mp4"

        # Patch moviepy import that happens inside the function
        with patch("moviepy.VideoFileClip") as mock_clip:
            mock_clip.side_effect = Exception("Failed to load video")

            with pytest.raises(StageError, match="Failed to combine videos"):
                await output_stage._combine_videos(scene_videos, output_path)


class TestOutputStageMetadataAndThumbnail:
    """Test metadata generation and thumbnail creation."""

    @pytest.fixture
    def output_stage(self):
        """Create OutputStage instance."""
        return OutputStage()

    @pytest.fixture
    def video_config(self):
        """Create VideoConfig."""
        return VideoConfig(
            video_id="test-123",
            title="Test Video",
            description="Test description",
            total_duration=20.0,
            scenes=[
                Scene(
                    scene_id="scene1",
                    scene_type="title",
                    narration="Title",
                    visual_content={"title": "Main Title"},
                    final_duration=10.0
                )
            ]
        )

    @pytest.mark.asyncio
    async def test_generate_metadata_basic(self, output_stage, video_config, tmp_path):
        """Test metadata generation with basic context."""
        output_path = tmp_path / "metadata.json"
        context = {
            "task_id": "task-123",
            "video_config": video_config
        }

        await output_stage._generate_metadata(video_config, output_path, context)

        assert output_path.exists()
        with open(output_path) as f:
            metadata = json.load(f)

        assert metadata["video_id"] == "test-123"
        assert metadata["title"] == "Test Video"
        assert metadata["total_duration"] == 20.0
        assert metadata["scene_count"] == 1
        assert metadata["language"] == "en"  # default
        assert len(metadata["scenes"]) == 1

    @pytest.mark.asyncio
    async def test_generate_metadata_with_input_config(self, output_stage, video_config, tmp_path):
        """Test metadata includes language from input_config."""
        output_path = tmp_path / "metadata.json"

        input_config = InputConfig(
            input_type="yaml",
            source="test.yaml",
            accent_color=(0, 0, 0),
            voice="male",
            languages=["es", "en"]  # Spanish primary
        )

        context = {
            "task_id": "task-123",
            "video_config": video_config,
            "input_config": input_config
        }

        await output_stage._generate_metadata(video_config, output_path, context)

        with open(output_path) as f:
            metadata = json.load(f)

        assert metadata["language"] == "es"

    @pytest.mark.asyncio
    async def test_generate_metadata_includes_scene_details(self, output_stage, video_config, tmp_path):
        """Test metadata includes scene-level details."""
        output_path = tmp_path / "metadata.json"
        context = {"task_id": "task-123"}

        await output_stage._generate_metadata(video_config, output_path, context)

        with open(output_path) as f:
            metadata = json.load(f)

        scene = metadata["scenes"][0]
        assert scene["scene_id"] == "scene1"
        assert scene["type"] == "title"
        assert scene["title"] == "Main Title"
        assert scene["duration"] == 10.0

    @pytest.mark.asyncio
    async def test_generate_thumbnail_success(self, output_stage, tmp_path):
        """Test thumbnail generation extracts middle frame."""
        video_path = tmp_path / "video.mp4"
        thumbnail_path = tmp_path / "thumbnail.jpg"

        # Patch moviepy import that happens inside the function
        with patch("moviepy.VideoFileClip") as mock_clip_class:
            mock_clip = MagicMock()
            mock_clip.duration = 10.0
            mock_clip.get_frame.return_value = [[0, 0, 0]]  # Fake frame
            mock_clip_class.return_value = mock_clip

            with patch("matplotlib.pyplot.imsave") as mock_imsave:
                await output_stage._generate_thumbnail(video_path, thumbnail_path)

                # Verify frame was extracted from middle
                mock_clip.get_frame.assert_called_once_with(5.0)
                mock_imsave.assert_called_once()

    @pytest.mark.asyncio
    async def test_generate_thumbnail_handles_failure(self, output_stage, tmp_path):
        """Test thumbnail generation logs warning on failure."""
        video_path = tmp_path / "video.mp4"
        thumbnail_path = tmp_path / "thumbnail.jpg"

        # Patch moviepy import that happens inside the function
        with patch("moviepy.VideoFileClip") as mock_clip:
            mock_clip.side_effect = Exception("Failed to load")

            # Should not raise, only log warning
            await output_stage._generate_thumbnail(video_path, thumbnail_path)

            # Thumbnail should not exist
            assert not thumbnail_path.exists()


class TestOutputStageExecute:
    """Test OutputStage.execute main workflow."""

    @pytest.fixture
    def output_stage(self):
        """Create OutputStage instance."""
        return OutputStage()

    @pytest.mark.asyncio
    async def test_execute_routes_to_complete_video(self, output_stage, tmp_path):
        """Test execute routes to _handle_complete_video when final_video_path present."""
        context = {
            "task_id": "task-123",
            "final_video_path": tmp_path / "final.mp4",
            "video_config": MagicMock(),
            "video_dir": tmp_path
        }

        output_stage._handle_complete_video = AsyncMock(return_value=StageResult(
            success=True,
            stage_name="output_handling"
        ))

        result = await output_stage.execute(context)

        output_stage._handle_complete_video.assert_called_once_with(context)
        assert result.success

    @pytest.mark.asyncio
    async def test_execute_routes_to_scene_videos(self, output_stage, tmp_path):
        """Test execute routes to _handle_scene_videos when scene_videos present."""
        context = {
            "task_id": "task-123",
            "scene_videos": [tmp_path / "scene1.mp4"],
            "video_config": MagicMock(),
            "video_dir": tmp_path
        }

        output_stage._handle_scene_videos = AsyncMock(return_value=StageResult(
            success=True,
            stage_name="output_handling"
        ))

        result = await output_stage.execute(context)

        output_stage._handle_scene_videos.assert_called_once_with(context)
        assert result.success

    @pytest.mark.asyncio
    async def test_execute_raises_when_no_video_artifacts(self, output_stage):
        """Test execute raises StageError when no video artifacts found."""
        context = {
            "task_id": "task-123",
            "video_config": MagicMock()
        }

        with pytest.raises(StageError, match="No video artifacts found"):
            await output_stage.execute(context)


# ============================================================================
# AUDIO GENERATION STAGE TESTS (69 missing lines)
# ============================================================================

class TestAudioGenerationStageVoiceRotation:
    """Test AudioGenerationStage voice rotation logic."""

    @pytest.fixture
    def audio_stage(self):
        """Create AudioGenerationStage instance."""
        return AudioGenerationStage()

    @pytest.fixture
    def video_config_multi_voice(self):
        """Create VideoConfig with multiple scenes for voice rotation."""
        return VideoConfig(
            video_id="multi-voice-test",
            title="Multi Voice Test",
            description="Test voice rotation",
            voices=["male", "female", "british"],
            scenes=[
                Scene(
                    scene_id=f"scene{i}",
                    scene_type="command",
                    narration=f"This is scene {i}",
                    visual_content={},
                    voice="male"  # Will be rotated
                )
                for i in range(5)
            ]
        )

    @pytest.mark.asyncio
    async def test_voice_rotation_cycles_through_voices(self, audio_stage, video_config_multi_voice, tmp_path):
        """Test voice rotation cycles through available voices."""
        context = {
            "task_id": "task-123",
            "video_config": video_config_multi_voice
        }

        with patch("video_gen.stages.audio_generation_stage.config") as mock_config:
            mock_config.audio_dir = tmp_path / "audio"
            mock_config.get_voice = Mock(return_value="en-US-GuyNeural")

            with patch("video_gen.stages.audio_generation_stage.edge_tts.Communicate") as mock_communicate:
                mock_comm = AsyncMock()
                mock_comm.save = AsyncMock()
                mock_communicate.return_value = mock_comm

                audio_stage._get_audio_duration = AsyncMock(return_value=3.0)
                audio_stage._generate_timing_report = AsyncMock(return_value=tmp_path / "timing.json")
                audio_stage.emit_progress = AsyncMock()

                result = await audio_stage.execute(context)

                # Verify voices were rotated
                scenes = video_config_multi_voice.scenes
                assert scenes[0].voice == "male"
                assert scenes[1].voice == "female"
                assert scenes[2].voice == "british"
                assert scenes[3].voice == "male"  # Cycles back
                assert scenes[4].voice == "female"

    @pytest.mark.asyncio
    async def test_audio_generation_assigns_voice_to_scene(self, audio_stage, tmp_path):
        """Test audio generation assigns rotated voice to scene."""
        video_config = VideoConfig(
            video_id="test",
            title="Test",
            description="Test",
            voices=["male", "female"],
            scenes=[
                Scene(scene_id="1", scene_type="title", narration="Test 1", visual_content={}, voice="male"),
                Scene(scene_id="2", scene_type="title", narration="Test 2", visual_content={}, voice="male")
            ]
        )

        context = {
            "task_id": "task-123",
            "video_config": video_config
        }

        with patch("video_gen.stages.audio_generation_stage.config") as mock_config:
            mock_config.audio_dir = tmp_path / "audio"
            mock_config.get_voice = Mock(return_value="en-US-GuyNeural")

            with patch("video_gen.stages.audio_generation_stage.edge_tts.Communicate") as mock_communicate:
                mock_comm = AsyncMock()
                mock_comm.save = AsyncMock()
                mock_communicate.return_value = mock_comm

                audio_stage._get_audio_duration = AsyncMock(return_value=2.5)
                audio_stage._generate_timing_report = AsyncMock(return_value=tmp_path / "timing.json")
                audio_stage.emit_progress = AsyncMock()

                result = await audio_stage.execute(context)

                # Check voice assignment
                assert video_config.scenes[0].voice == "male"
                assert video_config.scenes[1].voice == "female"


class TestAudioGenerationStageAudioDuration:
    """Test audio duration measurement."""

    @pytest.fixture
    def audio_stage(self):
        """Create AudioGenerationStage instance."""
        return AudioGenerationStage()

    @pytest.mark.asyncio
    async def test_get_audio_duration_parses_ffmpeg_output(self, audio_stage, tmp_path):
        """Test _get_audio_duration parses ffmpeg output correctly."""
        audio_file = tmp_path / "test.mp3"
        audio_file.write_text("fake audio")

        ffmpeg_output = """
Input #0, mp3, from 'test.mp3':
  Duration: 00:00:05.23, start: 0.000000, bitrate: 128 kb/s
    Stream #0:0: Audio: mp3, 44100 Hz, stereo, fltp, 128 kb/s
"""

        with patch("video_gen.stages.audio_generation_stage.subprocess.run") as mock_run:
            mock_run.return_value = Mock(stderr=ffmpeg_output)

            duration = await audio_stage._get_audio_duration(audio_file)

            assert duration == 5.23

    @pytest.mark.asyncio
    async def test_get_audio_duration_handles_parse_failure(self, audio_stage, tmp_path):
        """Test _get_audio_duration returns default on parse failure."""
        audio_file = tmp_path / "test.mp3"
        audio_file.write_text("fake audio")

        with patch("video_gen.stages.audio_generation_stage.subprocess.run") as mock_run:
            mock_run.return_value = Mock(stderr="No duration info")

            duration = await audio_stage._get_audio_duration(audio_file)

            # Should return default
            assert duration == 5.0

    @pytest.mark.asyncio
    async def test_get_audio_duration_handles_exception(self, audio_stage, tmp_path):
        """Test _get_audio_duration handles subprocess exception."""
        audio_file = tmp_path / "test.mp3"

        with patch("video_gen.stages.audio_generation_stage.subprocess.run") as mock_run:
            mock_run.side_effect = Exception("ffmpeg failed")

            duration = await audio_stage._get_audio_duration(audio_file)

            assert duration == 5.0


class TestAudioGenerationStageTimingReport:
    """Test timing report generation."""

    @pytest.fixture
    def audio_stage(self):
        """Create AudioGenerationStage instance."""
        return AudioGenerationStage()

    @pytest.mark.asyncio
    async def test_generate_timing_report_creates_file(self, audio_stage, tmp_path):
        """Test timing report is created with correct structure."""
        video_config = VideoConfig(
            video_id="test-123",
            title="Test Video",
            description="Test",
            total_duration=10.0,
            voices=["male", "female"],
            accent_color="blue",
            scenes=[
                Scene(
                    scene_id="scene1",
                    scene_type="title",
                    narration="Welcome to the tutorial",
                    visual_content={"title": "Welcome"},
                    voice="male",
                    final_duration=5.0,
                    actual_audio_duration=4.0
                ),
                Scene(
                    scene_id="scene2",
                    scene_type="command",
                    narration="Run this command",
                    visual_content={"command": "ls"},
                    voice="female",
                    final_duration=5.0,
                    actual_audio_duration=4.5
                )
            ]
        )

        output_dir = tmp_path / "audio"
        output_dir.mkdir()

        report_path = await audio_stage._generate_timing_report(video_config, output_dir)

        assert report_path.exists()

        with open(report_path) as f:
            report = json.load(f)

        assert report["video_id"] == "test-123"
        assert report["title"] == "Test Video"
        assert report["total_duration"] == 10.0
        assert report["total_scenes"] == 2
        assert report["voices_config"] == ["male", "female"]
        assert report["accent_color"] == [59, 130, 246]  # blue RGB
        assert len(report["scenes"]) == 2

    @pytest.mark.asyncio
    async def test_timing_report_includes_cumulative_times(self, audio_stage, tmp_path):
        """Test timing report calculates cumulative start/end times."""
        video_config = VideoConfig(
            video_id="test",
            title="Test",
            description="Test",
            total_duration=15.0,
            scenes=[
                Scene(
                    scene_id="s1",
                    scene_type="title",
                    narration="Scene 1",
                    visual_content={},
                    voice="male",
                    final_duration=5.0,
                    actual_audio_duration=4.0
                ),
                Scene(
                    scene_id="s2",
                    scene_type="command",
                    narration="Scene 2",
                    visual_content={},
                    voice="female",
                    final_duration=10.0,
                    actual_audio_duration=9.0
                )
            ]
        )

        output_dir = tmp_path / "audio"
        output_dir.mkdir()

        report_path = await audio_stage._generate_timing_report(video_config, output_dir)

        with open(report_path) as f:
            report = json.load(f)

        # Check cumulative timing
        assert report["scenes"][0]["start_time"] == 0
        assert report["scenes"][0]["end_time"] == 5.0
        assert report["scenes"][1]["start_time"] == 5.0
        assert report["scenes"][1]["end_time"] == 15.0

    @pytest.mark.asyncio
    async def test_timing_report_accent_color_mapping(self, audio_stage, tmp_path):
        """Test timing report maps accent colors to RGB."""
        color_tests = [
            ("blue", [59, 130, 246]),
            ("orange", [255, 107, 53]),
            ("purple", [139, 92, 246]),
            ("green", [16, 185, 129]),
            ("pink", [236, 72, 153]),
            ("cyan", [34, 211, 238]),
            ("unknown", [59, 130, 246])  # default to blue
        ]

        # Create minimal scene for validation (scenes list cannot be empty)
        test_scene = Scene(
            scene_id="test_scene",
            scene_type="title",
            narration="Test",
            visual_content={"title": "Test"},
            voice="male",
            final_duration=3.0,
            actual_audio_duration=2.5
        )

        for color_name, expected_rgb in color_tests:
            video_config = VideoConfig(
                video_id="test",
                title="Test",
                description="Test",
                accent_color=color_name,
                scenes=[test_scene]
            )

            output_dir = tmp_path / "audio"
            output_dir.mkdir(exist_ok=True)

            report_path = await audio_stage._generate_timing_report(video_config, output_dir)

            with open(report_path) as f:
                report = json.load(f)

            assert report["accent_color"] == expected_rgb


class TestAudioGenerationStageErrors:
    """Test audio generation error handling."""

    @pytest.fixture
    def audio_stage(self):
        """Create AudioGenerationStage instance."""
        return AudioGenerationStage()

    @pytest.mark.asyncio
    async def test_audio_generation_raises_on_tts_failure(self, audio_stage, tmp_path):
        """Test audio generation raises AudioGenerationError on TTS failure."""
        video_config = VideoConfig(
            video_id="test",
            title="Test",
            description="Test",
            scenes=[
                Scene(
                    scene_id="scene1",
                    scene_type="title",
                    narration="Test",
                    visual_content={},
                    voice="male"
                )
            ]
        )

        context = {
            "task_id": "task-123",
            "video_config": video_config
        }

        with patch("video_gen.stages.audio_generation_stage.config") as mock_config:
            mock_config.audio_dir = tmp_path / "audio"
            mock_config.get_voice = Mock(return_value="en-US-GuyNeural")

            with patch("video_gen.stages.audio_generation_stage.edge_tts.Communicate") as mock_communicate:
                mock_comm = AsyncMock()
                mock_comm.save = AsyncMock(side_effect=Exception("TTS failed"))
                mock_communicate.return_value = mock_comm

                audio_stage.emit_progress = AsyncMock()

                with pytest.raises(AudioGenerationError, match="Failed to generate audio"):
                    await audio_stage.execute(context)


# ============================================================================
# VIDEO GENERATION STAGE TESTS (42 missing lines)
# ============================================================================

class TestVideoGenerationStageRender:
    """Test VideoGenerationStage rendering."""

    @pytest.fixture
    def video_stage(self):
        """Create VideoGenerationStage instance."""
        return VideoGenerationStage()

    @pytest.mark.asyncio
    async def test_render_simple_scene_creates_video(self, video_stage, tmp_path):
        """Test _render_simple_scene creates video file."""
        scene = Scene(
            scene_id="scene1",
            scene_type="title",
            narration="Welcome",
            visual_content={"title": "Welcome", "bg_color": [30, 30, 30]},
            final_duration=5.0
        )

        scene_timing = {"duration": 5.0}
        output_path = tmp_path / "scene.mp4"
        audio_file = tmp_path / "audio.mp3"
        audio_file.write_text("fake audio")

        # Patch moviepy imports that happen inside the function
        with patch("moviepy.ColorClip") as mock_bg, \
             patch("moviepy.TextClip") as mock_text, \
             patch("moviepy.CompositeVideoClip") as mock_comp, \
             patch("moviepy.AudioFileClip") as mock_audio, \
             patch("video_gen.stages.video_generation_stage.config") as mock_config:

            mock_config.fonts = {"title": "Arial"}

            # Mock video clip
            mock_video = MagicMock()
            mock_video.write_videofile = MagicMock()
            mock_video.with_audio = Mock(return_value=mock_video)
            mock_comp.return_value = mock_video

            # Mock text clip
            mock_txt = MagicMock()
            mock_txt.with_position = Mock(return_value=mock_txt)
            mock_txt.with_duration = Mock(return_value=mock_txt)
            mock_text.return_value = mock_txt

            # Create fake output file
            output_path.write_text("fake video")

            await video_stage._render_simple_scene(scene, scene_timing, output_path, audio_file)

            # Verify video was written
            mock_video.write_videofile.assert_called_once()

    @pytest.mark.asyncio
    async def test_render_simple_scene_validates_output(self, video_stage, tmp_path):
        """Test _render_simple_scene validates output file was created."""
        scene = Scene(
            scene_id="scene1",
            scene_type="title",
            narration="Test",
            visual_content={},
            final_duration=3.0
        )

        scene_timing = {"duration": 3.0}
        output_path = tmp_path / "scene.mp4"
        audio_file = tmp_path / "audio.mp3"

        # Patch moviepy imports that happen inside the function
        with patch("moviepy.ColorClip"), \
             patch("moviepy.TextClip"), \
             patch("moviepy.CompositeVideoClip") as mock_comp, \
             patch("video_gen.stages.video_generation_stage.config") as mock_config:

            mock_config.fonts = {"title": "Arial"}

            mock_video = MagicMock()
            mock_video.write_videofile = MagicMock()
            mock_video.with_audio = Mock(return_value=mock_video)
            mock_comp.return_value = mock_video

            # Don't create output file - should raise error
            with pytest.raises(VideoGenerationError, match="Video file creation failed"):
                await video_stage._render_simple_scene(scene, scene_timing, output_path, audio_file)

    @pytest.mark.asyncio
    async def test_video_generation_raises_on_unified_generator_failure(self, video_stage, tmp_path):
        """Test execute raises VideoGenerationError when UnifiedVideoGenerator fails."""
        video_config = VideoConfig(
            video_id="test",
            title="Test",
            description="Test",
            total_duration=5.0,
            scenes=[
                Scene(
                    scene_id="scene1",
                    scene_type="title",
                    narration="Test",
                    visual_content={},
                    final_duration=5.0
                )
            ]
        )

        timing_report = tmp_path / "timing.json"
        timing_report.write_text('{"video_id": "test"}')

        context = {
            "task_id": "task-123",
            "video_config": video_config,
            "timing_report": timing_report,
            "audio_dir": tmp_path / "audio"
        }

        with patch("video_gen.stages.video_generation_stage.config") as mock_config:
            mock_config.video_dir = tmp_path / "video"

            video_stage.emit_progress = AsyncMock()

            # Mock generator to return None
            video_stage.generator._generate_single_video = Mock(return_value=None)

            with pytest.raises(VideoGenerationError, match="UnifiedVideoGenerator failed"):
                await video_stage.execute(context)


# ============================================================================
# SCRIPT GENERATION STAGE TESTS (16 missing lines)
# ============================================================================

class TestScriptGenerationStageEnhancement:
    """Test ScriptGenerationStage AI enhancement."""

    @pytest.fixture
    def script_stage(self):
        """Create ScriptGenerationStage instance."""
        return ScriptGenerationStage()

    @pytest.mark.asyncio
    async def test_script_generation_with_ai_enhancement(self, script_stage):
        """Test script generation uses AI enhancer when available."""
        video_config = VideoConfig(
            video_id="test",
            title="Test",
            description="Test",
            scenes=[
                Scene(
                    scene_id="scene1",
                    scene_type="command",
                    narration="",
                    visual_content={"command": "ls -la"}
                )
            ]
        )

        context = {
            "task_id": "task-123",
            "video_config": video_config
        }

        # Mock AI enhancer
        script_stage.ai_enhancer = AsyncMock()
        script_stage.ai_enhancer.enhance = AsyncMock(return_value="Enhanced narration")
        script_stage.narration_generator.generate = AsyncMock(return_value="Basic narration")
        script_stage.emit_progress = AsyncMock()

        with patch("video_gen.stages.script_generation_stage.config") as mock_config:
            mock_config.get = Mock(return_value=True)  # enhance_scripts = True

            result = await script_stage.execute(context)

            assert result.success
            assert video_config.scenes[0].narration == "Enhanced narration"
            script_stage.ai_enhancer.enhance.assert_called_once()

    @pytest.mark.asyncio
    async def test_script_generation_without_ai_enhancement(self, script_stage):
        """Test script generation works without AI enhancer."""
        video_config = VideoConfig(
            video_id="test",
            title="Test",
            description="Test",
            scenes=[
                Scene(
                    scene_id="scene1",
                    scene_type="title",
                    narration="",
                    visual_content={"title": "Main Title"}
                )
            ]
        )

        context = {
            "task_id": "task-123",
            "video_config": video_config
        }

        script_stage.ai_enhancer = None
        script_stage.narration_generator.generate = AsyncMock(return_value="Basic narration")
        script_stage.emit_progress = AsyncMock()

        result = await script_stage.execute(context)

        assert result.success
        assert video_config.scenes[0].narration == "Basic narration"

    @pytest.mark.asyncio
    async def test_script_generation_handles_error(self, script_stage):
        """Test script generation handles narration generation errors."""
        video_config = VideoConfig(
            video_id="test",
            title="Test",
            description="Test",
            scenes=[
                Scene(
                    scene_id="scene1",
                    scene_type="title",
                    narration="",
                    visual_content={}
                )
            ]
        )

        context = {
            "task_id": "task-123",
            "video_config": video_config
        }

        script_stage.narration_generator.generate = AsyncMock(side_effect=Exception("Generation failed"))
        script_stage.emit_progress = AsyncMock()

        with pytest.raises(StageError, match="Script generation failed"):
            await script_stage.execute(context)

    @pytest.mark.asyncio
    async def test_script_generation_passes_scene_object(self, script_stage):
        """Test script generation passes scene object to generator."""
        video_config = VideoConfig(
            video_id="test",
            title="Test",
            description="Test",
            scenes=[
                Scene(
                    scene_id="scene1",
                    scene_type="list",
                    narration="",
                    visual_content={"items": ["Item 1", "Item 2"]}
                )
            ]
        )

        context = {
            "task_id": "task-123",
            "video_config": video_config
        }

        script_stage.narration_generator.generate = AsyncMock(return_value="Generated narration")
        script_stage.emit_progress = AsyncMock()

        result = await script_stage.execute(context)

        # Verify scene object was passed (not scene.content)
        call_args = script_stage.narration_generator.generate.call_args
        assert isinstance(call_args[0][0], Scene)
        assert call_args[1]["scene_type"] == "list"
