"""
Tests for Unified Audio Generator
==================================
Comprehensive test suite for audio generation functionality.
"""

import pytest
import asyncio
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock, MagicMock
import json
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from video_gen.audio_generator.unified import (
    UnifiedAudioGenerator,
    AudioGenerationConfig,
    AudioGenerationResult,
    SceneAudioResult
)
from video_gen.shared.models import VideoConfig, SceneConfig


class TestAudioGenerationConfig:
    """Test AudioGenerationConfig dataclass."""

    def test_default_initialization(self, tmp_path):
        """Test configuration with defaults."""
        config = AudioGenerationConfig(output_dir=tmp_path)

        assert config.output_dir == tmp_path
        assert config.rate == "+0%"
        assert config.volume == "+0%"
        assert config.generate_timing_report is True
        assert config.cache_enabled is False
        assert config.voices is not None

    def test_custom_voices(self, tmp_path):
        """Test configuration with custom voices."""
        custom_voices = {"male": "en-US-TestVoice"}
        config = AudioGenerationConfig(
            output_dir=tmp_path,
            voices=custom_voices
        )

        assert config.voices == custom_voices

    def test_output_dir_creation(self, tmp_path):
        """Test that output directory is created."""
        test_dir = tmp_path / "audio_output"
        config = AudioGenerationConfig(output_dir=test_dir)

        assert test_dir.exists()
        assert test_dir.is_dir()


class TestSceneAudioResult:
    """Test SceneAudioResult dataclass."""

    def test_result_creation(self, tmp_path):
        """Test creating scene audio result."""
        audio_file = tmp_path / "scene_01.mp3"
        audio_file.touch()

        result = SceneAudioResult(
            scene_id="test_scene",
            audio_file=audio_file,
            duration=5.5,
            narration="Test narration",
            voice="male"
        )

        assert result.scene_id == "test_scene"
        assert result.audio_file == audio_file
        assert result.duration == 5.5

    def test_to_dict(self, tmp_path):
        """Test converting result to dictionary."""
        audio_file = tmp_path / "scene_01.mp3"
        audio_file.touch()

        result = SceneAudioResult(
            scene_id="test_scene",
            audio_file=audio_file,
            duration=5.5,
            narration="Test narration",
            voice="male"
        )

        result_dict = result.to_dict()

        assert result_dict["scene_id"] == "test_scene"
        assert "audio_file" in result_dict
        assert result_dict["duration"] == 5.5


class TestAudioGenerationResult:
    """Test AudioGenerationResult dataclass."""

    def test_success_property(self, tmp_path):
        """Test success property based on errors."""
        result1 = AudioGenerationResult(
            video_id="test_video",
            audio_dir=tmp_path
        )
        assert result1.success is True

        result2 = AudioGenerationResult(
            video_id="test_video",
            audio_dir=tmp_path,
            errors=["Some error"]
        )
        assert result2.success is False

    def test_to_dict_complete(self, tmp_path):
        """Test converting complete result to dictionary."""
        audio_file = tmp_path / "scene_01.mp3"
        audio_file.touch()

        scene_result = SceneAudioResult(
            scene_id="test_scene",
            audio_file=audio_file,
            duration=5.5,
            narration="Test",
            voice="male"
        )

        result = AudioGenerationResult(
            video_id="test_video",
            audio_dir=tmp_path,
            total_duration=10.0,
            scene_results=[scene_result]
        )

        result_dict = result.to_dict()

        assert result_dict["video_id"] == "test_video"
        assert result_dict["total_duration"] == 10.0
        assert result_dict["scene_count"] == 1
        assert result_dict["success"] is True


class TestUnifiedAudioGenerator:
    """Test UnifiedAudioGenerator class."""

    @pytest.fixture
    def audio_config(self, tmp_path):
        """Create test audio configuration."""
        return AudioGenerationConfig(
            output_dir=tmp_path / "audio",
            voices={"male": "en-US-TestVoice"}
        )

    @pytest.fixture
    def sample_scene(self):
        """Create sample scene configuration."""
        return SceneConfig(
            scene_id="test_scene_01",
            scene_type="title",
            narration="This is a test narration",
            visual_content={"title": "Test", "subtitle": "Demo"},
            voice="male",
            min_duration=3.0,
            max_duration=10.0
        )

    @pytest.fixture
    def sample_video(self, sample_scene):
        """Create sample video configuration."""
        return VideoConfig(
            video_id="test_video",
            title="Test Video",
            description="Test Description",
            scenes=[sample_scene],
            accent_color="blue"
        )

    def test_generator_initialization(self, audio_config):
        """Test generator initialization."""
        generator = UnifiedAudioGenerator(audio_config)

        assert generator.config == audio_config
        assert generator.progress_callback is None

    def test_generator_with_progress_callback(self, audio_config):
        """Test generator with progress callback."""
        callback = Mock()
        generator = UnifiedAudioGenerator(audio_config, callback)

        assert generator.progress_callback == callback

    @pytest.mark.asyncio
    async def test_generate_for_video_structure(self, audio_config, sample_video):
        """Test video generation creates proper structure."""
        generator = UnifiedAudioGenerator(audio_config)

        # Mock TTS and duration measurement
        with patch('video_gen.audio_generator.unified.edge_tts.Communicate') as mock_tts, \
             patch.object(generator, '_measure_audio_duration', return_value=5.0):

            mock_comm = AsyncMock()
            mock_tts.return_value = mock_comm

            result = await generator.generate_for_video(sample_video)

            # Verify result structure
            assert result.video_id == "test_video"
            assert result.audio_dir.exists()
            assert result.success is True

    @pytest.mark.asyncio
    async def test_progress_callback_invocation(self, audio_config, sample_video):
        """Test that progress callbacks are invoked."""
        callback = Mock()
        generator = UnifiedAudioGenerator(audio_config, callback)

        with patch('video_gen.audio_generator.unified.edge_tts.Communicate') as mock_tts, \
             patch.object(generator, '_measure_audio_duration', return_value=5.0):

            mock_comm = AsyncMock()
            mock_tts.return_value = mock_comm

            await generator.generate_for_video(sample_video)

            # Verify callback was called
            assert callback.called

    @pytest.mark.asyncio
    async def test_scene_audio_generation(self, audio_config, sample_scene, tmp_path):
        """Test generating audio for a single scene."""
        generator = UnifiedAudioGenerator(audio_config)

        with patch('video_gen.audio_generator.unified.edge_tts.Communicate') as mock_tts, \
             patch.object(generator, '_measure_audio_duration', return_value=5.5):

            mock_comm = AsyncMock()
            mock_tts.return_value = mock_comm

            result = await generator._generate_scene_audio(
                scene=sample_scene,
                output_dir=tmp_path,
                scene_num=1
            )

            # Verify result
            assert result.scene_id == "test_scene_01"
            assert result.duration == 5.5
            assert result.voice == "male"

    def test_measure_audio_duration(self, audio_config, tmp_path):
        """Test measuring audio duration with FFmpeg."""
        generator = UnifiedAudioGenerator(audio_config)

        audio_file = tmp_path / "test_audio.mp3"
        audio_file.write_bytes(b"fake audio content" * 1000)

        # Mock FFmpeg output
        mock_ffmpeg_output = """
Duration: 00:00:05.50, start: 0.000000, bitrate: 128 kb/s
        """

        with patch('subprocess.run') as mock_run:
            mock_run.return_value.stderr = mock_ffmpeg_output
            duration = generator._measure_audio_duration(audio_file)

            assert duration == 5.5

    def test_estimate_duration_from_filesize(self, audio_config, tmp_path):
        """Test duration estimation from file size."""
        generator = UnifiedAudioGenerator(audio_config)

        # Create 15KB file (should be ~5 seconds at 3KB/sec)
        audio_file = tmp_path / "test_audio.mp3"
        audio_file.write_bytes(b"x" * 15000)

        duration = generator._estimate_duration_from_filesize(audio_file)

        assert duration == pytest.approx(5.0, rel=0.1)

    @pytest.mark.asyncio
    async def test_timing_report_generation(self, audio_config, sample_video, tmp_path):
        """Test timing report is generated correctly."""
        generator = UnifiedAudioGenerator(audio_config)

        scene_result = SceneAudioResult(
            scene_id="test_scene_01",
            audio_file=tmp_path / "scene_01.mp3",
            duration=5.5,
            narration="Test narration",
            voice="male"
        )

        report_path = await generator._create_timing_report(
            video=sample_video,
            scene_results=[scene_result],
            output_dir=tmp_path
        )

        # Verify report exists and has correct content
        assert report_path.exists()

        with open(report_path) as f:
            report = json.load(f)

        assert report["video_id"] == "test_video"
        assert report["title"] == "Test Video"
        assert len(report["scenes"]) == 1
        assert report["scenes"][0]["scene_id"] == "test_scene_01"

    @pytest.mark.asyncio
    async def test_video_set_generation(self, audio_config, sample_video):
        """Test generating audio for multiple videos."""
        video2 = VideoConfig(
            video_id="test_video_2",
            title="Test Video 2",
            description="Test Description 2",
            scenes=sample_video.scenes.copy(),
            accent_color="blue"
        )

        videos = [sample_video, video2]
        generator = UnifiedAudioGenerator(audio_config)

        with patch('video_gen.audio_generator.unified.edge_tts.Communicate') as mock_tts, \
             patch.object(generator, '_measure_audio_duration', return_value=5.0):

            mock_comm = AsyncMock()
            mock_tts.return_value = mock_comm

            results = await generator.generate_for_video_set(videos)

            assert len(results) == 2
            assert "test_video" in results
            assert "test_video_2" in results

    @pytest.mark.asyncio
    async def test_error_handling_in_scene(self, audio_config, sample_video):
        """Test error handling during scene generation."""
        generator = UnifiedAudioGenerator(audio_config)

        with patch('video_gen.audio_generator.unified.edge_tts.Communicate') as mock_tts:
            mock_tts.side_effect = Exception("TTS failed")

            result = await generator.generate_for_video(sample_video)

            # Should have errors but not crash
            assert result.success is False
            assert len(result.errors) > 0

    @pytest.mark.asyncio
    async def test_scene_duration_update(self, audio_config, sample_video):
        """Test that scene durations are updated correctly."""
        generator = UnifiedAudioGenerator(audio_config)

        with patch('video_gen.audio_generator.unified.edge_tts.Communicate') as mock_tts, \
             patch.object(generator, '_measure_audio_duration', return_value=7.0):

            mock_comm = AsyncMock()
            mock_tts.return_value = mock_comm

            await generator.generate_for_video(sample_video)

            # Scene should be updated with audio info
            scene = sample_video.scenes[0]
            assert scene.actual_audio_duration == 7.0
            assert scene.final_duration == max(scene.min_duration, 7.0 + 1.0)
            assert scene.audio_file is not None


class TestBackwardCompatibilityFunctions:
    """Test backward compatibility functions."""

    @pytest.mark.asyncio
    async def test_generate_audio_for_video(self, tmp_path):
        """Test legacy single video function."""
        from video_gen.audio_generator.unified import generate_audio_for_video

        scene = SceneConfig(
            scene_id="test_scene",
            scene_type="title",
            narration="Test",
            visual_content={},
            voice="male"
        )

        video = VideoConfig(
            video_id="test_video",
            title="Test",
            description="Test",
            scenes=[scene]
        )

        with patch('video_gen.audio_generator.unified.edge_tts.Communicate') as mock_tts, \
             patch('video_gen.audio_generator.unified.UnifiedAudioGenerator._measure_audio_duration', return_value=5.0):

            mock_comm = AsyncMock()
            mock_tts.return_value = mock_comm

            result = await generate_audio_for_video(video, tmp_path)

            assert result.success is True

    @pytest.mark.asyncio
    async def test_generate_audio_for_video_set(self, tmp_path):
        """Test legacy video set function."""
        from video_gen.audio_generator.unified import generate_audio_for_video_set

        scene = SceneConfig(
            scene_id="test_scene",
            scene_type="title",
            narration="Test",
            visual_content={},
            voice="male"
        )

        video = VideoConfig(
            video_id="test_video",
            title="Test",
            description="Test",
            scenes=[scene]
        )

        with patch('video_gen.audio_generator.unified.edge_tts.Communicate') as mock_tts, \
             patch('video_gen.audio_generator.unified.UnifiedAudioGenerator._measure_audio_duration', return_value=5.0):

            mock_comm = AsyncMock()
            mock_tts.return_value = mock_comm

            results = await generate_audio_for_video_set([video], tmp_path)

            assert len(results) == 1
            assert results["test_video"].success is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
