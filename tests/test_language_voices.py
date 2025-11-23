"""
Tests for per-language voice assignment feature
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from pathlib import Path

from video_gen.stages.audio_generation_stage import AudioGenerationStage
from video_gen.shared.models import VideoConfig, SceneConfig


@pytest.fixture
def sample_video_config_with_language_voices():
    """Create a sample video config with language_voices."""
    return VideoConfig(
        video_id="multilingual_video",
        title="Multilingual Test",
        description="Testing per-language voices",
        scenes=[
            SceneConfig(
                scene_id="scene_001",
                scene_type="title",
                narration="Welcome",
                visual_content={"title": "Welcome", "subtitle": "Bienvenido"},
                voice="male",
                min_duration=3.0,
                max_duration=10.0,
            ),
            SceneConfig(
                scene_id="scene_002",
                scene_type="list",
                narration="Key points",
                visual_content={"title": "Points", "items": ["A", "B", "C"]},
                voice="female",
                min_duration=5.0,
                max_duration=15.0,
            ),
        ],
        accent_color="blue",
        voices=["male", "female"],
        language_voices={
            "es": "male_warm",
            "fr": "female_friendly",
            "de": "male"
        }
    )


@pytest.fixture
def audio_generation_stage():
    """Create AudioGenerationStage instance."""
    stage = AudioGenerationStage()
    # Mock the audio directory to avoid filesystem operations
    with patch('video_gen.shared.config.config.audio_dir', Path('/tmp/audio')):
        yield stage


class TestLanguageVoices:
    """Test suite for per-language voice assignment."""

    @pytest.mark.asyncio
    async def test_language_voices_field_in_video_config(
        self, sample_video_config_with_language_voices
    ):
        """Test that VideoConfig accepts language_voices field."""
        config = sample_video_config_with_language_voices

        assert config.language_voices is not None
        assert isinstance(config.language_voices, dict)
        assert config.language_voices["es"] == "male_warm"
        assert config.language_voices["fr"] == "female_friendly"
        assert config.language_voices["de"] == "male"

    @pytest.mark.asyncio
    async def test_audio_generation_uses_language_voice(
        self, audio_generation_stage
    ):
        """Test that AudioGenerationStage uses language-specific voice."""
        # Create a config with a single scene that will receive language voice
        # (scene.voice is None or "male" triggers voice assignment)
        config = VideoConfig(
            video_id="spanish_video",
            title="Spanish Test",
            description="Testing Spanish voice",
            scenes=[
                SceneConfig(
                    scene_id="scene_001",
                    scene_type="title",
                    narration="Bienvenido",
                    visual_content={"title": "Bienvenido"},
                    # voice defaults to None, so language voice will be assigned
                )
            ],
            language_voices={"es": "male_warm", "fr": "female_friendly"}
        )

        context = {
            "video_config": config,
            "target_language": "es",
            "task_id": "test_task"
        }

        # Mock Edge TTS and ffmpeg
        with patch('edge_tts.Communicate') as mock_tts, \
             patch.object(audio_generation_stage, '_get_audio_duration', return_value=5.0), \
             patch.object(audio_generation_stage, '_generate_timing_report', return_value=Path('/tmp/report.json')), \
             patch('pathlib.Path.mkdir'):

            mock_communicate = AsyncMock()
            mock_communicate.save = AsyncMock()
            mock_tts.return_value = mock_communicate

            result = await audio_generation_stage.execute(context)

            # Verify Spanish voice was used
            assert result.success is True
            # Check that male_warm voice was selected for Spanish
            assert result.metadata["voices_used"] == ["male_warm"]

    @pytest.mark.asyncio
    async def test_audio_generation_fallback_to_default_voice(
        self, audio_generation_stage, sample_video_config_with_language_voices
    ):
        """Test fallback to default voice when language not in language_voices."""
        context = {
            "video_config": sample_video_config_with_language_voices,
            "target_language": "it",  # Italian not in language_voices
            "task_id": "test_task"
        }

        # Mock Edge TTS and ffmpeg
        with patch('edge_tts.Communicate') as mock_tts, \
             patch.object(audio_generation_stage, '_get_audio_duration', return_value=5.0), \
             patch.object(audio_generation_stage, '_generate_timing_report', return_value=Path('/tmp/report.json')), \
             patch('pathlib.Path.mkdir'):

            mock_communicate = AsyncMock()
            mock_communicate.save = AsyncMock()
            mock_tts.return_value = mock_communicate

            result = await audio_generation_stage.execute(context)

            # Should use default voice rotation
            assert result.success is True
            # Voices should be from default rotation
            voices_used = set(result.metadata["voices_used"])
            assert voices_used.issubset({"male", "female"})

    @pytest.mark.asyncio
    async def test_audio_generation_without_target_language(
        self, audio_generation_stage, sample_video_config_with_language_voices
    ):
        """Test audio generation without target_language uses default rotation."""
        context = {
            "video_config": sample_video_config_with_language_voices,
            # No target_language specified
            "task_id": "test_task"
        }

        # Mock Edge TTS and ffmpeg
        with patch('edge_tts.Communicate') as mock_tts, \
             patch.object(audio_generation_stage, '_get_audio_duration', return_value=5.0), \
             patch.object(audio_generation_stage, '_generate_timing_report', return_value=Path('/tmp/report.json')), \
             patch('pathlib.Path.mkdir'):

            mock_communicate = AsyncMock()
            mock_communicate.save = AsyncMock()
            mock_tts.return_value = mock_communicate

            result = await audio_generation_stage.execute(context)

            # Should use default voice rotation
            assert result.success is True
            voices_used = set(result.metadata["voices_used"])
            assert voices_used.issubset({"male", "female"})

    @pytest.mark.asyncio
    async def test_video_config_without_language_voices(self):
        """Test VideoConfig works without language_voices field."""
        config = VideoConfig(
            video_id="simple_video",
            title="Simple Video",
            description="No language voices",
            scenes=[
                SceneConfig(
                    scene_id="scene_001",
                    scene_type="title",
                    narration="Test",
                    visual_content={"title": "Test"},
                )
            ],
            accent_color="blue",
            # No language_voices specified
        )

        assert config.language_voices is None
        assert config.voices == ["male"]  # Default

    @pytest.mark.asyncio
    async def test_language_voices_validation(self):
        """Test that language_voices accepts valid voice identifiers."""
        valid_voices = ["male", "female", "male_warm", "female_friendly"]

        for voice in valid_voices:
            config = VideoConfig(
                video_id="test",
                title="Test",
                description="Test",
                scenes=[
                    SceneConfig(
                        scene_id="scene_001",
                        scene_type="title",
                        narration="Test",
                        visual_content={"title": "Test"},
                    )
                ],
                language_voices={"es": voice}
            )
            assert config.language_voices["es"] == voice

    @pytest.mark.asyncio
    async def test_multiple_languages_different_voices(
        self, audio_generation_stage
    ):
        """Test multiple languages with different voice assignments."""
        # Helper function to create fresh config for each language test
        def create_config():
            return VideoConfig(
                video_id="multi_lang",
                title="Multi-language",
                description="Multiple languages",
                scenes=[
                    SceneConfig(
                        scene_id="scene_001",
                        scene_type="title",
                        narration="Test",
                        visual_content={"title": "Test"},
                    )
                ],
                language_voices={
                    "es": "male_warm",
                    "fr": "female",
                    "de": "male",
                    "it": "female_friendly"
                }
            )

        # Test Spanish with fresh config
        context_es = {
            "video_config": create_config(),
            "target_language": "es",
            "task_id": "test"
        }

        with patch('edge_tts.Communicate') as mock_tts, \
             patch.object(audio_generation_stage, '_get_audio_duration', return_value=5.0), \
             patch.object(audio_generation_stage, '_generate_timing_report', return_value=Path('/tmp/report.json')), \
             patch('pathlib.Path.mkdir'):

            mock_communicate = AsyncMock()
            mock_communicate.save = AsyncMock()
            mock_tts.return_value = mock_communicate

            result_es = await audio_generation_stage.execute(context_es)
            assert result_es.metadata["voices_used"] == ["male_warm"]

        # Test French with fresh config (avoids mutation from Spanish test)
        context_fr = {
            "video_config": create_config(),
            "target_language": "fr",
            "task_id": "test"
        }

        with patch('edge_tts.Communicate') as mock_tts, \
             patch.object(audio_generation_stage, '_get_audio_duration', return_value=5.0), \
             patch.object(audio_generation_stage, '_generate_timing_report', return_value=Path('/tmp/report.json')), \
             patch('pathlib.Path.mkdir'):

            mock_communicate = AsyncMock()
            mock_communicate.save = AsyncMock()
            mock_tts.return_value = mock_communicate

            result_fr = await audio_generation_stage.execute(context_fr)
            assert result_fr.metadata["voices_used"] == ["female"]
