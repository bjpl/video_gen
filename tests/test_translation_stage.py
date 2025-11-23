"""
Tests for TranslationStage

These tests require the ANTHROPIC_API_KEY environment variable to be set,
or proper mocking of the config singleton. Tests will skip if the
translation stage cannot be initialized.
"""

import pytest
import os
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from pathlib import Path

from video_gen.shared.models import VideoConfig, SceneConfig
from video_gen.shared.exceptions import TranslationError


# Check if translation stage can be imported and initialized
def _can_init_translation_stage():
    """Check if TranslationStage can be initialized for testing."""
    try:
        from video_gen.shared.config import config
        # Check if API key is available in config
        return config.get_api_key("anthropic") is not None
    except Exception:
        return False


# Skip all tests if translation stage cannot be initialized
TRANSLATION_AVAILABLE = _can_init_translation_stage()
pytestmark = pytest.mark.skipif(
    not TRANSLATION_AVAILABLE,
    reason="TranslationStage requires ANTHROPIC_API_KEY environment variable"
)


@pytest.fixture
def sample_video_config():
    """Create a sample video config for testing."""
    return VideoConfig(
        video_id="test_video",
        title="Test Video",
        description="A test video for translation",
        scenes=[
            SceneConfig(
                scene_id="scene_001",
                scene_type="title",
                narration="Welcome to the test video",
                visual_content={
                    "title": "Test Video",
                    "subtitle": "Learn testing"
                },
                voice="male",
                min_duration=3.0,
                max_duration=10.0,
            ),
            SceneConfig(
                scene_id="scene_002",
                scene_type="list",
                narration="Here are the key points",
                visual_content={
                    "title": "Key Points",
                    "items": ["Point 1", "Point 2", "Point 3"]
                },
                voice="female",
                min_duration=5.0,
                max_duration=15.0,
            ),
        ],
        accent_color="blue",
    )


@pytest.fixture
def translation_stage():
    """Create TranslationStage instance with mocked Claude client.

    Note: This fixture requires ANTHROPIC_API_KEY to be set in the environment
    for the Config singleton to have the key available. The actual API calls
    are mocked to avoid real network requests.
    """
    from video_gen.stages.translation_stage import TranslationStage

    # Patch the Anthropic client initialization
    with patch('anthropic.Anthropic') as mock_anthropic:
        mock_client = MagicMock()
        mock_anthropic.return_value = mock_client

        stage = TranslationStage()
        # Replace with mock client to avoid real API calls
        stage.claude_client = mock_client
        return stage


class TestTranslationStage:
    """Test suite for TranslationStage."""

    @pytest.mark.asyncio
    async def test_translation_stage_initialization(self, translation_stage):
        """Test that TranslationStage initializes correctly."""
        assert translation_stage.name == "translation"
        # Google translator may be None if not installed
        # assert translation_stage.google_translator is not None

    @pytest.mark.asyncio
    async def test_skip_source_language_translation(
        self, translation_stage, sample_video_config
    ):
        """Test that translation is skipped when source equals target."""
        context = {
            "video_config": sample_video_config,
            "source_language": "en",
            "target_languages": ["en", "es"],
            "task_id": "test_task"
        }

        result = await translation_stage.execute(context)

        assert result.success is True
        assert "translated_configs" in result.artifacts
        assert "en" in result.artifacts["translated_configs"]
        # EN should be same as original
        assert result.artifacts["translated_configs"]["en"] == sample_video_config

    @pytest.mark.asyncio
    async def test_translate_with_google(self, translation_stage):
        """Test Google Translate fallback (if available)."""
        # Mock google translator
        mock_translator = Mock()
        mock_translator.translate = Mock(return_value=Mock(text="Bonjour le monde"))
        translation_stage.google_translator = mock_translator

        translated = await translation_stage._translate_with_google(
            "Hello world",
            "en",
            "fr"
        )

        assert translated == "Bonjour le monde"

    @pytest.mark.asyncio
    async def test_translate_with_claude(self, translation_stage):
        """Test Claude API translation."""
        # Mock Claude client
        mock_client = Mock()
        mock_response = Mock()
        mock_response.content = [Mock(text="Hola mundo")]
        mock_client.messages.create = Mock(return_value=mock_response)

        translation_stage.claude_client = mock_client

        translated = await translation_stage._translate_with_claude(
            "Hello world",
            "en",
            "es"
        )

        assert translated == "Hola mundo"
        assert mock_client.messages.create.called

    @pytest.mark.asyncio
    async def test_translate_scene(self, translation_stage, sample_video_config):
        """Test scene translation."""
        scene = sample_video_config.scenes[0]

        with patch.object(
            translation_stage,
            "_translate_text",
            side_effect=lambda text, src, tgt: f"[{tgt}] {text}"
        ):
            translated_scene = await translation_stage._translate_scene(
                scene, "en", "es"
            )

            assert translated_scene.scene_id == "scene_001_es"
            assert translated_scene.scene_type == "title"
            assert "[es]" in translated_scene.narration
            assert "[es]" in translated_scene.visual_content["title"]

    @pytest.mark.asyncio
    async def test_translate_visual_content_list_type(self, translation_stage):
        """Test translation of visual content with lists."""
        visual_content = {
            "title": "Key Points",
            "items": ["First item", "Second item", "Third item"]
        }

        with patch.object(
            translation_stage,
            "_translate_text",
            side_effect=lambda text, src, tgt: f"[{tgt}] {text}"
        ):
            translated = await translation_stage._translate_visual_content(
                visual_content, "list", "en", "fr"
            )

            assert "[fr]" in translated["title"]
            assert len(translated["items"]) == 3
            assert all("[fr]" in item for item in translated["items"])

    @pytest.mark.asyncio
    async def test_translate_video_config(
        self, translation_stage, sample_video_config
    ):
        """Test full video config translation."""
        with patch.object(
            translation_stage,
            "_translate_text",
            side_effect=lambda text, src, tgt: f"[{tgt}] {text}"
        ):
            translated = await translation_stage._translate_video_config(
                sample_video_config, "en", "de"
            )

            assert translated.video_id == "test_video_de"
            assert "[de]" in translated.title
            assert "[de]" in translated.description
            assert len(translated.scenes) == 2
            assert all("_de" in scene.scene_id for scene in translated.scenes)

    @pytest.mark.asyncio
    async def test_translation_error_handling(
        self, translation_stage, sample_video_config
    ):
        """Test that translation errors are properly raised."""
        context = {
            "video_config": sample_video_config,
            "source_language": "en",
            "target_languages": ["invalid_lang"],
            "task_id": "test_task"
        }

        with patch.object(
            translation_stage,
            "_translate_text",
            side_effect=Exception("Translation failed")
        ):
            with pytest.raises(TranslationError):
                await translation_stage.execute(context)

    @pytest.mark.asyncio
    async def test_empty_text_translation(self, translation_stage):
        """Test that empty text is handled gracefully."""
        result = await translation_stage._translate_text("", "en", "es")
        assert result == ""

        result = await translation_stage._translate_text("   ", "en", "es")
        assert result == "   "

    @pytest.mark.asyncio
    async def test_claude_fallback_to_google(self, translation_stage):
        """Test fallback from Claude to Google when Claude fails."""
        # Mock Claude client to raise exception
        mock_client = Mock()
        mock_client.messages.create = Mock(side_effect=Exception("Claude API error"))
        translation_stage.claude_client = mock_client

        # Mock Google Translate
        mock_translator = Mock()
        mock_translator.translate = Mock(return_value=Mock(text="Translated text"))
        translation_stage.google_translator = mock_translator

        result = await translation_stage._translate_text(
            "Test text", "en", "es"
        )

        assert result == "Translated text"

    @pytest.mark.asyncio
    async def test_multiple_languages_translation(
        self, translation_stage, sample_video_config
    ):
        """Test translation to multiple target languages."""
        context = {
            "video_config": sample_video_config,
            "source_language": "en",
            "target_languages": ["es", "fr", "de"],
            "task_id": "test_task"
        }

        with patch.object(
            translation_stage,
            "_translate_text",
            side_effect=lambda text, src, tgt: f"[{tgt}] {text}"
        ):
            result = await translation_stage.execute(context)

            assert result.success is True
            assert len(result.artifacts["translated_configs"]) == 3
            assert "es" in result.artifacts["translated_configs"]
            assert "fr" in result.artifacts["translated_configs"]
            assert "de" in result.artifacts["translated_configs"]

    @pytest.mark.asyncio
    async def test_progress_emission(self, translation_stage, sample_video_config):
        """Test that progress is emitted during translation."""
        context = {
            "video_config": sample_video_config,
            "source_language": "en",
            "target_languages": ["es", "fr"],
            "task_id": "test_task"
        }

        progress_calls = []

        async def mock_emit(task_id, progress, message):
            progress_calls.append((task_id, progress, message))

        translation_stage.emit_progress = mock_emit

        with patch.object(
            translation_stage,
            "_translate_text",
            side_effect=lambda text, src, tgt: text
        ):
            await translation_stage.execute(context)

            # Should have emitted progress for each language
            assert len(progress_calls) >= 2
            assert any("es" in call[2] for call in progress_calls)
            assert any("fr" in call[2] for call in progress_calls)
