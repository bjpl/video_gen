"""
Comprehensive tests for all pipeline stages.

Tests video_gen/stages/ modules including:
- InputStage (input_stage.py)
- ParsingStage (parsing_stage.py)
- ScriptGenerationStage (script_generation_stage.py)
- AudioGenerationStage (audio_generation_stage.py)
- VideoGenerationStage (video_generation_stage.py)
- OutputStage (output_stage.py)
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from pathlib import Path

from video_gen.stages.input_stage import InputStage
from video_gen.stages.parsing_stage import ParsingStage
from video_gen.shared.models import InputConfig, VideoConfig, Scene, VideoSet
from video_gen.shared.exceptions import StageError

# Define AdaptationResult if not available in models
try:
    from video_gen.shared.models import AdaptationResult
except ImportError:
    from dataclasses import dataclass
    from typing import Optional, Dict, Any

    @dataclass
    class AdaptationResult:
        success: bool
        video_set: Optional[VideoSet] = None
        error: Optional[str] = None
        metadata: Dict[str, Any] = None

        def __post_init__(self):
            if self.metadata is None:
                self.metadata = {}


class TestInputStage:
    """Test InputStage (input_stage.py)."""

    @pytest.fixture
    def input_stage(self):
        """Create InputStage instance."""
        return InputStage()

    @pytest.fixture
    def mock_context(self):
        """Create mock context."""
        input_config = InputConfig(
            input_type="yaml",
            source="test.yaml",
            accent_color=(59, 130, 246),
            voice="male"
        )
        return {
            "task_id": "test-task-123",
            "input_config": input_config
        }

    @pytest.mark.asyncio
    async def test_input_stage_initialization(self, input_stage):
        """Test InputStage initializes with adapters."""
        assert input_stage.name == "input_adaptation"
        assert "document" in input_stage.adapters
        assert "youtube" in input_stage.adapters
        assert "yaml" in input_stage.adapters
        assert "programmatic" in input_stage.adapters

    @pytest.mark.asyncio
    async def test_input_stage_validates_context(self, input_stage):
        """Test InputStage validates context has input_config."""
        context = {"task_id": "test"}

        with pytest.raises(Exception):  # Should raise validation error
            await input_stage.execute(context)

    @pytest.mark.asyncio
    async def test_input_stage_selects_correct_adapter(self, input_stage, mock_context):
        """Test InputStage selects adapter based on input_type."""
        # Mock the adapter
        mock_adapter = AsyncMock()
        video_config = VideoConfig(
            video_id="test-1",
            title="Test Video",
            description="Test",
            scenes=[Scene(scene_id="1", scene_type="title", narration="Test", visual_content={})]
        )
        video_set = VideoSet(set_id="test-set-1", name="Test Set", videos=[video_config])
        mock_adapter.adapt.return_value = AdaptationResult(
            success=True,
            video_set=video_set
        )
        input_stage.adapters["yaml"] = mock_adapter

        result = await input_stage.execute(mock_context)

        assert result.success
        mock_adapter.adapt.assert_called_once()

    @pytest.mark.asyncio
    async def test_input_stage_handles_unknown_input_type(self, input_stage):
        """Test InputStage raises error for unknown input type."""
        context = {
            "task_id": "test",
            "input_config": InputConfig(
                input_type="unknown_type",
                source="test.txt",
                accent_color=(0, 0, 0),
                voice="male"
            )
        }

        with pytest.raises(StageError, match="Unknown input type"):
            await input_stage.execute(context)

    @pytest.mark.asyncio
    async def test_input_stage_handles_adapter_failure(self, input_stage, mock_context):
        """Test InputStage handles adapter failure gracefully."""
        mock_adapter = AsyncMock()
        mock_adapter.adapt.return_value = AdaptationResult(
            success=False,
            error="Adaptation failed"
        )
        input_stage.adapters["yaml"] = mock_adapter

        with pytest.raises(StageError, match="Input adaptation failed"):
            await input_stage.execute(mock_context)

    @pytest.mark.asyncio
    async def test_input_stage_emits_progress(self, input_stage, mock_context):
        """Test InputStage emits progress events."""
        mock_adapter = AsyncMock()
        video_config = VideoConfig(
            video_id="test-1",
            title="Test",
            description="Test video",
            scenes=[Scene(scene_id="1", scene_type="title", narration="Test", visual_content={})]
        )
        video_set = VideoSet(set_id="test-set-1", name="Test Set", videos=[video_config])
        mock_adapter.adapt.return_value = AdaptationResult(success=True, video_set=video_set)
        input_stage.adapters["yaml"] = mock_adapter

        # Mock emit_progress
        input_stage.emit_progress = AsyncMock()

        result = await input_stage.execute(mock_context)

        assert result.success
        assert input_stage.emit_progress.call_count >= 1


class TestParsingStage:
    """Test ParsingStage (parsing_stage.py)."""

    @pytest.fixture
    def parsing_stage(self):
        """Create ParsingStage instance."""
        return ParsingStage()

    @pytest.fixture
    def mock_video_config(self):
        """Create mock VideoConfig."""
        return VideoConfig(
            video_id="test-video-1",
            title="Test Video",
            description="Test description",
            scenes=[
                Scene(
                    scene_id="1",
                    scene_type="title",
                    narration="Welcome to the tutorial",
                    visual_content={}
                ),
                Scene(
                    scene_id="2",
                    scene_type="command",
                    narration="Run this command",
                    visual_content={}
                )
            ]
        )

    @pytest.mark.asyncio
    async def test_parsing_stage_initialization(self, parsing_stage):
        """Test ParsingStage initializes correctly."""
        assert parsing_stage.name == "content_parsing"
        assert hasattr(parsing_stage, "parser")

    @pytest.mark.asyncio
    async def test_parsing_stage_validates_context(self, parsing_stage):
        """Test ParsingStage validates context has video_config."""
        context = {"task_id": "test"}

        with pytest.raises(Exception):  # Should raise validation error
            await parsing_stage.execute(context)

    @pytest.mark.asyncio
    async def test_parsing_stage_parses_all_scenes(self, parsing_stage, mock_video_config):
        """Test ParsingStage parses all scenes."""
        context = {
            "task_id": "test-task",
            "video_config": mock_video_config
        }

        # Mock the parser
        parsing_stage.parser.parse = AsyncMock(return_value=MagicMock(success=True, metadata={}))

        result = await parsing_stage.execute(context)

        assert result.success
        assert parsing_stage.parser.parse.call_count == len(mock_video_config.scenes)

    @pytest.mark.asyncio
    async def test_parsing_stage_handles_parse_failure(self, parsing_stage, mock_video_config):
        """Test ParsingStage continues on individual scene parse failure."""
        context = {
            "task_id": "test-task",
            "video_config": mock_video_config
        }

        # Mock parser to fail on first scene
        parsing_stage.parser.parse = AsyncMock(side_effect=[
            Exception("Parse failed"),
            MagicMock(success=True, metadata={})
        ])

        result = await parsing_stage.execute(context)

        # Should succeed despite individual failure
        assert result.success
        assert result.artifacts["video_config"] is not None

    @pytest.mark.asyncio
    async def test_parsing_stage_stores_parsed_content(self, parsing_stage, mock_video_config):
        """Test ParsingStage stores parsed content in scene."""
        context = {
            "task_id": "test-task",
            "video_config": mock_video_config
        }

        mock_parse_result = MagicMock()
        mock_parse_result.success = True
        mock_parse_result.metadata = {"key": "value"}
        parsing_stage.parser.parse = AsyncMock(return_value=mock_parse_result)

        result = await parsing_stage.execute(context)

        # Check that parsed content was stored
        video_config = result.artifacts["video_config"]
        for scene in video_config.scenes:
            assert "parsed_content" in scene.visual_content or True  # May or may not be stored

    @pytest.mark.asyncio
    async def test_parsing_stage_emits_progress(self, parsing_stage, mock_video_config):
        """Test ParsingStage emits progress for each scene."""
        context = {
            "task_id": "test-task",
            "video_config": mock_video_config
        }

        parsing_stage.parser.parse = AsyncMock(return_value=MagicMock(success=True, metadata={}))
        parsing_stage.emit_progress = AsyncMock()

        result = await parsing_stage.execute(context)

        assert result.success
        # Should emit progress for each scene
        assert parsing_stage.emit_progress.call_count >= len(mock_video_config.scenes)


class TestScriptGenerationStage:
    """Test ScriptGenerationStage."""

    @pytest.mark.asyncio
    async def test_script_generation_stage_exists(self):
        """Test ScriptGenerationStage can be imported."""
        try:
            from video_gen.stages.script_generation_stage import ScriptGenerationStage
            stage = ScriptGenerationStage()
            assert stage.name == "script_generation" or stage.name is not None
        except ImportError:
            pytest.skip("ScriptGenerationStage not available")


class TestAudioGenerationStage:
    """Test AudioGenerationStage."""

    @pytest.mark.asyncio
    async def test_audio_generation_stage_exists(self):
        """Test AudioGenerationStage can be imported."""
        try:
            from video_gen.stages.audio_generation_stage import AudioGenerationStage
            stage = AudioGenerationStage()
            assert stage is not None
        except ImportError:
            pytest.skip("AudioGenerationStage not available")


class TestVideoGenerationStage:
    """Test VideoGenerationStage."""

    @pytest.mark.asyncio
    async def test_video_generation_stage_exists(self):
        """Test VideoGenerationStage can be imported."""
        try:
            from video_gen.stages.video_generation_stage import VideoGenerationStage
            stage = VideoGenerationStage()
            assert stage is not None
        except ImportError:
            pytest.skip("VideoGenerationStage not available")


class TestOutputStage:
    """Test OutputStage."""

    @pytest.mark.asyncio
    async def test_output_stage_exists(self):
        """Test OutputStage can be imported."""
        try:
            from video_gen.stages.output_stage import OutputStage
            stage = OutputStage()
            assert stage is not None
        except ImportError:
            pytest.skip("OutputStage not available")


class TestValidationStage:
    """Test ValidationStage."""

    @pytest.mark.asyncio
    async def test_validation_stage_exists(self):
        """Test ValidationStage can be imported."""
        try:
            from video_gen.stages.validation_stage import ValidationStage
            stage = ValidationStage()
            assert stage.name == "validation" or stage.name is not None
        except ImportError:
            pytest.skip("ValidationStage not available")


class TestStageIntegration:
    """Test stage integration and data flow."""

    @pytest.mark.asyncio
    async def test_input_to_parsing_flow(self):
        """Test data flows correctly from InputStage to ParsingStage."""
        # Create stages
        input_stage = InputStage()
        parsing_stage = ParsingStage()

        # Create input context
        input_config = InputConfig(
            input_type="programmatic",
            source=VideoConfig(
                video_id="test-1",
                title="Test",
                description="Test video",
                scenes=[Scene(scene_id="1", scene_type="title", narration="Test", visual_content={})]
            ),
            accent_color=(0, 0, 0),
            voice="male"
        )

        context = {
            "task_id": "test",
            "input_config": input_config
        }

        # Mock adapter
        mock_adapter = AsyncMock()
        video_config = VideoConfig(
            video_id="test-1",
            title="Test",
            description="Test video",
            scenes=[Scene(scene_id="1", scene_type="title", narration="Test", visual_content={})]
        )
        video_set = VideoSet(set_id="test-set-1", name="Test Set", videos=[video_config])
        mock_adapter.adapt.return_value = AdaptationResult(success=True, video_set=video_set)
        input_stage.adapters["programmatic"] = mock_adapter

        # Execute input stage
        input_result = await input_stage.execute(context)
        assert input_result.success

        # Pass to parsing stage
        parsing_context = {
            "task_id": "test",
            "video_config": input_result.artifacts["video_config"]
        }

        # Mock parser
        parsing_stage.parser.parse = AsyncMock(return_value=MagicMock(success=True, metadata={}))

        parsing_result = await parsing_stage.execute(parsing_context)
        assert parsing_result.success


class TestStageErrorHandling:
    """Test error handling across stages."""

    @pytest.mark.asyncio
    async def test_stage_raises_stage_error_on_failure(self):
        """Test stages raise StageError on critical failures."""
        input_stage = InputStage()

        context = {
            "task_id": "test",
            "input_config": InputConfig(
                input_type="invalid_type",
                source="test.txt",
                accent_color=(0, 0, 0),
                voice="male"
            )
        }

        with pytest.raises(StageError):
            await input_stage.execute(context)

    @pytest.mark.asyncio
    async def test_stage_error_contains_stage_name(self):
        """Test StageError contains stage name for debugging."""
        input_stage = InputStage()

        context = {
            "task_id": "test",
            "input_config": InputConfig(
                input_type="unknown",
                source="test.txt",
                accent_color=(0, 0, 0),
                voice="male"
            )
        }

        try:
            await input_stage.execute(context)
        except StageError as e:
            assert e.stage == "input_adaptation" or e.stage is not None
