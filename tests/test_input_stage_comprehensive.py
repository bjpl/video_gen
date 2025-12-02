"""
Comprehensive tests for InputStage to achieve 80%+ coverage.

Tests cover:
- Happy path for all adapter types (document, youtube, yaml, programmatic)
- Error handling (missing files, invalid adapters, adapter failures)
- Edge cases (empty content, malformed data, unicode)
- State transitions and progress emission
- Context validation
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from pathlib import Path

from video_gen.stages.input_stage import InputStage
from video_gen.shared.models import InputConfig, VideoConfig, SceneConfig, VideoSet
from video_gen.input_adapters.base import InputAdapterResult
from video_gen.shared.exceptions import StageError
from video_gen.pipeline.stage import StageResult


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def input_stage():
    """Create InputStage instance."""
    return InputStage(test_mode=True)


@pytest.fixture
def mock_event_emitter():
    """Create mock event emitter."""
    emitter = Mock()
    emitter.emit = AsyncMock()
    return emitter


@pytest.fixture
def sample_video_config():
    """Create sample VideoConfig for testing."""
    return VideoConfig(
        video_id="test-video-123",
        title="Test Video",
        description="Test description",
        scenes=[
            SceneConfig(
                scene_id="scene1",
                scene_type="title",
                narration="Welcome to the test",
                visual_content={"title": "Welcome"}
            )
        ]
    )


@pytest.fixture
def sample_video_set(sample_video_config):
    """Create sample VideoSet."""
    return VideoSet(
        set_id="test-set",
        name="Test Video Set",
        description="Test set",
        videos=[sample_video_config]
    )


@pytest.fixture
def sample_adapter_result(sample_video_set):
    """Create sample InputAdapterResult."""
    return InputAdapterResult(
        success=True,
        video_set=sample_video_set,
        metadata={"source": "test"}
    )


# ============================================================================
# HAPPY PATH TESTS
# ============================================================================

class TestInputStageHappyPath:
    """Test successful execution paths for InputStage."""

    @pytest.mark.asyncio
    async def test_document_adapter_success(self, input_stage, sample_adapter_result, tmp_path):
        """Test successful document adaptation."""
        # Create test document
        test_doc = tmp_path / "test.md"
        test_doc.write_text("# Test Document\n\nTest content")

        # Create input config
        config = InputConfig(
            input_type="document",
            source=str(test_doc),
            accent_color="blue",
            voice="male"
        )

        context = {
            "task_id": "task-123",
            "input_config": config
        }

        # Mock adapter
        with patch.object(input_stage.adapters["document"], "adapt", return_value=sample_adapter_result):
            result = await input_stage.execute(context)

        assert result.success
        assert "video_config" in result.artifacts
        assert result.artifacts["video_config"].video_id == "test-video-123"
        assert result.metadata["adapter_used"] == "document"
        assert result.metadata["scene_count"] == 1
        assert result.metadata["input_type"] == "document"

    @pytest.mark.asyncio
    async def test_yaml_adapter_success(self, input_stage, sample_adapter_result, tmp_path):
        """Test successful YAML adaptation."""
        # Create test YAML
        test_yaml = tmp_path / "test.yaml"
        test_yaml.write_text("video_id: test-123\ntitle: Test")

        config = InputConfig(
            input_type="yaml",
            source=str(test_yaml),
            accent_color="orange"
        )

        context = {
            "task_id": "task-456",
            "input_config": config
        }

        # Mock adapter
        with patch.object(input_stage.adapters["yaml"], "adapt", return_value=sample_adapter_result):
            result = await input_stage.execute(context)

        assert result.success
        assert "video_config" in result.artifacts

    @pytest.mark.asyncio
    async def test_programmatic_adapter_success(self, input_stage, sample_video_config, sample_adapter_result):
        """Test successful programmatic adaptation."""
        config = InputConfig(
            input_type="programmatic",
            source=sample_video_config,
            accent_color="purple"
        )

        context = {
            "task_id": "task-789",
            "input_config": config
        }

        # Mock adapter
        with patch.object(input_stage.adapters["programmatic"], "adapt", return_value=sample_adapter_result):
            result = await input_stage.execute(context)

        assert result.success
        assert "video_config" in result.artifacts

    @pytest.mark.asyncio
    async def test_youtube_adapter_success(self, input_stage, sample_adapter_result):
        """Test successful YouTube adaptation."""
        config = InputConfig(
            input_type="youtube",
            source="https://youtube.com/watch?v=test123",
            accent_color="green"
        )

        context = {
            "task_id": "task-youtube",
            "input_config": config
        }

        # Mock adapter
        with patch.object(input_stage.adapters["youtube"], "adapt", return_value=sample_adapter_result):
            result = await input_stage.execute(context)

        assert result.success
        assert "video_config" in result.artifacts

    @pytest.mark.asyncio
    async def test_multiple_scenes(self, input_stage, sample_video_set, tmp_path):
        """Test adaptation with multiple scenes."""
        # Add more scenes to video config
        video_config = sample_video_set.videos[0]
        video_config.scenes.append(
            SceneConfig(
                scene_id="scene2",
                scene_type="command",
                narration="Run this command",
                visual_content={"command": "ls -la"}
            )
        )
        video_config.scenes.append(
            SceneConfig(
                scene_id="scene3",
                scene_type="outro",
                narration="Thanks for watching",
                visual_content={"message": "Bye"}
            )
        )

        adapter_result = InputAdapterResult(
            success=True,
            video_set=sample_video_set,
            metadata={"source": "test"}
        )

        test_doc = tmp_path / "test.md"
        test_doc.write_text("# Test")

        config = InputConfig(
            input_type="document",
            source=str(test_doc)
        )

        context = {
            "task_id": "task-multi",
            "input_config": config
        }

        with patch.object(input_stage.adapters["document"], "adapt", return_value=adapter_result):
            result = await input_stage.execute(context)

        assert result.success
        assert result.metadata["scene_count"] == 3


# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

class TestInputStageErrors:
    """Test error handling in InputStage."""

    @pytest.mark.asyncio
    async def test_missing_context_input_config(self, input_stage):
        """Test error when input_config is missing from context."""
        context = {
            "task_id": "task-123"
            # Missing input_config
        }

        with pytest.raises(StageError) as exc_info:
            await input_stage.execute(context)

        assert "input_config" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_unknown_adapter_type(self, input_stage):
        """Test error with unknown input type."""
        config = InputConfig(
            input_type="unknown_type",  # Invalid
            source="test.txt"
        )

        context = {
            "task_id": "task-unknown",
            "input_config": config
        }

        with pytest.raises(StageError) as exc_info:
            await input_stage.execute(context)

        error_msg = str(exc_info.value).lower()
        assert "unknown input type" in error_msg
        assert "unknown_type" in error_msg

    @pytest.mark.asyncio
    async def test_adapter_returns_failure(self, input_stage, tmp_path):
        """Test handling when adapter returns failure result."""
        test_doc = tmp_path / "test.md"
        test_doc.write_text("# Test")

        config = InputConfig(
            input_type="document",
            source=str(test_doc)
        )

        context = {
            "task_id": "task-fail",
            "input_config": config
        }

        # Mock adapter to return failure
        failed_result = InputAdapterResult(
            success=False,
            video_set=None,
            error="Adapter failed to parse document"
        )

        with patch.object(input_stage.adapters["document"], "adapt", return_value=failed_result):
            with pytest.raises(StageError) as exc_info:
                await input_stage.execute(context)

            error_msg = str(exc_info.value).lower()
            assert "input adaptation failed" in error_msg
            assert "adapter failed" in error_msg

    @pytest.mark.asyncio
    async def test_adapter_returns_empty_video_set(self, input_stage, tmp_path):
        """Test handling when adapter returns empty video set."""
        test_doc = tmp_path / "test.md"
        test_doc.write_text("# Test")

        config = InputConfig(
            input_type="document",
            source=str(test_doc)
        )

        context = {
            "task_id": "task-empty",
            "input_config": config
        }

        # Mock adapter to return empty video set
        empty_result = InputAdapterResult(
            success=True,
            video_set=VideoSet(set_id="empty", name="Empty", videos=[]),
            metadata={}
        )

        with patch.object(input_stage.adapters["document"], "adapt", return_value=empty_result):
            with pytest.raises(StageError) as exc_info:
                await input_stage.execute(context)

            error_msg = str(exc_info.value).lower()
            assert "no video config generated" in error_msg

    @pytest.mark.asyncio
    async def test_adapter_raises_exception(self, input_stage, tmp_path):
        """Test handling when adapter raises exception."""
        test_doc = tmp_path / "test.md"
        test_doc.write_text("# Test")

        config = InputConfig(
            input_type="document",
            source=str(test_doc)
        )

        context = {
            "task_id": "task-exception",
            "input_config": config
        }

        # Mock adapter to raise exception
        with patch.object(input_stage.adapters["document"], "adapt", side_effect=ValueError("Invalid format")):
            with pytest.raises(StageError) as exc_info:
                await input_stage.execute(context)

            error_msg = str(exc_info.value).lower()
            assert "input adaptation error" in error_msg
            assert "invalid format" in error_msg


# ============================================================================
# EDGE CASES
# ============================================================================

class TestInputStageEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_empty_document(self, input_stage, sample_video_set, tmp_path):
        """Test adaptation of empty document."""
        test_doc = tmp_path / "empty.md"
        test_doc.write_text("")

        config = InputConfig(
            input_type="document",
            source=str(test_doc)
        )

        context = {
            "task_id": "task-empty-doc",
            "input_config": config
        }

        adapter_result = InputAdapterResult(
            success=True,
            video_set=sample_video_set,
            metadata={"source": "empty"}
        )

        with patch.object(input_stage.adapters["document"], "adapt", return_value=adapter_result):
            result = await input_stage.execute(context)

        assert result.success

    @pytest.mark.asyncio
    async def test_unicode_content(self, input_stage, sample_video_set, tmp_path):
        """Test adaptation with unicode characters."""
        test_doc = tmp_path / "unicode.md"
        test_doc.write_text("# 测试文档 🎥\n\n日本語 コンテンツ")

        config = InputConfig(
            input_type="document",
            source=str(test_doc)
        )

        context = {
            "task_id": "task-unicode",
            "input_config": config
        }

        adapter_result = InputAdapterResult(
            success=True,
            video_set=sample_video_set,
            metadata={"source": "unicode"}
        )

        with patch.object(input_stage.adapters["document"], "adapt", return_value=adapter_result):
            result = await input_stage.execute(context)

        assert result.success

    @pytest.mark.asyncio
    async def test_large_document(self, input_stage, sample_video_set, tmp_path):
        """Test adaptation of large document."""
        test_doc = tmp_path / "large.md"
        # Create large content (10MB)
        large_content = "# Large Document\n\n" + ("Lorem ipsum " * 100000)
        test_doc.write_text(large_content)

        config = InputConfig(
            input_type="document",
            source=str(test_doc)
        )

        context = {
            "task_id": "task-large",
            "input_config": config
        }

        adapter_result = InputAdapterResult(
            success=True,
            video_set=sample_video_set,
            metadata={"source": "large"}
        )

        with patch.object(input_stage.adapters["document"], "adapt", return_value=adapter_result):
            result = await input_stage.execute(context)

        assert result.success

    @pytest.mark.asyncio
    async def test_special_characters_in_path(self, input_stage, sample_video_set, tmp_path):
        """Test adaptation with special characters in file path."""
        test_doc = tmp_path / "test file (with spaces) & symbols!.md"
        test_doc.write_text("# Test")

        config = InputConfig(
            input_type="document",
            source=str(test_doc)
        )

        context = {
            "task_id": "task-special-chars",
            "input_config": config
        }

        adapter_result = InputAdapterResult(
            success=True,
            video_set=sample_video_set,
            metadata={"source": "special"}
        )

        with patch.object(input_stage.adapters["document"], "adapt", return_value=adapter_result):
            result = await input_stage.execute(context)

        assert result.success

    @pytest.mark.asyncio
    async def test_case_insensitive_input_type(self, input_stage, sample_adapter_result, tmp_path):
        """Test that input_type is case-insensitive."""
        test_doc = tmp_path / "test.md"
        test_doc.write_text("# Test")

        config = InputConfig(
            input_type="DOCUMENT",  # Uppercase
            source=str(test_doc)
        )

        context = {
            "task_id": "task-case",
            "input_config": config
        }

        with patch.object(input_stage.adapters["document"], "adapt", return_value=sample_adapter_result):
            result = await input_stage.execute(context)

        assert result.success

    @pytest.mark.asyncio
    async def test_video_count_parameter(self, input_stage, sample_adapter_result, tmp_path):
        """Test video_count parameter is passed to adapter."""
        test_doc = tmp_path / "test.md"
        test_doc.write_text("# Test")

        config = InputConfig(
            input_type="document",
            source=str(test_doc),
            video_count=3
        )

        context = {
            "task_id": "task-count",
            "input_config": config
        }

        # Mock adapter and verify video_count is passed
        adapter_mock = AsyncMock(return_value=sample_adapter_result)
        input_stage.adapters["document"].adapt = adapter_mock

        result = await input_stage.execute(context)

        assert result.success
        # Verify adapter was called with video_count
        adapter_mock.assert_called_once()
        call_kwargs = adapter_mock.call_args[1]
        assert call_kwargs.get("video_count") == 3

    @pytest.mark.asyncio
    async def test_split_by_h2_parameter(self, input_stage, sample_adapter_result, tmp_path):
        """Test split_by_h2 parameter is passed to adapter."""
        test_doc = tmp_path / "test.md"
        test_doc.write_text("# Test\n## Section 1\n## Section 2")

        config = InputConfig(
            input_type="document",
            source=str(test_doc),
            split_by_h2=True
        )

        context = {
            "task_id": "task-split",
            "input_config": config
        }

        # Mock adapter and verify split_by_h2 is passed
        adapter_mock = AsyncMock(return_value=sample_adapter_result)
        input_stage.adapters["document"].adapt = adapter_mock

        result = await input_stage.execute(context)

        assert result.success
        # Verify adapter was called with split_by_h2
        adapter_mock.assert_called_once()
        call_kwargs = adapter_mock.call_args[1]
        assert call_kwargs.get("split_by_h2") is True


# ============================================================================
# PROGRESS EMISSION TESTS
# ============================================================================

class TestInputStageProgress:
    """Test progress emission during execution."""

    @pytest.mark.asyncio
    async def test_progress_emission(self, mock_event_emitter, sample_adapter_result, tmp_path):
        """Test that progress is emitted during execution."""
        input_stage = InputStage(event_emitter=mock_event_emitter, test_mode=True)

        test_doc = tmp_path / "test.md"
        test_doc.write_text("# Test")

        config = InputConfig(
            input_type="document",
            source=str(test_doc)
        )

        context = {
            "task_id": "task-progress",
            "input_config": config
        }

        with patch.object(input_stage.adapters["document"], "adapt", return_value=sample_adapter_result):
            await input_stage.execute(context)

        # Verify progress events were emitted
        assert mock_event_emitter.emit.call_count >= 2  # At least start and end


# ============================================================================
# METADATA TESTS
# ============================================================================

class TestInputStageMetadata:
    """Test metadata generation and tracking."""

    @pytest.mark.asyncio
    async def test_metadata_includes_input_metadata(self, input_stage, tmp_path):
        """Test that input_metadata from adapter is preserved."""
        test_doc = tmp_path / "test.md"
        test_doc.write_text("# Test")

        config = InputConfig(
            input_type="document",
            source=str(test_doc)
        )

        context = {
            "task_id": "task-metadata",
            "input_config": config
        }

        # Create video set with metadata
        video_config = VideoConfig(
            video_id="test-123",
            title="Test",
            description="Test",
            scenes=[
                SceneConfig(
                    scene_id="s1",
                    scene_type="title",
                    narration="Test",
                    visual_content={"title": "Test"}
                )
            ]
        )

        adapter_result = InputAdapterResult(
            success=True,
            video_set=VideoSet(set_id="test", name="Test", videos=[video_config]),
            metadata={"custom_key": "custom_value", "source_format": "markdown"}
        )

        with patch.object(input_stage.adapters["document"], "adapt", return_value=adapter_result):
            result = await input_stage.execute(context)

        assert result.success
        assert "input_metadata" in result.artifacts
        assert result.artifacts["input_metadata"]["custom_key"] == "custom_value"
        assert result.artifacts["input_metadata"]["source_format"] == "markdown"

    @pytest.mark.asyncio
    async def test_result_metadata_completeness(self, input_stage, sample_adapter_result, tmp_path):
        """Test that result metadata includes all expected fields."""
        test_doc = tmp_path / "test.md"
        test_doc.write_text("# Test")

        config = InputConfig(
            input_type="document",
            source=str(test_doc),
            accent_color="purple"
        )

        context = {
            "task_id": "task-complete-metadata",
            "input_config": config
        }

        with patch.object(input_stage.adapters["document"], "adapt", return_value=sample_adapter_result):
            result = await input_stage.execute(context)

        # Verify all expected metadata fields
        assert result.metadata["adapter_used"] == "document"
        assert result.metadata["scene_count"] == 1
        assert result.metadata["input_type"] == "document"
        assert result.success is True
        assert result.stage_name == "input_adaptation"
