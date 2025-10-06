"""
Test suite for pipeline orchestrator.
"""

import asyncio
import pytest
from pathlib import Path

from video_gen.pipeline import PipelineOrchestrator, Stage, StageResult
from video_gen.pipeline.state_manager import StateManager, TaskStatus
from video_gen.pipeline.events import EventEmitter, EventType
from video_gen.shared.models import VideoConfig, SceneConfig, InputConfig
from video_gen.stages import ValidationStage


class DummyStage(Stage):
    """Dummy stage for testing."""

    def __init__(self, name: str, should_fail: bool = False, event_emitter=None):
        super().__init__(name, event_emitter)
        self.should_fail = should_fail
        self.executed = False

    async def execute(self, context):
        self.executed = True
        await asyncio.sleep(0.1)  # Simulate work

        if self.should_fail:
            raise Exception(f"{self.name} failed intentionally")

        return StageResult(
            success=True,
            stage_name=self.name,
            artifacts={f"{self.name}_output": f"result_{self.name}"},
            metadata={"test": True}
        )


@pytest.fixture
def temp_state_dir(tmp_path):
    """Create temporary state directory."""
    return tmp_path / "state"


@pytest.fixture
def orchestrator(temp_state_dir):
    """Create orchestrator with temp state manager."""
    state_manager = StateManager(temp_state_dir)
    return PipelineOrchestrator(state_manager=state_manager)


@pytest.fixture
def sample_video_config():
    """Create sample video config."""
    return VideoConfig(
        video_id="test_video",
        title="Test Video",
        description="Test video for pipeline",
        scenes=[
            SceneConfig(
                scene_id="scene_01",
                scene_type="title",
                narration="This is a test video.",
                visual_content={"title": "Test", "subtitle": "Video"}
            ),
            SceneConfig(
                scene_id="scene_02",
                scene_type="outro",
                narration="Thank you for watching.",
                visual_content={"main_text": "The End"}
            )
        ]
    )


@pytest.mark.asyncio
async def test_orchestrator_basic_execution(orchestrator, sample_video_config):
    """Test basic pipeline execution."""

    # Register stages
    orchestrator.register_stages([
        DummyStage("stage1"),
        DummyStage("stage2"),
        DummyStage("stage3"),
    ])

    # Create input config
    input_config = InputConfig(
        input_type="programmatic",
        source="test"
    )

    # Execute
    result = await orchestrator.execute(input_config)

    # Verify
    assert result.success
    assert result.task_id is not None


@pytest.mark.asyncio
async def test_orchestrator_with_failure(orchestrator):
    """Test pipeline with failing stage."""

    orchestrator.register_stages([
        DummyStage("stage1"),
        DummyStage("stage2", should_fail=True),
        DummyStage("stage3"),
    ])

    input_config = InputConfig(input_type="programmatic", source="test")

    result = await orchestrator.execute(input_config)

    # Pipeline should continue despite failure
    assert not result.success
    assert len(result.errors) > 0


@pytest.mark.asyncio
async def test_state_persistence(orchestrator, temp_state_dir):
    """Test that state is persisted after each stage."""

    orchestrator.register_stages([
        DummyStage("stage1"),
        DummyStage("stage2"),
    ])

    input_config = InputConfig(input_type="programmatic", source="test")

    result = await orchestrator.execute(input_config)

    # Verify state file exists
    state_files = list(temp_state_dir.glob("*.json"))
    assert len(state_files) == 1

    # Load state
    task_state = orchestrator.state_manager.load(result.task_id)
    assert task_state.status == TaskStatus.COMPLETED
    assert len(task_state.get_completed_stages()) == 2


@pytest.mark.asyncio
async def test_resume_capability(orchestrator):
    """Test resuming from a paused/failed task."""

    # First execution - will fail on stage2
    orchestrator.register_stages([
        DummyStage("stage1"),
        DummyStage("stage2", should_fail=True),
        DummyStage("stage3"),
    ])

    input_config = InputConfig(input_type="programmatic", source="test")

    result1 = await orchestrator.execute(input_config, task_id="resume_test")

    assert not result1.success

    # Fix the failing stage and resume
    orchestrator.stages = []
    orchestrator.stage_map = {}
    orchestrator.register_stages([
        DummyStage("stage1"),
        DummyStage("stage2"),  # Now works
        DummyStage("stage3"),
    ])

    result2 = await orchestrator.execute(input_config, task_id="resume_test", resume=True)

    # Should complete successfully
    assert result2.success


@pytest.mark.asyncio
async def test_event_emission(orchestrator, sample_video_config):
    """Test that events are emitted during execution."""

    events_received = []

    def event_listener(event):
        events_received.append(event)

    orchestrator.event_emitter.on_all(event_listener)

    orchestrator.register_stages([
        DummyStage("stage1", event_emitter=orchestrator.event_emitter),
        DummyStage("stage2", event_emitter=orchestrator.event_emitter),
    ])

    input_config = InputConfig(input_type="programmatic", source="test")

    await orchestrator.execute(input_config)

    # Check events
    assert len(events_received) > 0

    event_types = [e.type for e in events_received]
    assert EventType.PIPELINE_STARTED in event_types
    assert EventType.STAGE_STARTED in event_types
    assert EventType.STAGE_COMPLETED in event_types
    assert EventType.PIPELINE_COMPLETED in event_types


@pytest.mark.asyncio
async def test_validation_stage(sample_video_config):
    """Test validation stage."""

    stage = ValidationStage()

    context = {
        "task_id": "test",
        "video_config": sample_video_config
    }

    result = await stage.execute(context)

    assert result.success
    assert result.metadata["scene_count"] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
