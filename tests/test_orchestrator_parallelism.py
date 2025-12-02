"""
Tests for Pipeline Orchestrator Parallel Execution

Comprehensive tests for phase-based parallel stage execution:
- ExecutionPhase configuration
- Sequential phase execution
- Parallel phase execution with asyncio.gather
- Mixed phase execution (some parallel, some sequential)
- Error handling in parallel execution
- Resume functionality with parallelism
- Performance metrics logging
"""

import asyncio
import pytest
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
from unittest.mock import AsyncMock, MagicMock, patch

from video_gen.pipeline.orchestrator import (
    PipelineOrchestrator,
    ExecutionPhase,
    DEFAULT_EXECUTION_PHASES,
)
from video_gen.pipeline.stage import Stage, StageResult
from video_gen.pipeline.state_manager import StateManager, TaskState, TaskStatus
from video_gen.pipeline.events import EventEmitter, Event, EventType
from video_gen.shared.models import InputConfig


# ============================================================================
# Test Fixtures
# ============================================================================

class MockStage(Stage):
    """Mock stage for testing with configurable behavior."""

    def __init__(
        self,
        name: str,
        duration: float = 0.1,
        should_fail: bool = False,
        error_message: str = "Stage failed",
        artifacts: Dict[str, Any] = None
    ):
        super().__init__(name)
        self.mock_duration = duration
        self.should_fail = should_fail
        self.error_message = error_message
        self.mock_artifacts = artifacts or {f"{name}_output": f"{name}_value"}
        self.execution_count = 0
        self.execution_times: List[datetime] = []

    async def execute(self, context: Dict[str, Any]) -> StageResult:
        """Execute mock stage with configurable delay."""
        self.execution_count += 1
        self.execution_times.append(datetime.now())

        # Simulate work with actual async delay
        await asyncio.sleep(self.mock_duration)

        if self.should_fail:
            return StageResult(
                stage_name=self.name,
                success=False,
                error=self.error_message,
                duration=self.mock_duration,
                artifacts={},
                warnings=[]
            )

        return StageResult(
            stage_name=self.name,
            success=True,
            error=None,
            duration=self.mock_duration,
            artifacts=self.mock_artifacts,
            warnings=[]
        )


@pytest.fixture
def mock_state_manager():
    """Create mock state manager."""
    manager = MagicMock(spec=StateManager)
    manager.exists.return_value = False

    # Track saved states
    saved_states = []
    def save_state(state):
        saved_states.append(state)
    manager.save.side_effect = save_state
    manager.saved_states = saved_states

    return manager


@pytest.fixture
def mock_event_emitter():
    """Create mock event emitter."""
    emitter = MagicMock(spec=EventEmitter)
    emitter.emit = AsyncMock()
    return emitter


@pytest.fixture
def sample_input_config():
    """Create sample input configuration."""
    config = MagicMock(spec=InputConfig)
    config.to_dict.return_value = {
        "document_source": "test.txt",
        "output_path": "/tmp/output",
    }
    return config


# ============================================================================
# ExecutionPhase Tests
# ============================================================================

class TestExecutionPhase:
    """Tests for ExecutionPhase dataclass."""

    def test_phase_creation_sequential(self):
        """Test creating sequential phase."""
        phase = ExecutionPhase(
            name="test_phase",
            stages=["stage1", "stage2"],
            parallel=False
        )
        assert phase.name == "test_phase"
        assert phase.stages == ["stage1", "stage2"]
        assert phase.parallel is False

    def test_phase_creation_parallel(self):
        """Test creating parallel phase."""
        phase = ExecutionPhase(
            name="parallel_phase",
            stages=["audio", "script"],
            parallel=True
        )
        assert phase.name == "parallel_phase"
        assert phase.parallel is True

    def test_phase_repr_sequential(self):
        """Test phase string representation for sequential."""
        phase = ExecutionPhase("prep", ["a", "b"], parallel=False)
        assert "sequential" in repr(phase)

    def test_phase_repr_parallel(self):
        """Test phase string representation for parallel."""
        phase = ExecutionPhase("gen", ["a", "b"], parallel=True)
        assert "parallel" in repr(phase)


class TestDefaultExecutionPhases:
    """Tests for default phase configuration."""

    def test_default_phases_exist(self):
        """Test that default phases are defined."""
        assert DEFAULT_EXECUTION_PHASES is not None
        assert len(DEFAULT_EXECUTION_PHASES) == 4

    def test_preparation_phase_sequential(self):
        """Test preparation phase is sequential."""
        prep = DEFAULT_EXECUTION_PHASES[0]
        assert prep.name == "preparation"
        assert prep.parallel is False
        assert "input_adaptation" in prep.stages
        assert "content_parsing" in prep.stages

    def test_generation_phase_parallel(self):
        """Test generation phase is parallel."""
        gen = DEFAULT_EXECUTION_PHASES[1]
        assert gen.name == "generation"
        assert gen.parallel is True
        assert "script_generation" in gen.stages
        assert "audio_generation" in gen.stages

    def test_assembly_phase_sequential(self):
        """Test assembly phase is sequential."""
        assembly = DEFAULT_EXECUTION_PHASES[2]
        assert assembly.name == "assembly"
        assert assembly.parallel is False
        assert "video_generation" in assembly.stages

    def test_finalization_phase_sequential(self):
        """Test finalization phase is sequential."""
        final = DEFAULT_EXECUTION_PHASES[3]
        assert final.name == "finalization"
        assert final.parallel is False
        assert "output_handling" in final.stages


# ============================================================================
# Orchestrator Initialization Tests
# ============================================================================

class TestOrchestratorInitialization:
    """Tests for orchestrator initialization with parallelism settings."""

    def test_default_parallelism_enabled(self, mock_state_manager, mock_event_emitter):
        """Test that parallelism is enabled by default."""
        orchestrator = PipelineOrchestrator(
            state_manager=mock_state_manager,
            event_emitter=mock_event_emitter
        )
        assert orchestrator.enable_parallelism is True

    def test_parallelism_can_be_disabled(self, mock_state_manager, mock_event_emitter):
        """Test that parallelism can be disabled."""
        orchestrator = PipelineOrchestrator(
            state_manager=mock_state_manager,
            event_emitter=mock_event_emitter,
            enable_parallelism=False
        )
        assert orchestrator.enable_parallelism is False

    def test_default_phases_used(self, mock_state_manager, mock_event_emitter):
        """Test that default phases are used when none provided."""
        orchestrator = PipelineOrchestrator(
            state_manager=mock_state_manager,
            event_emitter=mock_event_emitter
        )
        assert orchestrator.execution_phases == DEFAULT_EXECUTION_PHASES

    def test_custom_phases_accepted(self, mock_state_manager, mock_event_emitter):
        """Test that custom phases are accepted."""
        custom_phases = [
            ExecutionPhase("custom", ["stage1", "stage2"], parallel=True)
        ]
        orchestrator = PipelineOrchestrator(
            state_manager=mock_state_manager,
            event_emitter=mock_event_emitter,
            execution_phases=custom_phases
        )
        assert orchestrator.execution_phases == custom_phases


# ============================================================================
# Sequential Execution Tests
# ============================================================================

class TestSequentialExecution:
    """Tests for sequential stage execution."""

    @pytest.mark.asyncio
    async def test_sequential_stages_execute_in_order(
        self, mock_state_manager, mock_event_emitter, sample_input_config
    ):
        """Test that sequential stages execute in order."""
        orchestrator = PipelineOrchestrator(
            state_manager=mock_state_manager,
            event_emitter=mock_event_emitter,
            execution_phases=[
                ExecutionPhase("test", ["stage1", "stage2", "stage3"], parallel=False)
            ]
        )

        stages = [
            MockStage("stage1", duration=0.05),
            MockStage("stage2", duration=0.05),
            MockStage("stage3", duration=0.05),
        ]
        orchestrator.register_stages(stages)

        result = await orchestrator.execute(sample_input_config)

        # All stages should execute
        assert all(s.execution_count == 1 for s in stages)

        # Execution should be sequential (each starts after previous)
        for i in range(1, len(stages)):
            assert stages[i].execution_times[0] >= stages[i-1].execution_times[0]

    @pytest.mark.asyncio
    async def test_sequential_context_propagation(
        self, mock_state_manager, mock_event_emitter, sample_input_config
    ):
        """Test that context propagates through sequential stages."""
        orchestrator = PipelineOrchestrator(
            state_manager=mock_state_manager,
            event_emitter=mock_event_emitter,
            execution_phases=[
                ExecutionPhase("test", ["stage1", "stage2"], parallel=False)
            ]
        )

        context_checks = []

        class ContextCheckStage(MockStage):
            async def execute(self, context):
                context_checks.append(dict(context))
                return await super().execute(context)

        stages = [
            ContextCheckStage("stage1", artifacts={"key1": "value1"}),
            ContextCheckStage("stage2", artifacts={"key2": "value2"}),
        ]
        orchestrator.register_stages(stages)

        await orchestrator.execute(sample_input_config)

        # Second stage should have first stage's output
        assert "key1" not in context_checks[0]  # First stage doesn't have it yet
        assert "key1" in context_checks[1]  # Second stage has it


# ============================================================================
# Parallel Execution Tests
# ============================================================================

class TestParallelExecution:
    """Tests for parallel stage execution."""

    @pytest.mark.asyncio
    async def test_parallel_stages_execute_concurrently(
        self, mock_state_manager, mock_event_emitter, sample_input_config
    ):
        """Test that parallel stages execute concurrently."""
        orchestrator = PipelineOrchestrator(
            state_manager=mock_state_manager,
            event_emitter=mock_event_emitter,
            execution_phases=[
                ExecutionPhase("test", ["stage1", "stage2", "stage3"], parallel=True)
            ],
            enable_parallelism=True
        )

        # Each stage takes 0.1 seconds
        stages = [
            MockStage("stage1", duration=0.1),
            MockStage("stage2", duration=0.1),
            MockStage("stage3", duration=0.1),
        ]
        orchestrator.register_stages(stages)

        start = datetime.now()
        await orchestrator.execute(sample_input_config)
        total_time = (datetime.now() - start).total_seconds()

        # All stages should execute
        assert all(s.execution_count == 1 for s in stages)

        # Total time should be ~0.1s (parallel) not ~0.3s (sequential)
        # Allow some overhead
        assert total_time < 0.25, f"Expected parallel execution, took {total_time}s"

    @pytest.mark.asyncio
    async def test_parallel_disabled_falls_back_to_sequential(
        self, mock_state_manager, mock_event_emitter, sample_input_config
    ):
        """Test that disabling parallelism forces sequential execution."""
        orchestrator = PipelineOrchestrator(
            state_manager=mock_state_manager,
            event_emitter=mock_event_emitter,
            execution_phases=[
                ExecutionPhase("test", ["stage1", "stage2"], parallel=True)
            ],
            enable_parallelism=False  # Disabled
        )

        stages = [
            MockStage("stage1", duration=0.1),
            MockStage("stage2", duration=0.1),
        ]
        orchestrator.register_stages(stages)

        start = datetime.now()
        await orchestrator.execute(sample_input_config)
        total_time = (datetime.now() - start).total_seconds()

        # Should take ~0.2s (sequential) not ~0.1s (parallel)
        assert total_time >= 0.18, f"Expected sequential execution, took {total_time}s"

    @pytest.mark.asyncio
    async def test_parallel_artifacts_merged(
        self, mock_state_manager, mock_event_emitter, sample_input_config
    ):
        """Test that artifacts from parallel stages are merged."""
        orchestrator = PipelineOrchestrator(
            state_manager=mock_state_manager,
            event_emitter=mock_event_emitter,
            execution_phases=[
                ExecutionPhase("parallel", ["stage1", "stage2"], parallel=True),
                ExecutionPhase("final", ["stage3"], parallel=False),
            ]
        )

        final_context = None

        class ContextCaptureStage(MockStage):
            async def execute(self, context):
                nonlocal final_context
                final_context = dict(context)
                return await super().execute(context)

        stages = [
            MockStage("stage1", artifacts={"audio_path": "/audio.mp3"}),
            MockStage("stage2", artifacts={"script_text": "Hello world"}),
            ContextCaptureStage("stage3", artifacts={}),
        ]
        orchestrator.register_stages(stages)

        await orchestrator.execute(sample_input_config)

        # Final stage should have both parallel outputs
        assert "audio_path" in final_context
        assert "script_text" in final_context


# ============================================================================
# Mixed Phase Execution Tests
# ============================================================================

class TestMixedPhaseExecution:
    """Tests for mixed sequential and parallel phase execution."""

    @pytest.mark.asyncio
    async def test_sequential_then_parallel_then_sequential(
        self, mock_state_manager, mock_event_emitter, sample_input_config
    ):
        """Test typical pipeline: seq -> parallel -> seq."""
        orchestrator = PipelineOrchestrator(
            state_manager=mock_state_manager,
            event_emitter=mock_event_emitter,
            execution_phases=[
                ExecutionPhase("prep", ["input", "parse"], parallel=False),
                ExecutionPhase("gen", ["audio", "script"], parallel=True),
                ExecutionPhase("final", ["video"], parallel=False),
            ]
        )

        stages = [
            MockStage("input", duration=0.05),
            MockStage("parse", duration=0.05),
            MockStage("audio", duration=0.1),
            MockStage("script", duration=0.1),
            MockStage("video", duration=0.05),
        ]
        orchestrator.register_stages(stages)

        result = await orchestrator.execute(sample_input_config)

        assert result.success
        assert all(s.execution_count == 1 for s in stages)


# ============================================================================
# Error Handling Tests
# ============================================================================

class TestParallelErrorHandling:
    """Tests for error handling in parallel execution."""

    @pytest.mark.asyncio
    async def test_parallel_stage_failure_captured(
        self, mock_state_manager, mock_event_emitter, sample_input_config
    ):
        """Test that failures in parallel stages are captured."""
        orchestrator = PipelineOrchestrator(
            state_manager=mock_state_manager,
            event_emitter=mock_event_emitter,
            execution_phases=[
                ExecutionPhase("test", ["good", "bad"], parallel=True)
            ]
        )

        stages = [
            MockStage("good", should_fail=False),
            MockStage("bad", should_fail=True, error_message="Test error"),
        ]
        orchestrator.register_stages(stages)

        result = await orchestrator.execute(sample_input_config)

        assert not result.success

    @pytest.mark.asyncio
    async def test_critical_parallel_failure_aborts(
        self, mock_state_manager, mock_event_emitter, sample_input_config
    ):
        """Test that critical stage failure aborts pipeline."""
        orchestrator = PipelineOrchestrator(
            state_manager=mock_state_manager,
            event_emitter=mock_event_emitter,
            execution_phases=[
                ExecutionPhase("gen", ["audio_generation", "script"], parallel=True),
                ExecutionPhase("final", ["video"], parallel=False),
            ]
        )

        stages = [
            MockStage("audio_generation", should_fail=True),  # Critical stage
            MockStage("script"),
            MockStage("video"),
        ]
        orchestrator.register_stages(stages)

        result = await orchestrator.execute(sample_input_config)

        assert not result.success
        # Video stage should not execute after critical failure
        assert stages[2].execution_count == 0

    @pytest.mark.asyncio
    async def test_exception_in_parallel_stage_handled(
        self, mock_state_manager, mock_event_emitter, sample_input_config
    ):
        """Test that exceptions in parallel stages are handled gracefully."""
        orchestrator = PipelineOrchestrator(
            state_manager=mock_state_manager,
            event_emitter=mock_event_emitter,
            execution_phases=[
                ExecutionPhase("test", ["normal", "exception"], parallel=True)
            ]
        )

        class ExceptionStage(MockStage):
            async def execute(self, context):
                raise RuntimeError("Unexpected error")

        stages = [
            MockStage("normal"),
            ExceptionStage("exception"),
        ]
        orchestrator.register_stages(stages)

        result = await orchestrator.execute(sample_input_config)

        assert not result.success


# ============================================================================
# Performance Metrics Tests
# ============================================================================

class TestPerformanceMetrics:
    """Tests for performance metrics in parallel execution."""

    @pytest.mark.asyncio
    async def test_parallel_speedup_logged(
        self, mock_state_manager, mock_event_emitter, sample_input_config, caplog
    ):
        """Test that parallel speedup is logged."""
        import logging
        caplog.set_level(logging.INFO)

        orchestrator = PipelineOrchestrator(
            state_manager=mock_state_manager,
            event_emitter=mock_event_emitter,
            execution_phases=[
                ExecutionPhase("test", ["stage1", "stage2"], parallel=True)
            ]
        )

        stages = [
            MockStage("stage1", duration=0.1),
            MockStage("stage2", duration=0.1),
        ]
        orchestrator.register_stages(stages)

        await orchestrator.execute(sample_input_config)

        # Check for speedup log message
        assert any("speedup" in record.message.lower() for record in caplog.records)


# ============================================================================
# Integration with State Manager Tests
# ============================================================================

class TestStateManagerIntegration:
    """Tests for state manager integration with parallelism."""

    @pytest.mark.asyncio
    async def test_parallel_stages_all_marked_started(
        self, mock_state_manager, mock_event_emitter, sample_input_config
    ):
        """Test that all parallel stages are marked as started."""
        orchestrator = PipelineOrchestrator(
            state_manager=mock_state_manager,
            event_emitter=mock_event_emitter,
            execution_phases=[
                ExecutionPhase("test", ["stage1", "stage2", "stage3"], parallel=True)
            ]
        )

        stages = [
            MockStage("stage1"),
            MockStage("stage2"),
            MockStage("stage3"),
        ]
        orchestrator.register_stages(stages)

        await orchestrator.execute(sample_input_config)

        # State should have been saved multiple times
        assert mock_state_manager.save.call_count >= 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
