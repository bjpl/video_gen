"""
Complete Pipeline Integration - All 6 stages wired together.

This module provides a pre-configured pipeline with all stages registered.
"""

from typing import Optional

from .orchestrator import PipelineOrchestrator
from .events import EventEmitter
from .state_manager import StateManager
from ..stages import (
    InputStage,
    ParsingStage,
    ScriptGenerationStage,
    AudioGenerationStage,
    VideoGenerationStage,
    OutputStage,
)


def create_complete_pipeline(
    state_manager: Optional[StateManager] = None,
    event_emitter: Optional[EventEmitter] = None,
    test_mode: bool = False
) -> PipelineOrchestrator:
    """
    Create a complete pipeline with all 6 stages registered.

    Pipeline stages (in order):
    1. Input Adaptation - Convert various inputs to VideoConfig
    2. Content Parsing - Parse and structure content
    3. Script Generation - Generate narration scripts
    4. Audio Generation - Generate TTS audio
    5. Video Generation - Render video scenes
    6. Output Handling - Combine and export final video

    Args:
        state_manager: Optional custom state manager
        event_emitter: Optional custom event emitter
        test_mode: If True, bypass security checks in adapters for testing

    Returns:
        Configured PipelineOrchestrator ready for execution
    """
    # Create orchestrator
    orchestrator = PipelineOrchestrator(
        state_manager=state_manager,
        event_emitter=event_emitter
    )

    # Register all stages in order
    orchestrator.register_stages([
        InputStage(event_emitter, test_mode=test_mode),
        ParsingStage(event_emitter),
        ScriptGenerationStage(event_emitter),
        AudioGenerationStage(event_emitter),
        VideoGenerationStage(event_emitter),
        OutputStage(event_emitter),
    ])

    return orchestrator


# Convenience singleton
_default_pipeline: Optional[PipelineOrchestrator] = None


def get_pipeline() -> PipelineOrchestrator:
    """Get or create the default pipeline instance."""
    global _default_pipeline

    if _default_pipeline is None:
        _default_pipeline = create_complete_pipeline()

    return _default_pipeline


class CompletePipeline:
    """
    Complete Pipeline wrapper class for backward compatibility.

    This class wraps the create_complete_pipeline() factory function
    to provide a class-based interface that existing code expects.

    Usage:
        pipeline = CompletePipeline()
        result = await pipeline.run(config)

        # Or with custom configuration:
        pipeline = CompletePipeline(test_mode=True)
    """

    def __init__(
        self,
        state_manager: Optional[StateManager] = None,
        event_emitter: Optional[EventEmitter] = None,
        test_mode: bool = False
    ):
        """
        Initialize the complete pipeline with all 6 stages.

        Args:
            state_manager: Optional custom state manager
            event_emitter: Optional custom event emitter
            test_mode: If True, bypass security checks for testing
        """
        self._orchestrator = create_complete_pipeline(
            state_manager=state_manager,
            event_emitter=event_emitter,
            test_mode=test_mode
        )

    @property
    def orchestrator(self) -> PipelineOrchestrator:
        """Access the underlying PipelineOrchestrator."""
        return self._orchestrator

    @property
    def state_manager(self) -> StateManager:
        """Access the pipeline's state manager."""
        return self._orchestrator.state_manager

    @property
    def event_emitter(self) -> Optional[EventEmitter]:
        """Access the pipeline's event emitter."""
        return self._orchestrator.event_emitter

    async def run(self, config: dict) -> dict:
        """
        Execute the complete pipeline.

        Args:
            config: Pipeline configuration dictionary

        Returns:
            Pipeline result dictionary
        """
        return await self._orchestrator.execute(config)

    async def execute(self, config: dict) -> dict:
        """
        Execute the complete pipeline (alias for run).

        Args:
            config: Pipeline configuration dictionary

        Returns:
            Pipeline result dictionary
        """
        return await self._orchestrator.execute(config)

    def get_status(self) -> dict:
        """Get current pipeline status."""
        return {
            "stages": [stage.name for stage in self._orchestrator.stages],
            "state": self._orchestrator.state_manager.get_current_state()
        }

    def __repr__(self) -> str:
        return f"CompletePipeline(stages={len(self._orchestrator.stages)})"
