"""
Pipeline Orchestrator - Core execution engine.

Coordinates all stages of the video generation pipeline:
1. Input Adaptation
2. Content Parsing
3. Script Generation
4. Audio Generation
5. Video Generation
6. Output Handling
"""

import asyncio
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from .stage import Stage, StageResult
from .state_manager import StateManager, TaskState, TaskStatus
from .events import EventEmitter, Event, EventType, event_emitter as default_event_emitter
from ..shared.models import InputConfig, PipelineResult
from ..shared.config import config
from ..shared.exceptions import VideoGenError

logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """
    Orchestrates the complete video generation pipeline.

    Features:
    - Automatic progression through all stages
    - State persistence after each stage
    - Resume capability from failures
    - Progress tracking and event emission
    - Error recovery and retry logic
    - Async and sync execution modes
    """

    def __init__(
        self,
        state_manager: Optional[StateManager] = None,
        event_emitter: Optional[EventEmitter] = None
    ):
        self.state_manager = state_manager or StateManager()
        self.event_emitter = event_emitter or default_event_emitter
        self.stages: List[Stage] = []
        self.stage_map: Dict[str, Stage] = {}

        logger.info("Pipeline orchestrator initialized")

    def register_stage(self, stage: Stage):
        """
        Register a stage in the pipeline.

        Stages are executed in the order they are registered.

        Args:
            stage: Stage instance to register
        """
        self.stages.append(stage)
        self.stage_map[stage.name] = stage
        logger.debug(f"Registered stage: {stage.name}")

    def register_stages(self, stages: List[Stage]):
        """Register multiple stages at once."""
        for stage in stages:
            self.register_stage(stage)

    async def execute(
        self,
        input_config: InputConfig,
        task_id: Optional[str] = None,
        resume: bool = False
    ) -> PipelineResult:
        """
        Execute the complete pipeline.

        Args:
            input_config: Input configuration
            task_id: Optional task ID (auto-generated if not provided)
            resume: If True, resume from last completed stage

        Returns:
            PipelineResult with all outputs and metadata

        Raises:
            VideoGenError: If pipeline execution fails
        """
        # Generate or use provided task ID
        if task_id is None:
            task_id = f"task_{uuid.uuid4().hex[:12]}"

        logger.info(f"Starting pipeline execution: {task_id}")
        start_time = datetime.now()

        # Create or load task state
        if resume and self.state_manager.exists(task_id):
            task_state = self.state_manager.load(task_id)
            logger.info(f"Resuming task from stage: {task_state.current_stage}")
        else:
            task_state = TaskState(
                task_id=task_id,
                input_config=input_config.to_dict()
            )

        # Update state
        task_state.status = TaskStatus.RUNNING
        task_state.started_at = datetime.now()

        # Register all stages in state
        for stage in self.stages:
            task_state.add_stage(stage.name)

        # Save initial state
        self.state_manager.save(task_state)

        # Emit start event
        await self.event_emitter.emit(Event(
            type=EventType.PIPELINE_STARTED,
            task_id=task_id,
            message="Pipeline started",
            data=input_config.to_dict()
        ))

        # Shared context across stages
        context: Dict[str, Any] = {
            "task_id": task_id,
            "input_config": input_config,
            "config": config,
        }

        # Determine starting point for resume
        start_index = 0
        if resume and task_state.current_stage:
            completed_stages = task_state.get_completed_stages()
            if completed_stages:
                last_completed = completed_stages[-1]
                try:
                    start_index = self.stages.index(self.stage_map[last_completed]) + 1
                    logger.info(f"Resuming from stage index {start_index}")
                except (ValueError, KeyError):
                    logger.warning(f"Could not find stage {last_completed}, starting from beginning")

        # Execute stages
        all_results: List[StageResult] = []
        pipeline_success = True

        try:
            for i, stage in enumerate(self.stages[start_index:], start=start_index):
                logger.info(f"Executing stage {i+1}/{len(self.stages)}: {stage.name}")

                # Update state
                task_state.start_stage(stage.name)
                self.state_manager.save(task_state)

                # Execute stage
                result = await stage.run(context, task_id)
                all_results.append(result)

                if not result.success:
                    pipeline_success = False
                    task_state.fail_stage(stage.name, result.error)
                    self.state_manager.save(task_state)

                    logger.error(f"Stage {stage.name} failed: {result.error}")

                    # Check if we should continue or abort
                    if self._should_abort_on_failure(stage.name):
                        logger.error("Aborting pipeline due to critical failure")
                        break
                    else:
                        logger.warning("Continuing pipeline despite failure")
                        continue

                # Stage succeeded - update context and state
                context.update(result.artifacts)
                task_state.complete_stage(stage.name, {
                    k: str(v) if isinstance(v, Path) else str(v)
                    for k, v in result.artifacts.items()
                })
                task_state.warnings.extend(result.warnings)
                self.state_manager.save(task_state)

                logger.info(
                    f"Stage {stage.name} completed successfully "
                    f"({result.duration:.2f}s)"
                )

            # Pipeline completed
            end_time = datetime.now()
            total_duration = (end_time - start_time).total_seconds()

            # Update final state
            task_state.status = TaskStatus.COMPLETED if pipeline_success else TaskStatus.FAILED
            task_state.completed_at = end_time
            task_state.overall_progress = 1.0

            # Build result
            result = self._build_pipeline_result(
                task_id=task_id,
                success=pipeline_success,
                context=context,
                all_results=all_results,
                task_state=task_state,
                duration=total_duration
            )

            task_state.result = result.to_dict()
            self.state_manager.save(task_state)

            # Emit completion event
            await self.event_emitter.emit(Event(
                type=EventType.PIPELINE_COMPLETED if pipeline_success else EventType.PIPELINE_FAILED,
                task_id=task_id,
                message=f"Pipeline {'completed' if pipeline_success else 'failed'}",
                data={
                    "duration": total_duration,
                    "success": pipeline_success,
                    "stages_completed": len(task_state.get_completed_stages()),
                    "stages_failed": len(task_state.get_failed_stages()),
                }
            ))

            logger.info(
                f"Pipeline {'completed' if pipeline_success else 'failed'}: "
                f"{task_id} (duration: {total_duration:.2f}s)"
            )

            return result

        except Exception as e:
            # Unexpected error
            error_msg = f"Pipeline execution failed: {e}"
            logger.error(error_msg, exc_info=True)

            task_state.status = TaskStatus.FAILED
            task_state.errors.append(error_msg)
            self.state_manager.save(task_state)

            # Emit failure event
            await self.event_emitter.emit(Event(
                type=EventType.PIPELINE_FAILED,
                task_id=task_id,
                message=error_msg,
                data={"error": str(e)}
            ))

            raise VideoGenError(
                error_msg,
                details={
                    "task_id": task_id,
                    "current_stage": task_state.current_stage,
                    "completed_stages": task_state.get_completed_stages(),
                }
            )

    def execute_sync(
        self,
        input_config: InputConfig,
        task_id: Optional[str] = None,
        resume: bool = False
    ) -> PipelineResult:
        """
        Synchronous wrapper for execute().

        Args:
            input_config: Input configuration
            task_id: Optional task ID
            resume: If True, resume from last completed stage

        Returns:
            PipelineResult
        """
        return asyncio.run(self.execute(input_config, task_id, resume))

    async def execute_async(
        self,
        input_config: InputConfig,
        task_id: Optional[str] = None
    ) -> str:
        """
        Execute pipeline asynchronously in background.

        Returns task_id immediately and executes in background.

        Args:
            input_config: Input configuration
            task_id: Optional task ID

        Returns:
            Task ID for tracking
        """
        if task_id is None:
            task_id = f"task_{uuid.uuid4().hex[:12]}"

        # Create and track background task
        task = asyncio.create_task(self.execute(input_config, task_id))

        # Store task for potential cancellation
        if not hasattr(self, '_background_tasks'):
            self._background_tasks = {}
        self._background_tasks[task_id] = task

        # Clean up completed tasks
        def cleanup_callback(future):
            self._background_tasks.pop(task_id, None)
        task.add_done_callback(cleanup_callback)

        return task_id

    def get_status(self, task_id: str) -> Optional[TaskState]:
        """
        Get current status of a task.

        Args:
            task_id: Task ID to query

        Returns:
            TaskState or None if not found
        """
        if self.state_manager.exists(task_id):
            return self.state_manager.load(task_id)
        return None

    def cancel(self, task_id: str) -> bool:
        """
        Cancel a running task.

        Args:
            task_id: Task ID to cancel

        Returns:
            True if cancelled, False if not found or already completed
        """
        if not self.state_manager.exists(task_id):
            return False

        task_state = self.state_manager.load(task_id)

        if task_state.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
            return False

        task_state.status = TaskStatus.CANCELLED
        self.state_manager.save(task_state)

        logger.info(f"Task cancelled: {task_id}")
        return True

    def _should_abort_on_failure(self, stage_name: str) -> bool:
        """
        Determine if pipeline should abort on stage failure.

        Args:
            stage_name: Name of failed stage

        Returns:
            True if should abort, False if should continue
        """
        # Critical stages that should abort pipeline
        critical_stages = [
            "input_adaptation",
            "content_parsing",
            "audio_generation",
        ]

        return stage_name in critical_stages

    def _build_pipeline_result(
        self,
        task_id: str,
        success: bool,
        context: Dict[str, Any],
        all_results: List[StageResult],
        task_state: TaskState,
        duration: float
    ) -> PipelineResult:
        """Build final PipelineResult from execution context."""

        # Extract video config from context
        video_config = context.get("video_config")

        # Build result
        return PipelineResult(
            success=success,
            task_id=task_id,
            video_config=video_config,
            video_path=context.get("final_video_path"),
            audio_dir=context.get("audio_dir"),
            timing_report=context.get("timing_report"),
            total_duration=video_config.total_duration if video_config else 0.0,
            scene_count=len(video_config.scenes) if video_config else 0,
            generation_time=duration,
            timestamp=datetime.now(),
            errors=task_state.errors,
            warnings=task_state.warnings,
        )

    def list_tasks(self, status: Optional[TaskStatus] = None) -> List[TaskState]:
        """
        List all tasks, optionally filtered by status.

        Args:
            status: Optional status filter

        Returns:
            List of TaskState objects
        """
        return self.state_manager.list_tasks(status)

    def cleanup_old_tasks(self, days: int = 7):
        """
        Clean up task states older than specified days.

        Args:
            days: Number of days to keep
        """
        self.state_manager.cleanup_old_tasks(days)
