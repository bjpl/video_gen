"""
Base stage class for pipeline execution.

All pipeline stages inherit from this base class.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional

from .events import EventEmitter, Event, EventType
from ..shared.exceptions import StageError

# Forward reference for type hints
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .state_manager import StateManager

logger = logging.getLogger(__name__)


@dataclass
class StageResult:
    """Result from a stage execution."""

    success: bool
    stage_name: str
    duration: float = 0.0
    artifacts: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    warnings: list = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "success": self.success,
            "stage_name": self.stage_name,
            "duration": self.duration,
            "artifacts": self.artifacts,
            "metadata": self.metadata,
            "error": self.error,
            "warnings": self.warnings,
        }


class Stage(ABC):
    """
    Base class for all pipeline stages.

    Provides:
    - Consistent execution interface
    - Progress tracking
    - Error handling
    - Event emission
    - Logging
    - State persistence for SSE progress updates
    """

    def __init__(self, name: str, event_emitter: Optional[EventEmitter] = None):
        self.name = name
        self.event_emitter = event_emitter
        self.logger = logging.getLogger(f"{__name__}.{name}")
        # State management for progress persistence (set by orchestrator)
        self._state_manager: Optional['StateManager'] = None
        self._task_id: Optional[str] = None

    def set_state_manager(self, state_manager: 'StateManager', task_id: str):
        """Set state manager for progress persistence."""
        self._state_manager = state_manager
        self._task_id = task_id

    @abstractmethod
    async def execute(self, context: Dict[str, Any]) -> StageResult:
        """
        Execute the stage.

        Args:
            context: Shared context containing all data from previous stages

        Returns:
            StageResult with artifacts and metadata

        Raises:
            StageError: If stage execution fails
        """

    async def run(self, context: Dict[str, Any], task_id: str) -> StageResult:
        """
        Run the stage with full error handling and event emission.

        This is the main entry point - don't override unless you know what you're doing.

        Args:
            context: Shared context
            task_id: ID of the current task

        Returns:
            StageResult
        """
        start_time = datetime.now()
        self.logger.info(f"Starting stage: {self.name}")

        # Emit start event
        if self.event_emitter:
            await self.event_emitter.emit(Event(
                type=EventType.STAGE_STARTED,
                task_id=task_id,
                stage=self.name,
                progress=0.0,
                message=f"Starting {self.name}"
            ))

        try:
            # Execute the stage
            result = await self.execute(context)

            # Calculate duration
            end_time = datetime.now()
            result.duration = (end_time - start_time).total_seconds()

            # Log warnings
            for warning in result.warnings:
                self.logger.warning(f"{self.name}: {warning}")

            # Emit completion event
            if self.event_emitter:
                await self.event_emitter.emit(Event(
                    type=EventType.STAGE_COMPLETED,
                    task_id=task_id,
                    stage=self.name,
                    progress=1.0,
                    message=f"Completed {self.name}",
                    data=result.metadata
                ))

            self.logger.info(
                f"Completed stage: {self.name} "
                f"(duration: {result.duration:.2f}s, "
                f"artifacts: {len(result.artifacts)})"
            )

            return result

        except Exception as e:
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            error_msg = f"{self.name} failed: {str(e)}"
            self.logger.error(error_msg, exc_info=True)

            # Emit failure event
            if self.event_emitter:
                await self.event_emitter.emit(Event(
                    type=EventType.STAGE_FAILED,
                    task_id=task_id,
                    stage=self.name,
                    message=error_msg,
                    data={"error": str(e)}
                ))

            # Return failed result
            return StageResult(
                success=False,
                stage_name=self.name,
                duration=duration,
                error=str(e)
            )

    async def emit_progress(self, task_id: str, progress: float, message: str = None):
        """
        Emit progress update event and persist to state manager atomically.

        This ensures progress is visible in SSE stream (which polls state files).
        Uses atomic updates to prevent race conditions in parallel execution.

        Args:
            task_id: Current task ID
            progress: Progress value (0.0 to 1.0)
            message: Optional progress message
        """
        # Persist progress to state manager for SSE polling using atomic operation
        if self._state_manager:
            try:
                await self._state_manager.update_stage_progress_atomic(
                    task_id=task_id,
                    stage_name=self.name,
                    progress=progress,
                    message=message
                )
                self.logger.debug(f"Progress persisted: {self.name}={progress:.1%} ({message})")
            except Exception as e:
                self.logger.warning(f"Failed to persist progress: {e}")

        # Also emit event (for any listeners)
        if self.event_emitter:
            await self.event_emitter.emit(Event(
                type=EventType.STAGE_PROGRESS,
                task_id=task_id,
                stage=self.name,
                progress=progress,
                message=message or f"{self.name}: {progress:.0%}"
            ))

    def validate_context(self, context: Dict[str, Any], required_keys: list):
        """
        Validate that required keys exist in context.

        Args:
            context: Context dictionary
            required_keys: List of required key names

        Raises:
            StageError: If required keys are missing
        """
        missing_keys = [key for key in required_keys if key not in context]
        if missing_keys:
            raise StageError(
                f"{self.name}: Missing required context keys: {missing_keys}",
                stage=self.name,
                details={"missing_keys": missing_keys}
            )

    async def run_subprocess(self, cmd: list, cwd: str = None) -> tuple[str, str, int]:
        """
        Run a subprocess asynchronously.

        Args:
            cmd: Command and arguments as list
            cwd: Working directory

        Returns:
            Tuple of (stdout, stderr, returncode)

        Raises:
            StageError: If subprocess fails
        """
        self.logger.debug(f"Running command: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd
            )

            stdout, stderr = await process.communicate()

            return (
                stdout.decode() if stdout else "",
                stderr.decode() if stderr else "",
                process.returncode
            )

        except Exception as e:
            raise StageError(
                f"Subprocess failed: {e}",
                stage=self.name,
                details={"command": cmd}
            )
