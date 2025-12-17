"""
State management for pipeline execution.

Handles task persistence, resume capability, and progress tracking.
Thread-safe with async locks and optimistic locking for parallel execution.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any
from ..shared.config import config
from ..shared.exceptions import StateError

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """Status of a pipeline task."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class StageState:
    """State of a single pipeline stage."""

    name: str
    status: TaskStatus = TaskStatus.PENDING
    progress: float = 0.0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    artifacts: Dict[str, str] = field(default_factory=dict)  # Generated files
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "status": self.status.value,
            "progress": self.progress,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error,
            "artifacts": self.artifacts,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StageState':
        """Create from dictionary."""
        return cls(
            name=data["name"],
            status=TaskStatus(data["status"]),
            progress=data["progress"],
            started_at=datetime.fromisoformat(data["started_at"]) if data["started_at"] else None,
            completed_at=datetime.fromisoformat(data["completed_at"]) if data["completed_at"] else None,
            error=data.get("error"),
            artifacts=data.get("artifacts", {}),
            metadata=data.get("metadata", {}),
        )


@dataclass
class TaskState:
    """
    Complete state of a pipeline task.

    Enables resume capability, progress tracking, and error recovery.
    Version tracking for optimistic locking in parallel execution.
    """

    task_id: str
    input_config: Dict[str, Any]
    status: TaskStatus = TaskStatus.PENDING
    current_stage: Optional[str] = None
    overall_progress: float = 0.0

    # Stage states
    stages: Dict[str, StageState] = field(default_factory=dict)

    # Timing
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Results and errors
    result: Optional[Dict[str, Any]] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Version for optimistic locking (prevents race conditions)
    version: int = 0

    def add_stage(self, stage_name: str):
        """Add a new stage to track."""
        if stage_name not in self.stages:
            self.stages[stage_name] = StageState(name=stage_name)

    def start_stage(self, stage_name: str):
        """Mark a stage as started."""
        self.add_stage(stage_name)
        self.stages[stage_name].status = TaskStatus.RUNNING
        self.stages[stage_name].started_at = datetime.now()
        self.stages[stage_name].progress = 0.0  # Ensure progress starts at 0
        self.current_stage = stage_name
        self._recalculate_overall_progress()  # Update overall progress

    def update_stage_progress(self, stage_name: str, progress: float):
        """Update progress for a stage."""
        if stage_name in self.stages:
            self.stages[stage_name].progress = min(1.0, max(0.0, progress))
            self._recalculate_overall_progress()

    def complete_stage(self, stage_name: str, artifacts: Dict[str, str] = None):
        """Mark a stage as completed."""
        if stage_name in self.stages:
            self.stages[stage_name].status = TaskStatus.COMPLETED
            self.stages[stage_name].progress = 1.0
            self.stages[stage_name].completed_at = datetime.now()
            if artifacts:
                self.stages[stage_name].artifacts.update(artifacts)
            self._recalculate_overall_progress()

    def fail_stage(self, stage_name: str, error: str):
        """Mark a stage as failed."""
        if stage_name in self.stages:
            self.stages[stage_name].status = TaskStatus.FAILED
            self.stages[stage_name].progress = 0.0  # Failed stages contribute 0 to progress
            self.stages[stage_name].error = error
            self.stages[stage_name].completed_at = datetime.now()  # Record end time
            self.errors.append(f"{stage_name}: {error}")
            self._recalculate_overall_progress()  # Update overall progress

    def _recalculate_overall_progress(self):
        """Recalculate overall progress based on stage progress."""
        if not self.stages:
            self.overall_progress = 0.0
            return

        total_progress = sum(stage.progress for stage in self.stages.values())
        self.overall_progress = total_progress / len(self.stages)

    def get_completed_stages(self) -> List[str]:
        """Get list of completed stage names."""
        return [
            name for name, stage in self.stages.items()
            if stage.status == TaskStatus.COMPLETED
        ]

    def get_failed_stages(self) -> List[str]:
        """Get list of failed stage names."""
        return [
            name for name, stage in self.stages.items()
            if stage.status == TaskStatus.FAILED
        ]

    def can_resume(self) -> bool:
        """Check if task can be resumed."""
        return (
            self.status in [TaskStatus.PAUSED, TaskStatus.FAILED]
            and len(self.get_completed_stages()) > 0
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        # Convert result to dict if it has to_dict method (for VideoConfig, etc.)
        result_value = self.result
        if result_value is not None and hasattr(result_value, 'to_dict'):
            result_value = result_value.to_dict()

        # Convert input_config items if they have to_dict method
        input_config_value = self.input_config
        if isinstance(input_config_value, dict):
            input_config_value = {}
            for key, val in self.input_config.items():
                if hasattr(val, 'to_dict'):
                    input_config_value[key] = val.to_dict()
                else:
                    input_config_value[key] = val
        elif hasattr(input_config_value, 'to_dict'):
            input_config_value = input_config_value.to_dict()

        return {
            "task_id": self.task_id,
            "input_config": input_config_value,
            "status": self.status.value,
            "current_stage": self.current_stage,
            "overall_progress": self.overall_progress,
            "stages": {name: stage.to_dict() for name, stage in self.stages.items()},
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "result": result_value,
            "errors": self.errors,
            "warnings": self.warnings,
            "metadata": self.metadata,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TaskState':
        """Create from dictionary."""
        return cls(
            task_id=data["task_id"],
            input_config=data["input_config"],
            status=TaskStatus(data["status"]),
            current_stage=data.get("current_stage"),
            overall_progress=data["overall_progress"],
            stages={
                name: StageState.from_dict(stage_data)
                for name, stage_data in data.get("stages", {}).items()
            },
            created_at=datetime.fromisoformat(data["created_at"]),
            started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else None,
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            result=data.get("result"),
            errors=data.get("errors", []),
            warnings=data.get("warnings", []),
            metadata=data.get("metadata", {}),
            version=data.get("version", 0),  # Backward compatible default
        )


class StateManager:
    """
    Manages persistence and retrieval of task states.

    Provides:
    - Thread-safe state persistence to disk with async locks
    - Optimistic locking to detect concurrent modifications
    - Atomic update operations for parallel stage execution
    - Resume capability
    - Progress tracking
    - Task querying

    Thread Safety:
    - Uses per-task asyncio.Lock to serialize access to state files
    - Version tracking detects conflicting concurrent updates
    - Atomic operations prevent partial state corruption
    """

    def __init__(self, state_dir: Optional[Path] = None):
        self.state_dir = state_dir or config.state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        # Per-task locks for thread-safe access
        self._locks: Dict[str, asyncio.Lock] = {}
        self._locks_lock = asyncio.Lock()  # Lock for the locks dict itself
        logger.info(f"State manager initialized: {self.state_dir}")

    def _get_state_file(self, task_id: str) -> Path:
        """Get path to state file for a task."""
        return self.state_dir / f"{task_id}.json"

    async def _get_lock(self, task_id: str) -> asyncio.Lock:
        """
        Get or create a lock for a specific task.

        Thread-safe creation of per-task locks.

        Args:
            task_id: Task identifier

        Returns:
            Asyncio lock for the task
        """
        async with self._locks_lock:
            if task_id not in self._locks:
                self._locks[task_id] = asyncio.Lock()
            return self._locks[task_id]

    def save(self, state: TaskState) -> Path:
        """
        Save task state to disk (synchronous wrapper for backward compatibility).

        For new code using parallel execution, use save_async() instead.

        Args:
            state: TaskState to save

        Returns:
            Path to saved state file

        Raises:
            StateError: If save fails
        """
        return self.save_sync(state)

    async def save_async(self, state: TaskState) -> Path:
        """
        Save task state to disk with thread-safe locking.

        Increments version number to enable optimistic locking.
        Uses per-task lock to prevent concurrent writes.

        Args:
            state: TaskState to save

        Returns:
            Path to saved state file

        Raises:
            StateError: If save fails
        """
        lock = await self._get_lock(state.task_id)
        async with lock:
            try:
                # Increment version for optimistic locking
                state.version += 1

                state_file = self._get_state_file(state.task_id)

                # Atomic write: write to temp file, then rename
                temp_file = state_file.with_suffix('.tmp')

                with open(temp_file, 'w') as f:
                    json.dump(state.to_dict(), f, indent=2)

                # Atomic rename (overwrites existing file)
                temp_file.replace(state_file)

                logger.debug(f"State saved: {state_file} (version {state.version})")
                return state_file

            except Exception as e:
                raise StateError(
                    f"Failed to save state: {e}",
                    details={"task_id": state.task_id}
                )

    def save_sync(self, state: TaskState) -> Path:
        """
        Synchronous wrapper for save_async() - runs in current or new event loop.

        WARNING: Not thread-safe for parallel execution! Use save_async() instead.

        Args:
            state: TaskState to save

        Returns:
            Path to saved state file
        """
        try:
            # Run in new event loop if needed
            try:
                loop = asyncio.get_running_loop()
                # If loop is running, create a new thread (fallback)
                import threading
                result = None
                error = None

                def run_save():
                    nonlocal result, error
                    try:
                        new_loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(new_loop)
                        result = new_loop.run_until_complete(self.save_async(state))
                        new_loop.close()
                    except Exception as e:
                        error = e

                thread = threading.Thread(target=run_save)
                thread.start()
                thread.join()

                if error:
                    raise error
                return result
            except RuntimeError:
                # No event loop running, create new one
                return asyncio.run(self.save_async(state))
        except Exception as e:
            raise StateError(
                f"Failed to save state: {e}",
                details={"task_id": state.task_id}
            )

    def load(self, task_id: str) -> TaskState:
        """
        Load task state from disk (synchronous wrapper for backward compatibility).

        For new code using parallel execution, use load_async() instead.

        Args:
            task_id: ID of task to load

        Returns:
            Loaded TaskState

        Raises:
            StateError: If load fails or state not found
        """
        return self.load_sync(task_id)

    async def load_async(self, task_id: str) -> TaskState:
        """
        Load task state from disk with thread-safe locking.

        Args:
            task_id: ID of task to load

        Returns:
            Loaded TaskState

        Raises:
            StateError: If load fails or state not found
        """
        lock = await self._get_lock(task_id)
        async with lock:
            try:
                state_file = self._get_state_file(task_id)

                if not state_file.exists():
                    raise StateError(
                        f"State not found: {task_id}",
                        details={"task_id": task_id}
                    )

                with open(state_file, 'r') as f:
                    data = json.load(f)

                state = TaskState.from_dict(data)
                logger.debug(f"State loaded: {state_file} (version {state.version})")
                return state

            except json.JSONDecodeError as e:
                raise StateError(
                    f"Invalid state file: {e}",
                    details={"task_id": task_id}
                )
            except Exception as e:
                raise StateError(
                    f"Failed to load state: {e}",
                    details={"task_id": task_id}
                )

    def load_sync(self, task_id: str) -> TaskState:
        """
        Synchronous wrapper for load_async() - runs in current or new event loop.

        WARNING: Not thread-safe for parallel execution! Use load_async() instead.

        Args:
            task_id: ID of task to load

        Returns:
            Loaded TaskState
        """
        try:
            try:
                loop = asyncio.get_running_loop()
                # If loop is running, create a new thread (fallback)
                import threading
                result = None
                error = None

                def run_load():
                    nonlocal result, error
                    try:
                        new_loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(new_loop)
                        result = new_loop.run_until_complete(self.load_async(task_id))
                        new_loop.close()
                    except Exception as e:
                        error = e

                thread = threading.Thread(target=run_load)
                thread.start()
                thread.join()

                if error:
                    raise error
                return result
            except RuntimeError:
                # No event loop running, create new one
                return asyncio.run(self.load_async(task_id))
        except Exception as e:
            raise StateError(
                f"Failed to load state: {e}",
                details={"task_id": task_id}
            )

    def exists(self, task_id: str) -> bool:
        """Check if state exists for a task."""
        return self._get_state_file(task_id).exists()

    def delete(self, task_id: str) -> bool:
        """
        Delete state for a task.

        Args:
            task_id: ID of task to delete

        Returns:
            True if deleted, False if not found
        """
        state_file = self._get_state_file(task_id)
        if state_file.exists():
            state_file.unlink()
            logger.info(f"State deleted: {task_id}")
            return True
        return False

    def list_tasks(self, status: Optional[TaskStatus] = None) -> List[TaskState]:
        """
        List all tasks, optionally filtered by status.

        Args:
            status: Optional status to filter by

        Returns:
            List of TaskState objects
        """
        tasks = []
        for state_file in self.state_dir.glob("*.json"):
            try:
                with open(state_file, 'r') as f:
                    data = json.load(f)
                state = TaskState.from_dict(data)

                if status is None or state.status == status:
                    tasks.append(state)
            except Exception as e:
                logger.warning(f"Failed to load state file {state_file}: {e}")

        return sorted(tasks, key=lambda s: s.created_at, reverse=True)

    def cleanup_old_tasks(self, days: int = 7):
        """
        Clean up task states older than specified days.

        Args:
            days: Number of days to keep
        """
        from datetime import timedelta
        cutoff = datetime.now() - timedelta(days=days)

        deleted = 0
        for state_file in self.state_dir.glob("*.json"):
            try:
                with open(state_file, 'r') as f:
                    data = json.load(f)
                created_at = datetime.fromisoformat(data["created_at"])

                if created_at < cutoff:
                    state_file.unlink()
                    deleted += 1
            except Exception as e:
                logger.warning(f"Error processing {state_file}: {e}")

        logger.info(f"Cleaned up {deleted} old task states")

    async def update_atomic(
        self,
        task_id: str,
        update_fn: callable,
        max_retries: int = 3
    ) -> TaskState:
        """
        Atomically update task state with optimistic locking.

        Loads state, applies update function, and saves with version check.
        Retries on version conflicts (other concurrent updates).

        Args:
            task_id: Task to update
            update_fn: Function that modifies TaskState (receives state, returns modified state)
            max_retries: Maximum retry attempts on version conflicts

        Returns:
            Updated TaskState

        Raises:
            StateError: If update fails after retries
        """
        for attempt in range(max_retries):
            try:
                # Load current state
                state = await self.load_async(task_id)
                original_version = state.version

                # Apply update function
                updated_state = update_fn(state)

                # Verify version hasn't changed (optimistic locking)
                current_state = await self.load_async(task_id)
                if current_state.version != original_version:
                    logger.warning(
                        f"Version conflict detected for {task_id} "
                        f"(expected {original_version}, got {current_state.version}). "
                        f"Retrying ({attempt + 1}/{max_retries})..."
                    )
                    await asyncio.sleep(0.1 * (attempt + 1))  # Exponential backoff
                    continue

                # Save updated state
                await self.save_async(updated_state)
                logger.debug(f"Atomic update succeeded for {task_id} (version {updated_state.version})")
                return updated_state

            except Exception as e:
                if attempt == max_retries - 1:
                    raise StateError(
                        f"Atomic update failed after {max_retries} attempts: {e}",
                        details={"task_id": task_id, "attempt": attempt + 1}
                    )
                logger.warning(f"Update attempt {attempt + 1} failed: {e}")
                await asyncio.sleep(0.1 * (attempt + 1))

        raise StateError(
            f"Atomic update failed after {max_retries} attempts",
            details={"task_id": task_id}
        )

    async def update_stage_progress_atomic(
        self,
        task_id: str,
        stage_name: str,
        progress: float,
        message: Optional[str] = None
    ):
        """
        Atomically update stage progress with retry logic.

        Safe for parallel execution - prevents race conditions.

        Args:
            task_id: Task identifier
            stage_name: Stage to update
            progress: Progress value (0.0 to 1.0)
            message: Optional progress message
        """
        def update(state: TaskState) -> TaskState:
            state.update_stage_progress(stage_name, progress)
            if message and stage_name in state.stages:
                state.stages[stage_name].metadata["message"] = message
            return state

        await self.update_atomic(task_id, update)

    async def complete_stage_atomic(
        self,
        task_id: str,
        stage_name: str,
        artifacts: Dict[str, str] = None
    ):
        """
        Atomically mark stage as completed.

        Safe for parallel execution.

        Args:
            task_id: Task identifier
            stage_name: Stage to complete
            artifacts: Generated artifacts
        """
        def update(state: TaskState) -> TaskState:
            state.complete_stage(stage_name, artifacts)
            return state

        await self.update_atomic(task_id, update)

    async def fail_stage_atomic(
        self,
        task_id: str,
        stage_name: str,
        error: str
    ):
        """
        Atomically mark stage as failed.

        Safe for parallel execution.

        Args:
            task_id: Task identifier
            stage_name: Stage that failed
            error: Error message
        """
        def update(state: TaskState) -> TaskState:
            state.fail_stage(stage_name, error)
            return state

        await self.update_atomic(task_id, update)
