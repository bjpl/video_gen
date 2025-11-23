"""
State management for pipeline execution.

Handles task persistence, resume capability, and progress tracking.
"""

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

    def add_stage(self, stage_name: str):
        """Add a new stage to track."""
        if stage_name not in self.stages:
            self.stages[stage_name] = StageState(name=stage_name)

    def start_stage(self, stage_name: str):
        """Mark a stage as started."""
        self.add_stage(stage_name)
        self.stages[stage_name].status = TaskStatus.RUNNING
        self.stages[stage_name].started_at = datetime.now()
        self.current_stage = stage_name

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
            self.stages[stage_name].error = error
            self.errors.append(f"{stage_name}: {error}")

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
        )


class StateManager:
    """
    Manages persistence and retrieval of task states.

    Provides:
    - State persistence to disk
    - Resume capability
    - Progress tracking
    - Task querying
    """

    def __init__(self, state_dir: Optional[Path] = None):
        self.state_dir = state_dir or config.state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"State manager initialized: {self.state_dir}")

    def _get_state_file(self, task_id: str) -> Path:
        """Get path to state file for a task."""
        return self.state_dir / f"{task_id}.json"

    def save(self, state: TaskState) -> Path:
        """
        Save task state to disk.

        Args:
            state: TaskState to save

        Returns:
            Path to saved state file

        Raises:
            StateError: If save fails
        """
        try:
            state_file = self._get_state_file(state.task_id)

            with open(state_file, 'w') as f:
                json.dump(state.to_dict(), f, indent=2)

            logger.debug(f"State saved: {state_file}")
            return state_file

        except Exception as e:
            raise StateError(
                f"Failed to save state: {e}",
                details={"task_id": state.task_id}
            )

    def load(self, task_id: str) -> TaskState:
        """
        Load task state from disk.

        Args:
            task_id: ID of task to load

        Returns:
            Loaded TaskState

        Raises:
            StateError: If load fails or state not found
        """
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
            logger.debug(f"State loaded: {state_file}")
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
