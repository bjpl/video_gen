# State Management Specification

**Version:** 1.0
**Status:** Design Phase
**Last Updated:** 2025-10-04

---

## Table of Contents

1. [Overview](#overview)
2. [Requirements](#requirements)
3. [Task State Model](#task-state-model)
4. [Storage Backend](#storage-backend)
5. [StateManager Implementation](#statemanager-implementation)
6. [Checkpoint & Resume](#checkpoint--resume)
7. [Audit Trail](#audit-trail)
8. [Artifact Management](#artifact-management)
9. [API Reference](#api-reference)

---

## Overview

### Purpose

The State Management system provides:
- **Task persistence** across pipeline stages
- **Resume capability** after failures or interruptions
- **Audit trail** of all operations
- **Artifact tracking** for generated files
- **Progress monitoring** for real-time updates

### Key Features

| Feature | Description |
|---------|-------------|
| **Persistence** | Task state saved to disk (JSON or SQLite) |
| **Resume** | Continue from last completed stage |
| **Rollback** | Revert to previous checkpoint |
| **Audit Log** | Complete history of state changes |
| **Artifact Tracking** | Track all generated files |
| **Concurrent Access** | Thread-safe operations |

---

## Requirements

### Functional Requirements

1. **Task Creation**
   - Create new task with unique ID
   - Store input configuration
   - Initialize empty stage list

2. **State Persistence**
   - Save task state after each stage
   - Store stage outputs as checkpoints
   - Maintain artifacts registry

3. **Resume Capability**
   - Restore task from any checkpoint
   - Determine next stage to execute
   - Preserve all previous outputs

4. **Progress Tracking**
   - Calculate overall progress (0-100%)
   - Track current stage
   - Estimate time remaining

5. **Error Handling**
   - Store error details
   - Support retry attempts
   - Track failure reasons

6. **Cleanup**
   - Archive completed tasks
   - Remove failed tasks (optional)
   - Clean up temporary artifacts

### Non-Functional Requirements

1. **Performance**
   - State save/load < 100ms
   - Support 1000+ tasks
   - Minimal memory footprint

2. **Reliability**
   - Atomic state updates
   - No data loss on crash
   - Graceful degradation

3. **Scalability**
   - Support concurrent tasks
   - Handle large artifacts (GB files)
   - Efficient querying

---

## Task State Model

### Core Models

```python
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
from pathlib import Path

class TaskStatus(str, Enum):
    """Task status states"""
    PENDING = "pending"      # Created but not started
    RUNNING = "running"      # Currently executing
    PAUSED = "paused"        # Manually paused
    COMPLETED = "completed"  # Successfully finished
    FAILED = "failed"        # Failed after retries
    CANCELLED = "cancelled"  # Cancelled by user

class StageStatus(str, Enum):
    """Stage status states"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

@dataclass
class StageResult:
    """Result from a single stage execution"""
    name: str
    status: StageStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    output: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    retry_count: int = 0
    artifacts: List[Path] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        return {
            "name": self.name,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "output": self.output,
            "error": self.error,
            "retry_count": self.retry_count,
            "artifacts": [str(p) for p in self.artifacts]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StageResult':
        """Deserialize from dictionary"""
        return cls(
            name=data["name"],
            status=StageStatus(data["status"]),
            started_at=datetime.fromisoformat(data["started_at"]),
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            duration_seconds=data.get("duration_seconds", 0.0),
            output=data.get("output", {}),
            error=data.get("error"),
            retry_count=data.get("retry_count", 0),
            artifacts=[Path(p) for p in data.get("artifacts", [])]
        )

@dataclass
class Task:
    """Complete task state"""
    id: str
    status: TaskStatus
    input_config: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    stages: List[StageResult] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None

    @property
    def is_new(self) -> bool:
        """Check if task has never been executed"""
        return len(self.stages) == 0

    @property
    def current_stage(self) -> Optional[str]:
        """Get name of current stage"""
        for stage in reversed(self.stages):
            if stage.status == StageStatus.RUNNING:
                return stage.name
        return None

    @property
    def last_completed_stage(self) -> Optional[str]:
        """Get name of last completed stage"""
        for stage in reversed(self.stages):
            if stage.status == StageStatus.COMPLETED:
                return stage.name
        return None

    @property
    def progress(self) -> float:
        """Calculate overall progress (0.0 - 1.0)"""
        if not self.stages:
            return 0.0

        completed = sum(
            1 for s in self.stages
            if s.status == StageStatus.COMPLETED
        )
        total = len(self.stages)

        # Add partial progress for current stage
        current = self.current_stage
        if current:
            # Assume current stage is 50% done
            return (completed + 0.5) / total

        return completed / total if total > 0 else 0.0

    @property
    def total_duration(self) -> float:
        """Total execution time in seconds"""
        return sum(s.duration_seconds for s in self.stages)

    @property
    def all_artifacts(self) -> List[Path]:
        """Get all artifacts from all stages"""
        artifacts = []
        for stage in self.stages:
            artifacts.extend(stage.artifacts)
        return artifacts

    def get_stage(self, name: str) -> Optional[StageResult]:
        """Get stage by name"""
        for stage in self.stages:
            if stage.name == name:
                return stage
        return None

    def add_stage_result(self, result: StageResult):
        """Add or update stage result"""
        # Remove existing stage with same name
        self.stages = [
            s for s in self.stages if s.name != result.name
        ]
        # Add new result
        self.stages.append(result)
        self.updated_at = datetime.now()

    def get_input_for_stage(self, stage_name: str) -> Dict[str, Any]:
        """Get input data for a specific stage"""
        # Find previous stage
        prev_index = -1
        for i, s in enumerate(self.stages):
            if s.name == stage_name:
                prev_index = i - 1
                break

        if prev_index >= 0:
            # Use output from previous stage
            return self.stages[prev_index].output
        else:
            # First stage uses input config
            return self.input_config

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        return {
            "id": self.id,
            "status": self.status.value,
            "input_config": self.input_config,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "stages": [s.to_dict() for s in self.stages],
            "metadata": self.metadata,
            "error": self.error,
            "result": self.result
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Task':
        """Deserialize from dictionary"""
        return cls(
            id=data["id"],
            status=TaskStatus(data["status"]),
            input_config=data["input_config"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            stages=[StageResult.from_dict(s) for s in data.get("stages", [])],
            metadata=data.get("metadata", {}),
            error=data.get("error"),
            result=data.get("result")
        )
```

### State Transitions

```
Task State Machine:

                    ┌─────────┐
                    │ PENDING │ (initial)
                    └────┬────┘
                         │
                         │ start execution
                         ▼
                    ┌─────────┐
           ┌────────│ RUNNING │────────┐
           │        └─────────┘        │
           │                           │
    user pauses                   stage fails
           │                           │
           ▼                           ▼
      ┌────────┐                  ┌────────┐
      │ PAUSED │                  │ FAILED │
      └────┬───┘                  └────┬───┘
           │                           │
      user resumes               user retries
           │                           │
           └────────┐         ┌────────┘
                    │         │
                    ▼         ▼
                ┌──────────────┐
                │   RUNNING    │
                └──────┬───────┘
                       │
                  all stages OK
                       │
                       ▼
                ┌────────────┐
                │ COMPLETED  │ (terminal)
                └────────────┘

Stage State Machine:

   ┌─────────┐
   │ PENDING │ (initial)
   └────┬────┘
        │
        │ stage starts
        ▼
   ┌─────────┐
   │ RUNNING │
   └────┬────┘
        │
   ┌────┴────┐
   │         │
success    failure
   │         │
   ▼         ▼
┌──────┐  ┌────────┐
│ DONE │  │ FAILED │
└──────┘  └────┬───┘
              │
         retry logic
              │
              ▼
         ┌─────────┐
         │ RUNNING │
         └─────────┘
```

---

## Storage Backend

### Interface

```python
from abc import ABC, abstractmethod

class StorageBackend(ABC):
    """Abstract storage backend interface"""

    @abstractmethod
    async def save_task(self, task: Task) -> None:
        """Save task state"""
        pass

    @abstractmethod
    async def load_task(self, task_id: str) -> Optional[Task]:
        """Load task state"""
        pass

    @abstractmethod
    async def delete_task(self, task_id: str) -> None:
        """Delete task state"""
        pass

    @abstractmethod
    async def list_tasks(
        self,
        status: Optional[TaskStatus] = None,
        limit: int = 100
    ) -> List[Task]:
        """List tasks with optional filtering"""
        pass

    @abstractmethod
    async def task_exists(self, task_id: str) -> bool:
        """Check if task exists"""
        pass
```

### JSON File Backend

```python
import json
import aiofiles
from pathlib import Path

class JSONStorageBackend(StorageBackend):
    """JSON file-based storage backend"""

    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.base_path.mkdir(parents=True, exist_ok=True)

    def _task_path(self, task_id: str) -> Path:
        """Get file path for task"""
        return self.base_path / f"{task_id}.json"

    async def save_task(self, task: Task) -> None:
        """Save task to JSON file"""
        path = self._task_path(task.id)

        # Atomic write using temp file
        temp_path = path.with_suffix('.tmp')

        async with aiofiles.open(temp_path, 'w') as f:
            await f.write(
                json.dumps(
                    task.to_dict(),
                    indent=2,
                    default=str
                )
            )

        # Atomic rename
        temp_path.replace(path)

    async def load_task(self, task_id: str) -> Optional[Task]:
        """Load task from JSON file"""
        path = self._task_path(task_id)

        if not path.exists():
            return None

        async with aiofiles.open(path, 'r') as f:
            data = json.loads(await f.read())
            return Task.from_dict(data)

    async def delete_task(self, task_id: str) -> None:
        """Delete task file"""
        path = self._task_path(task_id)
        if path.exists():
            path.unlink()

    async def list_tasks(
        self,
        status: Optional[TaskStatus] = None,
        limit: int = 100
    ) -> List[Task]:
        """List tasks from directory"""
        tasks = []

        for path in self.base_path.glob("*.json"):
            task = await self.load_task(path.stem)
            if task:
                if status is None or task.status == status:
                    tasks.append(task)

                if len(tasks) >= limit:
                    break

        # Sort by updated_at (most recent first)
        tasks.sort(key=lambda t: t.updated_at, reverse=True)
        return tasks

    async def task_exists(self, task_id: str) -> bool:
        """Check if task file exists"""
        return self._task_path(task_id).exists()
```

### SQLite Backend (Optional)

```python
import aiosqlite
from typing import Optional, List

class SQLiteStorageBackend(StorageBackend):
    """SQLite-based storage backend"""

    def __init__(self, db_path: Path):
        self.db_path = db_path

    async def initialize(self):
        """Create tables if they don't exist"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    input_config TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    stages TEXT,
                    metadata TEXT,
                    error TEXT,
                    result TEXT
                )
            """)
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_status
                ON tasks(status)
            """)
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_updated
                ON tasks(updated_at DESC)
            """)
            await db.commit()

    async def save_task(self, task: Task) -> None:
        """Save task to database"""
        async with aiosqlite.connect(self.db_path) as db:
            data = task.to_dict()
            await db.execute(
                """
                INSERT OR REPLACE INTO tasks
                (id, status, input_config, created_at, updated_at,
                 stages, metadata, error, result)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["id"],
                    data["status"],
                    json.dumps(data["input_config"]),
                    data["created_at"],
                    data["updated_at"],
                    json.dumps(data.get("stages", [])),
                    json.dumps(data.get("metadata", {})),
                    data.get("error"),
                    json.dumps(data.get("result")) if data.get("result") else None
                )
            )
            await db.commit()

    async def load_task(self, task_id: str) -> Optional[Task]:
        """Load task from database"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM tasks WHERE id = ?",
                (task_id,)
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None

                # Convert row to dict
                data = dict(row)
                # Parse JSON fields
                data["input_config"] = json.loads(data["input_config"])
                data["stages"] = json.loads(data["stages"]) if data["stages"] else []
                data["metadata"] = json.loads(data["metadata"]) if data["metadata"] else {}
                data["result"] = json.loads(data["result"]) if data["result"] else None

                return Task.from_dict(data)

    async def list_tasks(
        self,
        status: Optional[TaskStatus] = None,
        limit: int = 100
    ) -> List[Task]:
        """List tasks with optional filtering"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            if status:
                query = """
                    SELECT * FROM tasks
                    WHERE status = ?
                    ORDER BY updated_at DESC
                    LIMIT ?
                """
                params = (status.value, limit)
            else:
                query = """
                    SELECT * FROM tasks
                    ORDER BY updated_at DESC
                    LIMIT ?
                """
                params = (limit,)

            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                tasks = []
                for row in rows:
                    data = dict(row)
                    data["input_config"] = json.loads(data["input_config"])
                    data["stages"] = json.loads(data["stages"]) if data["stages"] else []
                    data["metadata"] = json.loads(data["metadata"]) if data["metadata"] else {}
                    data["result"] = json.loads(data["result"]) if data["result"] else None
                    tasks.append(Task.from_dict(data))
                return tasks
```

---

## StateManager Implementation

### Core StateManager

```python
class StateManager:
    """
    Manages task state persistence and recovery.
    """

    def __init__(
        self,
        storage: StorageBackend,
        artifact_dir: Path
    ):
        self.storage = storage
        self.artifact_dir = artifact_dir
        self.artifact_dir.mkdir(parents=True, exist_ok=True)

    def _generate_task_id(self) -> str:
        """Generate unique task ID"""
        import uuid
        return f"task_{uuid.uuid4().hex[:12]}"

    def _task_artifact_dir(self, task_id: str) -> Path:
        """Get artifact directory for task"""
        return self.artifact_dir / task_id

    async def create_task(
        self,
        input_config: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> Task:
        """Create a new task"""
        task = Task(
            id=self._generate_task_id(),
            status=TaskStatus.PENDING,
            input_config=input_config,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            metadata=metadata or {}
        )

        # Create artifact directory
        self._task_artifact_dir(task.id).mkdir(
            parents=True,
            exist_ok=True
        )

        # Save initial state
        await self.storage.save_task(task)

        return task

    async def restore_task(self, task_id: str) -> Task:
        """Restore task from storage"""
        task = await self.storage.load_task(task_id)

        if not task:
            raise TaskNotFoundError(
                f"Task {task_id} not found"
            )

        return task

    async def start_task(self, task_id: str):
        """Mark task as running"""
        task = await self.restore_task(task_id)
        task.status = TaskStatus.RUNNING
        task.updated_at = datetime.now()
        await self.storage.save_task(task)

    async def start_stage(
        self,
        task_id: str,
        stage_name: str
    ):
        """Mark stage as started"""
        task = await self.restore_task(task_id)

        # Create or update stage result
        stage = task.get_stage(stage_name)
        if not stage:
            stage = StageResult(
                name=stage_name,
                status=StageStatus.RUNNING,
                started_at=datetime.now()
            )
            task.add_stage_result(stage)
        else:
            stage.status = StageStatus.RUNNING
            stage.started_at = datetime.now()

        await self.storage.save_task(task)

    async def complete_stage(
        self,
        task_id: str,
        stage_name: str,
        output: Dict[str, Any],
        artifacts: List[Path] = None
    ):
        """Mark stage as completed"""
        task = await self.restore_task(task_id)

        stage = task.get_stage(stage_name)
        if stage:
            stage.status = StageStatus.COMPLETED
            stage.completed_at = datetime.now()
            stage.duration_seconds = (
                stage.completed_at - stage.started_at
            ).total_seconds()
            stage.output = output
            stage.artifacts = artifacts or []

        await self.storage.save_task(task)

    async def fail_stage(
        self,
        task_id: str,
        stage_name: str,
        error: str
    ):
        """Mark stage as failed"""
        task = await self.restore_task(task_id)

        stage = task.get_stage(stage_name)
        if stage:
            stage.status = StageStatus.FAILED
            stage.completed_at = datetime.now()
            stage.duration_seconds = (
                stage.completed_at - stage.started_at
            ).total_seconds()
            stage.error = error

        await self.storage.save_task(task)

    async def complete_task(
        self,
        task_id: str,
        result: Optional[Dict[str, Any]] = None
    ):
        """Mark task as completed"""
        task = await self.restore_task(task_id)
        task.status = TaskStatus.COMPLETED
        task.updated_at = datetime.now()
        task.result = result
        await self.storage.save_task(task)

    async def fail_task(
        self,
        task_id: str,
        error: str
    ):
        """Mark task as failed"""
        task = await self.restore_task(task_id)
        task.status = TaskStatus.FAILED
        task.updated_at = datetime.now()
        task.error = error
        await self.storage.save_task(task)

    async def get_task_status(
        self,
        task_id: str
    ) -> Dict[str, Any]:
        """Get task status summary"""
        task = await self.restore_task(task_id)

        return {
            "task_id": task.id,
            "status": task.status.value,
            "progress": task.progress,
            "current_stage": task.current_stage,
            "created_at": task.created_at.isoformat(),
            "updated_at": task.updated_at.isoformat(),
            "duration": task.total_duration,
            "error": task.error
        }

    async def list_tasks(
        self,
        status: Optional[TaskStatus] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """List tasks with status summary"""
        tasks = await self.storage.list_tasks(status, limit)

        return [
            {
                "task_id": t.id,
                "status": t.status.value,
                "progress": t.progress,
                "created_at": t.created_at.isoformat(),
                "updated_at": t.updated_at.isoformat()
            }
            for t in tasks
        ]

    async def cleanup_task(
        self,
        task_id: str,
        keep_artifacts: bool = False
    ):
        """Clean up task and optionally its artifacts"""
        # Delete task state
        await self.storage.delete_task(task_id)

        # Delete artifacts if requested
        if not keep_artifacts:
            artifact_dir = self._task_artifact_dir(task_id)
            if artifact_dir.exists():
                shutil.rmtree(artifact_dir)
```

---

## Checkpoint & Resume

### Resume Logic

```python
class ResumeManager:
    """Handle checkpoint and resume logic"""

    def __init__(self, state_manager: StateManager):
        self.state = state_manager

    async def can_resume(self, task_id: str) -> bool:
        """Check if task can be resumed"""
        task = await self.state.restore_task(task_id)

        # Can resume if:
        # - Task failed or paused
        # - At least one stage completed
        return (
            task.status in [TaskStatus.FAILED, TaskStatus.PAUSED]
            and len([s for s in task.stages if s.status == StageStatus.COMPLETED]) > 0
        )

    async def get_resume_point(
        self,
        task_id: str
    ) -> Optional[str]:
        """Determine which stage to resume from"""
        task = await self.state.restore_task(task_id)

        # Find last completed stage
        last_completed = task.last_completed_stage

        if not last_completed:
            # No completed stages, start from beginning
            return None

        # Resume from next stage
        stage_names = [s.name for s in task.stages]
        last_index = stage_names.index(last_completed)

        if last_index + 1 < len(stage_names):
            return stage_names[last_index + 1]
        else:
            # All stages completed
            return None

    async def create_checkpoint(
        self,
        task_id: str,
        checkpoint_name: str
    ) -> Path:
        """Create a named checkpoint"""
        task = await self.state.restore_task(task_id)

        # Create checkpoint file
        checkpoint_dir = self.state.artifact_dir / task_id / "checkpoints"
        checkpoint_dir.mkdir(parents=True, exist_ok=True)

        checkpoint_file = checkpoint_dir / f"{checkpoint_name}.json"

        async with aiofiles.open(checkpoint_file, 'w') as f:
            await f.write(
                json.dumps(
                    task.to_dict(),
                    indent=2,
                    default=str
                )
            )

        return checkpoint_file

    async def restore_checkpoint(
        self,
        task_id: str,
        checkpoint_name: str
    ) -> Task:
        """Restore from a named checkpoint"""
        checkpoint_file = (
            self.state.artifact_dir /
            task_id /
            "checkpoints" /
            f"{checkpoint_name}.json"
        )

        if not checkpoint_file.exists():
            raise ValueError(
                f"Checkpoint {checkpoint_name} not found"
            )

        async with aiofiles.open(checkpoint_file, 'r') as f:
            data = json.loads(await f.read())
            task = Task.from_dict(data)

        # Save restored task
        await self.state.storage.save_task(task)

        return task
```

---

## Audit Trail

### Audit Log

```python
@dataclass
class AuditEntry:
    """Single audit log entry"""
    timestamp: datetime
    task_id: str
    event_type: str
    details: Dict[str, Any]
    user: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "task_id": self.task_id,
            "event_type": self.event_type,
            "details": self.details,
            "user": self.user
        }

class AuditLogger:
    """Track all state changes"""

    def __init__(self, log_file: Path):
        self.log_file = log_file

    async def log(
        self,
        task_id: str,
        event_type: str,
        details: Dict[str, Any],
        user: Optional[str] = None
    ):
        """Log an audit entry"""
        entry = AuditEntry(
            timestamp=datetime.now(),
            task_id=task_id,
            event_type=event_type,
            details=details,
            user=user
        )

        # Append to log file
        async with aiofiles.open(self.log_file, 'a') as f:
            await f.write(
                json.dumps(entry.to_dict()) + "\n"
            )

    async def get_audit_trail(
        self,
        task_id: str
    ) -> List[AuditEntry]:
        """Get complete audit trail for task"""
        entries = []

        async with aiofiles.open(self.log_file, 'r') as f:
            async for line in f:
                data = json.loads(line)
                if data["task_id"] == task_id:
                    entry = AuditEntry(
                        timestamp=datetime.fromisoformat(data["timestamp"]),
                        task_id=data["task_id"],
                        event_type=data["event_type"],
                        details=data["details"],
                        user=data.get("user")
                    )
                    entries.append(entry)

        return entries
```

---

## Artifact Management

### Artifact Tracker

```python
class ArtifactManager:
    """Track and manage generated artifacts"""

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir

    def register_artifact(
        self,
        task_id: str,
        stage: str,
        artifact_path: Path,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Register a new artifact"""
        artifact_info = {
            "path": str(artifact_path),
            "stage": stage,
            "size_bytes": artifact_path.stat().st_size,
            "created_at": datetime.now().isoformat(),
            "metadata": metadata or {}
        }

        # Save artifact registry
        registry_path = self.base_dir / task_id / "artifacts.json"

        if registry_path.exists():
            with open(registry_path, 'r') as f:
                registry = json.load(f)
        else:
            registry = []

        registry.append(artifact_info)

        with open(registry_path, 'w') as f:
            json.dump(registry, f, indent=2)

        return artifact_info

    def get_artifacts(
        self,
        task_id: str,
        stage: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get artifacts for task"""
        registry_path = self.base_dir / task_id / "artifacts.json"

        if not registry_path.exists():
            return []

        with open(registry_path, 'r') as f:
            registry = json.load(f)

        if stage:
            return [
                a for a in registry
                if a["stage"] == stage
            ]

        return registry

    def cleanup_artifacts(
        self,
        task_id: str,
        keep_final: bool = True
    ):
        """Clean up task artifacts"""
        artifacts = self.get_artifacts(task_id)

        for artifact in artifacts:
            # Keep final output if requested
            if keep_final and artifact.get("stage") == "output":
                continue

            path = Path(artifact["path"])
            if path.exists():
                path.unlink()
```

---

## API Reference

### StateManager Methods

```python
# Task creation
async def create_task(input_config: Dict, metadata: Dict = None) -> Task

# Task retrieval
async def restore_task(task_id: str) -> Task
async def get_task_status(task_id: str) -> Dict
async def list_tasks(status: TaskStatus = None, limit: int = 100) -> List[Dict]

# Task state updates
async def start_task(task_id: str)
async def complete_task(task_id: str, result: Dict = None)
async def fail_task(task_id: str, error: str)

# Stage state updates
async def start_stage(task_id: str, stage_name: str)
async def complete_stage(task_id: str, stage_name: str, output: Dict, artifacts: List[Path] = None)
async def fail_stage(task_id: str, stage_name: str, error: str)

# Cleanup
async def cleanup_task(task_id: str, keep_artifacts: bool = False)
```

### Usage Example

```python
# Initialize
storage = JSONStorageBackend(Path(".video-gen/tasks"))
state_manager = StateManager(storage, Path(".video-gen/artifacts"))

# Create task
task = await state_manager.create_task(
    input_config={"source": "README.md"},
    metadata={"user": "john"}
)

# Execute stages
await state_manager.start_task(task.id)

await state_manager.start_stage(task.id, "input")
# ... execute stage ...
await state_manager.complete_stage(
    task.id,
    "input",
    output={"video_config": {...}},
    artifacts=[Path("input.yaml")]
)

# Complete task
await state_manager.complete_task(
    task.id,
    result={"video_path": "output.mp4"}
)

# Later: Resume from checkpoint
task = await state_manager.restore_task(task.id)
resume_manager = ResumeManager(state_manager)
next_stage = await resume_manager.get_resume_point(task.id)
```

---

**Document Status:** Ready for Implementation
**Dependencies:** Requires PIPELINE_ARCHITECTURE.md
**Next:** See API_CONTRACTS.md
