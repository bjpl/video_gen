"""
Video Generation System - Core Package
=======================================
Production-ready video generation pipeline with state management,
error recovery, and progress tracking.
"""

from .pipeline.orchestrator import PipelineOrchestrator
from .pipeline.stage import Stage, StageResult
from .pipeline.state_manager import StateManager, TaskState
from .pipeline.events import EventEmitter, Event

__version__ = "2.0.0"
__all__ = [
    "PipelineOrchestrator",
    "Stage",
    "StageResult",
    "StateManager",
    "TaskState",
    "EventEmitter",
    "Event",
]
