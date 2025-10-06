"""
Event system for progress tracking and real-time updates.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class EventType(Enum):
    """Types of events that can be emitted."""

    PIPELINE_STARTED = "pipeline.started"
    PIPELINE_COMPLETED = "pipeline.completed"
    PIPELINE_FAILED = "pipeline.failed"

    STAGE_STARTED = "stage.started"
    STAGE_PROGRESS = "stage.progress"
    STAGE_COMPLETED = "stage.completed"
    STAGE_FAILED = "stage.failed"

    VALIDATION_WARNING = "validation.warning"
    VALIDATION_ERROR = "validation.error"

    AUDIO_GENERATING = "audio.generating"
    AUDIO_GENERATED = "audio.generated"

    VIDEO_RENDERING = "video.rendering"
    VIDEO_RENDERED = "video.rendered"

    STATE_SAVED = "state.saved"
    STATE_RESTORED = "state.restored"


@dataclass
class Event:
    """Event object containing event data."""

    type: EventType
    task_id: str
    timestamp: datetime = field(default_factory=datetime.now)
    stage: Optional[str] = None
    progress: Optional[float] = None  # 0.0 to 1.0
    message: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization."""
        return {
            "type": self.type.value,
            "task_id": self.task_id,
            "timestamp": self.timestamp.isoformat(),
            "stage": self.stage,
            "progress": self.progress,
            "message": self.message,
            "data": self.data,
        }

    def __str__(self) -> str:
        """String representation of event."""
        parts = [f"[{self.type.value}]"]
        if self.stage:
            parts.append(f"stage={self.stage}")
        if self.progress is not None:
            parts.append(f"progress={self.progress:.1%}")
        if self.message:
            parts.append(f"msg={self.message}")
        return " ".join(parts)


class EventEmitter:
    """
    Event emitter for broadcasting pipeline events.

    Supports both synchronous and asynchronous listeners.
    Thread-safe for concurrent operations.
    """

    def __init__(self):
        self._listeners: Dict[EventType, List[Callable]] = {}
        self._async_listeners: Dict[EventType, List[Callable]] = {}
        self._global_listeners: List[Callable] = []
        self._async_global_listeners: List[Callable] = []
        self._lock = asyncio.Lock()
        self._enabled = True

    def on(self, event_type: EventType, callback: Callable):
        """
        Register a synchronous event listener.

        Args:
            event_type: Type of event to listen for
            callback: Function to call when event is emitted (receives Event object)
        """
        if event_type not in self._listeners:
            self._listeners[event_type] = []
        self._listeners[event_type].append(callback)

    def on_async(self, event_type: EventType, callback: Callable):
        """
        Register an asynchronous event listener.

        Args:
            event_type: Type of event to listen for
            callback: Async function to call when event is emitted
        """
        if event_type not in self._async_listeners:
            self._async_listeners[event_type] = []
        self._async_listeners[event_type].append(callback)

    def on_all(self, callback: Callable):
        """Register a global listener for all events."""
        self._global_listeners.append(callback)

    def on_all_async(self, callback: Callable):
        """Register an async global listener for all events."""
        self._async_global_listeners.append(callback)

    def off(self, event_type: EventType, callback: Callable):
        """Unregister an event listener."""
        if event_type in self._listeners:
            self._listeners[event_type] = [
                cb for cb in self._listeners[event_type] if cb != callback
            ]
        if event_type in self._async_listeners:
            self._async_listeners[event_type] = [
                cb for cb in self._async_listeners[event_type] if cb != callback
            ]

    async def emit(self, event: Event):
        """
        Emit an event to all registered listeners.

        Args:
            event: Event object to emit
        """
        if not self._enabled:
            return

        async with self._lock:
            # Log event
            logger.debug(f"Event emitted: {event}")

            # Call global listeners
            for callback in self._global_listeners:
                try:
                    callback(event)
                except Exception as e:
                    logger.error(f"Error in global listener: {e}", exc_info=True)

            for callback in self._async_global_listeners:
                try:
                    await callback(event)
                except Exception as e:
                    logger.error(f"Error in async global listener: {e}", exc_info=True)

            # Call type-specific listeners
            if event.type in self._listeners:
                for callback in self._listeners[event.type]:
                    try:
                        callback(event)
                    except Exception as e:
                        logger.error(f"Error in event listener: {e}", exc_info=True)

            if event.type in self._async_listeners:
                for callback in self._async_listeners[event.type]:
                    try:
                        await callback(event)
                    except Exception as e:
                        logger.error(f"Error in async event listener: {e}", exc_info=True)

    def emit_sync(self, event: Event):
        """Synchronous emit (creates event loop if needed)."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(self.emit(event))
            else:
                loop.run_until_complete(self.emit(event))
        except RuntimeError:
            # No event loop available
            asyncio.run(self.emit(event))

    def enable(self):
        """Enable event emission."""
        self._enabled = True

    def disable(self):
        """Disable event emission (useful for testing)."""
        self._enabled = False

    def clear(self):
        """Clear all registered listeners."""
        self._listeners.clear()
        self._async_listeners.clear()
        self._global_listeners.clear()
        self._async_global_listeners.clear()


# Global event emitter instance
event_emitter = EventEmitter()
