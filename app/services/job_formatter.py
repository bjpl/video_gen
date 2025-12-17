"""
Job formatting service.

Provides formatting of task state for the jobs monitor frontend.
"""
from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path
import logging

from app.formatters.duration_formatter import _format_duration

logger = logging.getLogger(__name__)

# Stage display names mapping (internal name -> user-friendly name)
STAGE_DISPLAY_NAMES = {
    "input_adaptation": "Preparation",
    "content_parsing": "Scenes",
    "script_generation": "Narration",
    "audio_generation": "Synthesis",
    "video_generation": "Composition",
    "output_handling": "Finalization",
    "validation": "Validation",
    "translation": "Translation",
}

# Ordered stages for display (matches the 6-stage pipeline)
ORDERED_STAGES = [
    "input_adaptation",
    "content_parsing",
    "script_generation",
    "audio_generation",
    "video_generation",
    "output_handling",
]


def _format_job_for_monitor(task_state) -> Dict[str, Any]:
    """
    Format a TaskState for the jobs monitor frontend.

    Converts internal stage data to the format expected by jobs.html JavaScript.

    Args:
        task_state: TaskState object from state manager

    Returns:
        Dictionary with job data for frontend display
    """
    # Extract document/source name from input config
    input_config = task_state.input_config or {}
    source = input_config.get("source", "Unknown")

    # Get friendly document name
    if isinstance(source, str):
        if source.startswith("{"):
            # JSON data - try to extract set name
            try:
                import json
                data = json.loads(source)
                document_name = data.get("set_name", data.get("title", "Video Set"))
            except:
                document_name = "Video Set"
        elif "/" in source or "\\" in source:
            # File path - get filename
            document_name = Path(source).stem
        elif source.startswith("http"):
            # URL - show truncated
            document_name = source[:40] + "..." if len(source) > 40 else source
        else:
            document_name = source[:50] if len(source) > 50 else source
    else:
        document_name = "Video Generation"

    # Calculate elapsed time
    started_at = task_state.started_at
    if started_at:
        if isinstance(started_at, str):
            started_at = datetime.fromisoformat(started_at)
        elapsed_seconds = (datetime.now() - started_at).total_seconds()
        elapsed = _format_duration(elapsed_seconds)
    else:
        elapsed = "0:00"

    # Calculate total duration for completed jobs
    total_duration = None
    if task_state.completed_at and task_state.started_at:
        completed_at = task_state.completed_at
        if isinstance(completed_at, str):
            completed_at = datetime.fromisoformat(completed_at)
        if isinstance(started_at, str):
            started_at = datetime.fromisoformat(started_at)
        total_seconds = (completed_at - started_at).total_seconds()
        total_duration = _format_duration(total_seconds)

    # Build stage progress info with enhanced error details
    stages_info = []
    current_stage_name = task_state.current_stage
    failed_stage_error = None  # Track error from failed stage

    for stage_name in ORDERED_STAGES:
        stage_state = task_state.stages.get(stage_name)

        if stage_state:
            stage_status_value = stage_state.status.value if hasattr(stage_state.status, 'value') else stage_state.status

            if stage_status_value == "completed":
                status = "completed"
            elif stage_status_value == "running":
                status = "active"
            elif stage_status_value == "failed":
                status = "failed"
                # Capture the error from this failed stage
                if stage_state.error:
                    failed_stage_error = {
                        "stage": STAGE_DISPLAY_NAMES.get(stage_name, stage_name),
                        "error": stage_state.error
                    }
            else:
                status = "pending"

            # Calculate stage duration
            duration = None
            if stage_state.started_at and stage_state.completed_at:
                stage_start = stage_state.started_at
                stage_end = stage_state.completed_at
                if isinstance(stage_start, str):
                    stage_start = datetime.fromisoformat(stage_start)
                if isinstance(stage_end, str):
                    stage_end = datetime.fromisoformat(stage_end)
                duration = f"{(stage_end - stage_start).total_seconds():.1f}s"

            # Include stage progress for active stages
            stage_progress = int(stage_state.progress * 100) if stage_state.progress else 0
        else:
            # Stage not yet registered
            status = "pending"
            duration = None
            stage_progress = 0

        stages_info.append({
            "name": STAGE_DISPLAY_NAMES.get(stage_name, stage_name),
            "internal_name": stage_name,
            "status": status,
            "duration": duration,
            "progress": stage_progress,
            "error": stage_state.error if stage_state and stage_state.error else None
        })

    # Get current stage display name
    current_stage_display = STAGE_DISPLAY_NAMES.get(
        current_stage_name, current_stage_name or "Initializing"
    )

    # Calculate progress as percentage (0-100)
    progress = int(task_state.overall_progress * 100)

    # Build comprehensive error info for failed jobs
    error_details = None
    if task_state.errors or failed_stage_error:
        error_details = {
            "errors": task_state.errors if task_state.errors else [],
            "failed_stage": failed_stage_error,
            "error_count": len(task_state.errors) if task_state.errors else 0,
            "summary": task_state.errors[0] if task_state.errors else (
                f"Failed at {failed_stage_error['stage']}: {failed_stage_error['error'][:100]}" if failed_stage_error else "Unknown error"
            )
        }

    return {
        "id": task_state.task_id,
        "document": document_name,
        "current_stage": current_stage_display,
        "progress": progress,
        "elapsed": elapsed,
        "total_duration": total_duration,
        "stages": stages_info,
        "status": task_state.status.value if hasattr(task_state.status, 'value') else task_state.status,
        "errors": task_state.errors if task_state.errors else [],
        "error_details": error_details,
        "warnings": task_state.warnings if task_state.warnings else [],
        "created_at": task_state.created_at.isoformat() if task_state.created_at else None,
    }


def _add_queue_positions(queued_jobs: List[Dict]) -> List[Dict]:
    """Add queue position numbers to queued jobs."""
    for i, job in enumerate(queued_jobs, start=1):
        job["queue_position"] = i
    return queued_jobs
