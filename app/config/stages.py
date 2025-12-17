"""
Pipeline stage configuration and display names.

This module defines the stage names and ordering for the video generation pipeline.
Used for progress tracking and user-facing display.
"""
from typing import Dict, List


# Stage display names mapping (internal name -> user-friendly name)
STAGE_DISPLAY_NAMES: Dict[str, str] = {
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
ORDERED_STAGES: List[str] = [
    "input_adaptation",
    "content_parsing",
    "script_generation",
    "audio_generation",
    "video_generation",
    "output_handling",
]


def get_stage_display_name(stage_name: str) -> str:
    """
    Get user-friendly display name for a pipeline stage.

    Args:
        stage_name: Internal stage identifier

    Returns:
        User-friendly stage name, or the original name if not found
    """
    return STAGE_DISPLAY_NAMES.get(stage_name, stage_name)


def get_stage_index(stage_name: str) -> int:
    """
    Get the index of a stage in the pipeline sequence.

    Args:
        stage_name: Internal stage identifier

    Returns:
        Zero-based index of the stage, or -1 if not found
    """
    try:
        return ORDERED_STAGES.index(stage_name)
    except ValueError:
        return -1


def get_stage_progress_percentage(stage_name: str) -> float:
    """
    Calculate overall progress percentage at the start of a given stage.

    Args:
        stage_name: Internal stage identifier

    Returns:
        Progress percentage (0.0 to 1.0) at the start of this stage
    """
    index = get_stage_index(stage_name)
    if index < 0:
        return 0.0

    total_stages = len(ORDERED_STAGES)
    return index / total_stages
