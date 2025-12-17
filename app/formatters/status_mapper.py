"""
Status mapping utilities for pipeline to API conversion.

Provides status mapping and type inference for backward compatibility.
"""
from typing import Dict, Any


def _map_status(pipeline_status: str) -> str:
    """
    Map pipeline status to API status for backward compatibility.

    Pipeline uses: pending, running, paused, completed, failed, cancelled
    API expects: processing, complete, failed
    """
    status_map = {
        "pending": "processing",
        "running": "processing",
        "paused": "processing",
        "completed": "complete",
        "failed": "failed",
        "cancelled": "failed"
    }
    return status_map.get(pipeline_status, "processing")


def _infer_type_from_input(input_config: Dict[str, Any]) -> str:
    """
    Infer task type from input config for backward compatibility.

    Args:
        input_config: Input configuration dictionary

    Returns:
        Task type string (document, youtube, generate, multilingual)
    """
    input_type = input_config.get("input_type", "unknown")

    type_map = {
        "document": "document",
        "youtube": "youtube",
        "programmatic": "generate",
        "yaml": "generate",
        "wizard": "generate"
    }

    result_type = type_map.get(input_type, "generate")

    # Check for multilingual
    languages = input_config.get("languages", [])
    if len(languages) > 1:
        return "multilingual"

    return result_type
