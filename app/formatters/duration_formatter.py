"""
Duration formatting utilities.

Provides human-readable duration formatting.
"""


def _format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string (M:SS or H:MM:SS)."""
    if seconds < 0:
        return "0:00"

    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)

    if hours > 0:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes}:{secs:02d}"
