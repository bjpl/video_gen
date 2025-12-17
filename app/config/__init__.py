"""
Configuration package for the video generation system.

This package contains application configuration including:
- stages: Pipeline stage names and ordering
- app_config: Application paths and template setup
"""
from .stages import (
    STAGE_DISPLAY_NAMES,
    ORDERED_STAGES,
    get_stage_display_name,
    get_stage_index,
    get_stage_progress_percentage,
)
from .app_config import (
    BASE_DIR,
    get_templates,
    get_static_dir,
    get_uploads_dir,
)

__all__ = [
    # Stage configuration
    "STAGE_DISPLAY_NAMES",
    "ORDERED_STAGES",
    "get_stage_display_name",
    "get_stage_index",
    "get_stage_progress_percentage",
    # App configuration
    "BASE_DIR",
    "get_templates",
    "get_static_dir",
    "get_uploads_dir",
]
