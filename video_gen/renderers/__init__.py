"""
Video Scene Renderers
=====================
Modular scene rendering system for video generation.

This package provides specialized renderers for all 12 scene types,
extracted from the monolithic generate_documentation_videos.py script
into clean, testable modules.

Architecture:
- constants.py: Visual design constants (colors, fonts, dimensions)
- base.py: Shared utilities (easing, backgrounds, base frames)
- basic_scenes.py: Title, command, list, outro
- educational_scenes.py: Quiz, exercise, learning objectives
- comparison_scenes.py: Code comparison, problem, solution
- checkpoint_scenes.py: Checkpoint, quote

Usage:
    from video_gen.renderers import create_title_keyframes, create_quiz_keyframes

    # Generate title scene keyframes
    start_frame, end_frame = create_title_keyframes(
        title="Introduction to Python",
        subtitle="Learn the basics",
        accent_color=(59, 130, 246)
    )
"""

# Import all constants
from .constants import (
    WIDTH, HEIGHT, FPS,
    BG_LIGHT, BG_WHITE,
    ACCENT_ORANGE, ACCENT_BLUE, ACCENT_PURPLE, ACCENT_GREEN, ACCENT_PINK, ACCENT_CYAN,
    TEXT_DARK, TEXT_GRAY, TEXT_LIGHT, CODE_BLUE,
    CARD_BG, CARD_SHADOW,
    font_title, font_subtitle, font_header, font_desc, font_code, font_small, font_tiny,
    get_font_path
)

# Import base utilities
from .base import (
    ease_out_cubic,
    create_modern_mesh_bg,
    create_base_frame
)

# Import basic scene renderers
from .basic_scenes import (
    create_title_keyframes,
    create_command_keyframes,
    create_list_keyframes,
    create_outro_keyframes
)

# Import educational scene renderers
from .educational_scenes import (
    create_quiz_keyframes,
    create_learning_objectives_keyframes,
    create_exercise_keyframes
)

# Import comparison scene renderers
from .comparison_scenes import (
    create_code_comparison_keyframes,
    create_problem_keyframes,
    create_solution_keyframes
)

# Import checkpoint scene renderers
from .checkpoint_scenes import (
    create_checkpoint_keyframes,
    create_quote_keyframes
)

# Public API - all scene renderers + utilities
__all__ = [
    # Constants
    'WIDTH', 'HEIGHT', 'FPS',
    'BG_LIGHT', 'BG_WHITE',
    'ACCENT_ORANGE', 'ACCENT_BLUE', 'ACCENT_PURPLE', 'ACCENT_GREEN', 'ACCENT_PINK', 'ACCENT_CYAN',
    'TEXT_DARK', 'TEXT_GRAY', 'TEXT_LIGHT', 'CODE_BLUE',
    'CARD_BG', 'CARD_SHADOW',
    'font_title', 'font_subtitle', 'font_header', 'font_desc', 'font_code', 'font_small', 'font_tiny',
    'get_font_path',

    # Base utilities
    'ease_out_cubic',
    'create_modern_mesh_bg',
    'create_base_frame',

    # Basic scenes
    'create_title_keyframes',
    'create_command_keyframes',
    'create_list_keyframes',
    'create_outro_keyframes',

    # Educational scenes
    'create_quiz_keyframes',
    'create_learning_objectives_keyframes',
    'create_exercise_keyframes',

    # Comparison scenes
    'create_code_comparison_keyframes',
    'create_problem_keyframes',
    'create_solution_keyframes',

    # Checkpoint scenes
    'create_checkpoint_keyframes',
    'create_quote_keyframes',
]

# Version
__version__ = '1.0.0'
