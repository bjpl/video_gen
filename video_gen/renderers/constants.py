"""
Visual Design Constants
========================
Colors, dimensions, and fonts for video rendering.

This module provides cross-platform font detection and consistent
visual styling across all scene renderers.
"""

import sys
from pathlib import Path
from PIL import ImageFont

# Video dimensions
WIDTH = 1920
HEIGHT = 1080
FPS = 30

# Background colors
BG_LIGHT = (245, 248, 252)
BG_WHITE = (255, 255, 255)

# Accent colors
ACCENT_ORANGE = (255, 107, 53)
ACCENT_BLUE = (59, 130, 246)
ACCENT_PURPLE = (139, 92, 246)
ACCENT_GREEN = (16, 185, 129)
ACCENT_PINK = (236, 72, 153)
ACCENT_CYAN = (34, 211, 238)

# Text colors
TEXT_DARK = (15, 23, 42)
TEXT_GRAY = (100, 116, 139)
TEXT_LIGHT = (148, 163, 184)
CODE_BLUE = (59, 130, 246)

# UI colors
CARD_BG = (255, 255, 255)
CARD_SHADOW = (203, 213, 225)


def get_font_path(font_name: str) -> str:
    """Get platform-specific font path.

    Args:
        font_name: Font filename (e.g., 'arial.ttf')

    Returns:
        Full path to font file
    """
    if sys.platform == "win32":
        return f"C:/Windows/Fonts/{font_name}"
    elif sys.platform == "darwin":
        return f"/System/Library/Fonts/Supplemental/{font_name}"
    else:  # Linux
        # Try common locations
        for base_path in ["/usr/share/fonts/truetype", "/usr/share/fonts/TTF"]:
            font_path = Path(base_path) / font_name
            if font_path.exists():
                return str(font_path)
        # Fallback
        return font_name


# Font definitions with cross-platform support
try:
    font_title = ImageFont.truetype(get_font_path("arialbd.ttf"), 120)
    font_subtitle = ImageFont.truetype(get_font_path("arial.ttf"), 48)
    font_header = ImageFont.truetype(get_font_path("arialbd.ttf"), 64)
    font_desc = ImageFont.truetype(get_font_path("arial.ttf"), 38)
    font_code = ImageFont.truetype(get_font_path("consola.ttf"), 32)
    font_small = ImageFont.truetype(get_font_path("arial.ttf"), 28)
    font_tiny = ImageFont.truetype(get_font_path("arial.ttf"), 24)
except OSError:
    # Fallback to default font if platform fonts not found
    font_title = ImageFont.load_default()
    font_subtitle = ImageFont.load_default()
    font_header = ImageFont.load_default()
    font_desc = ImageFont.load_default()
    font_code = ImageFont.load_default()
    font_small = ImageFont.load_default()
    font_tiny = ImageFont.load_default()


# Export all constants
__all__ = [
    'WIDTH', 'HEIGHT', 'FPS',
    'BG_LIGHT', 'BG_WHITE',
    'ACCENT_ORANGE', 'ACCENT_BLUE', 'ACCENT_PURPLE', 'ACCENT_GREEN', 'ACCENT_PINK', 'ACCENT_CYAN',
    'TEXT_DARK', 'TEXT_GRAY', 'TEXT_LIGHT', 'CODE_BLUE',
    'CARD_BG', 'CARD_SHADOW',
    'font_title', 'font_subtitle', 'font_header', 'font_desc', 'font_code', 'font_small', 'font_tiny',
    'get_font_path'
]
