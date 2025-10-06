"""
Base Rendering Utilities
=========================
Shared functions for all scene renderers.

Provides:
- Easing functions for smooth animations
- Background generation with modern mesh design
- Base frame creation with consistent styling
"""

from PIL import Image, ImageDraw
from typing import Tuple

from .constants import (
    WIDTH, HEIGHT,
    BG_LIGHT, BG_WHITE, CARD_SHADOW,
    font_subtitle
)


def ease_out_cubic(t: float) -> float:
    """Apply cubic ease-out easing function.

    Creates smooth, natural-looking animations where movement
    decelerates towards the end.

    Args:
        t: Progress value between 0.0 and 1.0

    Returns:
        Eased value between 0.0 and 1.0

    Examples:
        >>> ease_out_cubic(0.0)
        0.0
        >>> ease_out_cubic(0.5)
        0.875
        >>> ease_out_cubic(1.0)
        1.0
    """
    return 1 - pow(1 - t, 3)


def create_modern_mesh_bg(
    width: int,
    height: int,
    accent_color: Tuple[int, int, int]
) -> Image.Image:
    """Create modern mesh background with gradient orbs and grid.

    Args:
        width: Image width in pixels
        height: Image height in pixels
        accent_color: RGB tuple for accent color

    Returns:
        PIL Image with mesh background
    """
    img = Image.new('RGB', (width, height), BG_LIGHT)
    draw = ImageDraw.Draw(img, 'RGBA')

    # Draw gradient orbs
    draw.ellipse([1200, -300, 2200, 500], fill=accent_color + (15,))
    draw.ellipse([-200, 600, 600, 1300], fill=accent_color + (20,))
    draw.ellipse([1400, 700, 2000, 1200], fill=accent_color + (12,))

    # Draw grid
    for i in range(0, width, 40):
        draw.line([(i, 0), (i, height)], fill=CARD_SHADOW + (30,), width=1)
    for i in range(0, height, 40):
        draw.line([(0, i), (width, i)], fill=CARD_SHADOW + (30,), width=1)

    return img


def create_base_frame(accent_color: Tuple[int, int, int]) -> Image.Image:
    """Create base frame with branding and accent styling.

    Adds consistent elements to all frames:
    - Modern mesh background
    - Accent color border (left side)
    - Bottom accent stripe
    - CC logo (bottom right)

    Args:
        accent_color: RGB tuple for accent color

    Returns:
        PIL Image ready for additional content
    """
    img = create_modern_mesh_bg(WIDTH, HEIGHT, accent_color).convert('RGBA')
    draw = ImageDraw.Draw(img, 'RGBA')

    # Left border accent
    draw.rectangle([0, 0, 12, HEIGHT], fill=accent_color + (255,))

    # Bottom stripe
    draw.rectangle([0, HEIGHT-12, WIDTH, HEIGHT], fill=accent_color + (120,))

    # CC logo (bottom right)
    logo_size = 60
    logo_x, logo_y = WIDTH - 120, HEIGHT - 90
    draw.rounded_rectangle(
        [logo_x, logo_y, logo_x + logo_size, logo_y + logo_size],
        radius=12,
        fill=accent_color + (255,)
    )
    draw.text((logo_x + 12, logo_y + 8), "CC", font=font_subtitle, fill=BG_WHITE + (255,))

    return img


__all__ = ['ease_out_cubic', 'create_modern_mesh_bg', 'create_base_frame']
