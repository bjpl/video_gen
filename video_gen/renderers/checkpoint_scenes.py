"""
Checkpoint and Quote Scene Renderers

This module provides specialized scene renderers for checkpoint progress tracking
and quote/callout presentations in educational and documentation videos.
"""

from typing import List, Tuple, Optional, Dict, Any
from PIL import Image, ImageDraw, ImageFont

# Import constants from parent module or define locally
# Note: These should ideally be imported from a shared config module
WIDTH, HEIGHT = 1920, 1080

# Color definitions
BG_LIGHT = (245, 248, 252)
BG_WHITE = (255, 255, 255)
ACCENT_ORANGE = (255, 107, 53)
ACCENT_BLUE = (59, 130, 246)
ACCENT_GREEN = (16, 185, 129)
TEXT_DARK = (15, 23, 42)
TEXT_GRAY = (100, 116, 139)
TEXT_LIGHT = (148, 163, 184)
CARD_BG = (255, 255, 255)
CARD_SHADOW = (203, 213, 225)

# Font definitions
try:
    font_title = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", 120)
    font_subtitle = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 48)
    font_header = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", 64)
    font_desc = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 38)
    font_small = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 28)
except Exception:
    # Fallback to default font if TrueType fonts not available
    font_title = ImageFont.load_default()
    font_subtitle = ImageFont.load_default()
    font_header = ImageFont.load_default()
    font_desc = ImageFont.load_default()
    font_small = ImageFont.load_default()


def create_base_frame(accent_color: Tuple[int, int, int]) -> Image.Image:
    """
    Create base frame with modern mesh background and branding.

    Args:
        accent_color: RGB tuple for accent color

    Returns:
        PIL Image with base frame design
    """
    # Create mesh background
    img = Image.new('RGB', (WIDTH, HEIGHT), BG_LIGHT)
    draw = ImageDraw.Draw(img, 'RGBA')

    # Add mesh gradient overlays
    draw.ellipse([1200, -300, 2200, 500], fill=accent_color + (15,))
    draw.ellipse([-200, 600, 600, 1300], fill=accent_color + (20,))
    draw.ellipse([1400, 700, 2000, 1200], fill=accent_color + (12,))

    # Grid pattern
    for i in range(0, WIDTH, 40):
        draw.line([(i, 0), (i, HEIGHT)], fill=CARD_SHADOW + (30,), width=1)
    for i in range(0, HEIGHT, 40):
        draw.line([(0, i), (WIDTH, i)], fill=CARD_SHADOW + (30,), width=1)

    img = img.convert('RGBA')
    draw = ImageDraw.Draw(img, 'RGBA')

    # Side accent bar
    draw.rectangle([0, 0, 12, HEIGHT], fill=accent_color + (255,))
    draw.rectangle([0, HEIGHT-12, WIDTH, HEIGHT], fill=accent_color + (120,))

    # Logo
    logo_size = 60
    logo_x, logo_y = WIDTH - 120, HEIGHT - 90
    draw.rounded_rectangle([logo_x, logo_y, logo_x + logo_size, logo_y + logo_size],
                          radius=12, fill=accent_color + (255,))
    draw.text((logo_x + 12, logo_y + 8), "CC", font=font_subtitle, fill=BG_WHITE + (255,))

    return img


def create_quote_keyframes(
    quote_text: str,
    attribution: str,
    accent_color: Tuple[int, int, int]
) -> Tuple[Image.Image, Image.Image]:
    """
    Create quote/callout scene with large centered quote and attribution.

    Visual: Large quotation mark icon, centered quote text in card with accent
    background, and attribution at bottom.

    Args:
        quote_text: The quote text to display (will be auto-wrapped)
        attribution: Attribution text (e.g., author, source)
        accent_color: RGB tuple for accent color (e.g., ACCENT_BLUE)

    Returns:
        Tuple of (start_frame, end_frame) as PIL Images in RGB mode

    Example:
        >>> start, end = create_quote_keyframes(
        ...     "Quality is not an act, it is a habit",
        ...     "Aristotle",
        ...     ACCENT_BLUE
        ... )
    """
    base = create_base_frame(accent_color)
    start_frame = base.copy()
    end_frame = base.copy()
    draw = ImageDraw.Draw(end_frame, 'RGBA')

    # Quote icon (large quotation mark)
    quote_size = 120
    quote_x = (WIDTH - quote_size) // 2
    quote_y = 240
    draw.ellipse([quote_x, quote_y, quote_x + quote_size, quote_y + quote_size],
                fill=accent_color + (30,), outline=accent_color + (150,), width=3)
    draw.text((quote_x + 20, quote_y + 5), '"', font=font_title, fill=accent_color + (255,))

    # Quote card
    card_w = 1400
    card_h = 480
    card_x = (WIDTH - card_w) // 2
    card_y = 400

    # Shadow
    draw.rounded_rectangle(
        [card_x + 8, card_y + 8, card_x + card_w + 8, card_y + card_h + 8],
        radius=20, fill=CARD_SHADOW + (100,)
    )
    # Card with accent background
    draw.rounded_rectangle([card_x, card_y, card_x + card_w, card_y + card_h],
                          radius=20, fill=accent_color + (15,), outline=accent_color + (100,), width=2)

    # Quote text (wrapped manually if needed)
    quote_lines = []
    words = quote_text.split()
    current_line = []

    for word in words:
        test_line = ' '.join(current_line + [word])
        bbox = draw.textbbox((0, 0), test_line, font=font_header)
        if bbox[2] - bbox[0] > card_w - 100:  # Line too long
            if current_line:
                quote_lines.append(' '.join(current_line))
                current_line = [word]
        else:
            current_line.append(word)

    if current_line:
        quote_lines.append(' '.join(current_line))

    # Draw quote lines (max 3-4 lines)
    quote_y_start = card_y + 80
    line_height = 70

    for i, line in enumerate(quote_lines[:4]):
        bbox = draw.textbbox((0, 0), line, font=font_header)
        w = bbox[2] - bbox[0]
        x = (WIDTH - w) // 2
        draw.text((x, quote_y_start + i * line_height), line,
                 font=font_header, fill=TEXT_DARK + (255,))

    # Attribution
    if attribution:
        attr_y = card_y + card_h - 100
        # Dash before attribution
        draw.text((card_x + 80, attr_y), "—", font=font_desc, fill=accent_color + (255,))
        draw.text((card_x + 120, attr_y), attribution, font=font_desc, fill=TEXT_GRAY + (255,))

    return start_frame.convert('RGB'), end_frame.convert('RGB')


def create_checkpoint_keyframes(
    checkpoint_num: int,
    completed_topics: List[str],
    review_questions: List[str],
    next_topics: List[str],
    accent_color: Tuple[int, int, int]
) -> Tuple[Image.Image, Image.Image]:
    """
    Create learning checkpoint/progress scene with three-column layout.

    Visual: Checkpoint badge at top, three columns showing completed topics
    (with checkmarks), review questions (with bullets), and next topics
    (with bullets).

    Args:
        checkpoint_num: Checkpoint number to display
        completed_topics: List of completed topic strings
        review_questions: List of review question strings
        next_topics: List of upcoming topic strings
        accent_color: RGB tuple for accent color (e.g., ACCENT_ORANGE)

    Returns:
        Tuple of (start_frame, end_frame) as PIL Images in RGB mode

    Example:
        >>> start, end = create_checkpoint_keyframes(
        ...     checkpoint_num=1,
        ...     completed_topics=["Variables", "Functions", "Loops"],
        ...     review_questions=["What is a variable?", "How do loops work?"],
        ...     next_topics=["Classes", "Objects", "Inheritance"],
        ...     accent_color=ACCENT_GREEN
        ... )
    """
    base = create_base_frame(accent_color)
    start_frame = base.copy()
    end_frame = base.copy()
    draw = ImageDraw.Draw(end_frame, 'RGBA')

    # Checkpoint badge
    badge_w, badge_h = 300, 60
    badge_x, badge_y = (WIDTH - badge_w) // 2, 180
    draw.rounded_rectangle([badge_x, badge_y, badge_x + badge_w, badge_y + badge_h],
                          radius=30, fill=accent_color + (40,), outline=accent_color + (200,), width=3)

    badge_text = f"✓ CHECKPOINT {checkpoint_num}"
    bbox = draw.textbbox((0, 0), badge_text, font=font_subtitle)
    w = bbox[2] - bbox[0]
    draw.text(((WIDTH - w) // 2, badge_y + 12), badge_text,
              font=font_subtitle, fill=accent_color + (255,))

    # Three columns: Completed, Review, Next
    col_width = 450
    col_spacing = 50
    total_width = col_width * 3 + col_spacing * 2
    start_x = (WIDTH - total_width) // 2
    start_y = 300

    columns = [
        ("Completed", completed_topics, ACCENT_GREEN),
        ("Review", review_questions, ACCENT_ORANGE),
        ("Next", next_topics, accent_color)
    ]

    for col_idx, (col_title, items, col_color) in enumerate(columns):
        col_x = start_x + col_idx * (col_width + col_spacing)

        # Column card
        card_h = 450
        draw.rounded_rectangle([col_x, start_y, col_x + col_width, start_y + card_h],
                              radius=15, fill=CARD_BG + (255,))
        draw.rounded_rectangle([col_x, start_y, col_x + col_width, start_y + card_h],
                              radius=15, outline=col_color + (120,), width=2)

        # Column header
        header_h = 60
        draw.rounded_rectangle([col_x, start_y, col_x + col_width, start_y + header_h],
                              radius=15, fill=col_color + (30,))

        bbox_header = draw.textbbox((0, 0), col_title, font=font_desc)
        w_header = bbox_header[2] - bbox_header[0]
        draw.text((col_x + (col_width - w_header) // 2, start_y + 18), col_title,
                  font=font_desc, fill=col_color + (255,))

        # Items
        item_y = start_y + header_h + 30
        for i, item in enumerate(items[:6]):  # Max 6 items per column
            # Checkmark or bullet
            if col_idx == 0:  # Completed
                draw.text((col_x + 20, item_y), "✓", font=font_small, fill=ACCENT_GREEN + (255,))
            else:
                draw.ellipse([col_x + 25, item_y + 8, col_x + 35, item_y + 18],
                            fill=col_color + (200,))

            # Item text (truncate if too long)
            item_text = item[:40] + "..." if len(item) > 40 else item
            draw.text((col_x + 50, item_y), item_text,
                      font=font_small, fill=TEXT_DARK + (255,))

            item_y += 50

    return start_frame.convert('RGB'), end_frame.convert('RGB')


__all__ = [
    'create_quote_keyframes',
    'create_checkpoint_keyframes',
]
