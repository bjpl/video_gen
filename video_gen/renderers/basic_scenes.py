"""
Basic Scene Rendering Functions
=================================
Core scene types for video generation: title, command, list, and outro.

This module contains the four fundamental scene renderers used across
all video types. Each function creates start and end keyframes that
can be interpolated for smooth animations.

Scene Types:
    - Title: Opening/section title with subtitle
    - Command: Code/command display with terminal styling
    - List: Numbered or bulleted item lists
    - Outro: Closing scene with call-to-action

All functions return (start_frame, end_frame) tuples as RGB PIL Images.
"""

from PIL import Image, ImageDraw
from typing import Tuple, List, Union

from .constants import (
    WIDTH, HEIGHT,
    BG_WHITE, TEXT_DARK, TEXT_GRAY, TEXT_LIGHT,
    ACCENT_GREEN, CODE_BLUE, CARD_BG, CARD_SHADOW,
    font_title, font_subtitle, font_header, font_desc,
    font_code, font_small, font_tiny
)
from .base import create_base_frame


def create_title_keyframes(
    title: str,
    subtitle: str,
    accent_color: Tuple[int, int, int]
) -> Tuple[Image.Image, Image.Image]:
    """Create title scene with badge, main title, underline, and subtitle.

    Renders a centered title card with:
    - "GUIDE" badge at top
    - Large main title text
    - Accent color underline
    - Descriptive subtitle

    Args:
        title: Main title text (e.g., "Quick Reference")
        subtitle: Subtitle/description text
        accent_color: RGB tuple for accent color theming

    Returns:
        Tuple of (start_frame, end_frame) as RGB PIL Images.
        Start frame is blank base, end frame has full content.

    Example:
        >>> start, end = create_title_keyframes(
        ...     "Quick Reference",
        ...     "5-Minute Workflow Commands",
        ...     ACCENT_ORANGE
        ... )
    """
    base = create_base_frame(accent_color)
    start_frame = base.copy()
    end_frame = base.copy()
    draw = ImageDraw.Draw(end_frame, 'RGBA')

    # "GUIDE" badge
    badge_w, badge_h = 200, 60
    badge_x = (WIDTH - badge_w) // 2
    badge_y = 280
    draw.rounded_rectangle([badge_x, badge_y, badge_x + badge_w, badge_y + badge_h],
                          radius=30, fill=accent_color + (40,), outline=accent_color + (200,), width=2)
    badge_text = "GUIDE"
    bbox_badge = draw.textbbox((0, 0), badge_text, font=font_small)
    w_badge = bbox_badge[2] - bbox_badge[0]
    draw.text(((WIDTH - w_badge) // 2, badge_y + 16), badge_text,
              font=font_small, fill=accent_color + (255,))

    # Main title
    bbox = draw.textbbox((0, 0), title, font=font_title)
    w = bbox[2] - bbox[0]
    x = (WIDTH - w) // 2
    draw.text((x, 380), title, font=font_title, fill=TEXT_DARK + (255,))

    # Accent underline
    draw.rectangle([x, 520, x + w, 526], fill=accent_color + (255,))

    # Subtitle
    bbox2 = draw.textbbox((0, 0), subtitle, font=font_subtitle)
    w2 = bbox2[2] - bbox2[0]
    x2 = (WIDTH - w2) // 2
    draw.text((x2, 560), subtitle, font=font_subtitle, fill=TEXT_GRAY + (255,))

    return start_frame.convert('RGB'), end_frame.convert('RGB')


def create_command_keyframes(
    header: str,
    description: str,
    commands: List[str],
    accent_color: Tuple[int, int, int]
) -> Tuple[Image.Image, Image.Image]:
    """Create command/code display scene with terminal styling.

    Renders a terminal-style card showing commands with:
    - Header icon and text
    - macOS-style window with traffic lights
    - Syntax-highlighted command lines
    - Support for multiple line types (commands, output, comments)

    Line Prefixes:
        - "$" or "python": Command prompt (blue)
        - "→": Output/result (green arrow)
        - "✓": Success message (green)
        - "#": Comment (gray)
        - "-": Bullet point (accent dot)

    Args:
        header: Scene header text
        description: Header description text
        commands: List of command/output lines
        accent_color: RGB tuple for accent color theming

    Returns:
        Tuple of (start_frame, end_frame) as RGB PIL Images.
        Start has header only, end has full command card.

    Example:
        >>> start, end = create_command_keyframes(
        ...     "Complete Workflow",
        ...     "Generate Video with Audio",
        ...     ["$ python generate.py", "→ Output: video.mp4"],
        ...     ACCENT_BLUE
        ... )
    """
    base = create_base_frame(accent_color)
    start_frame = base.copy()
    draw = ImageDraw.Draw(start_frame, 'RGBA')

    # Header icon
    icon_size = 80
    icon_x = 120
    icon_y = 90
    draw.rounded_rectangle([icon_x, icon_y, icon_x + icon_size, icon_y + icon_size],
                          radius=16, fill=accent_color + (40,), outline=accent_color + (200,), width=3)
    draw.text((icon_x + 18, icon_y + 12), "❯", font=font_title, fill=accent_color + (255,))

    # Header text
    header_x = icon_x + icon_size + 30
    draw.text((header_x, 100), header, font=font_header, fill=TEXT_DARK + (255,))
    draw.text((header_x, 180), description, font=font_desc, fill=TEXT_GRAY + (255,))

    # End frame with command card
    end_frame = start_frame.copy()
    draw = ImageDraw.Draw(end_frame, 'RGBA')

    # Command card
    card_w, card_h = 1400, 580
    card_x, card_y = (WIDTH - card_w) // 2, 320

    # Card shadow
    draw.rounded_rectangle(
        [card_x + 6, card_y + 6, card_x + card_w + 6, card_y + card_h + 6],
        radius=20, fill=CARD_SHADOW + (100,)
    )
    # Card background
    draw.rounded_rectangle([card_x, card_y, card_x + card_w, card_y + card_h],
                          radius=20, fill=CARD_BG + (255,))

    # Card header bar
    header_bar_h = 50
    draw.rounded_rectangle([card_x, card_y, card_x + card_w, card_y + header_bar_h],
                          radius=20, fill=accent_color + (30,))
    draw.line([(card_x, card_y + header_bar_h), (card_x + card_w, card_y + header_bar_h)],
             fill=accent_color + (100,), width=2)

    # Traffic light dots (macOS style)
    dot_y = card_y + 18
    for i, dot_color in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        dot_x = card_x + 30 + (i * 30)
        draw.ellipse([dot_x, dot_y, dot_x + 14, dot_y + 14], fill=dot_color + (255,))

    # Command lines
    code_y = card_y + header_bar_h + 50
    for line in commands:
        if line.strip():
            if line.startswith('$') or line.startswith('python'):
                # Command line
                prompt_x = card_x + 50
                draw.text((prompt_x, code_y), "❯", font=font_code, fill=accent_color + (255,))
                draw.text((prompt_x + 30, code_y), line[2:] if line.startswith('$ ') else line,
                         font=font_code, fill=CODE_BLUE + (255,))
            elif line.startswith('→'):
                # Output/result
                draw.text((card_x + 50, code_y), "→", font=font_code, fill=ACCENT_GREEN + (255,))
                draw.text((card_x + 80, code_y), line[2:], font=font_code, fill=TEXT_DARK + (255,))
            elif line.startswith('✓'):
                # Success message
                draw.text((card_x + 50, code_y), line, font=font_code, fill=ACCENT_GREEN + (255,))
            elif line.startswith('#'):
                # Comment
                draw.text((card_x + 50, code_y), line, font=font_code, fill=TEXT_LIGHT + (255,))
            elif line.startswith('-'):
                # Bullet point
                draw.ellipse([card_x + 55, code_y + 12, card_x + 63, code_y + 20],
                           fill=accent_color + (255,))
                draw.text((card_x + 75, code_y), line[2:], font=font_small, fill=TEXT_GRAY + (255,))
            else:
                # Plain text
                draw.text((card_x + 50, code_y), line, font=font_small, fill=TEXT_GRAY + (255,))
        code_y += 48

    return start_frame.convert('RGB'), end_frame.convert('RGB')


def create_list_keyframes(
    header: str,
    description: str,
    items: List[Union[str, Tuple[str, str]]],
    accent_color: Tuple[int, int, int]
) -> Tuple[Image.Image, Image.Image]:
    """Create numbered list scene with card-based items.

    Renders a list of items with:
    - Header icon and text
    - Individual cards for each item
    - Numbered badges
    - Support for title+description pairs

    Args:
        header: Scene header text
        description: Header description text
        items: List of strings or (title, description) tuples
        accent_color: RGB tuple for accent color theming

    Returns:
        Tuple of (start_frame, end_frame) as RGB PIL Images.
        Start has header only, end has full list.

    Example:
        >>> start, end = create_list_keyframes(
        ...     "Voice Options",
        ...     "Choose Your Style",
        ...     [("Andrew", "Professional"), ("Aria", "Clear")],
        ...     ACCENT_GREEN
        ... )
    """
    base = create_base_frame(accent_color)
    start_frame = base.copy()
    draw = ImageDraw.Draw(start_frame, 'RGBA')

    # Header icon
    icon_size = 80
    icon_x = 120
    icon_y = 90
    draw.rounded_rectangle([icon_x, icon_y, icon_x + icon_size, icon_y + icon_size],
                          radius=16, fill=accent_color + (40,), outline=accent_color + (200,), width=3)
    draw.text((icon_x + 14, icon_y + 8), "☰", font=font_title, fill=accent_color + (255,))

    # Header text
    header_x = icon_x + icon_size + 30
    draw.text((header_x, 100), header, font=font_header, fill=TEXT_DARK + (255,))
    draw.text((header_x, 180), description, font=font_desc, fill=TEXT_GRAY + (255,))

    # End frame with list
    end_frame = start_frame.copy()
    draw = ImageDraw.Draw(end_frame, 'RGBA')

    # Main card
    card_w, card_h = 1400, 620
    card_x, card_y = (WIDTH - card_w) // 2, 300

    # Card shadow
    draw.rounded_rectangle(
        [card_x + 6, card_y + 6, card_x + card_w + 6, card_y + card_h + 6],
        radius=20, fill=CARD_SHADOW + (100,)
    )
    # Card background
    draw.rounded_rectangle([card_x, card_y, card_x + card_w, card_y + card_h],
                          radius=20, fill=CARD_BG + (255,))

    # List items
    list_y = card_y + 60
    for i, item in enumerate(items, 1):
        item_card_x = card_x + 40
        item_card_w = card_w - 80
        item_card_h = 85 if isinstance(item, tuple) else 65

        # Item card
        draw.rounded_rectangle([item_card_x, list_y, item_card_x + item_card_w, list_y + item_card_h],
                              radius=12, fill=accent_color + (15,), outline=accent_color + (80,), width=1)

        # Numbered badge
        number_size = 36
        number_x = item_card_x + 20
        number_y = list_y + (item_card_h - number_size) // 2
        draw.rounded_rectangle([number_x, number_y, number_x + number_size, number_y + number_size],
                              radius=8, fill=accent_color + (255,))
        num_text = str(i)
        bbox_num = draw.textbbox((0, 0), num_text, font=font_small)
        num_w = bbox_num[2] - bbox_num[0]
        draw.text((number_x + (number_size - num_w) // 2, number_y + 4), num_text,
                 font=font_small, fill=BG_WHITE + (255,))

        # Item text
        text_x = number_x + number_size + 24

        if isinstance(item, tuple):
            # Title + description
            title, desc = item
            draw.text((text_x, list_y + 12), title, font=font_desc, fill=TEXT_DARK + (255,))
            draw.text((text_x, list_y + 48), desc, font=font_small, fill=TEXT_GRAY + (255,))
            list_y += item_card_h + 18
        else:
            # Simple item
            draw.text((text_x, list_y + 18), item, font=font_desc, fill=TEXT_DARK + (255,))
            list_y += item_card_h + 18

    return start_frame.convert('RGB'), end_frame.convert('RGB')


def create_outro_keyframes(
    main_text: str,
    sub_text: str,
    accent_color: Tuple[int, int, int]
) -> Tuple[Image.Image, Image.Image]:
    """Create outro/call-to-action scene.

    Renders a closing scene with:
    - Checkmark icon
    - Main message
    - Call-to-action pill button

    Args:
        main_text: Primary outro message
        sub_text: Call-to-action text (e.g., "See README.md")
        accent_color: RGB tuple for accent color theming

    Returns:
        Tuple of (start_frame, end_frame) as RGB PIL Images.
        Start frame is blank base, end frame has full content.

    Example:
        >>> start, end = create_outro_keyframes(
        ...     "Fast. Simple. Powerful.",
        ...     "See QUICK_REFERENCE.md",
        ...     ACCENT_ORANGE
        ... )
    """
    base = create_base_frame(accent_color)
    start_frame = base.copy()
    end_frame = base.copy()
    draw = ImageDraw.Draw(end_frame, 'RGBA')

    # Checkmark icon
    check_size = 100
    check_x = (WIDTH - check_size) // 2
    check_y = 320
    draw.ellipse([check_x, check_y, check_x + check_size, check_y + check_size],
                fill=accent_color + (40,), outline=accent_color + (255,), width=4)
    draw.text((check_x + 18, check_y + 10), "✓", font=font_title, fill=accent_color + (255,))

    # Main text
    bbox = draw.textbbox((0, 0), main_text, font=font_header)
    w = bbox[2] - bbox[0]
    x = (WIDTH - w) // 2
    draw.text((x, 450), main_text, font=font_header, fill=TEXT_DARK + (255,))

    # Call-to-action pill
    bbox2 = draw.textbbox((0, 0), sub_text, font=font_subtitle)
    w2 = bbox2[2] - bbox2[0]
    x2 = (WIDTH - w2) // 2

    pill_w = w2 + 60
    pill_h = 60
    pill_x = (WIDTH - pill_w) // 2
    pill_y = 550
    draw.rounded_rectangle([pill_x, pill_y, pill_x + pill_w, pill_y + pill_h],
                          radius=30, fill=accent_color + (255,))
    draw.text((x2, pill_y + 12), sub_text, font=font_subtitle, fill=BG_WHITE + (255,))

    return start_frame.convert('RGB'), end_frame.convert('RGB')


__all__ = [
    'create_title_keyframes',
    'create_command_keyframes',
    'create_list_keyframes',
    'create_outro_keyframes'
]
