"""
Comparison and Problem-Solving Scene Renderers

This module provides rendering functions for specialized educational and technical scenes:
- Code comparison (before/after visualization)
- Problem presentation (coding challenges)
- Solution presentation (code solutions with explanations)

These renderers are optimized for technical documentation, coding tutorials,
and educational content that requires side-by-side comparisons or problem-solution pairs.
"""

from PIL import Image, ImageDraw
from typing import Tuple

__all__ = [
    'create_code_comparison_keyframes',
    'create_problem_keyframes',
    'create_solution_keyframes'
]

# Design system constants
WIDTH, HEIGHT = 1920, 1080
BG_LIGHT = (245, 248, 252)
BG_WHITE = (255, 255, 255)
ACCENT_GREEN = (16, 185, 129)
ACCENT_ORANGE = (255, 107, 53)
ACCENT_PINK = (236, 72, 153)
TEXT_DARK = (15, 23, 42)
TEXT_GRAY = (100, 116, 139)
TEXT_LIGHT = (148, 163, 184)
CODE_BLUE = (59, 130, 246)
CARD_BG = (255, 255, 255)
CARD_SHADOW = (203, 213, 225)

# Font configuration
from PIL import ImageFont
try:
    font_title = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", 120)
    font_header = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", 64)
    font_desc = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 38)
    font_code = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 32)
    font_small = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 28)
except Exception:
    # Fallback to default font if TrueType fonts not available
    font_title = ImageFont.load_default()
    font_header = ImageFont.load_default()
    font_desc = ImageFont.load_default()
    font_code = ImageFont.load_default()
    font_small = ImageFont.load_default()


def create_modern_mesh_bg(width: int, height: int, accent_color: Tuple[int, int, int]) -> Image.Image:
    """Create modern mesh background with gradient effects."""
    img = Image.new('RGB', (width, height), BG_LIGHT)
    draw = ImageDraw.Draw(img, 'RGBA')

    draw.ellipse([1200, -300, 2200, 500], fill=accent_color + (15,))
    draw.ellipse([-200, 600, 600, 1300], fill=accent_color + (20,))
    draw.ellipse([1400, 700, 2000, 1200], fill=accent_color + (12,))

    for i in range(0, width, 40):
        draw.line([(i, 0), (i, height)], fill=CARD_SHADOW + (30,), width=1)
    for i in range(0, height, 40):
        draw.line([(0, i), (width, i)], fill=CARD_SHADOW + (30,), width=1)

    return img


def create_base_frame(accent_color: Tuple[int, int, int]) -> Image.Image:
    """Create base frame with branding elements."""
    img = create_modern_mesh_bg(WIDTH, HEIGHT, accent_color).convert('RGBA')
    draw = ImageDraw.Draw(img, 'RGBA')

    draw.rectangle([0, 0, 12, HEIGHT], fill=accent_color + (255,))
    draw.rectangle([0, HEIGHT-12, WIDTH, HEIGHT], fill=accent_color + (120,))

    logo_size = 60
    logo_x, logo_y = WIDTH - 120, HEIGHT - 90
    draw.rounded_rectangle([logo_x, logo_y, logo_x + logo_size, logo_y + logo_size],
                          radius=12, fill=accent_color + (255,))
    try:
        font_subtitle = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 48)
    except (OSError, IOError):
        font_subtitle = ImageFont.load_default()
    draw.text((logo_x + 12, logo_y + 8), "CC", font=font_subtitle, fill=BG_WHITE + (255,))

    return img


def create_code_comparison_keyframes(
    header: str,
    before_code: str,
    after_code: str,
    accent_color: Tuple[int, int, int],
    before_label: str = "Before",
    after_label: str = "After"
) -> Tuple[Image.Image, Image.Image]:
    """
    Create side-by-side code comparison scene.

    Visual: Split screen with before/after code blocks highlighting the transformation
    or improvement. Perfect for demonstrating refactoring, optimization, or bug fixes.

    Args:
        header: Scene title/header text
        before_code: Code snippet for left side (before state)
        after_code: Code snippet for right side (after state)
        accent_color: RGB tuple for accent color theme
        before_label: Label for left card (default: "Before")
        after_label: Label for right card (default: "After")

    Returns:
        Tuple of (start_frame, end_frame) as PIL Image objects in RGB mode

    Example:
        start, end = create_code_comparison_keyframes(
            "Performance Optimization",
            "def slow():\n    return [x**2 for x in range(1000)]",
            "def fast():\n    return numpy.square(numpy.arange(1000))",
            ACCENT_BLUE
        )
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
    draw.text((icon_x + 16, icon_y + 8), "⚡", font=font_title, fill=accent_color + (255,))

    header_x = icon_x + icon_size + 30
    draw.text((header_x, 110), header, font=font_header, fill=TEXT_DARK + (255,))

    # Animated end frame with code comparison
    end_frame = start_frame.copy()
    draw = ImageDraw.Draw(end_frame, 'RGBA')

    # Split screen layout
    split_x = WIDTH // 2
    card_margin = 80
    card_y = 260
    card_h = 620

    # Left card (Before)
    left_card_w = split_x - card_margin - 30
    left_card_x = card_margin

    # Shadow
    draw.rounded_rectangle(
        [left_card_x + 6, card_y + 6, left_card_x + left_card_w + 6, card_y + card_h + 6],
        radius=20, fill=CARD_SHADOW + (100,)
    )
    # Card
    draw.rounded_rectangle([left_card_x, card_y, left_card_x + left_card_w, card_y + card_h],
                          radius=20, fill=CARD_BG + (255,))

    # Before label with red tint
    label_h = 50
    draw.rounded_rectangle([left_card_x, card_y, left_card_x + left_card_w, card_y + label_h],
                          radius=20, fill=(255, 95, 86, 40))
    draw.text((left_card_x + 30, card_y + 12), before_label, font=font_desc, fill=(255, 95, 86, 255))

    # Before code
    code_y = card_y + label_h + 40
    before_lines = before_code.split('\n')[:10]  # Max 10 lines
    for line in before_lines:
        if line.strip():
            draw.text((left_card_x + 30, code_y), line, font=font_code, fill=TEXT_DARK + (200,))
        code_y += 48

    # Right card (After)
    right_card_x = split_x + 30
    right_card_w = WIDTH - right_card_x - card_margin

    # Shadow
    draw.rounded_rectangle(
        [right_card_x + 6, card_y + 6, right_card_x + right_card_w + 6, card_y + card_h + 6],
        radius=20, fill=CARD_SHADOW + (100,)
    )
    # Card
    draw.rounded_rectangle([right_card_x, card_y, right_card_x + right_card_w, card_y + card_h],
                          radius=20, fill=CARD_BG + (255,))

    # After label with green tint
    draw.rounded_rectangle([right_card_x, card_y, right_card_x + right_card_w, card_y + label_h],
                          radius=20, fill=ACCENT_GREEN + (40,))
    draw.text((right_card_x + 30, card_y + 12), after_label, font=font_desc, fill=ACCENT_GREEN + (255,))

    # After code
    code_y = card_y + label_h + 40
    after_lines = after_code.split('\n')[:10]  # Max 10 lines
    for line in after_lines:
        if line.strip():
            draw.text((right_card_x + 30, code_y), line, font=font_code, fill=TEXT_DARK + (255,))
        code_y += 48

    # Arrow between cards
    arrow_x = split_x - 40
    arrow_y = card_y + card_h // 2 - 40
    draw.ellipse([arrow_x, arrow_y, arrow_x + 80, arrow_y + 80],
                fill=accent_color + (255,))
    draw.text((arrow_x + 18, arrow_y + 10), "→", font=font_title, fill=BG_WHITE + (255,))

    return start_frame.convert('RGB'), end_frame.convert('RGB')


def create_problem_keyframes(
    problem_number: int,
    title: str,
    problem_text: str,
    difficulty: str,
    accent_color: Tuple[int, int, int]
) -> Tuple[Image.Image, Image.Image]:
    """
    Create problem presentation scene for coding challenges.

    Visual: Professional problem card with difficulty badge and formatted problem description.
    Designed for LeetCode-style coding challenges, algorithm problems, or technical exercises.

    Args:
        problem_number: Problem identifier/number
        title: Problem title (e.g., "Two Sum", "Binary Search")
        problem_text: Full problem description
        difficulty: One of "easy", "medium", or "hard" (affects color coding)
        accent_color: RGB tuple for accent color theme

    Returns:
        Tuple of (start_frame, end_frame) as PIL Image objects in RGB mode

    Example:
        start, end = create_problem_keyframes(
            1,
            "Two Sum",
            "Given an array of integers, return indices of two numbers that add up to target.",
            "easy",
            ACCENT_GREEN
        )
    """
    base = create_base_frame(accent_color)
    start_frame = base.copy()
    end_frame = base.copy()
    draw = ImageDraw.Draw(end_frame, 'RGBA')

    # Difficulty badge
    difficulty_colors = {
        'easy': ACCENT_GREEN,
        'medium': ACCENT_ORANGE,
        'hard': ACCENT_PINK
    }
    diff_color = difficulty_colors.get(difficulty.lower(), CODE_BLUE)

    badge_w, badge_h = 180, 50
    badge_x, badge_y = (WIDTH - badge_w) // 2, 200
    draw.rounded_rectangle([badge_x, badge_y, badge_x + badge_w, badge_y + badge_h],
                          radius=25, fill=diff_color + (40,), outline=diff_color + (200,), width=2)

    diff_text = f"{difficulty.upper()}"
    bbox = draw.textbbox((0, 0), diff_text, font=font_desc)
    w = bbox[2] - bbox[0]
    draw.text(((WIDTH - w) // 2, badge_y + 10), diff_text,
              font=font_desc, fill=diff_color + (255,))

    # Problem number
    prob_num = f"Problem #{problem_number}"
    bbox_num = draw.textbbox((0, 0), prob_num, font=font_small)
    w_num = bbox_num[2] - bbox_num[0]
    draw.text(((WIDTH - w_num) // 2, 280), prob_num,
              font=font_small, fill=TEXT_LIGHT + (200,))

    # Title
    bbox_title = draw.textbbox((0, 0), title, font=font_header)
    w_title = bbox_title[2] - bbox_title[0]
    draw.text(((WIDTH - w_title) // 2, 320), title,
              font=font_header, fill=TEXT_DARK + (255,))

    # Problem card
    card_w = 1400
    card_h = 400
    card_x = (WIDTH - card_w) // 2
    card_y = 440

    draw.rounded_rectangle([card_x, card_y, card_x + card_w, card_y + card_h],
                          radius=20, fill=CARD_BG + (255,))
    draw.rounded_rectangle([card_x, card_y, card_x + card_w, card_y + card_h],
                          radius=20, outline=CARD_SHADOW + (120,), width=2)

    # Problem text (wrap if needed)
    problem_lines = []
    words = problem_text.split()
    current_line = []
    for word in words:
        test_line = ' '.join(current_line + [word])
        bbox = draw.textbbox((0, 0), test_line, font=font_desc)
        if bbox[2] - bbox[0] > card_w - 100:
            problem_lines.append(' '.join(current_line))
            current_line = [word]
        else:
            current_line.append(word)
    if current_line:
        problem_lines.append(' '.join(current_line))

    # Draw problem text
    text_y = card_y + 60
    for line in problem_lines[:8]:  # Max 8 lines
        draw.text((card_x + 50, text_y), line, font=font_desc, fill=TEXT_DARK + (255,))
        text_y += 48

    # Icon
    icon_size = 80
    icon_x, icon_y = card_x + card_w - icon_size - 40, card_y + 40
    draw.ellipse([icon_x, icon_y, icon_x + icon_size, icon_y + icon_size],
                 fill=accent_color + (30,))
    draw.text((icon_x + 20, icon_y + 10), "?", font=font_title, fill=accent_color + (200,))

    return start_frame.convert('RGB'), end_frame.convert('RGB')


def create_solution_keyframes(
    title: str,
    solution_code: list,
    explanation: str,
    accent_color: Tuple[int, int, int]
) -> Tuple[Image.Image, Image.Image]:
    """
    Create solution presentation scene.

    Visual: Code solution with dark theme and optional explanation text below.
    Perfect for showing the answer to coding challenges or demonstrating implementation details.

    Args:
        title: Solution title (e.g., "Optimal Solution", "O(n) Approach")
        solution_code: List of code lines (strings) to display
        explanation: Brief explanation text (can be empty string)
        accent_color: RGB tuple for accent color theme

    Returns:
        Tuple of (start_frame, end_frame) as PIL Image objects in RGB mode

    Example:
        start, end = create_solution_keyframes(
            "Hash Table Solution",
            ["def twoSum(nums, target):", "    seen = {}", "    for i, n in enumerate(nums):"],
            "Time complexity: O(n), Space complexity: O(n)",
            ACCENT_GREEN
        )
    """
    base = create_base_frame(accent_color)
    start_frame = base.copy()
    end_frame = base.copy()
    draw = ImageDraw.Draw(end_frame, 'RGBA')

    # "Solution" badge
    badge_w, badge_h = 200, 50
    badge_x, badge_y = (WIDTH - badge_w) // 2, 180
    draw.rounded_rectangle([badge_x, badge_y, badge_x + badge_w, badge_y + badge_h],
                          radius=25, fill=ACCENT_GREEN + (40,), outline=ACCENT_GREEN + (200,), width=2)

    badge_text = "SOLUTION"
    bbox = draw.textbbox((0, 0), badge_text, font=font_desc)
    w = bbox[2] - bbox[0]
    draw.text(((WIDTH - w) // 2, badge_y + 8), badge_text,
              font=font_desc, fill=ACCENT_GREEN + (255,))

    # Title
    bbox_title = draw.textbbox((0, 0), title, font=font_header)
    w_title = bbox_title[2] - bbox_title[0]
    draw.text(((WIDTH - w_title) // 2, 260), title,
              font=font_header, fill=TEXT_DARK + (255,))

    # Code card
    code_w = 1400
    code_h = 450
    code_x = (WIDTH - code_w) // 2
    code_y = 360

    draw.rounded_rectangle([code_x, code_y, code_x + code_w, code_y + code_h],
                          radius=20, fill=(30, 41, 59) + (255,))  # Dark code bg

    # Solution code
    code_y_text = code_y + 40
    for i, line in enumerate(solution_code[:12]):  # Max 12 lines
        draw.text((code_x + 50, code_y_text + i * 36), line,
                  font=font_code, fill=(226, 232, 240) + (255,))  # Light code text

    # Explanation at bottom
    if explanation:
        exp_y = code_y + code_h + 30
        # Wrap explanation
        exp_words = explanation.split()
        exp_line = []
        for word in exp_words:
            test = ' '.join(exp_line + [word])
            bbox = draw.textbbox((0, 0), test, font=font_small)
            if bbox[2] - bbox[0] > 1200:
                text = ' '.join(exp_line)
                bbox_exp = draw.textbbox((0, 0), text, font=font_small)
                w_exp = bbox_exp[2] - bbox_exp[0]
                draw.text(((WIDTH - w_exp) // 2, exp_y), text,
                          font=font_small, fill=TEXT_GRAY + (255,))
                exp_y += 32
                exp_line = [word]
            else:
                exp_line.append(word)

        if exp_line:
            text = ' '.join(exp_line)
            bbox_exp = draw.textbbox((0, 0), text, font=font_small)
            w_exp = bbox_exp[2] - bbox_exp[0]
            draw.text(((WIDTH - w_exp) // 2, exp_y), text,
                      font=font_small, fill=TEXT_GRAY + (255,))

    return start_frame.convert('RGB'), end_frame.convert('RGB')
