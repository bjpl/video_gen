"""
Educational scene rendering functions for video generation.

This module provides specialized rendering functions for educational content including:
- Quiz questions with multiple choice options
- Learning objectives for lessons and courses
- Practice exercises with instructions

All functions follow the keyframe animation pattern, returning start and end frames
that can be interpolated for smooth animations.
"""

from typing import List, Dict, Any, Tuple, Union
from PIL import Image, ImageDraw

from .constants import (
    WIDTH, HEIGHT,
    BG_WHITE, ACCENT_PURPLE, ACCENT_GREEN, ACCENT_ORANGE, ACCENT_PINK,
    TEXT_DARK, TEXT_GRAY, TEXT_LIGHT, CARD_BG, CARD_SHADOW
)
from .base import create_base_frame


# Font imports - these should be available from the main script's font loading
# In a full refactor, fonts would be loaded in a centralized location
try:
    from PIL import ImageFont
    font_header = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", 64)
    font_desc = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 38)
    font_subtitle = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 48)
    font_small = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 28)
    font_tiny = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 24)
except Exception:
    # Fallback to default font if system fonts unavailable
    font_header = ImageFont.load_default()
    font_desc = ImageFont.load_default()
    font_subtitle = ImageFont.load_default()
    font_small = ImageFont.load_default()
    font_tiny = ImageFont.load_default()


__all__ = [
    'create_quiz_keyframes',
    'create_learning_objectives_keyframes',
    'create_exercise_keyframes'
]


def create_quiz_keyframes(
    question: str,
    options: List[str],
    correct_answer: str,
    show_answer: bool,
    accent_color: Tuple[int, int, int]
) -> Tuple[Image.Image, Image.Image]:
    """
    Create quiz question scene with multiple choice options.

    Visual design features:
    - Purple "QUIZ" badge at top
    - Question text in accent-colored card
    - Four options in 2x2 grid layout
    - Correct answer highlighted in green when show_answer is True
    - Checkmark appears on correct answer when revealed

    Args:
        question: The quiz question text (auto-wrapped to fit card width)
        options: List of 4 answer options (supports up to 4)
        correct_answer: The correct answer string (must match one option exactly)
        show_answer: Whether to reveal the correct answer with highlighting
        accent_color: RGB tuple for the accent color (e.g., ACCENT_BLUE)

    Returns:
        Tuple of (start_frame, end_frame) as PIL Image objects in RGB mode

    Example:
        >>> start, end = create_quiz_keyframes(
        ...     "What is the capital of France?",
        ...     ["London", "Paris", "Berlin", "Madrid"],
        ...     "Paris",
        ...     show_answer=True,
        ...     accent_color=ACCENT_BLUE
        ... )
    """
    base = create_base_frame(accent_color)
    start_frame = base.copy()
    end_frame = base.copy()
    draw = ImageDraw.Draw(end_frame, 'RGBA')

    # "Quiz" badge
    badge_w, badge_h = 160, 50
    badge_x, badge_y = (WIDTH - badge_w) // 2, 180
    draw.rounded_rectangle([badge_x, badge_y, badge_x + badge_w, badge_y + badge_h],
                          radius=25, fill=ACCENT_PURPLE + (40,), outline=ACCENT_PURPLE + (200,), width=2)

    badge_text = "QUIZ"
    bbox = draw.textbbox((0, 0), badge_text, font=font_desc)
    w = bbox[2] - bbox[0]
    draw.text(((WIDTH - w) // 2, badge_y + 8), badge_text,
              font=font_desc, fill=ACCENT_PURPLE + (255,))

    # Question card
    card_w = 1400
    card_h = 140
    card_x = (WIDTH - card_w) // 2
    card_y = 270

    draw.rounded_rectangle([card_x, card_y, card_x + card_w, card_y + card_h],
                          radius=15, fill=accent_color + (20,))

    # Question text
    q_lines = []
    words = question.split()
    current_line = []
    for word in words:
        test_line = ' '.join(current_line + [word])
        bbox = draw.textbbox((0, 0), test_line, font=font_desc)
        if bbox[2] - bbox[0] > card_w - 100:
            q_lines.append(' '.join(current_line))
            current_line = [word]
        else:
            current_line.append(word)
    if current_line:
        q_lines.append(' '.join(current_line))

    q_y = card_y + 30
    for line in q_lines[:3]:  # Max 3 lines for question
        bbox_q = draw.textbbox((0, 0), line, font=font_desc)
        w_q = bbox_q[2] - bbox_q[0]
        draw.text(((WIDTH - w_q) // 2, q_y), line,
                  font=font_desc, fill=TEXT_DARK + (255,))
        q_y += 42

    # Options (4 boxes in 2x2 grid)
    opt_w, opt_h = 650, 100
    opt_spacing = 50
    opt_start_x = (WIDTH - (opt_w * 2 + opt_spacing)) // 2
    opt_start_y = 460

    for i, option in enumerate(options[:4]):  # Max 4 options
        row = i // 2
        col = i % 2
        opt_x = opt_start_x + col * (opt_w + opt_spacing)
        opt_y = opt_start_y + row * (opt_h + opt_spacing)

        # Highlight correct answer if showing
        if show_answer and option == correct_answer:
            opt_color = ACCENT_GREEN
            opt_bg = ACCENT_GREEN + (30,)
        else:
            opt_color = accent_color
            opt_bg = CARD_BG + (255,)

        draw.rounded_rectangle([opt_x, opt_y, opt_x + opt_w, opt_y + opt_h],
                              radius=12, fill=opt_bg)
        draw.rounded_rectangle([opt_x, opt_y, opt_x + opt_w, opt_y + opt_h],
                              radius=12, outline=opt_color + (150,), width=2)

        # Option text (truncate if needed)
        opt_text = option[:50] + "..." if len(option) > 50 else option
        draw.text((opt_x + 20, opt_y + 30), opt_text,
                  font=font_desc, fill=TEXT_DARK + (255,))

        # Checkmark for correct answer
        if show_answer and option == correct_answer:
            draw.text((opt_x + opt_w - 60, opt_y + 20), "✓",
                      font=font_header, fill=ACCENT_GREEN + (255,))

    return start_frame.convert('RGB'), end_frame.convert('RGB')


def create_learning_objectives_keyframes(
    lesson_title: str,
    objectives: List[Union[str, Dict[str, Any]]],
    lesson_info: Dict[str, Any],
    accent_color: Tuple[int, int, int]
) -> Tuple[Image.Image, Image.Image]:
    """
    Create learning objectives scene for lesson introduction.

    Visual design features:
    - "Learning Objectives" header at top
    - Lesson title and metadata (duration, difficulty, prerequisites)
    - Numbered objectives in a clean card layout
    - Up to 8 objectives displayed

    Args:
        lesson_title: Title of the lesson/course
        objectives: List of learning objectives (strings or dicts with 'objective' key)
        lesson_info: Dict containing optional keys:
            - 'duration': Lesson duration in minutes (int)
            - 'difficulty': Difficulty level ('easy', 'medium', 'hard')
            - 'prerequisites': List of prerequisite topics
        accent_color: RGB tuple for the accent color

    Returns:
        Tuple of (start_frame, end_frame) as PIL Image objects in RGB mode

    Example:
        >>> start, end = create_learning_objectives_keyframes(
        ...     "Python Fundamentals",
        ...     [
        ...         "Understand variables and data types",
        ...         "Master control flow structures",
        ...         "Write functions and modules"
        ...     ],
        ...     {"duration": 45, "difficulty": "medium", "prerequisites": ["Intro to Programming"]},
        ...     ACCENT_BLUE
        ... )
    """
    base = create_base_frame(accent_color)
    start_frame = base.copy()
    end_frame = base.copy()
    draw = ImageDraw.Draw(end_frame, 'RGBA')

    # "Learning Objectives" header
    header_text = "Learning Objectives"
    bbox_header = draw.textbbox((0, 0), header_text, font=font_header)
    w_header = bbox_header[2] - bbox_header[0]
    draw.text(((WIDTH - w_header) // 2, 180), header_text,
              font=font_header, fill=accent_color + (255,))

    # Lesson title
    bbox_lesson = draw.textbbox((0, 0), lesson_title, font=font_subtitle)
    w_lesson = bbox_lesson[2] - bbox_lesson[0]
    draw.text(((WIDTH - w_lesson) // 2, 260), lesson_title,
              font=font_subtitle, fill=TEXT_GRAY + (255,))

    # Lesson info bar (duration, difficulty, etc.)
    if lesson_info:
        info_y = 320
        info_parts = []
        if 'duration' in lesson_info:
            info_parts.append(f"⏱ {lesson_info['duration']} min")
        if 'difficulty' in lesson_info:
            info_parts.append(f"📊 {lesson_info['difficulty'].title()}")
        if 'prerequisites' in lesson_info and lesson_info['prerequisites']:
            prereq_count = len(lesson_info['prerequisites'])
            info_parts.append(f"📚 {prereq_count} prerequisite(s)")

        info_text = "  •  ".join(info_parts)
        bbox_info = draw.textbbox((0, 0), info_text, font=font_small)
        w_info = bbox_info[2] - bbox_info[0]
        draw.text(((WIDTH - w_info) // 2, info_y), info_text,
                  font=font_small, fill=TEXT_LIGHT + (200,))

    # Objectives card
    card_w = 1200
    card_h = 450
    card_x = (WIDTH - card_w) // 2
    card_y = 380

    draw.rounded_rectangle([card_x, card_y, card_x + card_w, card_y + card_h],
                          radius=20, fill=CARD_BG + (255,))
    draw.rounded_rectangle([card_x, card_y, card_x + card_w, card_y + card_h],
                          radius=20, outline=accent_color + (120,), width=2)

    # Objectives list
    obj_y = card_y + 50
    for i, objective in enumerate(objectives[:8]):  # Max 8 objectives
        # Numbered circle
        circle_size = 40
        circle_x = card_x + 50
        circle_y = obj_y + 5

        draw.ellipse([circle_x, circle_y, circle_x + circle_size, circle_y + circle_size],
                     fill=accent_color + (40,))

        num_text = str(i + 1)
        bbox_num = draw.textbbox((0, 0), num_text, font=font_small)
        w_num = bbox_num[2] - bbox_num[0]
        draw.text((circle_x + (circle_size - w_num) // 2, circle_y + 8), num_text,
                  font=font_small, fill=accent_color + (255,))

        # Objective text
        if isinstance(objective, dict):
            obj_text = objective.get('objective', str(objective))
        else:
            obj_text = str(objective)

        # Truncate if too long
        obj_text = obj_text[:70] + "..." if len(obj_text) > 70 else obj_text

        draw.text((card_x + 110, obj_y + 8), obj_text,
                  font=font_desc, fill=TEXT_DARK + (255,))

        obj_y += 52

    return start_frame.convert('RGB'), end_frame.convert('RGB')


def create_exercise_keyframes(
    title: str,
    instructions: List[str],
    difficulty: str,
    estimated_time: str,
    accent_color: Tuple[int, int, int]
) -> Tuple[Image.Image, Image.Image]:
    """
    Create practice exercise instructions scene.

    Visual design features:
    - "Practice Exercise" header
    - Exercise title with difficulty and time badges
    - Numbered instruction steps in a card
    - Color-coded difficulty badges (green/orange/pink)

    Args:
        title: Exercise title/name
        instructions: List of instruction steps (up to 8 displayed)
        difficulty: Difficulty level ('easy', 'medium', 'hard')
        estimated_time: Estimated completion time (e.g., "30 min", "1 hour")
        accent_color: RGB tuple for the accent color

    Returns:
        Tuple of (start_frame, end_frame) as PIL Image objects in RGB mode

    Example:
        >>> start, end = create_exercise_keyframes(
        ...     "Build a Todo List App",
        ...     [
        ...         "Create the HTML structure",
        ...         "Style with CSS",
        ...         "Add JavaScript functionality",
        ...         "Test in browser"
        ...     ],
        ...     difficulty="medium",
        ...     estimated_time="45 min",
        ...     accent_color=ACCENT_BLUE
        ... )
    """
    base = create_base_frame(accent_color)
    start_frame = base.copy()
    end_frame = base.copy()
    draw = ImageDraw.Draw(end_frame, 'RGBA')

    # "Practice Exercise" header
    header_text = "Practice Exercise"
    bbox_header = draw.textbbox((0, 0), header_text, font=font_header)
    w_header = bbox_header[2] - bbox_header[0]
    draw.text(((WIDTH - w_header) // 2, 160), header_text,
              font=font_header, fill=accent_color + (255,))

    # Title
    bbox_title = draw.textbbox((0, 0), title, font=font_subtitle)
    w_title = bbox_title[2] - bbox_title[0]
    draw.text(((WIDTH - w_title) // 2, 240), title,
              font=font_subtitle, fill=TEXT_GRAY + (255,))

    # Difficulty + Time badges
    info_y = 300
    badges = []
    if difficulty:
        badges.append((difficulty.upper(), difficulty))
    if estimated_time:
        badges.append((f"⏱ {estimated_time}", 'time'))

    badge_spacing = 20
    total_badge_w = sum([150 for _ in badges]) + badge_spacing * (len(badges) - 1)
    badge_x = (WIDTH - total_badge_w) // 2

    for badge_text, badge_type in badges:
        badge_w, badge_h = 150, 40

        if badge_type in ['easy', 'medium', 'hard']:
            colors = {'easy': ACCENT_GREEN, 'medium': ACCENT_ORANGE, 'hard': ACCENT_PINK}
            badge_color = colors.get(badge_type, accent_color)
        else:
            badge_color = accent_color

        draw.rounded_rectangle([badge_x, info_y, badge_x + badge_w, info_y + badge_h],
                              radius=20, fill=badge_color + (30,))

        bbox_b = draw.textbbox((0, 0), badge_text, font=font_tiny)
        w_b = bbox_b[2] - bbox_b[0]
        draw.text((badge_x + (badge_w - w_b) // 2, info_y + 10), badge_text,
                  font=font_tiny, fill=badge_color + (255,))

        badge_x += badge_w + badge_spacing

    # Instructions card
    card_w = 1300
    card_h = 500
    card_x = (WIDTH - card_w) // 2
    card_y = 380

    draw.rounded_rectangle([card_x, card_y, card_x + card_w, card_y + card_h],
                          radius=20, fill=CARD_BG + (255,))
    draw.rounded_rectangle([card_x, card_y, card_x + card_w, card_y + card_h],
                          radius=20, outline=accent_color + (120,), width=2)

    # Instructions header
    inst_header = "Instructions:"
    draw.text((card_x + 40, card_y + 30), inst_header,
              font=font_desc, fill=accent_color + (255,))

    # Instruction steps
    inst_y = card_y + 90
    for i, instruction in enumerate(instructions[:8]):  # Max 8 instructions
        # Step number
        step_num = f"{i + 1}."
        draw.text((card_x + 50, inst_y), step_num,
                  font=font_desc, fill=accent_color + (255,))

        # Instruction text (truncate if needed)
        inst_text = instruction[:80] + "..." if len(instruction) > 80 else instruction
        draw.text((card_x + 100, inst_y), inst_text,
                  font=font_desc, fill=TEXT_DARK + (255,))

        inst_y += 52

    return start_frame.convert('RGB'), end_frame.convert('RGB')
