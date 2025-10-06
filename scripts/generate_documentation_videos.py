from PIL import Image, ImageDraw, ImageFont
import subprocess
import os
import shutil
import logging

# Setup logging
logger = logging.getLogger(__name__)

WIDTH, HEIGHT = 1920, 1080
FPS = 30

BG_LIGHT = (245, 248, 252)
BG_WHITE = (255, 255, 255)
ACCENT_ORANGE = (255, 107, 53)
ACCENT_BLUE = (59, 130, 246)
ACCENT_PURPLE = (139, 92, 246)
ACCENT_GREEN = (16, 185, 129)
ACCENT_PINK = (236, 72, 153)
ACCENT_CYAN = (34, 211, 238)
TEXT_DARK = (15, 23, 42)
TEXT_GRAY = (100, 116, 139)
TEXT_LIGHT = (148, 163, 184)
CODE_BLUE = (59, 130, 246)
CARD_BG = (255, 255, 255)
CARD_SHADOW = (203, 213, 225)

font_title = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", 120)
font_subtitle = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 48)
font_header = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", 64)
font_desc = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 38)
font_code = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 32)
font_small = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 28)
font_tiny = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 24)

def ease_out_cubic(t):
    return 1 - pow(1 - t, 3)

def create_modern_mesh_bg(width, height, accent_color):
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

def create_base_frame(accent_color):
    img = create_modern_mesh_bg(WIDTH, HEIGHT, accent_color).convert('RGBA')
    draw = ImageDraw.Draw(img, 'RGBA')

    draw.rectangle([0, 0, 12, HEIGHT], fill=accent_color + (255,))
    draw.rectangle([0, HEIGHT-12, WIDTH, HEIGHT], fill=accent_color + (120,))

    logo_size = 60
    logo_x, logo_y = WIDTH - 120, HEIGHT - 90
    draw.rounded_rectangle([logo_x, logo_y, logo_x + logo_size, logo_y + logo_size],
                          radius=12, fill=accent_color + (255,))
    draw.text((logo_x + 12, logo_y + 8), "CC", font=font_subtitle, fill=BG_WHITE + (255,))

    return img

def create_title_keyframes(title, subtitle, accent_color):
    base = create_base_frame(accent_color)
    start_frame = base.copy()
    end_frame = base.copy()
    draw = ImageDraw.Draw(end_frame, 'RGBA')

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

    bbox = draw.textbbox((0, 0), title, font=font_title)
    w = bbox[2] - bbox[0]
    x = (WIDTH - w) // 2
    draw.text((x, 380), title, font=font_title, fill=TEXT_DARK + (255,))

    draw.rectangle([x, 520, x + w, 526], fill=accent_color + (255,))

    bbox2 = draw.textbbox((0, 0), subtitle, font=font_subtitle)
    w2 = bbox2[2] - bbox2[0]
    x2 = (WIDTH - w2) // 2
    draw.text((x2, 560), subtitle, font=font_subtitle, fill=TEXT_GRAY + (255,))

    return start_frame.convert('RGB'), end_frame.convert('RGB')

def create_command_keyframes(header, description, commands, accent_color):
    base = create_base_frame(accent_color)
    start_frame = base.copy()
    draw = ImageDraw.Draw(start_frame, 'RGBA')

    icon_size = 80
    icon_x = 120
    icon_y = 90
    draw.rounded_rectangle([icon_x, icon_y, icon_x + icon_size, icon_y + icon_size],
                          radius=16, fill=accent_color + (40,), outline=accent_color + (200,), width=3)
    draw.text((icon_x + 18, icon_y + 12), "❯", font=font_title, fill=accent_color + (255,))

    header_x = icon_x + icon_size + 30
    draw.text((header_x, 100), header, font=font_header, fill=TEXT_DARK + (255,))
    draw.text((header_x, 180), description, font=font_desc, fill=TEXT_GRAY + (255,))

    end_frame = start_frame.copy()
    draw = ImageDraw.Draw(end_frame, 'RGBA')

    card_w, card_h = 1400, 580
    card_x, card_y = (WIDTH - card_w) // 2, 320

    draw.rounded_rectangle(
        [card_x + 6, card_y + 6, card_x + card_w + 6, card_y + card_h + 6],
        radius=20, fill=CARD_SHADOW + (100,)
    )
    draw.rounded_rectangle([card_x, card_y, card_x + card_w, card_y + card_h],
                          radius=20, fill=CARD_BG + (255,))

    header_bar_h = 50
    draw.rounded_rectangle([card_x, card_y, card_x + card_w, card_y + header_bar_h],
                          radius=20, fill=accent_color + (30,))
    draw.line([(card_x, card_y + header_bar_h), (card_x + card_w, card_y + header_bar_h)],
             fill=accent_color + (100,), width=2)

    dot_y = card_y + 18
    for i, dot_color in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        dot_x = card_x + 30 + (i * 30)
        draw.ellipse([dot_x, dot_y, dot_x + 14, dot_y + 14], fill=dot_color + (255,))

    code_y = card_y + header_bar_h + 50
    for line in commands:
        if line.strip():
            if line.startswith('$') or line.startswith('python'):
                prompt_x = card_x + 50
                draw.text((prompt_x, code_y), "❯", font=font_code, fill=accent_color + (255,))
                draw.text((prompt_x + 30, code_y), line[2:] if line.startswith('$ ') else line,
                         font=font_code, fill=CODE_BLUE + (255,))
            elif line.startswith('→'):
                draw.text((card_x + 50, code_y), "→", font=font_code, fill=ACCENT_GREEN + (255,))
                draw.text((card_x + 80, code_y), line[2:], font=font_code, fill=TEXT_DARK + (255,))
            elif line.startswith('✓'):
                draw.text((card_x + 50, code_y), line, font=font_code, fill=ACCENT_GREEN + (255,))
            elif line.startswith('#'):
                draw.text((card_x + 50, code_y), line, font=font_code, fill=TEXT_LIGHT + (255,))
            elif line.startswith('-'):
                draw.ellipse([card_x + 55, code_y + 12, card_x + 63, code_y + 20],
                           fill=accent_color + (255,))
                draw.text((card_x + 75, code_y), line[2:], font=font_small, fill=TEXT_GRAY + (255,))
            else:
                draw.text((card_x + 50, code_y), line, font=font_small, fill=TEXT_GRAY + (255,))
        code_y += 48

    return start_frame.convert('RGB'), end_frame.convert('RGB')

def create_list_keyframes(header, description, items, accent_color):
    base = create_base_frame(accent_color)
    start_frame = base.copy()
    draw = ImageDraw.Draw(start_frame, 'RGBA')

    icon_size = 80
    icon_x = 120
    icon_y = 90
    draw.rounded_rectangle([icon_x, icon_y, icon_x + icon_size, icon_y + icon_size],
                          radius=16, fill=accent_color + (40,), outline=accent_color + (200,), width=3)
    draw.text((icon_x + 14, icon_y + 8), "☰", font=font_title, fill=accent_color + (255,))

    header_x = icon_x + icon_size + 30
    draw.text((header_x, 100), header, font=font_header, fill=TEXT_DARK + (255,))
    draw.text((header_x, 180), description, font=font_desc, fill=TEXT_GRAY + (255,))

    end_frame = start_frame.copy()
    draw = ImageDraw.Draw(end_frame, 'RGBA')

    card_w, card_h = 1400, 620
    card_x, card_y = (WIDTH - card_w) // 2, 300

    draw.rounded_rectangle(
        [card_x + 6, card_y + 6, card_x + card_w + 6, card_y + card_h + 6],
        radius=20, fill=CARD_SHADOW + (100,)
    )
    draw.rounded_rectangle([card_x, card_y, card_x + card_w, card_y + card_h],
                          radius=20, fill=CARD_BG + (255,))

    list_y = card_y + 60
    for i, item in enumerate(items, 1):
        item_card_x = card_x + 40
        item_card_w = card_w - 80
        item_card_h = 85 if isinstance(item, tuple) else 65

        draw.rounded_rectangle([item_card_x, list_y, item_card_x + item_card_w, list_y + item_card_h],
                              radius=12, fill=accent_color + (15,), outline=accent_color + (80,), width=1)

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

        text_x = number_x + number_size + 24

        if isinstance(item, tuple):
            title, desc = item
            draw.text((text_x, list_y + 12), title, font=font_desc, fill=TEXT_DARK + (255,))
            draw.text((text_x, list_y + 48), desc, font=font_small, fill=TEXT_GRAY + (255,))
            list_y += item_card_h + 18
        else:
            draw.text((text_x, list_y + 18), item, font=font_desc, fill=TEXT_DARK + (255,))
            list_y += item_card_h + 18

    return start_frame.convert('RGB'), end_frame.convert('RGB')

def create_outro_keyframes(main_text, sub_text, accent_color):
    base = create_base_frame(accent_color)
    start_frame = base.copy()
    end_frame = base.copy()
    draw = ImageDraw.Draw(end_frame, 'RGBA')

    check_size = 100
    check_x = (WIDTH - check_size) // 2
    check_y = 320
    draw.ellipse([check_x, check_y, check_x + check_size, check_y + check_size],
                fill=accent_color + (40,), outline=accent_color + (255,), width=4)
    draw.text((check_x + 18, check_y + 10), "✓", font=font_title, fill=accent_color + (255,))

    bbox = draw.textbbox((0, 0), main_text, font=font_header)
    w = bbox[2] - bbox[0]
    x = (WIDTH - w) // 2
    draw.text((x, 450), main_text, font=font_header, fill=TEXT_DARK + (255,))

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

def create_code_comparison_keyframes(header, before_code, after_code, accent_color, before_label="Before", after_label="After"):
    """
    Create side-by-side code comparison scene
    Visual: Split screen with before/after code blocks
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

def create_quote_keyframes(quote_text, attribution, accent_color):
    """
    Create quote/callout scene
    Visual: Large centered quote with attribution
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


def create_problem_keyframes(problem_number, title, problem_text, difficulty, accent_color):
    """Create problem presentation scene (for coding challenges)"""
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
    diff_color = difficulty_colors.get(difficulty.lower(), ACCENT_BLUE)

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


def create_solution_keyframes(title, solution_code, explanation, accent_color):
    """Create solution presentation scene"""
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


def create_checkpoint_keyframes(checkpoint_num, completed_topics, review_questions, next_topics, accent_color):
    """Create learning checkpoint/progress scene"""
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


def create_quiz_keyframes(question, options, correct_answer, show_answer, accent_color):
    """Create quiz question scene"""
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


def create_learning_objectives_keyframes(lesson_title, objectives, lesson_info, accent_color):
    """Create learning objectives scene"""
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


def create_exercise_keyframes(title, instructions, difficulty, estimated_time, accent_color):
    """Create exercise instructions scene"""
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


VIDEO_DEFINITIONS = {
    "quick_reference": {
        "filename": "doc_video_01_quick_reference.mp4",
        "title": "Quick Reference Guide",
        "accent": ACCENT_ORANGE,
        "voice_mode": "single",
        "scenes": [
            {
                "type": "title",
                "duration": 4,
                "title": "Quick Reference",
                "subtitle": "5-Minute Workflow Commands",
                "narration": "Quick reference guide. Your five minute workflow for creating professional demo videos."
            },
            {
                "type": "command",
                "duration": 8,
                "header": "Complete Workflow",
                "description": "Generate Video with Audio in 40 Seconds",
                "commands": [
                    "$ cd claude_code_demos",
                    "$ python generate_narration_audio.py",
                    "$ cd scripts",
                    "$ python generate_video_with_audio.py",
                    "",
                    "→ Output: Full HD video with narration"
                ],
                "narration": "Run four simple commands to generate your complete video with professional audio narration. The entire process takes about forty seconds on GPU-enabled systems."
            },
            {
                "type": "command",
                "duration": 7,
                "header": "Individual Components",
                "description": "Generate Audio or Video Separately",
                "commands": [
                    "# Generate audio only",
                    "$ python generate_narration_audio.py",
                    "",
                    "# Generate video only",
                    "$ python generate_video_with_audio.py",
                    "",
                    "→ Modular generation for flexibility"
                ],
                "narration": "Generate audio and video separately for maximum flexibility. Create alternate voice options or modify video settings independently."
            },
            {
                "type": "list",
                "duration": 7,
                "header": "Voice Mix Modes",
                "description": "Choose Your Narration Style",
                "items": [
                    ("Single Voice", "One professional narrator"),
                    ("Varied Voices", "Alternating male and female"),
                    ("All Male", "Two male narrators"),
                    ("All Female", "Two female narrators")
                ],
                "narration": "Choose from four voice mix modes. Single voice for consistency, varied voices for engagement, or gender-specific options to match your brand."
            },
            {
                "type": "outro",
                "duration": 4,
                "main_text": "Fast. Simple. Powerful.",
                "sub_text": "See QUICK_REFERENCE.md",
                "narration": "Fast, simple, and powerful. See quick reference dot M D for complete command documentation."
            }
        ]
    },
    "troubleshooting": {
        "filename": "doc_video_02_troubleshooting.mp4",
        "title": "Troubleshooting Guide",
        "accent": ACCENT_BLUE,
        "voice_mode": "single",
        "scenes": [
            {
                "type": "title",
                "duration": 4,
                "title": "Troubleshooting",
                "subtitle": "Common Issues & Solutions",
                "narration": "Troubleshooting guide. Solving common issues in video generation workflows."
            },
            {
                "type": "list",
                "duration": 9,
                "header": "Quick Diagnosis",
                "description": "Check Your System Setup",
                "items": [
                    ("Audio Not Generated", "Check internet connection"),
                    ("Video Encoding Fails", "Verify FFmpeg installation"),
                    ("GPU Not Detected", "Update NVIDIA drivers"),
                    ("Out of Sync", "Regenerate audio files")
                ],
                "narration": "Start with quick diagnosis. The most common issues are missing audio files due to internet connectivity, encoding failures from FFmpeg setup, GPU detection problems requiring driver updates, and sync issues fixed by regenerating audio."
            },
            {
                "type": "command",
                "duration": 8,
                "header": "Verification Commands",
                "description": "Test Your Environment",
                "commands": [
                    "# Check dependencies",
                    "$ python -c \"from PIL import Image; print('OK')\"",
                    "$ python -c \"import edge_tts; print('OK')\"",
                    "",
                    "# Check GPU",
                    "$ nvidia-smi",
                    "$ ffmpeg -version | grep nvenc"
                ],
                "narration": "Use these verification commands to test your environment. Check Python dependencies for pillow and edge T T S, then verify GPU availability and FFmpeg N V E N C support."
            },
            {
                "type": "command",
                "duration": 7,
                "header": "Emergency Recovery",
                "description": "Complete Reset Procedure",
                "commands": [
                    "# Clean and regenerate",
                    "$ rm -rf audio/* temp_frames_audio/",
                    "$ pip install --upgrade pillow edge-tts",
                    "",
                    "$ python generate_narration_audio.py",
                    "$ cd scripts && python generate_video_with_audio.py"
                ],
                "narration": "If all else fails, use the emergency recovery procedure. Clean all temporary files, upgrade dependencies, and regenerate from scratch. This resolves ninety percent of persistent issues."
            },
            {
                "type": "list",
                "duration": 7,
                "header": "Performance Tips",
                "description": "Optimize Generation Speed",
                "items": [
                    ("Use GPU Encoding", "128x faster than CPU"),
                    ("Reduce Frame Rate", "Lower FPS = faster render"),
                    ("Close Other Apps", "Free GPU memory"),
                    ("Check Internet Speed", "For audio generation")
                ],
                "narration": "Optimize performance with these tips. GPU encoding is one hundred twenty eight times faster than CPU. Reduce frame rate for quicker renders. Close other applications to free GPU memory. Ensure fast internet for audio generation."
            },
            {
                "type": "outro",
                "duration": 4,
                "main_text": "Solutions at Your Fingertips",
                "sub_text": "See TROUBLESHOOTING.md",
                "narration": "Solutions at your fingertips. See troubleshooting dot M D for comprehensive problem-solving guides."
            }
        ]
    },
    "complete_workflow": {
        "filename": "doc_video_03_complete_workflow.mp4",
        "title": "Complete Workflow",
        "accent": ACCENT_PURPLE,
        "voice_mode": "varied",
        "scenes": [
            {
                "type": "title",
                "duration": 4,
                "title": "Complete Workflow",
                "subtitle": "End-to-End Production Guide",
                "narration": "Complete workflow guide. Your end to end production guide for professional demo videos.",
                "voice": "male_andrew"
            },
            {
                "type": "list",
                "duration": 10,
                "header": "Six Production Phases",
                "description": "From Concept to Final Video",
                "items": [
                    ("Planning & Design", "Define objectives and visual system"),
                    ("Video Creation", "Generate animated frames"),
                    ("Script Writing", "Craft professional narration"),
                    ("Audio Generation", "Create T T S voice tracks"),
                    ("Integration", "Merge video and audio"),
                    ("Quality Control", "Validate final output")
                ],
                "narration": "The workflow has six production phases. Planning and design to define your objectives. Video creation to generate animated frames. Script writing for professional narration. Audio generation using text to speech. Integration to merge everything together. And quality control to validate the final output.",
                "voice": "female_aria"
            },
            {
                "type": "command",
                "duration": 8,
                "header": "Phase 1: Planning",
                "description": "Set Up Project Structure",
                "commands": [
                    "# Create directory structure",
                    "$ mkdir -p videos audio scripts",
                    "",
                    "# Define design system",
                    "- Color palette: Dark theme with accent colors",
                    "- Typography: Arial family for consistency",
                    "- Layout: 1920x1080 Full HD resolution"
                ],
                "narration": "Phase one is planning. Create your directory structure for videos, audio, and scripts. Define your design system including color palette with dark theme and accent colors, typography using the Arial family, and layout at nineteen twenty by ten eighty Full H D resolution.",
                "voice": "male_brandon"
            },
            {
                "type": "command",
                "duration": 8,
                "header": "Phase 2: Video Creation",
                "description": "Generate Animated Frames with GPU",
                "commands": [
                    "# Key techniques",
                    "- Keyframe interpolation (95% efficiency)",
                    "- Cubic easing for smooth animation",
                    "- PIL/Pillow for frame generation",
                    "- GPU encoding with NVENC (128x faster)",
                    "",
                    "$ python generate_video_v3.0_animated.py"
                ],
                "narration": "Phase two is video creation. Use keyframe interpolation for ninety five percent efficiency gain. Apply cubic easing for smooth animations. Use P I L pillow for fast frame generation. Enable GPU encoding with N V E N C for one hundred twenty eight times speed improvement.",
                "voice": "female_ava"
            },
            {
                "type": "command",
                "duration": 8,
                "header": "Phase 3 & 4: Script & Audio",
                "description": "Professional Narration Generation",
                "commands": [
                    "# Write engaging script",
                    "- 135 words per minute pacing",
                    "- Conversational, professional tone",
                    "- Scene-by-scene timing",
                    "",
                    "# Generate audio with Edge-TTS",
                    "$ python generate_narration_audio.py",
                    "→ Neural TTS with 4 voice options"
                ],
                "narration": "Phases three and four cover script writing and audio generation. Write engaging scripts at one hundred thirty five words per minute. Use conversational yet professional tone with scene by scene timing. Generate audio using Edge T T S with neural network voices. Four voice options provide flexibility.",
                "voice": "male_andrew"
            },
            {
                "type": "command",
                "duration": 8,
                "header": "Phase 5 & 6: Integration & QC",
                "description": "Merge and Validate Final Output",
                "commands": [
                    "# Integrate video + audio",
                    "$ python generate_video_with_audio.py",
                    "",
                    "# Quality control checklist",
                    "✓ Audio syncs perfectly",
                    "✓ Visual quality is crisp",
                    "✓ Transitions are smooth",
                    "✓ File size is optimized"
                ],
                "narration": "Phases five and six are integration and quality control. Run the integration script to merge video and audio with frame perfect synchronization. Validate your output with the quality control checklist. Verify audio sync, visual clarity, smooth transitions, and optimized file size.",
                "voice": "female_aria"
            },
            {
                "type": "list",
                "duration": 8,
                "header": "Performance Metrics",
                "description": "Production Timeline",
                "items": [
                    ("Audio Generation", "10 seconds"),
                    ("Video Rendering", "25 seconds"),
                    ("GPU Encoding", "15 seconds"),
                    ("Total Time", "~40 seconds")
                ],
                "narration": "Here are the performance metrics. Audio generation takes ten seconds. Video rendering takes twenty five seconds. GPU encoding adds fifteen seconds. Total production time is approximately forty seconds for a one minute professional video.",
                "voice": "male_brandon"
            },
            {
                "type": "outro",
                "duration": 4,
                "main_text": "Professional Video Production",
                "sub_text": "See COMPLETE_WORKFLOW.md",
                "narration": "Professional video production made simple. See complete workflow dot M D for the full guide.",
                "voice": "female_ava"
            }
        ]
    },
    "audio_deep_dive": {
        "filename": "doc_video_04_audio_deep_dive.mp4",
        "title": "Audio Documentation",
        "accent": ACCENT_GREEN,
        "voice_mode": "varied",
        "scenes": [
            {
                "type": "title",
                "duration": 4,
                "title": "Audio Deep Dive",
                "subtitle": "Professional Voice Generation",
                "narration": "Audio deep dive. Mastering professional voice generation with open source text to speech.",
                "voice": "male_andrew"
            },
            {
                "type": "list",
                "duration": 8,
                "header": "Voice Options",
                "description": "Four Neural TTS Voices",
                "items": [
                    ("Andrew (Male)", "Confident, Professional"),
                    ("Brandon (Male)", "Warm, Engaging"),
                    ("Aria (Female)", "Crisp, Clear"),
                    ("Ava (Female)", "Friendly, Pleasant")
                ],
                "narration": "Four neural network voices are available. Andrew provides confident professional narration. Brandon offers warm engaging delivery. Aria delivers crisp clear technical content. Ava provides friendly pleasant onboarding experiences.",
                "voice": "female_aria"
            },
            {
                "type": "command",
                "duration": 8,
                "header": "Audio Generation",
                "description": "Create TTS Files with Edge-TTS",
                "commands": [
                    "# Install Edge-TTS",
                    "$ pip install edge-tts",
                    "",
                    "# Generate default voice",
                    "$ python generate_narration_audio.py",
                    "",
                    "# Generate all voices",
                    "$ python generate_alternate_voices.py"
                ],
                "narration": "Generate audio in three steps. Install edge T T S from python package index. Run generate narration audio for the default voice. Or run generate alternate voices to create all four voice options simultaneously.",
                "voice": "male_brandon"
            },
            {
                "type": "list",
                "duration": 8,
                "header": "Technical Specifications",
                "description": "Audio Quality Details",
                "items": [
                    ("Format", "MP3, 24 kHz mono"),
                    ("Engine", "Microsoft Edge TTS"),
                    ("Quality", "Neural network voices"),
                    ("File Size", "20-80 KB per scene")
                ],
                "narration": "Technical specifications ensure high quality. Audio format is M P three at twenty four kilohertz mono. The engine is Microsoft Edge T T S with free A P I access. Quality is neural network based for natural speech. File sizes range from twenty to eighty kilobytes per scene.",
                "voice": "female_ava"
            },
            {
                "type": "command",
                "duration": 8,
                "header": "Customization",
                "description": "Adjust Speaking Rate and Volume",
                "commands": [
                    "# Edit generation script",
                    "RATE = \"+20%\"   # 20% faster",
                    "RATE = \"-15%\"   # 15% slower",
                    "RATE = \"+0%\"    # Normal speed",
                    "",
                    "VOLUME = \"+10%\" # Louder",
                    "VOLUME = \"-5%\"  # Quieter"
                ],
                "narration": "Customize audio parameters easily. Adjust speaking rate with plus or minus percentages. Increase rate for faster delivery. Decrease for slower pacing. Modify volume up or down to match your requirements.",
                "voice": "male_andrew"
            },
            {
                "type": "command",
                "duration": 8,
                "header": "Voice Selection",
                "description": "Explore Available Voices",
                "commands": [
                    "# List all available voices",
                    "$ edge-tts --list-voices | grep \"en-US\"",
                    "",
                    "# Test a voice",
                    "$ edge-tts --voice en-US-AndrewNeural \\",
                    "           --text \"Test audio\" \\",
                    "           --write-media test.mp3"
                ],
                "narration": "Explore voice selection options. List all available English U S voices with the edge T T S command. Test any voice before committing to full generation. This ensures you choose the perfect narrator for your content.",
                "voice": "female_aria"
            },
            {
                "type": "outro",
                "duration": 4,
                "main_text": "Studio-Quality Narration",
                "sub_text": "See AUDIO_README.md",
                "narration": "Achieve studio quality narration. See audio readme dot M D for complete documentation.",
                "voice": "male_brandon"
            }
        ]
    },
    "documentation_index": {
        "filename": "doc_video_00_master_index.mp4",
        "title": "Documentation Index",
        "accent": ACCENT_PINK,
        "voice_mode": "single",
        "scenes": [
            {
                "type": "title",
                "duration": 4,
                "title": "Documentation Hub",
                "subtitle": "Complete Video Series Guide",
                "narration": "Documentation hub. Your complete guide to the Claude Code demo video production series."
            },
            {
                "type": "list",
                "duration": 10,
                "header": "Video Series Overview",
                "description": "5 Videos Covering Complete Workflow",
                "items": [
                    ("Quick Reference", "5-minute workflow commands"),
                    ("Troubleshooting", "Common issues and solutions"),
                    ("Complete Workflow", "End-to-end production guide"),
                    ("Audio Deep Dive", "Professional voice generation"),
                    ("Master Index", "This video")
                ],
                "narration": "This video series includes five comprehensive guides. Quick reference provides five minute workflow commands. Troubleshooting covers common issues and solutions. Complete workflow offers an end to end production guide. Audio deep dive explores professional voice generation. And master index, this video, ties everything together."
            },
            {
                "type": "list",
                "duration": 9,
                "header": "Documentation Files",
                "description": "10 Markdown Guides Available",
                "items": [
                    ("README", "Project overview"),
                    ("QUICK_REFERENCE", "Command cheat sheet"),
                    ("TROUBLESHOOTING", "Problem solving"),
                    ("COMPLETE_WORKFLOW", "Full guide"),
                    ("AUDIO_README", "Audio documentation")
                ],
                "narration": "Ten markdown documentation files support this project. README provides the project overview. Quick reference offers a command cheat sheet. Troubleshooting delivers problem solving guidance. Complete workflow contains the full production guide. Audio readme documents voice generation. Plus five additional specialized guides."
            },
            {
                "type": "outro",
                "duration": 4,
                "main_text": "Everything You Need",
                "sub_text": "Professional Video Production",
                "narration": "Everything you need for professional video production. Start with any guide based on your experience level."
            }
        ]
    }
}

def generate_video(video_name, video_config):
    logger.info(f"\n{'='*70}")
    logger.info(f"GENERATING: {video_config['title'].upper()}")
    logger.info(f"{'='*70}\n")

    scenes = video_config['scenes']
    accent = video_config['accent']

    TRANSITION_DURATION = 0.5
    ANIM_DURATION = 1.0
    trans_frames = int(TRANSITION_DURATION * FPS)
    anim_frames = int(ANIM_DURATION * FPS)

    temp_dir = f"temp_{video_name}"
    os.makedirs(temp_dir, exist_ok=True)

    frame_paths = []
    frame_idx = 0

    for scene_num, scene in enumerate(scenes):
        logger.info(f"🎨 Scene {scene_num + 1}: {scene.get('header', scene.get('title', 'Scene'))}...")

        if scene['type'] == 'title':
            start_frame, end_frame = create_title_keyframes(
                scene['title'], scene['subtitle'], accent
            )
        elif scene['type'] == 'command':
            start_frame, end_frame = create_command_keyframes(
                scene['header'], scene['description'], scene['commands'], accent
            )
        elif scene['type'] == 'list':
            start_frame, end_frame = create_list_keyframes(
                scene['header'], scene['description'], scene['items'], accent
            )
        elif scene['type'] == 'outro':
            start_frame, end_frame = create_outro_keyframes(
                scene['main_text'], scene['sub_text'], accent
            )

        for i in range(anim_frames):
            progress = ease_out_cubic(i / anim_frames)
            blended = Image.blend(start_frame, end_frame, progress)
            filename = f"{temp_dir}/frame_{frame_idx:05d}.png"
            blended.save(filename, "PNG", optimize=True)
            frame_paths.append(filename)
            frame_idx += 1

        hold_frames = scene['duration'] * FPS - anim_frames
        for _ in range(hold_frames):
            frame_paths.append(filename)

        if scene_num < len(scenes) - 1:
            next_scene = scenes[scene_num + 1]
            if next_scene['type'] == 'title':
                next_start, _ = create_title_keyframes(
                    next_scene['title'], next_scene['subtitle'], accent
                )
            elif next_scene['type'] == 'command':
                next_start, _ = create_command_keyframes(
                    next_scene['header'], next_scene['description'], next_scene['commands'], accent
                )
            elif next_scene['type'] == 'list':
                next_start, _ = create_list_keyframes(
                    next_scene['header'], next_scene['description'], next_scene['items'], accent
                )
            elif next_scene['type'] == 'outro':
                next_start, _ = create_outro_keyframes(
                    next_scene['main_text'], next_scene['sub_text'], accent
                )

            for i in range(trans_frames):
                progress = i / trans_frames
                blended = Image.blend(end_frame, next_start, progress)
                filename = f"{temp_dir}/frame_{frame_idx:05d}.png"
                blended.save(filename, "PNG", optimize=True)
                frame_paths.append(filename)
                frame_idx += 1

    logger.info(f"\n📊 Total frames: {len(frame_paths)}")
    logger.info(f"⏱️  Duration: {len(frame_paths) / FPS:.1f}s\n")

    concat_file = f"{temp_dir}/concat.txt"
    with open(concat_file, 'w') as f:
        for fp in frame_paths:
            f.write(f"file '{os.path.abspath(fp)}'\n")
            f.write("duration 0.0333333\n")

    narration_script_file = f"{temp_dir}/narration_script.txt"
    with open(narration_script_file, 'w') as f:
        for i, scene in enumerate(scenes, 1):
            f.write(f"Scene {i}: {scene.get('header', scene.get('title', 'Scene'))}\n")
            f.write(f"{scene['narration']}\n\n")

    logger.info(f"📝 Narration script saved: {narration_script_file}\n")

    logger.info(f"{'='*70}")
    logger.info("ENCODING VIDEO")
    logger.info(f"{'='*70}\n")

    output_filename = video_config['filename']

    ffmpeg_cmd = [
        "C:/Users/brand/AppData/Local/Programs/Python/Python310/lib/site-packages/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe",
        "-y", "-f", "concat", "-safe", "0", "-i", concat_file,
        "-c:v", "h264_nvenc", "-preset", "fast", "-gpu", "0",
        "-rc", "vbr", "-cq", "20", "-b:v", "8M",
        "-pix_fmt", "yuv420p",
        output_filename
    ]

    result = subprocess.run(ffmpeg_cmd, capture_output=False, text=True)

    if result.returncode == 0:
        file_size = os.path.getsize(output_filename)
        logger.info(f"\n✨ Video created: {output_filename}")
        logger.info(f"📦 Size: {file_size / (1024*1024):.1f} MB")
        logger.info(f"⏱️  Duration: {len(frame_paths) / FPS:.1f}s\n")

        shutil.rmtree(temp_dir)
        logger.info("✓ Cleaned up temp files")
    else:
        logger.error("\n❌ Error during encoding")

    return output_filename

if __name__ == "__main__":
    logger.info(f"\n{'='*70}")
    logger.info("DOCUMENTATION VIDEO SERIES GENERATOR")
    logger.info(f"{'='*70}\n")

    logger.info(f"Total videos to generate: {len(VIDEO_DEFINITIONS)}")
    logger.info(f"Estimated total time: ~3 minutes\n")

    generated_videos = []

    for video_name, video_config in VIDEO_DEFINITIONS.items():
        output = generate_video(video_name, video_config)
        generated_videos.append(output)
        logger.info(f"\n{'='*70}\n")

    logger.info(f"{'='*70}")
    logger.info("ALL VIDEOS GENERATED SUCCESSFULLY")
    logger.info(f"{'='*70}\n")

    logger.info("Generated videos:")
    for video in generated_videos:
        if os.path.exists(video):
            size = os.path.getsize(video) / (1024*1024)
            logger.info(f"  ✓ {video} ({size:.1f} MB)")

    logger.info("\n📝 Next step: Generate audio for each video")
    logger.info("    Run: python generate_documentation_audio.py")
    logger.info(f"\n{'='*70}\n")