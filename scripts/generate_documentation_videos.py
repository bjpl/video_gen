from PIL import Image, ImageDraw, ImageFont
import subprocess
import os
import shutil

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
    print(f"\n{'='*70}")
    print(f"GENERATING: {video_config['title'].upper()}")
    print(f"{'='*70}\n")

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
        print(f"🎨 Scene {scene_num + 1}: {scene.get('header', scene.get('title', 'Scene'))}...")

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

    print(f"\n📊 Total frames: {len(frame_paths)}")
    print(f"⏱️  Duration: {len(frame_paths) / FPS:.1f}s\n")

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

    print(f"📝 Narration script saved: {narration_script_file}\n")

    print(f"{'='*70}")
    print("ENCODING VIDEO")
    print(f"{'='*70}\n")

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
        print(f"\n✨ Video created: {output_filename}")
        print(f"📦 Size: {file_size / (1024*1024):.1f} MB")
        print(f"⏱️  Duration: {len(frame_paths) / FPS:.1f}s\n")

        shutil.rmtree(temp_dir)
        print("✓ Cleaned up temp files")
    else:
        print("\n❌ Error during encoding")

    return output_filename

if __name__ == "__main__":
    print(f"\n{'='*70}")
    print("DOCUMENTATION VIDEO SERIES GENERATOR")
    print(f"{'='*70}\n")

    print(f"Total videos to generate: {len(VIDEO_DEFINITIONS)}")
    print(f"Estimated total time: ~3 minutes\n")

    generated_videos = []

    for video_name, video_config in VIDEO_DEFINITIONS.items():
        output = generate_video(video_name, video_config)
        generated_videos.append(output)
        print(f"\n{'='*70}\n")

    print(f"{'='*70}")
    print("ALL VIDEOS GENERATED SUCCESSFULLY")
    print(f"{'='*70}\n")

    print("Generated videos:")
    for video in generated_videos:
        if os.path.exists(video):
            size = os.path.getsize(video) / (1024*1024)
            print(f"  ✓ {video} ({size:.1f} MB)")

    print("\n📝 Next step: Generate audio for each video")
    print("    Run: python generate_documentation_audio.py")
    print(f"\n{'='*70}\n")