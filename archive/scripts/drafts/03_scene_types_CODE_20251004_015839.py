"""
Generated Video Code: Six Scene Types Explained
Generated: 2025-10-04 01:58:39
"""

from unified_video_system import UnifiedVideo, UnifiedScene
from unified_video_system import ACCENT_PURPLE

VIDEO = UnifiedVideo(
    video_id="03_scene_types",
    title="Six Scene Types Explained",
    description="Visual building blocks for your videos",
    accent_color=ACCENT_PURPLE,
    version="v2.0",
    scenes=[
        UnifiedScene(
            scene_id="scene_01",
            scene_type="title",
            visual_content={
                "title": "Six Scene Types",
                "subtitle": "Visual Building Blocks",
            },
            narration="Six Scene Types. Mix and match to create any video structure",
            voice="male",
            min_duration=3.0,
            max_duration=15.0
        ),
        UnifiedScene(
            scene_id="scene_02",
            scene_type="list",
            visual_content={
                "header": "The Six Scene Types",
                "description": "Complete Visual Arsenal",
                "items": [
                    ('Title', 'Large centered titles for openings and chapters'),
                    ('Command', 'Terminal cards with syntax-highlighted code'),
                    ('List', 'Numbered items with titles and descriptions'),
                    ('Outro', 'Closing screens with call-to-action'),
                    ('Code Comparison', 'Side-by-side before and after code'),
                    ('Quote', 'Centered quotes with attribution'),
                ],
            },
            narration="Every visual layout you need for technical content. Key features include Title, Command, and List. Plus 3 more capabilities.",
            voice="female",
            min_duration=3.0,
            max_duration=15.0
        ),
        UnifiedScene(
            scene_id="scene_03",
            scene_type="code_comparison",
            visual_content={
                "header": "Code Comparison Scene",
                "before_code": "result = []
for x in data:
  if x > 0:
    result.append(x)
",
                "after_code": "result = [x for x in data if x > 0]
",
                "before_label": "Original Code",
                "after_label": "Refactored",
            },
            narration="Code Comparison Scene. List comprehension is more concise and Pythonic",
            voice="male_warm",
            min_duration=3.0,
            max_duration=15.0
        ),
        UnifiedScene(
            scene_id="scene_04",
            scene_type="quote",
            visual_content={
                "quote_text": "The right scene type makes complex topics clear and engaging",
                "attribution": "Video Gen Design Principle",
            },
            narration="Choosing the appropriate visual layout. The right scene type makes complex topics clear and engaging As Video Gen Design Principle said.",
            voice="female_friendly",
            min_duration=3.0,
            max_duration=15.0
        ),
        UnifiedScene(
            scene_id="scene_05",
            scene_type="command",
            visual_content={
                "header": "Using Scene Types in YAML",
                "description": "Simple Configuration",
                "commands": [
                    "scenes:",
                    "  - type: title",
                    "  - type: command",
                    "  - type: code_comparison",
                    "  - type: quote",
                    "  - type: list",
                    "  - type: outro",
                ],
            },
            narration="Define scene types in your YAML input files. Run these 7 commands to get started. This gives you Mix any combination, Each type has specific fields.",
            voice="male",
            min_duration=3.0,
            max_duration=15.0
        ),
        UnifiedScene(
            scene_id="scene_06",
            scene_type="outro",
            visual_content={
                "main_text": "Build Any Video Structure",
                "sub_text": "NEW_SCENE_TYPES_GUIDE.md",
            },
            narration="Build Any Video Structure. Six scene types cover ninety nine percent of technical content",
            voice="male",
            min_duration=3.0,
            max_duration=15.0
        ),
    ]
)

# Add this VIDEO object to ALL_VIDEOS list in generate_all_videos_unified_v2.py
# Then run: python generate_all_videos_unified_v2.py
