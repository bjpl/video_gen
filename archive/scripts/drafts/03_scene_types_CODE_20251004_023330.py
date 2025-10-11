"""
Generated Video Code: Six Scene Types Explained
Generated: 2025-10-04 02:33:30
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
            narration="Every video consists of six fundamental scene types. These components combine to form any video structure.",
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
            narration="Technical content requires specific visual layouts to communicate information effectively. These six scene types provide the structural foundation for clear documentation presentation.

The title scene establishes context and introduces the main topic or section. Command scenes demonstrate specific instructions or procedures that users need to execute. List scenes organize related items or concepts in a structured, scannable format. Outro scenes provide closure and transition to subsequent content sections. Code comparison scenes display multiple code examples side by side for direct analysis. Each scene type serves a distinct function in technical communication, allowing content creators to match visual structure to information purpose. Proper scene selection ensures documentation remains accessible and logically organized for technical audiences.",
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
            narration="The traditional for-loop approach requires four lines to iterate and append elements to a list. List comprehension consolidates this operation into a single expression, reducing code length while maintaining identical functionality.",
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
            narration="When selecting visual layouts for technical content, one key design principle states: "The right scene type makes complex topics clear and engaging" - Video Gen Design Principle.",
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
            narration="YAML scene types define different content structures for your input files. Each scene type contains specific required and optional fields that determine how content gets processed.

You can mix multiple scene types within a single YAML file. The processor identifies each type by its designated field structure and applies the appropriate parsing logic.

Command scenes require action and target fields. Dialog scenes need speaker and text parameters. Narrative scenes use description fields for contextual content.

Scene type validation occurs during file parsing. Invalid field combinations trigger error messages with specific correction guidance. This prevents runtime failures during content generation.

Auto-generated narration pulls from scene metadata when text fields are empty. The system creates appropriate transitions between different scene types to maintain content flow consistency.

Define custom",
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
            narration="These six scene types handle most technical video content. Check NEW_SCENE_TYPES_GUIDE.md for implementation details.",
            voice="male",
            min_duration=3.0,
            max_duration=15.0
        ),
    ]
)

# Add this VIDEO object to ALL_VIDEOS list in generate_all_videos_unified_v2.py
# Then run: python generate_all_videos_unified_v2.py
