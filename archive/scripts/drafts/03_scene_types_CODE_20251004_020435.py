"""
Generated Video Code: Six Scene Types Explained
Generated: 2025-10-04 02:04:35
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
            narration="Every video tells a story through six fundamental scene types. Master these visual building blocks, and you can mix and match them to create any video structure you need.",
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
            narration="When creating technical content, choosing the right visual layout makes all the difference for audience engagement. Let's explore the six essential scene types every technical creator should master.

First, the Title scene establishes your topic and sets professional expectations. Command scenes demonstrate specific actions or instructions with clear visual focus. List scenes, like this one, organize multiple related concepts for easy comprehension.

Outro scenes provide strong conclusions and clear next steps for your audience. Code Comparison scenes highlight differences between approaches, making complex technical concepts immediately understandable.

Each scene type serves a specific purpose in technical storytelling. By strategically combining these layouts, you'll create content that's both informative and visually compelling, keeping your audience engaged throughout your entire presentation",
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
            narration="Here we can see how list comprehension transforms four lines of verbose code into a single, elegant expression. This Pythonic approach maintains identical functionality while dramatically improving readability and reducing code complexity.",
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
            narration="As Video Gen's design principle wisely states: "The right scene type makes complex topics clear and engaging." This fundamental truth guides effective visual communication.",
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
            narration="Let's explore how to define different scene types in your YAML input files for maximum flexibility. Each scene type offers unique fields and capabilities that you can mix and match to create dynamic presentations. Watch as we run through seven essential commands that demonstrate how to structure your YAML files effectively. You'll discover how each scene type serves specific purposes while maintaining consistency across your project. These powerful configurations enable auto-generated narration and seamless scene transitions. By mastering these YAML structures, you'll streamline your workflow and create more engaging content effortlessly.",
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
            narration="You now have the complete framework to build any video structure. Six versatile scene types that handle ninety-nine percent of your technical content needs.

Whether you're explaining complex concepts, demonstrating procedures, or guiding viewers through processes, these building blocks give you the foundation for clear, engaging videos every time.

The NEW_SCENE_TYPES_GUIDE documentation contains detailed examples and implementation strategies for each scene type. Use it as your reference when planning your next project.

Remember, great technical videos aren't about perfection—they're about clarity and connection with your audience.

Start building your next video structure today. Your viewers are waiting.",
            voice="male",
            min_duration=3.0,
            max_duration=15.0
        ),
    ]
)

# Add this VIDEO object to ALL_VIDEOS list in generate_all_videos_unified_v2.py
# Then run: python generate_all_videos_unified_v2.py
