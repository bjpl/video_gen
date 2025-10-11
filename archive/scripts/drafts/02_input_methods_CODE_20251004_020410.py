"""
Generated Video Code: Three Input Methods
Generated: 2025-10-04 02:04:10
"""

from unified_video_system import UnifiedVideo, UnifiedScene
from unified_video_system import ACCENT_BLUE

VIDEO = UnifiedVideo(
    video_id="02_input_methods",
    title="Three Input Methods",
    description="Create videos from any source",
    accent_color=ACCENT_BLUE,
    version="v2.0",
    scenes=[
        UnifiedScene(
            scene_id="scene_01",
            scene_type="title",
            visual_content={
                "title": "Three Input Methods",
                "subtitle": "Choose Your Content Source",
            },
            narration="Choose your content source with three powerful input methods. Whether you're working with documents, YouTube videos, or prefer our guided wizard, the choice is yours.",
            voice="female",
            min_duration=3.0,
            max_duration=15.0
        ),
        UnifiedScene(
            scene_id="scene_02",
            scene_type="command",
            visual_content={
                "header": "Method 1: Document Parser",
                "description": "From README to Video in 30 Seconds",
                "commands": [
                    "$ python create_video.py --document README.md",
                    "# Parses structure automatically",
                    "# Extracts headings, code, lists",
                    "# Generates YAML and narration",
                    "→ Ready to generate in 30 seconds",
                ],
            },
            narration="Let's explore the fastest way to transform your existing documentation into professional videos using our document parser method.

This powerful approach works seamlessly with GitHub URLs and any existing documentation you already have, making it incredibly efficient.

We'll run through five simple commands that will automatically parse your content and generate polished video tutorials in minutes.

The beauty of this method is that it leverages all the hard work you've already put into creating documentation, instantly converting it into engaging visual content.

Watch as we execute each command and see how quickly your written guides become professional video presentations perfect for training and tutorials.",
            voice="male",
            min_duration=3.0,
            max_duration=15.0
        ),
        UnifiedScene(
            scene_id="scene_03",
            scene_type="command",
            visual_content={
                "header": "Method 2: YouTube Transcription",
                "description": "Condense Long Tutorials to Summaries",
                "commands": [
                    "$ python create_video.py --youtube-url 'VIDEO_URL'",
                    "# Fetches video transcript",
                    "# Analyzes segments",
                    "# Extracts key points",
                    "→ 60-second summary from 15-minute video",
                ],
            },
            narration="Now let's explore Method 2: YouTube Transcription, where we'll run five powerful commands to extract valuable insights. This approach lets you leverage existing content, create helpful reference videos, and efficiently summarize those lengthy tutorials. Watch as we execute these commands to transform any YouTube video into organized, actionable key points you can actually use.",
            voice="female",
            min_duration=3.0,
            max_duration=15.0
        ),
        UnifiedScene(
            scene_id="scene_04",
            scene_type="command",
            visual_content={
                "header": "Method 3: Interactive Wizard",
                "description": "Guided Step-by-Step Creation",
                "commands": [
                    "$ python create_video.py --wizard",
                    "# What's your video about?",
                    "# What topics to cover?",
                    "# What commands to show?",
                    "→ Professional script generated from your answers",
                ],
            },
            narration="Method three offers an interactive wizard that's perfect for beginners who want full control. Simply run these five guided commands to build professional videos through an intuitive question and answer interface.",
            voice="male_warm",
            min_duration=3.0,
            max_duration=15.0
        ),
        UnifiedScene(
            scene_id="scene_05",
            scene_type="list",
            visual_content={
                "header": "Choose the Right Method",
                "description": "Decision Guide",
                "items": [
                    ('Have Documentation?', 'Use document parser (fastest)'),
                    ('Found YouTube Video?', 'Use transcription fetcher'),
                    ('Starting from Scratch?', 'Use interactive wizard'),
                ],
            },
            narration="Selecting the right input method is crucial for creating effective content. Let's explore three key approaches to help you make the best choice.

First, ask yourself: do you have existing documentation? If you already possess written materials, guides, or reference documents, these can serve as an excellent foundation for your content creation process.

Next, consider whether you've found a relevant YouTube video. Video content can provide valuable insights, demonstrations, or explanations that might perfectly align with your project goals and save significant development time.

Finally, evaluate if you're starting completely from scratch. This approach offers maximum creative control and customization, allowing you to build content that precisely matches your specific requirements and vision.

Each method has distinct advantages depending on your timeline",
            voice="female_friendly",
            min_duration=3.0,
            max_duration=15.0
        ),
        UnifiedScene(
            scene_id="scene_06",
            scene_type="outro",
            visual_content={
                "main_text": "Three Paths, One Result",
                "sub_text": "THREE_INPUT_METHODS_GUIDE.md",
            },
            narration="Whether you're working with URLs, files, or direct text input, all three methods deliver the same powerful results. Each path is designed to seamlessly integrate with your existing workflow, so you can focus on what matters most - creating exceptional content.

The choice is yours - pick the input method that best matches your content source and get started today. Your documentation transformation journey begins with a single click.",
            voice="female",
            min_duration=3.0,
            max_duration=15.0
        ),
    ]
)

# Add this VIDEO object to ALL_VIDEOS list in generate_all_videos_unified_v2.py
# Then run: python generate_all_videos_unified_v2.py
