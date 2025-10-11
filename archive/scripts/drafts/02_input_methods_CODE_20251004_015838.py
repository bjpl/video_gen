"""
Generated Video Code: Three Input Methods
Generated: 2025-10-04 01:58:38
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
            narration="Three Input Methods. Documents, YouTube, or guided wizard - you choose",
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
            narration="Parse existing documentation into professional videos. Run these 2 commands to get started. This gives you Fastest method, Works with GitHub URLs.",
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
            narration="Extract key points from YouTube videos. Run these 2 commands to get started. This gives you Leverage existing content, Create reference videos.",
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
            narration="Build videos from scratch with guided questions. Run these 2 commands to get started. This gives you Perfect for beginners, Full control over content.",
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
            narration="Select the best input method for your content. Key features include Have Documentation?, Found YouTube Video?, and Starting from Scratch?.",
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
            narration="Three Paths, One Result. Choose the method that fits your content source",
            voice="female",
            min_duration=3.0,
            max_duration=15.0
        ),
    ]
)

# Add this VIDEO object to ALL_VIDEOS list in generate_all_videos_unified_v2.py
# Then run: python generate_all_videos_unified_v2.py
