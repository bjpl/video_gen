"""
Generated Video Code: Video Gen - System Introduction
Generated: 2025-10-04 02:03:25
"""

from unified_video_system import UnifiedVideo, UnifiedScene
from unified_video_system import ACCENT_CYAN

VIDEO = UnifiedVideo(
    video_id="01_video_gen_intro",
    title="Video Gen - System Introduction",
    description="Professional video production from any source",
    accent_color=ACCENT_CYAN,
    version="v2.0",
    scenes=[
        UnifiedScene(
            scene_id="scene_01",
            scene_type="title",
            visual_content={
                "title": "Video Gen",
                "subtitle": "Professional Video Production System",
            },
            narration="Transform any content into professional videos instantly with Video Gen.",
            voice="male",
            min_duration=3.0,
            max_duration=15.0
        ),
        UnifiedScene(
            scene_id="scene_02",
            scene_type="list",
            visual_content={
                "header": "What is Video Gen?",
                "description": "Complete Automated Workflow",
                "items": [
                    ('Three Input Methods', 'Documents, YouTube, or Interactive Wizard'),
                    ('Six Scene Types', 'Title, command, list, outro, code comparison, quote'),
                    ('Four Professional Voices', 'Neural TTS with male and female options'),
                    ('Perfect Audio Sync', 'Audio-first architecture guarantees synchronization'),
                ],
            },
            narration="Video Gen is a comprehensive production system designed for creating professional-quality videos efficiently. Let's explore the key features that make this platform so powerful.

The system offers three flexible input methods to accommodate different workflow preferences and content types. You can choose from six distinct scene types, giving you complete creative control over your video's structure and visual presentation.

Audio quality is enhanced through four professional voice options, each carefully selected to deliver clear, engaging narration for your content. The platform ensures perfect audio sync throughout your entire production, eliminating timing issues that can compromise video quality.

These integrated features work seamlessly together, providing everything you need to produce polished, professional videos from start to finish.",
            voice="female",
            min_duration=3.0,
            max_duration=15.0
        ),
        UnifiedScene(
            scene_id="scene_03",
            scene_type="quote",
            visual_content={
                "quote_text": "From idea to professional video in minutes, not hours",
                "attribution": "Video Gen Philosophy",
            },
            narration="This philosophy captures the essence of modern video creation: "From idea to professional video in minutes, not hours" - the Video Gen Philosophy.",
            voice="male_warm",
            min_duration=3.0,
            max_duration=15.0
        ),
        UnifiedScene(
            scene_id="scene_04",
            scene_type="command",
            visual_content={
                "header": "Quick Example",
                "description": "Create Video in One Command",
                "commands": [
                    "$ python create_video.py --wizard",
                    "# Answer a few questions",
                    "$ python generate_all_videos_unified_v2.py",
                    "$ python generate_videos_from_timings_v3_simple.py",
                    "→ Professional video ready!",
                ],
            },
            narration="Watch how just five simple commands can generate professional video content automatically. Run these commands in sequence and see immediate, high-quality results with minimal effort required.",
            voice="female",
            min_duration=3.0,
            max_duration=15.0
        ),
        UnifiedScene(
            scene_id="scene_05",
            scene_type="outro",
            visual_content={
                "main_text": "Ready to Create Videos?",
                "sub_text": "See GETTING_STARTED.md",
            },
            narration="Ready to create videos? Your journey to professional video creation starts here. Check out GETTING_STARTED.md to begin transforming your ideas into compelling visual stories today.",
            voice="male",
            min_duration=3.0,
            max_duration=15.0
        ),
    ]
)

# Add this VIDEO object to ALL_VIDEOS list in generate_all_videos_unified_v2.py
# Then run: python generate_all_videos_unified_v2.py
