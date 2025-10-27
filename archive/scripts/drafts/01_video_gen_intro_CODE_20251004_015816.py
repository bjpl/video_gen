"""
Generated Video Code: Video Gen - System Introduction
Generated: 2025-10-04 01:58:16
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
            narration="Video Gen. Create videos from any source in minutes",
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
            narration="A production-ready system for creating professional videos. Key features include Three Input Methods, Six Scene Types, and Four Professional Voices. Plus 1 more capabilities.",
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
            narration="The core promise of the system. From idea to professional video in minutes, not hours As Video Gen Philosophy said.",
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
            narration="See how easy it is to create professional videos. Run these 4 commands to get started. This gives you Four simple commands, Automated generation.",
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
            narration="Ready to Create Videos?. Your journey to professional video creation starts here",
            voice="male",
            min_duration=3.0,
            max_duration=15.0
        ),
    ]
)

# Add this VIDEO object to ALL_VIDEOS list in generate_all_videos_unified_v2.py
# Then run: python generate_all_videos_unified_v2.py
