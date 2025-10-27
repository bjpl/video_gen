"""
Generated Video Code: Video Gen - System Introduction
Generated: 2025-10-04 02:30:33
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
            narration="Video Gen is a video production system that converts source materials into finished videos. The system processes multiple input formats and generates output within minutes.",
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
            narration="Video Gen is a production system that converts input content into professional video output. The system provides four core capabilities that handle content creation and audio processing.

Three Input Methods allow content submission through text entry, script upload, or API integration. Each method processes the input data and converts it into the system's internal format for video generation.

Six Scene Types define the visual layout and presentation structure of the generated video. These templates include presentation slides, talking head format, screen recording overlay, split screen, full screen graphics, and picture-in-picture configurations.

Four Professional Voices provide narration options with different vocal characteristics and speaking styles. The voice synthesis engine generates audio tracks that match the input text with consistent pronunciation and pacing.

Perfect Audio",
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
            narration="The system's design philosophy centers on efficiency and speed. As stated in the Video Gen Philosophy: "From idea to professional video in minutes, not hours.",
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
            narration="Here's a basic workflow using five commands to generate video content programmatically. Each command handles a specific part of the pipeline: initializing the project, setting video parameters, adding content elements, applying rendering settings, and executing the build process. The system automates template selection, asset processing, and output formatting to produce standard video files without manual editing steps.",
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
            narration="Ready to create videos? See GETTING_STARTED.md for setup instructions and implementation details.",
            voice="male",
            min_duration=3.0,
            max_duration=15.0
        ),
    ]
)

# Add this VIDEO object to ALL_VIDEOS list in generate_all_videos_unified_v2.py
# Then run: python generate_all_videos_unified_v2.py
