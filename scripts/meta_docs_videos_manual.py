"""
Meta-Documentation Videos - Manual Creation
============================================
Uses the AI-generated narration from the SCRIPT files
Handles multi-line narration properly
"""

import sys
import asyncio
import logging

# Setup logging
logger = logging.getLogger(__name__)

sys.path.append('.')

from unified_video_system import (
    UnifiedVideo, UnifiedScene,
    ACCENT_CYAN, ACCENT_BLUE, ACCENT_PURPLE
)

# Video 1: System Introduction (AI-generated narration)
VIDEO_01 = UnifiedVideo(
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
            narration="Video Gen is a comprehensive production system for creating professional videos efficiently. The system offers three flexible input methods, six distinct scene types for creative control, four professional voice options for engaging narration, and perfect audio sync to eliminate timing issues. These integrated features work seamlessly together for polished results.",
            voice="female",
            min_duration=10.0,
            max_duration=60.0
        ),
        UnifiedScene(
            scene_id="scene_03",
            scene_type="quote",
            visual_content={
                "quote_text": "From idea to professional video in minutes, not hours",
                "attribution": "Video Gen Philosophy",
            },
            narration="This philosophy captures the essence of modern video creation. From idea to professional video in minutes, not hours. The Video Gen Philosophy.",
            voice="male_warm",
            min_duration=6.0,
            max_duration=12.0
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
            narration="Watch how just four simple commands generate professional video content automatically. Run these in sequence and see immediate high-quality results with minimal effort.",
            voice="female",
            min_duration=8.0,
            max_duration=15.0
        ),
        UnifiedScene(
            scene_id="scene_05",
            scene_type="outro",
            visual_content={
                "main_text": "Ready to Create Videos?",
                "sub_text": "See GETTING_STARTED.md",
            },
            narration="Ready to create videos? Your journey to professional video creation starts here. Check out getting started dot M D to begin transforming your ideas into compelling visual stories today.",
            voice="male",
            min_duration=6.0,
            max_duration=12.0
        ),
    ]
)

# Video 2: Three Input Methods (condensed AI narration for demo)
VIDEO_02 = UnifiedVideo(
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
            narration="Three input methods. Documents, YouTube, or guided wizard. You choose the path that fits your workflow.",
            voice="female",
            min_duration=5.0,
            max_duration=10.0
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
                    "→ Ready in 30 seconds",
                ],
            },
            narration="Parse existing documentation into professional videos. The document parser automatically extracts structure, headings, code blocks and lists. Works with local files or GitHub URLs for maximum flexibility.",
            voice="male",
            min_duration=10.0,
            max_duration=18.0
        ),
        UnifiedScene(
            scene_id="scene_03",
            scene_type="command",
            visual_content={
                "header": "Method 2: YouTube Transcription",
                "description": "Condense Long Tutorials",
                "commands": [
                    "$ python create_video.py --youtube-url 'URL'",
                    "# Fetches transcript, analyzes content",
                    "→ 60-second summary ready",
                ],
            },
            narration="Extract key points from YouTube videos. Fetch transcripts, analyze segments intelligently, and create concise reference videos from lengthy tutorials.",
            voice="female",
            min_duration=10.0,
            max_duration=18.0
        ),
        UnifiedScene(
            scene_id="scene_04",
            scene_type="command",
            visual_content={
                "header": "Method 3: Interactive Wizard",
                "description": "Guided Creation",
                "commands": [
                    "$ python create_video.py --wizard",
                    "# Answer guided questions",
                    "→ Professional script generated",
                ],
            },
            narration="Build videos from scratch with our interactive wizard. Answer simple questions about your content and the system generates professional narration automatically. Perfect for beginners.",
            voice="male_warm",
            min_duration=10.0,
            max_duration=18.0
        ),
        UnifiedScene(
            scene_id="scene_05",
            scene_type="outro",
            visual_content={
                "main_text": "Three Paths, One Result",
                "sub_text": "See Documentation",
            },
            narration="Three paths, one result. Choose the input method that fits your content source and workflow.",
            voice="female",
            min_duration=5.0,
            max_duration=10.0
        ),
    ]
)

# Video 3: Scene Types (condensed)
VIDEO_03 = UnifiedVideo(
    video_id="03_scene_types",
    title="Six Scene Types Explained",
    description="Visual building blocks",
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
            narration="Six scene types. Mix and match to create any video structure you need.",
            voice="male",
            min_duration=4.0,
            max_duration=8.0
        ),
        UnifiedScene(
            scene_id="scene_02",
            scene_type="list",
            visual_content={
                "header": "The Six Scene Types",
                "description": "Complete Visual Arsenal",
                "items": [
                    ('Title', 'Large centered titles'),
                    ('Command', 'Terminal cards with code'),
                    ('List', 'Numbered items'),
                    ('Outro', 'Closing call-to-action'),
                    ('Code Comparison', 'Side-by-side before and after'),
                    ('Quote', 'Centered quotes with attribution'),
                ],
            },
            narration="Every visual layout you need for technical content. Title scenes for openings, command scenes for code examples, list scenes for features, outro scenes for closing, code comparison for refactoring examples, and quote scenes for important principles.",
            voice="female",
            min_duration=12.0,
            max_duration=20.0
        ),
        UnifiedScene(
            scene_id="scene_03",
            scene_type="code_comparison",
            visual_content={
                "header": "Code Comparison Scene",
                "before_code": "result = []\nfor x in data:\n  if x > 0:\n    result.append(x)\n",
                "after_code": "result = [x for x in data if x > 0]\n",
                "before_label": "Original",
                "after_label": "Refactored",
            },
            narration="Code comparison scenes show before and after examples. List comprehension is more concise and Pythonic. Perfect for refactoring tutorials and best practices.",
            voice="male_warm",
            min_duration=8.0,
            max_duration=15.0
        ),
        UnifiedScene(
            scene_id="scene_04",
            scene_type="quote",
            visual_content={
                "quote_text": "The right scene type makes complex topics clear and engaging",
                "attribution": "Video Gen Design",
            },
            narration="Choosing the appropriate visual layout matters. The right scene type makes complex topics clear and engaging. A core Video Gen design principle.",
            voice="female_friendly",
            min_duration=6.0,
            max_duration=12.0
        ),
        UnifiedScene(
            scene_id="scene_05",
            scene_type="outro",
            visual_content={
                "main_text": "Build Any Structure",
                "sub_text": "NEW_SCENE_TYPES_GUIDE.md",
            },
            narration="Build any video structure. Six scene types cover ninety nine percent of technical content needs.",
            voice="male",
            min_duration=5.0,
            max_duration=10.0
        ),
    ]
)

ALL_VIDEOS = [VIDEO_01, VIDEO_02, VIDEO_03]

async def main():
    logger.info("\n" + "="*80)
    logger.info("META-DOCUMENTATION VIDEOS - AI-ENHANCED NARRATION")
    logger.info("="*80 + "\n")

    import os
    output_dir = "../audio/unified_system_v2"
    reports_dir = f"{output_dir}/reports"
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)

    for i, video in enumerate(ALL_VIDEOS, 1):
        logger.info(f"\n{'#'*80}")
        logger.info(f"# VIDEO {i}/{len(ALL_VIDEOS)}: {video.title}")
        logger.info(f"{'#'*80}\n")

        # Validation
        video.validate()
        video.save_validation_report(reports_dir)

        # Audio generation
        await video.generate_audio_with_timing(output_dir)

        # Timing report
        video.generate_timing_report()
        video.save_metadata_manifest(reports_dir)

    logger.info("\n" + "="*80)
    logger.info("✓ AUDIO COMPLETE FOR ALL 3 VIDEOS")
    logger.info("="*80 + "\n")

    total = sum(v.total_duration for v in ALL_VIDEOS)
    logger.info(f"Total duration: {total:.1f}s ({total/60:.1f} minutes)")
    logger.info("\nNext: python generate_videos_from_timings_v3_simple.py\n")

if __name__ == "__main__":
    asyncio.run(main())
