"""
Meta-Documentation Videos - Technical Narration
================================================
Uses AI-generated technical/educational narration (not marketing)
Updated with improved prompts for factual, educational tone
"""

import sys
import asyncio
sys.path.append('.')

from unified_video_system import (
    UnifiedVideo, UnifiedScene,
    ACCENT_CYAN, ACCENT_BLUE, ACCENT_PURPLE
)

# Video 1: System Introduction (Technical narration)
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
            narration="Video Gen is a video production system that converts source materials into finished videos. The system processes multiple input formats and generates output within minutes.",
            voice="male",
            min_duration=5.0,
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
            narration="Video Gen provides four core capabilities. Three input methods handle document parsing, YouTube transcript extraction, and interactive content creation. Six scene types define visual layouts for titles, commands, lists, outros, code comparisons, and quotes. Four neural TTS voices generate narration. The audio-first architecture ensures synchronization by measuring audio duration before video generation.",
            voice="female",
            min_duration=15.0,
            max_duration=25.0
        ),
        UnifiedScene(
            scene_id="scene_03",
            scene_type="quote",
            visual_content={
                "quote_text": "From idea to professional video in minutes, not hours",
                "attribution": "Video Gen Philosophy",
            },
            narration="The system's design focuses on speed and automation. From idea to professional video in minutes, not hours. This is the Video Gen design philosophy.",
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
            narration="The basic workflow uses four commands. The wizard collects input through interactive prompts. Generate all videos unified creates audio files with TTS and measures durations. Generate videos from timings renders frames and encodes the final output.",
            voice="female",
            min_duration=10.0,
            max_duration=18.0
        ),
        UnifiedScene(
            scene_id="scene_05",
            scene_type="outro",
            visual_content={
                "main_text": "Ready to Create Videos?",
                "sub_text": "See GETTING_STARTED.md",
            },
            narration="See getting started dot M D for installation instructions and usage examples.",
            voice="male",
            min_duration=4.0,
            max_duration=10.0
        ),
    ]
)

# Video 2: Three Input Methods (Technical)
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
            narration="Video Gen accepts input from three sources. Document files, YouTube transcripts, or interactive wizard prompts.",
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
            narration="The document parser extracts structure from markdown files. It identifies headings as scene divisions, code blocks as commands, and lists as items. The parser generates YAML configuration automatically.",
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
                    "→ Summary generated",
                ],
            },
            narration="The YouTube fetcher retrieves video transcripts through the API. It segments the transcript by topic, extracts key points, and generates condensed summaries from long-form content.",
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
                    "→ Script generated from responses",
                ],
            },
            narration="The interactive wizard collects input through command-line prompts. It asks for video topic, content structure, and scene details. The wizard generates YAML configuration from user responses.",
            voice="male_warm",
            min_duration=10.0,
            max_duration=18.0
        ),
        UnifiedScene(
            scene_id="scene_05",
            scene_type="outro",
            visual_content={
                "main_text": "Three Input Methods",
                "sub_text": "See Documentation",
            },
            narration="All three methods produce the same YAML format. Choose based on your source material.",
            voice="female",
            min_duration=4.0,
            max_duration=10.0
        ),
    ]
)

# Video 3: Scene Types (Technical)
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
            narration="The system provides six scene types. Each type defines a specific visual layout and rendering function.",
            voice="male",
            min_duration=4.0,
            max_duration=10.0
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
            narration="Six scene types cover different content structures. Title for section headers. Command for code examples with terminal styling. List for enumerated items. Outro for closing screens. Code comparison for side-by-side diffs. Quote for highlighted text with attribution.",
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
                "before_label": "Loop",
                "after_label": "Comprehension",
            },
            narration="Code comparison renders two code blocks side by side. The left shows the original implementation. The right shows the refactored version. This example demonstrates list comprehension syntax.",
            voice="male_warm",
            min_duration=10.0,
            max_duration=15.0
        ),
        UnifiedScene(
            scene_id="scene_04",
            scene_type="quote",
            visual_content={
                "quote_text": "The right scene type makes complex topics clear and engaging",
                "attribution": "Video Gen Design",
            },
            narration="Scene type selection affects content clarity. The right scene type makes complex topics clear and engaging. From the Video Gen design documentation.",
            voice="female_friendly",
            min_duration=6.0,
            max_duration=12.0
        ),
        UnifiedScene(
            scene_id="scene_05",
            scene_type="outro",
            visual_content={
                "main_text": "Six Scene Types",
                "sub_text": "NEW_SCENE_TYPES_GUIDE.md",
            },
            narration="See new scene types guide dot M D for implementation details and YAML syntax examples.",
            voice="male",
            min_duration=4.0,
            max_duration=10.0
        ),
    ]
)

ALL_VIDEOS = [VIDEO_01, VIDEO_02, VIDEO_03]

async def main():
    print("\n" + "="*80)
    print("META-DOCUMENTATION VIDEOS - TECHNICAL NARRATION")
    print("="*80 + "\n")

    import os
    output_dir = "../audio/unified_system_v2"
    reports_dir = f"{output_dir}/reports"
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)

    # Clean old audio directories
    import shutil
    for d in os.listdir(output_dir):
        if d.startswith(('01-', '02-', '03-')) and os.path.isdir(os.path.join(output_dir, d)):
            shutil.rmtree(os.path.join(output_dir, d))
            print(f"Cleaned old audio: {d}")

    for i, video in enumerate(ALL_VIDEOS, 1):
        print(f"\n{'#'*80}")
        print(f"# VIDEO {i}/{len(ALL_VIDEOS)}: {video.title}")
        print(f"{'#'*80}\n")

        video.validate()
        video.save_validation_report(reports_dir)

        await video.generate_audio_with_timing(output_dir)
        video.generate_timing_report()
        video.save_metadata_manifest(reports_dir)

    print("\n" + "="*80)
    print("✓ AUDIO COMPLETE - TECHNICAL NARRATION")
    print("="*80 + "\n")

    total = sum(v.total_duration for v in ALL_VIDEOS)
    print(f"Total duration: {total:.1f}s ({total/60:.1f} minutes)")
    print("\nNext: python generate_videos_from_timings_v3_simple.py\n")

if __name__ == "__main__":
    asyncio.run(main())
