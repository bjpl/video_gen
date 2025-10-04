"""
Complete Documentation Video Suite - Unified System v2.0
========================================================
Generates all 5 documentation videos with:
- Audio-duration-driven timing (100% accurate sync)
- Multi-stage validation
- Smart file naming with metadata
- Comprehensive reporting
"""

import sys
sys.path.append('.')

from unified_video_system import *
from generate_documentation_videos import (
    create_title_keyframes, create_command_keyframes,
    create_list_keyframes, create_outro_keyframes,
    ease_out_cubic, create_base_frame
)

ALL_VIDEOS = [
    UnifiedVideo(
        video_id="00_master_index",
        title="Documentation Hub - Master Index",
        description="Complete series overview and navigation",
        accent_color=ACCENT_PINK,
        version="v2.0",
        scenes=[
            UnifiedScene(
                scene_id="scene_01_title",
                scene_type="title",
                visual_content={
                    "title": "Documentation Hub",
                    "subtitle": "Complete Video Series Guide"
                },
                narration="Documentation hub. Your complete guide to the Claude Code demo video production series.",
                voice="male",
                min_duration=3.0,
                max_duration=8.0
            ),
            UnifiedScene(
                scene_id="scene_02_overview",
                scene_type="list",
                visual_content={
                    "header": "Video Series Overview",
                    "description": "5 Videos Covering Complete Workflow",
                    "items": [
                        ("Quick Reference", "5-minute workflow commands"),
                        ("Troubleshooting", "Common issues and solutions"),
                        ("Complete Workflow", "End-to-end production guide"),
                        ("Audio Deep Dive", "Professional voice generation"),
                        ("Master Index", "This video")
                    ]
                },
                narration="This video series includes five comprehensive guides. Quick reference provides five minute workflow commands. Troubleshooting covers common issues and solutions. Complete workflow offers an end to end production guide. Audio deep dive explores professional voice generation. And master index, this video, ties everything together.",
                voice="male",
                min_duration=10.0,
                max_duration=20.0
            ),
            UnifiedScene(
                scene_id="scene_03_documentation",
                scene_type="list",
                visual_content={
                    "header": "Documentation Files",
                    "description": "10 Markdown Guides Available",
                    "items": [
                        ("README", "Project overview"),
                        ("QUICK_REFERENCE", "Command cheat sheet"),
                        ("TROUBLESHOOTING", "Problem solving"),
                        ("COMPLETE_WORKFLOW", "Full guide"),
                        ("AUDIO_README", "Audio documentation")
                    ]
                },
                narration="Ten markdown documentation files support this project. README provides the project overview. Quick reference offers a command cheat sheet. Troubleshooting delivers problem solving guidance. Complete workflow contains the full production guide. Audio readme documents voice generation. Plus five additional specialized guides.",
                voice="male",
                min_duration=10.0,
                max_duration=20.0
            ),
            UnifiedScene(
                scene_id="scene_04_outro",
                scene_type="outro",
                visual_content={
                    "main_text": "Everything You Need",
                    "sub_text": "Professional Video Production"
                },
                narration="Everything you need for professional video production. Start with any guide based on your experience level.",
                voice="male",
                min_duration=3.0,
                max_duration=8.0
            )
        ]
    ),

    UnifiedVideo(
        video_id="01_quick_reference",
        title="Quick Reference Guide",
        description="5-minute workflow commands",
        accent_color=ACCENT_ORANGE,
        version="v2.0",
        scenes=[
            UnifiedScene(
                scene_id="scene_01_title",
                scene_type="title",
                visual_content={
                    "title": "Quick Reference",
                    "subtitle": "5-Minute Workflow Commands"
                },
                narration="Quick reference guide. Your five minute workflow for creating professional demo videos.",
                voice="male",
                min_duration=3.0,
                max_duration=8.0
            ),
            UnifiedScene(
                scene_id="scene_02_workflow",
                scene_type="command",
                visual_content={
                    "header": "Complete Workflow",
                    "description": "Generate Video with Audio in 40 Seconds",
                    "commands": [
                        "$ cd claude_code_demos",
                        "$ python generate_narration_audio.py",
                        "$ cd scripts",
                        "$ python generate_video_with_audio.py",
                        "",
                        "→ Output: Full HD video with narration"
                    ]
                },
                narration="Run four simple commands to generate your complete video with professional audio narration. The entire process takes about forty seconds on GPU-enabled systems.",
                voice="male",
                min_duration=8.0,
                max_duration=15.0
            ),
            UnifiedScene(
                scene_id="scene_03_components",
                scene_type="command",
                visual_content={
                    "header": "Individual Components",
                    "description": "Generate Audio or Video Separately",
                    "commands": [
                        "# Generate audio only",
                        "$ python generate_narration_audio.py",
                        "",
                        "# Generate video only",
                        "$ python generate_video_with_audio.py",
                        "",
                        "→ Modular generation for flexibility"
                    ]
                },
                narration="Generate audio and video separately for maximum flexibility. Create alternate voice options or modify video settings independently.",
                voice="male",
                min_duration=6.0,
                max_duration=12.0
            ),
            UnifiedScene(
                scene_id="scene_04_voices",
                scene_type="list",
                visual_content={
                    "header": "Voice Mix Modes",
                    "description": "Choose Your Narration Style",
                    "items": [
                        ("Single Voice", "One professional narrator"),
                        ("Varied Voices", "Alternating male and female"),
                        ("All Male", "Two male narrators"),
                        ("All Female", "Two female narrators")
                    ]
                },
                narration="Choose from four voice mix modes. Single voice for consistency, varied voices for engagement, or gender-specific options to match your brand.",
                voice="male",
                min_duration=8.0,
                max_duration=15.0
            ),
            UnifiedScene(
                scene_id="scene_05_outro",
                scene_type="outro",
                visual_content={
                    "main_text": "Fast. Simple. Powerful.",
                    "sub_text": "See QUICK_REFERENCE.md"
                },
                narration="Fast, simple, and powerful. See QUICK_REFERENCE dot M D for complete command documentation.",
                voice="male",
                min_duration=4.0,
                max_duration=10.0
            )
        ]
    ),

    UnifiedVideo(
        video_id="02_troubleshooting",
        title="Troubleshooting Guide",
        description="Common issues and solutions",
        accent_color=ACCENT_BLUE,
        version="v2.0",
        scenes=[
            UnifiedScene(
                scene_id="scene_01_title",
                scene_type="title",
                visual_content={
                    "title": "Troubleshooting",
                    "subtitle": "Common Issues & Solutions"
                },
                narration="Troubleshooting guide. Solving common issues in video generation workflows.",
                voice="male",
                min_duration=3.0,
                max_duration=8.0
            ),
            UnifiedScene(
                scene_id="scene_02_diagnosis",
                scene_type="list",
                visual_content={
                    "header": "Quick Diagnosis",
                    "description": "Check Your System Setup",
                    "items": [
                        ("Audio Not Generated", "Check internet connection"),
                        ("Video Encoding Fails", "Verify FFmpeg installation"),
                        ("GPU Not Detected", "Update NVIDIA drivers"),
                        ("Out of Sync", "Regenerate audio files")
                    ]
                },
                narration="Start with quick diagnosis. The most common issues are missing audio files due to internet connectivity, encoding failures from FFmpeg setup, GPU detection problems requiring driver updates, and sync issues fixed by regenerating audio.",
                voice="male",
                min_duration=12.0,
                max_duration=20.0
            ),
            UnifiedScene(
                scene_id="scene_03_verification",
                scene_type="command",
                visual_content={
                    "header": "Verification Commands",
                    "description": "Test Your Environment",
                    "commands": [
                        "# Check dependencies",
                        "$ python -c \"from PIL import Image; print('OK')\"",
                        "$ python -c \"import edge_tts; print('OK')\"",
                        "",
                        "# Check GPU",
                        "$ nvidia-smi",
                        "$ ffmpeg -version | grep nvenc"
                    ]
                },
                narration="Use these verification commands to test your environment. Check Python dependencies for pillow and edge T T S, then verify GPU availability and FFmpeg N V E N C support.",
                voice="male",
                min_duration=10.0,
                max_duration=16.0
            ),
            UnifiedScene(
                scene_id="scene_04_recovery",
                scene_type="command",
                visual_content={
                    "header": "Emergency Recovery",
                    "description": "Complete Reset Procedure",
                    "commands": [
                        "# Clean and regenerate",
                        "$ rm -rf audio/* temp_frames_audio/",
                        "$ pip install --upgrade pillow edge-tts",
                        "",
                        "$ python generate_narration_audio.py",
                        "$ cd scripts && python generate_video_with_audio.py"
                    ]
                },
                narration="If all else fails, use the emergency recovery procedure. Clean all temporary files, upgrade dependencies, and regenerate from scratch. This resolves ninety percent of persistent issues.",
                voice="male",
                min_duration=10.0,
                max_duration=16.0
            ),
            UnifiedScene(
                scene_id="scene_05_performance",
                scene_type="list",
                visual_content={
                    "header": "Performance Tips",
                    "description": "Optimize Generation Speed",
                    "items": [
                        ("Use GPU Encoding", "128x faster than CPU"),
                        ("Reduce Frame Rate", "Lower FPS = faster render"),
                        ("Close Other Apps", "Free GPU memory"),
                        ("Check Internet Speed", "For audio generation")
                    ]
                },
                narration="Optimize performance with these tips. GPU encoding is one hundred twenty eight times faster than CPU. Reduce frame rate for quicker renders. Close other applications to free GPU memory. Ensure fast internet for audio generation.",
                voice="male",
                min_duration=10.0,
                max_duration=18.0
            ),
            UnifiedScene(
                scene_id="scene_06_outro",
                scene_type="outro",
                visual_content={
                    "main_text": "Solutions at Your Fingertips",
                    "sub_text": "See TROUBLESHOOTING.md"
                },
                narration="Solutions at your fingertips. See TROUBLESHOOTING dot M D for comprehensive problem-solving guides.",
                voice="male",
                min_duration=4.0,
                max_duration=10.0
            )
        ]
    ),

    UnifiedVideo(
        video_id="03_complete_workflow",
        title="Complete Workflow Guide",
        description="End-to-end production process",
        accent_color=ACCENT_PURPLE,
        version="v2.0",
        scenes=[
            UnifiedScene(
                scene_id="scene_01_title",
                scene_type="title",
                visual_content={
                    "title": "Complete Workflow",
                    "subtitle": "End-to-End Production Guide"
                },
                narration="Complete workflow guide. Your end to end production guide for professional demo videos.",
                voice="male",
                min_duration=3.0,
                max_duration=8.0
            ),
            UnifiedScene(
                scene_id="scene_02_phases",
                scene_type="list",
                visual_content={
                    "header": "Six Production Phases",
                    "description": "From Concept to Final Video",
                    "items": [
                        ("Planning & Design", "Define objectives and visual system"),
                        ("Video Creation", "Generate animated frames"),
                        ("Script Writing", "Craft professional narration"),
                        ("Audio Generation", "Create TTS voice tracks"),
                        ("Integration", "Merge video and audio"),
                        ("Quality Control", "Validate final output")
                    ]
                },
                narration="The workflow has six production phases. Planning and design to define your objectives. Video creation to generate animated frames. Script writing for professional narration. Audio generation using text to speech. Integration to merge everything together. And quality control to validate the final output.",
                voice="female",
                min_duration=15.0,
                max_duration=25.0
            ),
            UnifiedScene(
                scene_id="scene_03_planning",
                scene_type="command",
                visual_content={
                    "header": "Phase 1: Planning",
                    "description": "Set Up Project Structure",
                    "commands": [
                        "# Create directory structure",
                        "$ mkdir -p videos audio scripts",
                        "",
                        "# Define design system",
                        "- Color palette: Dark theme with accent colors",
                        "- Typography: Arial family for consistency",
                        "- Layout: 1920x1080 Full HD resolution"
                    ]
                },
                narration="Phase one is planning. Create your directory structure for videos, audio, and scripts. Define your design system including color palette with dark theme and accent colors, typography using the Arial family, and layout at nineteen twenty by ten eighty Full H D resolution.",
                voice="male",
                min_duration=12.0,
                max_duration=20.0
            ),
            UnifiedScene(
                scene_id="scene_04_video_creation",
                scene_type="command",
                visual_content={
                    "header": "Phase 2: Video Creation",
                    "description": "Generate Animated Frames with GPU",
                    "commands": [
                        "# Key techniques",
                        "- Keyframe interpolation (95% efficiency)",
                        "- Cubic easing for smooth animation",
                        "- PIL/Pillow for frame generation",
                        "- GPU encoding with NVENC (128x faster)",
                        "",
                        "$ python generate_video_v3.0_animated.py"
                    ]
                },
                narration="Phase two is video creation. Use keyframe interpolation for ninety five percent efficiency gain. Apply cubic easing for smooth animations. Use P I L pillow for fast frame generation. Enable GPU encoding with N V E N C for one hundred twenty eight times speed improvement.",
                voice="female",
                min_duration=15.0,
                max_duration=25.0
            ),
            UnifiedScene(
                scene_id="scene_05_script_audio",
                scene_type="command",
                visual_content={
                    "header": "Phase 3 & 4: Script & Audio",
                    "description": "Professional Narration Generation",
                    "commands": [
                        "# Write engaging script",
                        "- 135 words per minute pacing",
                        "- Conversational, professional tone",
                        "- Scene-by-scene timing",
                        "",
                        "# Generate audio with Edge-TTS",
                        "$ python generate_narration_audio.py",
                        "→ Neural TTS with 4 voice options"
                    ]
                },
                narration="Phases three and four cover script writing and audio generation. Write engaging scripts at one hundred thirty five words per minute. Use conversational yet professional tone with scene by scene timing. Generate audio using Edge T T S with neural network voices. Four voice options provide flexibility.",
                voice="male",
                min_duration=15.0,
                max_duration=25.0
            ),
            UnifiedScene(
                scene_id="scene_06_integration_qc",
                scene_type="command",
                visual_content={
                    "header": "Phase 5 & 6: Integration & QC",
                    "description": "Merge and Validate Final Output",
                    "commands": [
                        "# Integrate video + audio",
                        "$ python generate_video_with_audio.py",
                        "",
                        "# Quality control checklist",
                        "✓ Audio syncs perfectly",
                        "✓ Visual quality is crisp",
                        "✓ Transitions are smooth",
                        "✓ File size is optimized"
                    ]
                },
                narration="Phases five and six are integration and quality control. Run the integration script to merge video and audio with frame perfect synchronization. Validate your output with the quality control checklist. Verify audio sync, visual clarity, smooth transitions, and optimized file size.",
                voice="female",
                min_duration=15.0,
                max_duration=25.0
            ),
            UnifiedScene(
                scene_id="scene_07_metrics",
                scene_type="list",
                visual_content={
                    "header": "Performance Metrics",
                    "description": "Production Timeline",
                    "items": [
                        ("Audio Generation", "10 seconds"),
                        ("Video Rendering", "25 seconds"),
                        ("GPU Encoding", "15 seconds"),
                        ("Total Time", "~40 seconds")
                    ]
                },
                narration="Here are the performance metrics. Audio generation takes ten seconds. Video rendering takes twenty five seconds. GPU encoding adds fifteen seconds. Total production time is approximately forty seconds for a one minute professional video.",
                voice="male",
                min_duration=12.0,
                max_duration=20.0
            ),
            UnifiedScene(
                scene_id="scene_08_outro",
                scene_type="outro",
                visual_content={
                    "main_text": "Professional Video Production",
                    "sub_text": "See COMPLETE_WORKFLOW.md"
                },
                narration="Professional video production made simple. See COMPLETE_WORKFLOW dot M D for the full guide.",
                voice="female",
                min_duration=4.0,
                max_duration=10.0
            )
        ]
    ),

    UnifiedVideo(
        video_id="04_audio_deep_dive",
        title="Audio Deep Dive",
        description="Professional voice generation mastery",
        accent_color=ACCENT_GREEN,
        version="v2.0",
        scenes=[
            UnifiedScene(
                scene_id="scene_01_title",
                scene_type="title",
                visual_content={
                    "title": "Audio Deep Dive",
                    "subtitle": "Professional Voice Generation"
                },
                narration="Audio deep dive. Mastering professional voice generation with open source text to speech.",
                voice="male",
                min_duration=3.0,
                max_duration=8.0
            ),
            UnifiedScene(
                scene_id="scene_02_voices",
                scene_type="list",
                visual_content={
                    "header": "Voice Options",
                    "description": "Four Neural TTS Voices",
                    "items": [
                        ("Andrew (Male)", "Confident, Professional"),
                        ("Brandon (Male)", "Warm, Engaging"),
                        ("Aria (Female)", "Crisp, Clear"),
                        ("Ava (Female)", "Friendly, Pleasant")
                    ]
                },
                narration="Four neural network voices are available. Andrew provides confident professional narration. Brandon offers warm engaging delivery. Aria delivers crisp clear technical content. Ava provides friendly pleasant onboarding experiences.",
                voice="female",
                min_duration=12.0,
                max_duration=20.0
            ),
            UnifiedScene(
                scene_id="scene_03_generation",
                scene_type="command",
                visual_content={
                    "header": "Audio Generation",
                    "description": "Create TTS Files with Edge-TTS",
                    "commands": [
                        "# Install Edge-TTS",
                        "$ pip install edge-tts",
                        "",
                        "# Generate default voice",
                        "$ python generate_narration_audio.py",
                        "",
                        "# Generate all voices",
                        "$ python generate_alternate_voices.py"
                    ]
                },
                narration="Generate audio in three steps. Install edge T T S from python package index. Run generate narration audio for the default voice. Or run generate alternate voices to create all four voice options simultaneously.",
                voice="male",
                min_duration=12.0,
                max_duration=20.0
            ),
            UnifiedScene(
                scene_id="scene_04_specs",
                scene_type="list",
                visual_content={
                    "header": "Technical Specifications",
                    "description": "Audio Quality Details",
                    "items": [
                        ("Format", "MP3, 24 kHz mono"),
                        ("Engine", "Microsoft Edge TTS"),
                        ("Quality", "Neural network voices"),
                        ("File Size", "20-80 KB per scene")
                    ]
                },
                narration="Technical specifications ensure high quality. Audio format is M P three at twenty four kilohertz mono. The engine is Microsoft Edge T T S with free A P I access. Quality is neural network based for natural speech. File sizes range from twenty to eighty kilobytes per scene.",
                voice="female",
                min_duration=15.0,
                max_duration=25.0
            ),
            UnifiedScene(
                scene_id="scene_05_customization",
                scene_type="command",
                visual_content={
                    "header": "Customization",
                    "description": "Adjust Speaking Rate and Volume",
                    "commands": [
                        "# Edit generation script",
                        "RATE = \"+20%\"   # 20% faster",
                        "RATE = \"-15%\"   # 15% slower",
                        "RATE = \"+0%\"    # Normal speed",
                        "",
                        "VOLUME = \"+10%\" # Louder",
                        "VOLUME = \"-5%\"  # Quieter"
                    ]
                },
                narration="Customize audio parameters easily. Adjust speaking rate with plus or minus percentages. Increase rate for faster delivery. Decrease for slower pacing. Modify volume up or down to match your requirements.",
                voice="male",
                min_duration=12.0,
                max_duration=20.0
            ),
            UnifiedScene(
                scene_id="scene_06_selection",
                scene_type="command",
                visual_content={
                    "header": "Voice Selection",
                    "description": "Explore Available Voices",
                    "commands": [
                        "# List all available voices",
                        "$ edge-tts --list-voices | grep \"en-US\"",
                        "",
                        "# Test a voice",
                        "$ edge-tts --voice en-US-AndrewNeural \\",
                        "           --text \"Test audio\" \\",
                        "           --write-media test.mp3"
                    ]
                },
                narration="Explore voice selection options. List all available English U S voices with the edge T T S command. Test any voice before committing to full generation. This ensures you choose the perfect narrator for your content.",
                voice="female",
                min_duration=12.0,
                max_duration=20.0
            ),
            UnifiedScene(
                scene_id="scene_07_outro",
                scene_type="outro",
                visual_content={
                    "main_text": "Studio-Quality Narration",
                    "sub_text": "See AUDIO_README.md"
                },
                narration="Achieve studio quality narration. See AUDIO_README dot M D for complete documentation.",
                voice="male",
                min_duration=4.0,
                max_duration=10.0
            )
        ]
    )
]


async def generate_all_videos():
    print("\n" + "="*80)
    print("UNIFIED VIDEO PRODUCTION SYSTEM v2.0")
    print("Batch Generation: All 5 Documentation Videos")
    print("="*80 + "\n")

    reports_dir = "../audio/unified_system_v2/reports"
    audio_base_dir = "../audio/unified_system_v2"
    os.makedirs(reports_dir, exist_ok=True)

    all_reports = []

    for i, video in enumerate(ALL_VIDEOS, 1):
        print(f"\n{'#'*80}")
        print(f"# VIDEO {i}/5: {video.title}")
        print(f"{'#'*80}\n")

        print("[STEP 1] Validation")
        print("-" * 80)
        if video.validate():
            print("✓ All validation checks passed")
        else:
            print("⚠️  Validation warnings:")
            for warning in video.validation_report.get('warnings', []):
                print(f"  - {warning}")

        validation_file = video.save_validation_report(reports_dir)

        print("\n[STEP 2] Preview & Storyboard")
        print("-" * 80)
        estimated = video.generate_preview()
        preview_file = video.save_preview_file(reports_dir)

        print("\n[STEP 3] Audio Generation with Timing")
        print("-" * 80)
        await video.generate_audio_with_timing(audio_base_dir)

        print("\n[STEP 4] Timing Report")
        print("-" * 80)
        timing_report = video.generate_timing_report()

        print("\n[STEP 5] Metadata Manifest")
        print("-" * 80)
        manifest_file = video.save_metadata_manifest(reports_dir)

        all_reports.append({
            'video_id': video.video_id,
            'title': video.title,
            'duration': video.total_duration,
            'scene_count': len(video.scenes),
            'files': {
                'validation': validation_file,
                'preview': preview_file,
                'audio_dir': video.audio_dir,
                'manifest': manifest_file
            }
        })

        print(f"\n✓ {video.title} preparation complete")
        print(f"  Duration: {video.total_duration:.2f}s")
        print(f"  Scenes: {len(video.scenes)}")
        print(f"  Audio files: {len(video.scenes)}")

    print("\n" + "="*80)
    print("✓ ALL VIDEOS PREPARED SUCCESSFULLY")
    print("="*80 + "\n")

    print("Summary:")
    print("-" * 80)
    total_duration = sum(r['duration'] for r in all_reports)
    total_scenes = sum(r['scene_count'] for r in all_reports)

    for report in all_reports:
        print(f"{report['video_id']:<25} {report['duration']:>6.1f}s  ({report['scene_count']} scenes)")

    print("-" * 80)
    print(f"{'TOTAL':<25} {total_duration:>6.1f}s  ({total_scenes} scenes)")
    print(f"\n Total runtime: {total_duration/60:.1f} minutes")
    print(f" All reports saved to: {reports_dir}/")
    print("="*80 + "\n")

    summary_file = os.path.join(reports_dir, f"batch_summary_{ALL_VIDEOS[0].generation_timestamp}.json")
    with open(summary_file, 'w') as f:
        json.dump({
            'total_videos': len(ALL_VIDEOS),
            'total_duration': total_duration,
            'total_scenes': total_scenes,
            'videos': all_reports,
            'timestamp': ALL_VIDEOS[0].generation_timestamp
        }, f, indent=2)

    print(f"Batch summary saved: {summary_file}\n")

if __name__ == "__main__":
    asyncio.run(generate_all_videos())