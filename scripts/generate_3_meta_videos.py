"""
Generate 3 Meta-Documentation Videos
=====================================
Simplified batch script that uses the generated CODE files directly
"""

import sys
import asyncio
import os
import logging

# Setup logging
logger = logging.getLogger(__name__)


sys.path.append('.')

from unified_video_system import (
    UnifiedVideo, UnifiedScene,
    ACCENT_CYAN, ACCENT_BLUE, ACCENT_PURPLE
)

# Define ACCENT_CYAN if needed
if 'ACCENT_CYAN' not in dir():
    ACCENT_CYAN = (34, 211, 238)

# Read and execute the generated VIDEO definitions
logger.info("Loading generated VIDEO objects...")

# Video 1
with open('drafts/01_video_gen_intro_CODE_20251004_020325.py', 'r') as f:
    code1 = f.read()
    # Replace imports and VIDEO name
    code1 = code1.replace('from unified_video_system import ACCENT_CYAN', '')
    code1 = code1.replace('VIDEO = ', 'VIDEO_01 = ')
    exec(code1, globals())

# Video 2
with open('drafts/02_input_methods_CODE_20251004_020410.py', 'r') as f:
    code2 = f.read()
    code2 = code2.replace('from unified_video_system import ACCENT_BLUE', '')
    code2 = code2.replace('VIDEO = ', 'VIDEO_02 = ')
    exec(code2, globals())

# Video 3
with open('drafts/03_scene_types_CODE_20251004_020435.py', 'r') as f:
    code3 = f.read()
    code3 = code3.replace('from unified_video_system import ACCENT_PURPLE', '')
    code3 = code3.replace('VIDEO = ', 'VIDEO_03 = ')
    exec(code3, globals())

ALL_VIDEOS = [VIDEO_01, VIDEO_02, VIDEO_03]

async def main():
    logger.info("\n" + "="*80)
    logger.info("GENERATING 3 META-DOCUMENTATION VIDEOS")
    logger.info("AI-Enhanced Narration | Multiple Voices | All Scene Types")
    logger.info("="*80 + "\n")

    output_dir = "../audio/unified_system_v2"
    reports_dir = f"{output_dir}/reports"

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)

    for i, video in enumerate(ALL_VIDEOS, 1):
        logger.info(f"\n{'#'*80}")
        logger.info(f"# VIDEO {i}/{len(ALL_VIDEOS)}: {video.title}")
        logger.info(f"{'#'*80}\n")

        # Validation
        logger.info("[VALIDATION]")
        if video.validate():
            logger.info("✓ Passed")
        else:
            logger.warning("⚠️  Warnings found")
            for w in video.validation_report.get('warnings', [])[:3]:
                logger.info(f"  {w}")

        video.save_validation_report(reports_dir)

        # Audio generation with timing
        logger.info("\n[AUDIO GENERATION]")
        await video.generate_audio_with_timing(output_dir)

        # Timing report
        logger.info("\n[TIMING REPORT]")
        video.generate_timing_report()

        video.save_metadata_manifest(reports_dir)

    logger.info("\n" + "="*80)
    logger.info("✓ AUDIO GENERATION COMPLETE FOR ALL 3 VIDEOS")
    logger.info("="*80)

    total_duration = sum(v.total_duration for v in ALL_VIDEOS)
    logger.info(f"\nTotal content: {total_duration:.1f}s ({total_duration/60:.1f} minutes)")
    logger.info(f"Videos: {len(ALL_VIDEOS)}")
    logger.info("\nNext step:")
    logger.info("  python generate_videos_from_timings_v3_simple.py")
    logger.info("\n" + "="*80 + "\n")

if __name__ == "__main__":
    asyncio.run(main())
