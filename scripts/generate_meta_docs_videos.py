"""
Generate Meta-Documentation Videos
===================================
Creates 3 videos that document the video generation system itself.
This demonstrates the system by using it to explain itself!
"""

import sys
import asyncio
import logging

# Setup logging
logger = logging.getLogger(__name__)

sys.path.append('.')

from unified_video_system import *

# Import the generated VIDEO objects
exec(open('drafts/01_video_gen_intro_CODE_20251004_020005.py').read().replace('VIDEO = ', 'VIDEO_01 = '))
exec(open('drafts/02_input_methods_CODE_20251004_015838.py').read().replace('VIDEO = ', 'VIDEO_02 = '))
exec(open('drafts/03_scene_types_CODE_20251004_015839.py').read().replace('VIDEO = ', 'VIDEO_03 = '))

META_DOCS_VIDEOS = [VIDEO_01, VIDEO_02, VIDEO_03]

async def generate_all_meta_docs():
    """Generate audio for all 3 meta-documentation videos"""
    logger.info("\n" + "="*80)
    logger.info("META-DOCUMENTATION VIDEO GENERATION")
    logger.info("Using the system to document itself!")
    logger.info("="*80 + "\n")

    output_dir = "../audio/unified_system_v2"
    reports_dir = f"{output_dir}/reports"

    import os
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)

    for i, video in enumerate(META_DOCS_VIDEOS, 1):
        logger.info(f"\n{'#'*80}")
        logger.info(f"# VIDEO {i}/{len(META_DOCS_VIDEOS)}: {video.title}")
        logger.info(f"{'#'*80}\n")

        # Validation
        logger.info("[STEP 1] VALIDATION")
        logger.info("-" * 80)
        if video.validate():
            logger.info("✓ All validation checks passed")
        else:
            logger.warning("⚠️  Validation warnings:")
            for warning in video.validation_report.get('warnings', []):
                logger.warning(f"  {warning}")

        video.save_validation_report(reports_dir)

        # Preview
        logger.info("\n[STEP 2] PREVIEW")
        logger.info("-" * 80)
        video.generate_preview()
        video.save_preview_file(reports_dir)

        # Audio generation
        logger.info("\n[STEP 3] AUDIO GENERATION")
        logger.info("-" * 80)
        await video.generate_audio_with_timing(output_dir)

        # Timing report
        logger.info("\n[STEP 4] TIMING REPORT")
        logger.info("-" * 80)
        video.generate_timing_report()

        # Metadata
        logger.info("\n[STEP 5] METADATA")
        logger.info("-" * 80)
        video.save_metadata_manifest(reports_dir)

    logger.info("\n" + "="*80)
    logger.info("✓ ALL 3 META-DOCUMENTATION VIDEOS PREPARED")
    logger.info("="*80)
    logger.info("\nNext step: Generate videos")
    logger.info("  python generate_videos_from_timings_v3_simple.py")
    logger.info("\n" + "="*80 + "\n")

if __name__ == "__main__":
    asyncio.run(generate_all_meta_docs())
