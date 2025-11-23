"""
Backward Compatibility Wrapper for Legacy Video Generation Scripts
====================================================================
Provides compatibility layer for existing scripts using the unified generator.

This wrapper allows legacy code to continue working while using the new
unified video generator under the hood.
"""

import sys
import logging
from pathlib import Path

# Setup logging
logger = logging.getLogger(__name__)

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from video_gen.video_generator.unified import (
    UnifiedVideoGenerator,
    generate_videos_from_timings
)

# Re-export for backward compatibility
__all__ = ['UnifiedVideoGenerator', 'generate_videos_from_timings']


def generate_all_videos_fast():
    """
    Backward compatible wrapper for v3_simple script
    Redirects to unified generator in fast mode
    """
    logger.info("\n" + "="*80)
    logger.info("VIDEO GENERATION - UNIFIED SYSTEM")
    logger.info("Using NumPy-accelerated blending + GPU encoding")
    logger.info("="*80 + "\n")

    from generate_all_videos_unified_v2 import ALL_VIDEOS
    import os

    output_dir = Path("../videos/unified_v3_fast")
    audio_base = Path("../audio/unified_system_v2")

    generator = UnifiedVideoGenerator(mode="fast", output_dir=output_dir)

    # Find videos with timing reports
    timing_reports = []
    for video in ALL_VIDEOS:
        sanitized_id = video.video_id.replace("_", "-")
        audio_dirs = [d for d in audio_base.iterdir()
                     if d.is_dir() and d.name.startswith(sanitized_id)]

        if audio_dirs:
            audio_dir = audio_dirs[0]
            timing_files = list(audio_dir.glob("*_timing_*.json"))

            if timing_files:
                timing_reports.append(timing_files[0])

    logger.info(f"Found {len(timing_reports)} videos ready for generation\n")

    # Generate videos
    results = generator.generate_from_timing_reports(timing_reports)

    logger.info(f"\n✓ Generated {len(results)} videos")
    return results


def generate_all_videos_optimized():
    """
    Backward compatible wrapper for v3_optimized script
    Redirects to unified generator in parallel mode
    """
    logger.info("\n" + "="*80)
    logger.info("VIDEO GENERATION - OPTIMIZED (PARALLEL)")
    logger.info("Using parallel processing for faster generation")
    logger.info("="*80 + "\n")

    from generate_all_videos_unified_v2 import ALL_VIDEOS
    import os

    output_dir = Path("../videos/unified_v3_optimized")
    audio_base = Path("../audio/unified_system_v2")

    generator = UnifiedVideoGenerator(mode="parallel", output_dir=output_dir)

    # Find videos with timing reports
    timing_reports = []
    for video in ALL_VIDEOS:
        sanitized_id = video.video_id.replace("_", "-")
        audio_dirs = [d for d in audio_base.iterdir()
                     if d.is_dir() and d.name.startswith(sanitized_id)]

        if audio_dirs:
            audio_dir = audio_dirs[0]
            timing_files = list(audio_dir.glob("*_timing_*.json"))

            if timing_files:
                timing_reports.append(timing_files[0])

    logger.info(f"Found {len(timing_reports)} videos ready for generation\n")

    # Generate videos in parallel
    results = generator.generate_from_timing_reports(timing_reports, parallel=True)

    logger.info(f"\n✓ Generated {len(results)} videos")
    return results


def generate_all_videos_baseline():
    """
    Backward compatible wrapper for v2 script
    Redirects to unified generator in baseline mode
    """
    logger.info("\n" + "="*80)
    logger.info("VIDEO GENERATION - BASELINE (v2)")
    logger.info("Using PIL blending for compatibility")
    logger.info("="*80 + "\n")

    from generate_all_videos_unified_v2 import ALL_VIDEOS
    import os

    output_dir = Path("../videos/unified_v2")
    audio_base = Path("../audio/unified_system_v2")

    generator = UnifiedVideoGenerator(mode="baseline", output_dir=output_dir)

    # Find videos with timing reports
    timing_reports = []
    for video in ALL_VIDEOS:
        sanitized_id = video.video_id.replace("_", "-")
        audio_dirs = [d for d in audio_base.iterdir()
                     if d.is_dir() and d.name.startswith(sanitized_id)]

        if audio_dirs:
            audio_dir = audio_dirs[0]
            timing_files = list(audio_dir.glob("*_timing_*.json"))

            if timing_files:
                timing_reports.append(timing_files[0])

    logger.info(f"Found {len(timing_reports)} videos ready for generation\n")

    # Generate videos
    results = generator.generate_from_timing_reports(timing_reports)

    logger.info(f"\n✓ Generated {len(results)} videos")
    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description='Unified video generation with multiple modes'
    )
    parser.add_argument(
        '--mode',
        choices=['fast', 'optimized', 'baseline'],
        default='fast',
        help='Generation mode (default: fast)'
    )

    args = parser.parse_args()

    if args.mode == 'fast':
        generate_all_videos_fast()
    elif args.mode == 'optimized':
        generate_all_videos_optimized()
    elif args.mode == 'baseline':
        generate_all_videos_baseline()
