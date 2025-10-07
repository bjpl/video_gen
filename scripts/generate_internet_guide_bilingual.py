#!/usr/bin/env python
"""
Generate 5 bilingual videos from Internet Guide Vol 1
=======================================================

Requirements:
- 5 videos (90 seconds each)
- Both English and Spanish (2 languages = 10 videos total)
- 3 voices rotated: male, female, male_warm (men and women)
- Source: Internet_Guide_Vol1_Core_Infrastructure.md

Output:
- 10 videos total (5 × 2 languages)
- Organized by language: internet_guide_en/, internet_guide_es/
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from video_gen.input_adapters.document import DocumentAdapter
from video_gen.pipeline import get_pipeline
from video_gen.shared.models import InputConfig, VideoSet, VideoConfig
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def generate_bilingual_internet_guide():
    """Generate 5 bilingual videos from Internet Guide Vol 1."""

    # Source document
    source_doc = Path(__file__).parent.parent / "inputs" / "Internet_Guide_Vol1_Core_Infrastructure.md"

    if not source_doc.exists():
        logger.error(f"❌ Source document not found: {source_doc}")
        return

    logger.info("🎬 Internet Guide Bilingual Video Generation")
    logger.info("=" * 60)
    logger.info(f"📄 Source: {source_doc.name}")
    logger.info(f"🎯 Videos: 5 videos × 2 languages = 10 total")
    logger.info(f"⏱️  Duration: 90 seconds each")
    logger.info(f"🎙️  Voices: 3 voices (male, female, male_warm)")
    logger.info(f"🌍 Languages: English, Spanish")
    logger.info("=" * 60)

    # Step 1: Parse document and split into 5 videos
    logger.info("\n📝 Step 1: Parsing document into 5 videos...")

    adapter = DocumentAdapter()

    # Parse with H2 splitting to get multiple videos
    # The document will be split by H2 sections
    result = await adapter.adapt(
        source=str(source_doc),
        accent_color="blue",
        voice="male",
        video_count=5,  # Request 5 videos
        split_by_h2=True,  # Split by H2 sections
        max_scenes_per_video=8  # Limit scenes per video for 90s target
    )

    if not result.success:
        logger.error(f"❌ Failed to parse document: {result.error}")
        return

    video_set = result.video_set
    logger.info(f"✅ Parsed into {len(video_set.videos)} videos")

    # Step 2: Adjust to exactly 5 videos if needed
    videos = video_set.videos[:5]  # Take first 5

    if len(videos) < 5:
        logger.warning(f"⚠️  Document only yielded {len(videos)} videos, proceeding with that")

    # Step 3: Assign 3 voices in rotation (male, female, male_warm)
    voices = ["male", "female", "male_warm"]

    for i, video in enumerate(videos):
        # Rotate through 3 voices
        assigned_voice = voices[i % 3]
        video.voices = [assigned_voice]

        logger.info(f"   Video {i+1}: {video.title[:50]}... (Voice: {assigned_voice})")

    logger.info(f"\n✅ Voice assignment complete")
    logger.info(f"   Video 1: male")
    logger.info(f"   Video 2: female")
    logger.info(f"   Video 3: male_warm")
    logger.info(f"   Video 4: male (rotated)")
    logger.info(f"   Video 5: female (rotated)")

    # Step 4: Create bilingual video set
    logger.info(f"\n🌍 Step 2: Setting up bilingual generation (EN + ES)...")

    bilingual_set = VideoSet(
        set_id="internet_guide_vol1",
        name="Internet Guide Vol 1: Core Infrastructure",
        description="Bilingual (EN/ES) video series on Internet fundamentals",
        videos=videos,
        metadata={
            "source": str(source_doc),
            "languages": ["en", "es"],
            "source_language": "en",
            "video_count": len(videos),
            "target_duration": 90,
            "voices_used": voices
        }
    )

    logger.info(f"✅ Bilingual set created")
    logger.info(f"   Set ID: {bilingual_set.set_id}")
    logger.info(f"   Videos: {len(bilingual_set.videos)}")
    logger.info(f"   Languages: {bilingual_set.metadata['languages']}")

    # Step 5: Execute pipeline for EACH video in EACH language
    logger.info(f"\n🚀 Step 3: Generating all videos...")
    logger.info(f"   Processing: {len(videos)} videos × 2 languages = {len(videos) * 2} total")
    logger.info("")

    pipeline = get_pipeline()
    languages = ["en", "es"]

    total_videos = len(videos) * len(languages)
    current = 0
    success_count = 0
    failed_count = 0

    for lang in languages:
        logger.info(f"\n{'='*60}")
        logger.info(f"🌍 Generating {lang.upper()} videos ({len(videos)} videos)")
        logger.info(f"{'='*60}")

        for i, video in enumerate(videos, 1):
            current += 1
            logger.info(f"\n[{current}/{total_videos}] Video {i}: {video.title[:60]}...")
            logger.info(f"   Language: {lang}")
            logger.info(f"   Voice: {video.voices[0]}")

            try:
                input_config = InputConfig(
                    input_type="programmatic",
                    source=video,  # Single video at a time
                    languages=[lang],  # One language at a time
                    accent_color="blue",
                    auto_generate=True,
                    use_ai_narration=True  # ✨ AI-enhanced narration (proper parameter!)
                )

                result = await pipeline.execute(input_config)

                if result.success:
                    success_count += 1
                    logger.info(f"   ✅ Generated successfully ({result.generation_time:.1f}s)")
                    if result.video_path:
                        logger.info(f"   📂 Output: {result.video_path}")
                else:
                    failed_count += 1
                    logger.error(f"   ❌ Failed: {result.errors}")

            except Exception as e:
                failed_count += 1
                logger.error(f"   ❌ Error: {e}")

    # Final summary
    logger.info("\n" + "=" * 60)
    logger.info("🎉 GENERATION COMPLETE!")
    logger.info("=" * 60)
    logger.info(f"✅ Successful: {success_count}/{total_videos}")
    logger.info(f"❌ Failed: {failed_count}/{total_videos}")
    logger.info(f"\n📂 Find your videos in:")
    logger.info(f"   output/ directory (organized by video ID)")


if __name__ == "__main__":
    print("""
╔════════════════════════════════════════════════════════════════╗
║  Internet Guide Vol 1 - Bilingual Video Generator             ║
║                                                                ║
║  📄 Source: Internet_Guide_Vol1_Core_Infrastructure.md         ║
║  🎯 Output: 5 videos in English + Spanish (10 total)          ║
║  ⏱️  Duration: ~90 seconds each                                ║
║  🎙️  Voices: male, female, male_warm (rotated)                ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
    """)

    print("⚙️  Starting generation...\n")

    asyncio.run(generate_bilingual_internet_guide())

    print("\n✅ Script complete!")
    print("📂 Check output/internet_guide_vol1_en/ and output/internet_guide_vol1_es/")
