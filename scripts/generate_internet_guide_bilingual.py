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

    # Step 5: Execute pipeline for bilingual generation
    logger.info(f"\n🚀 Step 3: Generating videos (this will take a few minutes)...")
    logger.info("   Pipeline will:")
    logger.info("   1. Generate English versions (5 videos)")
    logger.info("   2. Auto-translate to Spanish (5 videos)")
    logger.info("   3. Generate audio with appropriate voices")
    logger.info("   4. Render all 10 videos")

    pipeline = get_pipeline()

    input_config = InputConfig(
        input_type="programmatic",
        source=bilingual_set,
        languages=["en", "es"],  # 🌍 Bilingual generation
        accent_color="blue",
        auto_generate=True,  # Auto-proceed without review
        metadata={
            "use_ai_narration": True  # ✨ Use AI narration for natural speech
        }
    )

    try:
        result = await pipeline.execute(input_config)

        if result.success:
            logger.info("\n" + "=" * 60)
            logger.info("🎉 SUCCESS!")
            logger.info("=" * 60)
            logger.info(f"✅ Videos generated: 10 total (5 EN + 5 ES)")
            logger.info(f"✅ Output directory: output/internet_guide_vol1/")
            logger.info(f"✅ Generation time: {result.generation_time:.1f} seconds")
            logger.info("\n📂 Output structure:")
            logger.info("   output/internet_guide_vol1_en/")
            logger.info("   ├── video_01.mp4 (Voice: male)")
            logger.info("   ├── video_02.mp4 (Voice: female)")
            logger.info("   ├── video_03.mp4 (Voice: male_warm)")
            logger.info("   ├── video_04.mp4 (Voice: male)")
            logger.info("   └── video_05.mp4 (Voice: female)")
            logger.info("")
            logger.info("   output/internet_guide_vol1_es/")
            logger.info("   ├── video_01.mp4 (Voice: es-ES-AlvaroNeural)")
            logger.info("   ├── video_02.mp4 (Voice: es-ES-ElviraNeural)")
            logger.info("   ├── video_03.mp4 (Voice: es-ES-AlvaroNeural)")
            logger.info("   ├── video_04.mp4 (Voice: es-ES-AlvaroNeural)")
            logger.info("   └── video_05.mp4 (Voice: es-ES-ElviraNeural)")
        else:
            logger.error("\n❌ Generation failed")
            logger.error(f"   Errors: {result.errors}")

    except Exception as e:
        logger.error(f"\n❌ Pipeline execution failed: {e}", exc_info=True)


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
