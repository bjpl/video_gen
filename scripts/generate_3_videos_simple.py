"""Simple script to generate 3 videos by running pipeline 3 times."""

import asyncio
import sys
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from video_gen.shared.models import InputConfig
from video_gen.pipeline.orchestrator import PipelineOrchestrator
from video_gen.stages.input_stage import InputStage
from video_gen.stages.parsing_stage import ParsingStage
from video_gen.stages.script_generation_stage import ScriptGenerationStage
from video_gen.stages.audio_generation_stage import AudioGenerationStage
from video_gen.stages.video_generation_stage import VideoGenerationStage
from video_gen.stages.output_stage import OutputStage


async def generate_video(video_num: int, total: int):
    """Generate one video"""
    print(f"\n{'='*80}")
    print(f"GENERATING VIDEO {video_num}/{total}")
    print('='*80)

    # Create input config
    input_config = InputConfig(
        input_type="document",
        source="inputs/Internet_Guide_Vol1_Core_Infrastructure.md",
        accent_color="blue",
        voice="male",
        use_ai_narration=True,
        video_count=1,  # Generate 1 video at a time
        auto_generate=True,
        skip_review=True
    )

    # Create and configure pipeline
    orchestrator = PipelineOrchestrator()
    orchestrator.register_stages([
        InputStage(),
        ParsingStage(),
        ScriptGenerationStage(),
        AudioGenerationStage(),
        VideoGenerationStage(),
        OutputStage()
    ])

    # Execute
    result = await orchestrator.execute(input_config, resume=False)

    if result.success:
        print(f"✓ Video {video_num} complete: {result.video_path}")
        return result.video_path
    else:
        print(f"❌ Video {video_num} failed: {result.errors}")
        return None


async def main():
    print("="*80)
    print("GENERATING 3 INTERNET GUIDE VIDEOS")
    print("="*80)
    print("\nAll fixes applied:")
    print("  ✓ Metadata stripping")
    print("  ✓ Title length control")
    print("  ✓ Markdown artifact removal\n")

    videos = []

    # Generate each video sequentially
    for i in range(1, 4):
        video_path = await generate_video(i, 3)
        if video_path:
            videos.append(video_path)
        await asyncio.sleep(2)  # Brief pause between videos

    print("\n" + "="*80)
    print("GENERATION COMPLETE")
    print("="*80)
    print(f"\n✓ Successfully generated {len(videos)} videos:")
    for i, path in enumerate(videos, 1):
        print(f"  {i}. {path}")

    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
