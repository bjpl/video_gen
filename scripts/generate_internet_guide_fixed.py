"""Generate 3 videos from Internet Guide with fixes applied."""

import asyncio
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from video_gen.input_adapters.document import DocumentAdapter
from video_gen.shared.models import InputConfig
from video_gen.pipeline.orchestrator import PipelineOrchestrator


async def main():
    """Generate videos using the fixed document adapter."""

    # Create input config
    input_config = InputConfig(
        input_type="document",
        source="inputs/Internet_Guide_Vol1_Core_Infrastructure.md",
        accent_color="blue",
        voice="male",
        use_ai_narration=True,
        video_count=3,  # Generate 3 videos
        target_duration=60,  # 60 seconds each
        auto_generate=True,
        skip_review=True
    )

    print("=" * 80)
    print("GENERATING 3 VIDEOS FROM INTERNET GUIDE - WITH FIXES")
    print("=" * 80)
    print(f"\nSource: {input_config.source}")
    print(f"Video count: {input_config.video_count}")
    print(f"Target duration: {input_config.target_duration}s each")
    print(f"AI narration: {input_config.use_ai_narration}")
    print("\nFixes applied:")
    print("  ✓ Metadata stripping (*Generated:*, ---)")
    print("  ✓ Title length control (no AI expansion)")
    print("  ✓ Markdown artifact removal")
    print()

    # Initialize document adapter with AI
    adapter = DocumentAdapter(test_mode=False, use_ai=True)

    # Adapt document to video set
    print("Step 1: Parsing document and generating video set...")
    result = await adapter.adapt(
        input_config.source,
        accent_color=input_config.accent_color,
        voice=input_config.voice,
        video_count=input_config.video_count,
        target_duration=input_config.target_duration
    )

    if not result.success:
        print(f"❌ Error: {result.error}")
        return 1

    video_set = result.video_set
    print(f"✓ Generated {len(video_set.videos)} videos")
    for i, video in enumerate(video_set.videos, 1):
        print(f"  Video {i}: {video.title} ({len(video.scenes)} scenes)")

    # Initialize stages and execute pipeline
    print("\nStep 2: Executing full pipeline...")

    from video_gen.stages.input_stage import InputStage
    from video_gen.stages.parsing_stage import ParsingStage
    from video_gen.stages.script_generation_stage import ScriptGenerationStage
    from video_gen.stages.audio_generation_stage import AudioGenerationStage
    from video_gen.stages.video_generation_stage import VideoGenerationStage
    from video_gen.stages.output_stage import OutputStage

    orchestrator = PipelineOrchestrator()

    # Register all pipeline stages (proper order)
    orchestrator.register_stages([
        InputStage(),
        ParsingStage(),
        ScriptGenerationStage(),
        AudioGenerationStage(),
        VideoGenerationStage(),
        OutputStage()
    ])

    # Execute the pipeline for EACH video in the set
    generated_videos = []

    for video_idx, video in enumerate(video_set.videos, 1):
        print(f"\n{'=' * 80}")
        print(f"PROCESSING VIDEO {video_idx}/{len(video_set.videos)}")
        print(f"Title: {video.title}")
        print(f"Scenes: {len(video.scenes)}")
        print('=' * 80)

        try:
            # Skip the input and parsing stages since we already have the VideoConfig
            # Process directly through script -> audio -> video -> output stages

            from video_gen.stages.audio_generation_stage import AudioGenerationStage
            from video_gen.stages.video_generation_stage import VideoGenerationStage
            from video_gen.stages.output_stage import OutputStage

            # Process through audio generation
            print(f"  → Generating audio for {len(video.scenes)} scenes...")
            audio_stage = AudioGenerationStage()
            task_id = f"video_{video_idx}_{video.video_id}"

            audio_result = await audio_stage.run(
                context={
                    "video_config": video,
                    "input_config": input_config,
                    "task_id": task_id
                },
                task_id=task_id
            )

            if not audio_result.success:
                print(f"  ❌ Audio generation failed: {audio_result.error}")
                continue

            # Update video config with audio info and get audio artifacts
            updated_video = audio_result.artifacts.get("video_config", video)
            audio_dir = audio_result.artifacts.get("audio_dir")
            timing_report = audio_result.artifacts.get("timing_report")

            print(f"    ✓ Audio complete (audio_dir: {audio_dir})")

            # Process through video generation
            print(f"  → Rendering video...")
            video_stage = VideoGenerationStage()
            video_result = await video_stage.run(
                context={
                    "video_config": updated_video,
                    "input_config": input_config,
                    "task_id": task_id,
                    "timing_report": timing_report,  # Required by video stage
                    "audio_dir": audio_dir  # Required by video stage
                },
                task_id=task_id
            )

            if not video_result.success:
                print(f"  ❌ Video rendering failed: {video_result.error}")
                continue

            # Update with video file info
            final_video = video_result.artifacts.get("video_config", updated_video)
            final_video_path = video_result.artifacts.get("final_video_path")
            video_dir = video_result.artifacts.get("video_dir")

            print(f"    ✓ Video rendering complete: {final_video_path}")

            # Process through output stage
            print(f"  → Finalizing output...")
            output_stage = OutputStage()
            output_result = await output_stage.run(
                context={
                    "video_config": final_video,
                    "input_config": input_config,
                    "video_path": final_video_path,  # The rendered video file
                    "video_dir": video_dir,  # The video directory
                    "timing_report": timing_report,  # Pass timing through
                    "audio_dir": audio_dir,  # Pass audio through
                    "task_id": task_id
                },
                task_id=task_id
            )

            if output_result.success:
                final_path = output_result.artifacts.get("final_video_path")
                print(f"\n✓ Video {video_idx} completed successfully!")
                print(f"  Output: {final_path}")
                generated_videos.append(final_path)
            else:
                print(f"  ❌ Output handling failed: {output_result.error}")

        except Exception as e:
            print(f"\n❌ Error processing video {video_idx}: {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "=" * 80)
    print("GENERATION COMPLETE")
    print("=" * 80)
    print(f"\nGenerated {len(video_set.videos)} videos")
    print("Check the output/ directory for results")

    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
