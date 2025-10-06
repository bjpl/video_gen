"""
Demo script showing pipeline orchestrator usage.
"""

import asyncio
import logging
from pathlib import Path

from video_gen.pipeline import PipelineOrchestrator
from video_gen.pipeline.events import EventType
from video_gen.shared.models import VideoConfig, SceneConfig, InputConfig
from video_gen.stages import ValidationStage, AudioGenerationStage

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


def create_sample_video() -> VideoConfig:
    """Create a sample video configuration."""
    return VideoConfig(
        video_id="demo_video",
        title="Pipeline Demo Video",
        description="Demonstration of the pipeline orchestrator",
        accent_color="blue",
        scenes=[
            SceneConfig(
                scene_id="scene_01_intro",
                scene_type="title",
                narration="Welcome to the pipeline orchestrator demonstration. This is a production-ready video generation system.",
                visual_content={
                    "title": "Pipeline Orchestrator",
                    "subtitle": "Production Demo"
                },
                voice="male",
                min_duration=3.0,
                max_duration=8.0
            ),
            SceneConfig(
                scene_id="scene_02_features",
                scene_type="list",
                narration="The orchestrator provides automatic stage execution, state persistence, error recovery, and progress tracking.",
                visual_content={
                    "header": "Key Features",
                    "items": [
                        ("Automatic Execution", "End-to-end pipeline"),
                        ("State Management", "Resume from failures"),
                        ("Progress Tracking", "Real-time updates"),
                        ("Error Recovery", "Intelligent retry logic")
                    ]
                },
                voice="male",
                min_duration=7.0,
                max_duration=12.0
            ),
            SceneConfig(
                scene_id="scene_03_outro",
                scene_type="outro",
                narration="Fast, reliable, and production-ready. See the documentation for complete details.",
                visual_content={
                    "main_text": "Ready to Use",
                    "sub_text": "See docs for details"
                },
                voice="male",
                min_duration=3.0,
                max_duration=6.0
            )
        ]
    )


async def main():
    """Run the demo."""
    print("\n" + "="*80)
    print("PIPELINE ORCHESTRATOR DEMO")
    print("="*80 + "\n")

    # Create orchestrator
    orchestrator = PipelineOrchestrator()

    # Register event listener to see progress
    def print_event(event):
        if event.type in [EventType.PIPELINE_STARTED, EventType.PIPELINE_COMPLETED]:
            print(f"\n>>> {event.message}")
        elif event.type == EventType.STAGE_STARTED:
            print(f"\n[{event.stage}] Starting...")
        elif event.type == EventType.STAGE_PROGRESS:
            if event.progress:
                print(f"[{event.stage}] Progress: {event.progress:.0%} - {event.message}")
        elif event.type == EventType.STAGE_COMPLETED:
            print(f"[{event.stage}] Completed ✓")
        elif event.type == EventType.STAGE_FAILED:
            print(f"[{event.stage}] Failed ✗ - {event.message}")

    orchestrator.event_emitter.on_all(print_event)

    # Register stages
    print("Registering pipeline stages...")
    orchestrator.register_stages([
        ValidationStage(orchestrator.event_emitter),
        AudioGenerationStage(orchestrator.event_emitter),
        # VideoGenerationStage would go here
        # OutputStage would go here
    ])
    print(f"  → {len(orchestrator.stages)} stages registered\n")

    # Create input config
    video_config = create_sample_video()
    input_config = InputConfig(
        input_type="programmatic",
        source="demo"
    )

    # Add video config to context manually (normally would come from input adapter)
    # For this demo, we'll modify the first stage to inject it
    class ContextInjectionStage(ValidationStage):
        async def execute(self, context):
            context["video_config"] = video_config
            return await super().execute(context)

    # Replace first stage
    orchestrator.stages[0] = ContextInjectionStage(orchestrator.event_emitter)

    # Execute pipeline
    print("Starting pipeline execution...")
    print("-" * 80)

    try:
        result = await orchestrator.execute(input_config, task_id="demo_task_001")

        print("\n" + "="*80)
        print("PIPELINE EXECUTION COMPLETE")
        print("="*80)
        print(f"Success: {result.success}")
        print(f"Task ID: {result.task_id}")
        print(f"Total Duration: {result.total_duration:.2f}s")
        print(f"Scene Count: {result.scene_count}")
        print(f"Generation Time: {result.generation_time:.2f}s")

        if result.audio_dir:
            print(f"Audio Directory: {result.audio_dir}")

        if result.timing_report:
            print(f"Timing Report: {result.timing_report}")

        if result.warnings:
            print(f"\nWarnings ({len(result.warnings)}):")
            for warning in result.warnings:
                print(f"  - {warning}")

        if result.errors:
            print(f"\nErrors ({len(result.errors)}):")
            for error in result.errors:
                print(f"  - {error}")

        print("\n" + "="*80)

        # Show task state
        task_state = orchestrator.get_status(result.task_id)
        if task_state:
            print("\nTASK STATE:")
            print(f"  Status: {task_state.status.value}")
            print(f"  Overall Progress: {task_state.overall_progress:.0%}")
            print(f"  Completed Stages: {', '.join(task_state.get_completed_stages())}")
            if task_state.get_failed_stages():
                print(f"  Failed Stages: {', '.join(task_state.get_failed_stages())}")

    except Exception as e:
        print(f"\n❌ Pipeline failed: {e}")
        import traceback
        traceback.print_exc()

    print("\n" + "="*80 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
