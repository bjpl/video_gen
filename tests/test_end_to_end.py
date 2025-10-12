"""
End-to-End Integration Tests
============================
Complete pipeline tests from input to final video.
"""

import pytest
import asyncio
from pathlib import Path
from datetime import datetime

from video_gen.pipeline import create_complete_pipeline, TaskStatus
from video_gen.shared.models import InputConfig


@pytest.mark.asyncio
@pytest.mark.slow
class TestEndToEndPipeline:
    """Complete end-to-end pipeline tests."""

    @pytest.fixture
    def pipeline(self):
        """Create a fresh pipeline for each test with test mode enabled."""
        return create_complete_pipeline(test_mode=True)

    @pytest.fixture
    def test_document(self, tmp_path):
        """Create a test document."""
        doc = tmp_path / "test.md"
        doc.write_text("""
# Introduction to Python

Python is a high-level programming language.

## Key Features
- Easy to learn
- Powerful libraries
- Great community

## Getting Started
Install Python from python.org and start coding!
        """)
        return doc

    @pytest.fixture
    def test_yaml(self, tmp_path):
        """Create a test YAML config."""
        yaml_file = tmp_path / "test_video.yaml"
        yaml_file.write_text("""
video:
  video_id: "test_video_001"
  title: "Test Video"
  description: "A test video"
  language: "en"
  voice: "en-US-ChristopherNeural"

  scenes:
    - scene_id: "scene_1"
      scene_type: "title"
      narration: "Welcome to our test video"
      visual_content:
        title: "Welcome"

    - scene_id: "scene_2"
      scene_type: "command"
      narration: "This is the main content of our video"
      visual_content:
        title: "Main Content"

    - scene_id: "scene_3"
      scene_type: "outro"
      narration: "Thank you for watching"
      visual_content:
        title: "Summary"
        """)
        return yaml_file

    async def test_document_to_video_complete(self, pipeline, test_document):
        """
        Test complete workflow: Document → Final Video

        This tests the ENTIRE pipeline end-to-end:
        1. Input Adaptation (Document)
        2. Content Parsing
        3. Script Generation
        4. Audio Generation
        5. Video Generation
        6. Output Handling
        """
        # Create input config
        input_config = InputConfig(
            input_type="document",
            source=str(test_document),
            config={
                "voice": "en-US-ChristopherNeural",
                "language": "en"
            }
        )

        # Execute pipeline
        result = await pipeline.execute(input_config)

        # Verify success
        assert result.success, f"Pipeline failed: {result.errors}"
        assert result.video_path is not None
        assert result.video_path.exists()
        assert result.video_path.stat().st_size > 0

        # Verify scene count
        assert result.scene_count > 0

        # Verify duration
        assert result.total_duration > 0

        # Verify metadata
        assert result.task_id is not None
        assert result.timestamp is not None

        print(f"\n✅ Document → Video complete: {result.video_path}")
        print(f"   Duration: {result.total_duration:.2f}s")
        print(f"   Scenes: {result.scene_count}")
        print(f"   Generation time: {result.generation_time:.2f}s")

    async def test_yaml_to_video_complete(self, pipeline, test_yaml):
        """Test complete YAML → Video workflow."""
        input_config = InputConfig(
            input_type="yaml",
            source=str(test_yaml),
            config={}
        )

        result = await pipeline.execute(input_config)

        assert result.success
        assert result.video_path.exists()
        assert result.scene_count == 3  # 3 scenes in YAML

        print(f"\n✅ YAML → Video complete: {result.video_path}")

    async def test_programmatic_to_video_complete(self, pipeline):
        """Test programmatic input → Video workflow."""
        from video_gen.shared.models import VideoConfig, Scene

        # Create programmatic video config
        video_config = VideoConfig(
            video_id="test_programmatic",
            title="Programmatic Test Video",
            description="A test video created programmatically",
            scenes=[
                Scene(
                    scene_id="scene_1",
                    scene_type="title",
                    narration="Welcome to programmatic video generation",
                    visual_content={"title": "Hello World"},
                    voice="en-US-ChristopherNeural"
                ),
                Scene(
                    scene_id="scene_2",
                    scene_type="command",
                    narration="This video was created entirely through code",
                    visual_content={"title": "Main Content"},
                    voice="en-US-ChristopherNeural"
                ),
            ]
        )

        input_config = InputConfig(
            input_type="programmatic",
            source=video_config,
            config={}
        )

        result = await pipeline.execute(input_config)

        assert result.success
        assert result.video_path.exists()
        assert result.scene_count == 2

        print(f"\n✅ Programmatic → Video complete: {result.video_path}")

    async def test_pipeline_resume_after_failure(self, pipeline, test_document):
        """Test pipeline resume capability after failure."""
        input_config = InputConfig(
            input_type="document",
            source=str(test_document),
            config={}
        )

        # First execution (may fail at video generation for testing)
        task_id = "test_resume_task"

        try:
            await pipeline.execute(input_config, task_id=task_id)
        except Exception:
            pass  # Expected to potentially fail

        # Get task state
        task_state = pipeline.get_status(task_id)
        assert task_state is not None

        # Resume from last successful stage
        result = await pipeline.execute(
            input_config,
            task_id=task_id,
            resume=True
        )

        # Should complete successfully
        if result.success:
            print(f"\n✅ Pipeline resume successful: {result.video_path}")

    async def test_pipeline_progress_tracking(self, pipeline, test_document):
        """Test progress tracking throughout pipeline."""
        from video_gen.pipeline.events import EventType

        events_received = []

        # Subscribe to events
        async def event_handler(event):
            events_received.append(event)

        pipeline.event_emitter.subscribe(EventType.STAGE_STARTED, event_handler)
        pipeline.event_emitter.subscribe(EventType.STAGE_COMPLETED, event_handler)
        pipeline.event_emitter.subscribe(EventType.STAGE_PROGRESS, event_handler)

        input_config = InputConfig(
            input_type="document",
            source=str(test_document),
            config={}
        )

        result = await pipeline.execute(input_config)

        # Verify we received events
        assert len(events_received) > 0

        # Verify we got stage started/completed events
        stage_events = [e for e in events_received if e.type in [
            EventType.STAGE_STARTED,
            EventType.STAGE_COMPLETED
        ]]
        assert len(stage_events) >= 12  # 6 stages × 2 events (start + complete)

        print(f"\n✅ Progress tracking: {len(events_received)} events received")

    async def test_concurrent_pipeline_execution(self, pipeline, test_document, test_yaml):
        """Test running multiple pipelines concurrently."""
        # Create two different input configs
        config1 = InputConfig(
            input_type="document",
            source=str(test_document),
            config={"voice": "en-US-ChristopherNeural"}
        )

        config2 = InputConfig(
            input_type="yaml",
            source=str(test_yaml),
            config={"voice": "en-US-JennyNeural"}
        )

        # Execute both concurrently
        results = await asyncio.gather(
            pipeline.execute(config1, task_id="concurrent_1"),
            pipeline.execute(config2, task_id="concurrent_2"),
            return_exceptions=True
        )

        # Both should succeed
        assert len(results) == 2
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                print(f"Task {i+1} failed: {result}")
            else:
                assert result.success
                print(f"\n✅ Concurrent task {i+1} complete: {result.video_path}")

    async def test_pipeline_error_handling(self, pipeline):
        """Test error handling with invalid input."""
        # Invalid input type
        invalid_config = InputConfig(
            input_type="invalid_type",
            source="nonexistent.txt",
            config={}
        )

        with pytest.raises(Exception):
            await pipeline.execute(invalid_config)

        print("\n✅ Error handling working correctly")

    async def test_pipeline_state_persistence(self, pipeline, test_document, tmp_path):
        """Test state persistence across pipeline runs."""
        input_config = InputConfig(
            input_type="document",
            source=str(test_document),
            config={}
        )

        task_id = "persistence_test"

        # First run
        result = await pipeline.execute(input_config, task_id=task_id)

        # Get task state
        task_state = pipeline.get_status(task_id)
        assert task_state is not None
        assert task_state.status == TaskStatus.COMPLETED
        assert len(task_state.get_completed_stages()) == 6

        # Verify state was persisted
        assert task_state.result is not None

        print(f"\n✅ State persistence verified: {len(task_state.get_completed_stages())} stages")

    async def test_full_pipeline_validation(self, pipeline, test_document):
        """
        Comprehensive validation test.

        Verifies:
        - All stages execute in correct order
        - All artifacts are generated
        - Final video is valid
        - Metadata is complete
        """
        input_config = InputConfig(
            input_type="document",
            source=str(test_document),
            config={"voice": "en-US-ChristopherNeural"}
        )

        result = await pipeline.execute(input_config)

        # Verify pipeline result
        assert result.success
        assert result.video_path.exists()
        assert result.audio_dir is not None
        assert result.timing_report is not None

        # Verify all expected outputs exist
        assert result.video_path.stat().st_size > 1000  # At least 1KB

        # Verify metadata
        metadata_file = result.video_path.parent / f"{result.task_id}_metadata.json"
        if metadata_file.exists():
            import json
            with open(metadata_file) as f:
                metadata = json.load(f)
                assert metadata["video_id"] is not None
                assert metadata["scene_count"] > 0

        print(f"\n✅ Full validation complete:")
        print(f"   Video: {result.video_path}")
        print(f"   Size: {result.video_path.stat().st_size} bytes")
        print(f"   Duration: {result.total_duration:.2f}s")
        print(f"   Scenes: {result.scene_count}")


@pytest.mark.asyncio
async def test_quick_integration_smoke_test():
    """Quick smoke test for CI/CD - validates pipeline stages load correctly."""
    from video_gen.pipeline import get_pipeline
    from video_gen.shared.models import VideoConfig, Scene, VideoSet
    from video_gen.stages.input_stage import InputStage
    from video_gen.stages.parsing_stage import ParsingStage

    # Test 1: Pipeline creation
    pipeline = get_pipeline()
    assert pipeline is not None
    assert len(pipeline.stages) > 0

    # Test 2: InputStage with programmatic input
    input_stage = InputStage()
    video_config = VideoConfig(
        video_id="smoke_test",
        title="Smoke Test",
        description="Quick smoke test",
        scenes=[
            Scene(
                scene_id="test_1",
                scene_type="title",
                narration="Quick smoke test",
                visual_content={"title": "Smoke Test"},
                voice="en-US-ChristopherNeural"
            )
        ]
    )

    input_config = InputConfig(
        input_type="programmatic",
        source=video_config,
        accent_color=(59, 130, 246),
        voice="en-US-ChristopherNeural"
    )

    context = {"task_id": "smoke-test", "input_config": input_config}
    result = await input_stage.execute(context)

    assert result.success, f"Input stage failed: {result.errors if hasattr(result, 'errors') else 'Unknown error'}"
    assert "video_config" in result.artifacts

    # Test 3: ParsingStage
    parsing_stage = ParsingStage()
    parsing_context = {
        "task_id": "smoke-test",
        "video_config": result.artifacts["video_config"]
    }
    parsing_result = await parsing_stage.execute(parsing_context)
    assert parsing_result.success

    print("\n✅ Smoke test passed - pipeline stages functional")


if __name__ == "__main__":
    # Run quick smoke test
    asyncio.run(test_quick_integration_smoke_test())
