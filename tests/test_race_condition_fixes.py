"""
Tests for race condition fixes in parallel pipeline execution.

Verifies that concurrent state updates don't corrupt data or lose progress.
"""

import asyncio
import pytest
from pathlib import Path
from video_gen.pipeline.state_manager import StateManager, TaskState, TaskStatus


class TestStateManagerThreadSafety:
    """Test thread-safe state management for parallel execution."""

    @pytest.mark.asyncio
    async def test_concurrent_save_async_uses_locking(self, tmp_path):
        """Test that concurrent save_async calls don't corrupt state."""
        state_manager = StateManager(state_dir=tmp_path)

        # Create initial state
        state = TaskState(
            task_id="test_concurrent",
            input_config={"test": "data"}
        )
        state.add_stage("stage1")
        state.add_stage("stage2")

        # Save initial state
        await state_manager.save_async(state)

        # Simulate concurrent updates from different stages
        async def update_stage1():
            """Simulates stage1 updating progress."""
            for i in range(10):
                await state_manager.update_stage_progress_atomic(
                    "test_concurrent", "stage1", i / 10.0
                )
                await asyncio.sleep(0.001)

        async def update_stage2():
            """Simulates stage2 updating progress."""
            for i in range(10):
                await state_manager.update_stage_progress_atomic(
                    "test_concurrent", "stage2", i / 10.0
                )
                await asyncio.sleep(0.001)

        # Run concurrent updates
        await asyncio.gather(update_stage1(), update_stage2())

        # Load final state
        final_state = await state_manager.load_async("test_concurrent")

        # Both stages should have progress = 0.9 (last update)
        assert final_state.stages["stage1"].progress == pytest.approx(0.9, abs=0.01)
        assert final_state.stages["stage2"].progress == pytest.approx(0.9, abs=0.01)

        # Version should have incremented (at least 20 times)
        assert final_state.version >= 20

    @pytest.mark.asyncio
    async def test_atomic_update_prevents_lost_updates(self, tmp_path):
        """Test that atomic updates prevent lost concurrent modifications."""
        state_manager = StateManager(state_dir=tmp_path)

        # Create initial state
        state = TaskState(
            task_id="test_atomic",
            input_config={"test": "data"}
        )
        await state_manager.save_async(state)

        # Track number of successful updates
        success_count = 0
        lock = asyncio.Lock()

        async def increment_version():
            """Simulate multiple concurrent updates."""
            nonlocal success_count
            for _ in range(5):
                try:
                    def update_fn(s):
                        s.metadata["counter"] = s.metadata.get("counter", 0) + 1
                        return s

                    await state_manager.update_atomic("test_atomic", update_fn)
                    async with lock:
                        success_count += 1
                except Exception as e:
                    print(f"Update failed: {e}")
                await asyncio.sleep(0.001)

        # Run 5 concurrent updaters, each doing 5 updates = 25 total
        await asyncio.gather(*[increment_version() for _ in range(5)])

        # Load final state
        final_state = await state_manager.load_async("test_atomic")

        # All 25 updates should have succeeded
        assert success_count == 25
        assert final_state.metadata["counter"] == 25

        # Version should be at least 26 (initial save + 25 updates)
        assert final_state.version >= 26

    @pytest.mark.asyncio
    async def test_parallel_stage_completion_no_data_loss(self, tmp_path):
        """Test that completing stages in parallel doesn't lose artifacts."""
        state_manager = StateManager(state_dir=tmp_path)

        # Create state with multiple stages
        state = TaskState(
            task_id="test_parallel_complete",
            input_config={"test": "data"}
        )
        for i in range(5):
            state.add_stage(f"stage{i}")
        await state_manager.save_async(state)

        # Complete stages in parallel with different artifacts
        async def complete_stage(stage_num):
            await state_manager.complete_stage_atomic(
                "test_parallel_complete",
                f"stage{stage_num}",
                artifacts={f"output{stage_num}": f"result{stage_num}"}
            )

        # Complete all 5 stages concurrently
        await asyncio.gather(*[complete_stage(i) for i in range(5)])

        # Load final state
        final_state = await state_manager.load_async("test_parallel_complete")

        # All stages should be completed
        for i in range(5):
            stage = final_state.stages[f"stage{i}"]
            assert stage.status == TaskStatus.COMPLETED
            assert stage.progress == 1.0
            assert f"output{i}" in stage.artifacts
            assert stage.artifacts[f"output{i}"] == f"result{i}"

    @pytest.mark.asyncio
    async def test_optimistic_locking_detects_conflicts(self, tmp_path):
        """Test that optimistic locking detects and retries conflicts."""
        state_manager = StateManager(state_dir=tmp_path)

        # Create initial state
        state = TaskState(
            task_id="test_conflict",
            input_config={"test": "data"}
        )
        await state_manager.save_async(state)

        # Track retries
        retry_count = 0

        async def update_with_delay():
            """Update that takes some time, causing potential conflicts."""
            def slow_update(s):
                nonlocal retry_count
                # This simulates a slow operation
                import time
                time.sleep(0.01)
                s.metadata["update1"] = True
                return s

            try:
                await state_manager.update_atomic("test_conflict", slow_update, max_retries=5)
            except Exception as e:
                # Count retries from warning messages
                pass

        async def quick_update():
            """Quick update that should succeed immediately."""
            def fast_update(s):
                s.metadata["update2"] = True
                return s

            await state_manager.update_atomic("test_conflict", fast_update)

        # Run concurrent updates (slow one may conflict and retry)
        await asyncio.gather(update_with_delay(), quick_update())

        # Both updates should eventually succeed
        final_state = await state_manager.load_async("test_conflict")
        assert final_state.metadata.get("update1") is True
        assert final_state.metadata.get("update2") is True

    @pytest.mark.asyncio
    async def test_version_increments_on_every_save(self, tmp_path):
        """Test that version number increments correctly."""
        state_manager = StateManager(state_dir=tmp_path)

        # Create state
        state = TaskState(task_id="test_version", input_config={})
        assert state.version == 0

        # First save
        await state_manager.save_async(state)
        assert state.version == 1

        # Second save
        await state_manager.save_async(state)
        assert state.version == 2

        # Load and verify
        loaded = await state_manager.load_async("test_version")
        assert loaded.version == 2

        # Save loaded state
        await state_manager.save_async(loaded)
        assert loaded.version == 3

    def test_backward_compatible_sync_methods(self, tmp_path):
        """Test that old sync methods still work for backward compatibility."""
        state_manager = StateManager(state_dir=tmp_path)

        # Create state
        state = TaskState(task_id="test_sync", input_config={"test": "data"})

        # Save using old sync method (should work)
        state_manager.save(state)

        # Load using old sync method (should work)
        loaded = state_manager.load("test_sync")

        assert loaded.task_id == "test_sync"
        assert loaded.input_config == {"test": "data"}
        assert loaded.version >= 1  # Version still increments

    @pytest.mark.asyncio
    async def test_atomic_write_prevents_partial_corruption(self, tmp_path):
        """Test that atomic write (temp file + rename) prevents corruption."""
        state_manager = StateManager(state_dir=tmp_path)

        # Create large state
        state = TaskState(task_id="test_atomic_write", input_config={})
        for i in range(100):
            state.add_stage(f"stage{i}")

        # Save and verify no .tmp files left behind
        await state_manager.save_async(state)

        tmp_files = list(tmp_path.glob("*.tmp"))
        assert len(tmp_files) == 0, "Temporary files should be cleaned up"

        # Verify state file exists and is valid
        state_file = tmp_path / "test_atomic_write.json"
        assert state_file.exists()

        # Load should work without errors
        loaded = await state_manager.load_async("test_atomic_write")
        assert len(loaded.stages) == 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
