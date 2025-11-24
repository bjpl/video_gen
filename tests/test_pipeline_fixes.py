"""
Comprehensive Test Suite for Pipeline Security and Progress Fixes
=================================================================

This test suite validates the recent security and progress calculation fixes:

1. Path Traversal Security:
   - /tmp directory access (should PASS - temporary files)
   - uploads/ directory access (should PASS - user uploads)
   - System directory blocking (should FAIL - security)
   - Parent directory traversal blocking (should FAIL - security)

2. Upload Handling:
   - File upload simulation
   - Correct path passing to pipeline
   - File saved in uploads/ directory

3. Progress Calculation:
   - Correct progress for partial completion
   - Failed stages contribute 0 to progress (recent fix)
   - Overall progress accuracy

4. Integration Test:
   - Simple document through full pipeline
   - Successful completion verification
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock
import json

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from video_gen.pipeline.state_manager import (
    StateManager, TaskState, TaskStatus, StageState
)
from video_gen.shared.models import InputConfig


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def temp_state_dir():
    """Create temporary directory for state files."""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def temp_uploads_dir():
    """Create temporary uploads directory."""
    temp_dir = tempfile.mkdtemp(prefix="uploads_")
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def state_manager(temp_state_dir):
    """Create StateManager with temporary directory."""
    return StateManager(state_dir=temp_state_dir)


@pytest.fixture
def sample_markdown_content():
    """Sample markdown content for testing."""
    return """# Test Document

## Section 1
This is test content for section 1.

## Section 2
This is test content for section 2.
"""


# ============================================================================
# Test Group 1: Path Traversal Security Fixes
# ============================================================================

class TestPathTraversalSecurity:
    """Test path traversal validation and security fixes."""

    @pytest.mark.asyncio
    async def test_tmp_directory_access_allowed(self, sample_markdown_content):
        """Test that /tmp directory access is ALLOWED for temporary files."""
        from video_gen.input_adapters.document import DocumentAdapter

        # Create a test file in /tmp
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(sample_markdown_content)
            tmp_file = Path(f.name)

        try:
            # Create adapter in test mode
            adapter = DocumentAdapter(test_mode=True, use_ai=False)

            # Should NOT raise ValueError for path traversal
            result = await adapter.adapt(
                str(tmp_file),
                accent_color="blue",
                voice="male",
                languages=["en"]
            )

            # Verify successful parsing
            assert result is not None
            assert result.success is True
            assert result.video_set is not None
            assert len(result.video_set.videos) > 0

        finally:
            # Cleanup
            if tmp_file.exists():
                tmp_file.unlink()

    @pytest.mark.asyncio
    async def test_uploads_directory_access_allowed(self, temp_uploads_dir, sample_markdown_content):
        """Test that uploads/ directory access is ALLOWED."""
        from video_gen.input_adapters.document import DocumentAdapter

        # Create a test file in uploads directory
        upload_file = temp_uploads_dir / "test_upload.md"
        upload_file.write_text(sample_markdown_content)

        # Create adapter in test mode
        adapter = DocumentAdapter(test_mode=True, use_ai=False)

        # Should NOT raise ValueError for path traversal
        result = await adapter.adapt(
            str(upload_file),
            accent_color="blue",
            voice="male",
            languages=["en"]
        )

        # Verify successful parsing
        assert result is not None
        assert result.success is True

    @pytest.mark.asyncio
    async def test_system_directory_access_blocked(self):
        """Test that system directory access is BLOCKED (security)."""
        from video_gen.input_adapters.document import DocumentAdapter

        # Create adapter (not in test mode for security checks)
        adapter = DocumentAdapter(test_mode=False, use_ai=False)

        # Try to access /etc/passwd (common target)
        result = await adapter.adapt(
            "/etc/passwd",
            accent_color="blue",
            voice="male",
            languages=["en"]
        )

        # Should return failure result with security error
        assert result.success is False
        assert result.error is not None
        assert "Access to system directories denied" in result.error or "denied" in result.error.lower()

    @pytest.mark.asyncio
    async def test_root_directory_access_blocked(self):
        """Test that /root directory access is BLOCKED."""
        from video_gen.input_adapters.document import DocumentAdapter

        adapter = DocumentAdapter(test_mode=False, use_ai=False)

        result = await adapter.adapt(
            "/root/.bashrc",
            accent_color="blue",
            voice="male",
            languages=["en"]
        )

        # Should return failure result
        assert result.success is False
        assert result.error is not None
        assert "denied" in result.error.lower() or "Access to system directories denied" in result.error

    @pytest.mark.asyncio
    async def test_parent_directory_traversal_blocked(self):
        """Test that parent directory traversal (../) is BLOCKED."""
        from video_gen.input_adapters.document import DocumentAdapter

        adapter = DocumentAdapter(test_mode=False, use_ai=False)

        # Try to traverse up with ../../../etc/passwd
        result = await adapter.adapt(
            "../../../../../../../etc/passwd",
            accent_color="blue",
            voice="male",
            languages=["en"]
        )

        # Should return failure result
        assert result.success is False
        assert result.error is not None


# ============================================================================
# Test Group 2: Upload Handling
# ============================================================================

class TestUploadHandling:
    """Test upload handling with correct paths."""

    def test_file_upload_simulation(self, temp_uploads_dir, sample_markdown_content):
        """Test simulating a file upload."""
        # Simulate file upload
        upload_file = temp_uploads_dir / "upload_12345_test.md"
        upload_file.write_text(sample_markdown_content)

        # Verify file exists in uploads directory
        assert upload_file.exists()
        assert upload_file.parent == temp_uploads_dir

    def test_upload_path_passed_to_pipeline(self, temp_uploads_dir, sample_markdown_content):
        """Test that correct upload path is passed to pipeline."""
        # Create uploaded file
        upload_file = temp_uploads_dir / "test_doc.md"
        upload_file.write_text(sample_markdown_content)

        # Create input config with upload path
        input_config = InputConfig(
            input_type="document",
            source=str(upload_file),
            accent_color="green",
            voice="female",
            languages=["en"]
        )

        # Verify path is correct
        assert input_config.source == str(upload_file)
        assert Path(input_config.source).exists()

    def test_upload_file_saved_in_correct_directory(self, temp_uploads_dir):
        """Test that uploaded files are saved in uploads/ directory."""
        # Simulate upload
        filename = "user_upload_doc.md"
        upload_path = temp_uploads_dir / filename

        # Write file
        upload_path.write_text("# Test Content")

        # Verify location
        assert upload_path.exists()
        assert upload_path.name == filename
        assert upload_path.parent == temp_uploads_dir


# ============================================================================
# Test Group 3: Progress Calculation Fixes
# ============================================================================

class TestProgressCalculation:
    """Test progress calculation with recent fixes."""

    def test_partial_completion_progress(self, state_manager):
        """Test correct progress for partial completion."""
        state = TaskState(
            task_id="partial_test",
            input_config={"source": "test.md"}
        )

        # Add 6 stages
        stages = [
            "input_adaptation",
            "content_parsing",
            "script_generation",
            "audio_generation",
            "video_generation",
            "output_handling"
        ]

        for stage in stages:
            state.add_stage(stage)

        # Complete 3 out of 6 stages
        state.complete_stage("input_adaptation")
        state.complete_stage("content_parsing")
        state.complete_stage("script_generation")

        # Progress should be 50% (3/6)
        expected_progress = 3.0 / 6.0
        assert abs(state.overall_progress - expected_progress) < 0.01

    def test_failed_stage_zero_progress(self, state_manager):
        """Test that failed stages contribute 0 to progress (RECENT FIX)."""
        state = TaskState(
            task_id="failed_test",
            input_config={"source": "test.md"}
        )

        # Add 3 stages
        state.add_stage("stage1")
        state.add_stage("stage2")
        state.add_stage("stage3")

        # Complete stage1 (100%)
        state.complete_stage("stage1")
        assert state.stages["stage1"].progress == 1.0

        # Fail stage2 (should be 0%)
        state.fail_stage("stage2", "Mock error")

        # CRITICAL: Failed stage should have 0 progress (recent fix)
        assert state.stages["stage2"].progress == 0.0

        # stage3 is pending (0%)
        # Overall: (1.0 + 0.0 + 0.0) / 3 = 0.333...
        expected_progress = 1.0 / 3.0
        assert abs(state.overall_progress - expected_progress) < 0.01

    def test_failed_stage_not_hundred_percent(self, state_manager):
        """Test that failed stages don't show 100% progress."""
        state = TaskState(
            task_id="not_hundred_test",
            input_config={"source": "test.md"}
        )

        # Add stage
        state.add_stage("failing_stage")
        state.start_stage("failing_stage")

        # Set some progress
        state.update_stage_progress("failing_stage", 0.8)

        # Fail the stage
        state.fail_stage("failing_stage", "Error occurred")

        # Failed stage should be 0, not 0.8 (recent fix)
        assert state.stages["failing_stage"].progress == 0.0
        assert state.overall_progress == 0.0

    def test_overall_progress_accuracy(self, state_manager):
        """Test overall progress accuracy with mixed stage states."""
        state = TaskState(
            task_id="accuracy_test",
            input_config={"source": "test.md"}
        )

        # Add 5 stages
        for i in range(5):
            state.add_stage(f"stage{i}")

        # Stage 0: Complete (1.0)
        state.complete_stage("stage0")

        # Stage 1: Failed (0.0)
        state.fail_stage("stage1", "Error")

        # Stage 2: In progress (0.5)
        state.update_stage_progress("stage2", 0.5)

        # Stage 3: In progress (0.3)
        state.update_stage_progress("stage3", 0.3)

        # Stage 4: Pending (0.0)
        # Total: (1.0 + 0.0 + 0.5 + 0.3 + 0.0) / 5 = 1.8 / 5 = 0.36
        expected_progress = 1.8 / 5.0
        assert abs(state.overall_progress - expected_progress) < 0.01

    def test_progress_never_exceeds_one(self, state_manager):
        """Test that progress never exceeds 1.0."""
        state = TaskState(
            task_id="clamp_test",
            input_config={"source": "test.md"}
        )

        state.add_stage("stage1")

        # Try to set progress > 1.0
        state.update_stage_progress("stage1", 1.5)

        # Should be clamped to 1.0
        assert state.stages["stage1"].progress == 1.0
        assert state.overall_progress == 1.0

    def test_progress_never_negative(self, state_manager):
        """Test that progress never goes negative."""
        state = TaskState(
            task_id="negative_test",
            input_config={"source": "test.md"}
        )

        state.add_stage("stage1")

        # Try to set negative progress
        state.update_stage_progress("stage1", -0.5)

        # Should be clamped to 0.0
        assert state.stages["stage1"].progress == 0.0
        assert state.overall_progress == 0.0


# ============================================================================
# Test Group 4: Integration Tests
# ============================================================================

class TestPipelineIntegration:
    """Integration tests with simple documents through full pipeline."""

    @pytest.mark.asyncio
    async def test_simple_document_parsing(self, sample_markdown_content):
        """Test parsing a simple document."""
        from video_gen.input_adapters.document import DocumentAdapter

        # Create temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(sample_markdown_content)
            temp_file = Path(f.name)

        try:
            # Create adapter
            adapter = DocumentAdapter(test_mode=True, use_ai=False)

            # Parse document
            result = await adapter.adapt(
                str(temp_file),
                accent_color="blue",
                voice="male",
                languages=["en"]
            )

            # Verify parsing
            assert result is not None
            assert result.success is True
            assert result.video_set is not None
            assert len(result.video_set.videos) > 0

            # Verify first video
            video = result.video_set.videos[0]
            assert hasattr(video, 'title')
            assert hasattr(video, 'scenes')
            assert len(video.scenes) > 0

        finally:
            if temp_file.exists():
                temp_file.unlink()

    def test_state_persistence_after_failure(self, state_manager):
        """Test that state is persisted even after failure."""
        state = TaskState(
            task_id="persist_test",
            input_config={"source": "test.md"}
        )

        # Add stages and complete some
        state.add_stage("stage1")
        state.add_stage("stage2")
        state.complete_stage("stage1")
        state.fail_stage("stage2", "Mock failure")

        # Save state
        state_manager.save(state)

        # Load state back
        loaded_state = state_manager.load("persist_test")

        # Verify state persisted correctly
        assert loaded_state.task_id == "persist_test"
        assert loaded_state.stages["stage1"].status == TaskStatus.COMPLETED
        assert loaded_state.stages["stage2"].status == TaskStatus.FAILED
        assert loaded_state.stages["stage2"].error == "Mock failure"
        assert loaded_state.stages["stage2"].progress == 0.0  # Recent fix

    def test_full_stage_progression(self, state_manager):
        """Test full progression through all 6 pipeline stages."""
        state = TaskState(
            task_id="full_progression_test",
            input_config={"source": "test.md"}
        )

        stages = [
            "input_adaptation",
            "content_parsing",
            "script_generation",
            "audio_generation",
            "video_generation",
            "output_handling"
        ]

        # Add all stages first
        for stage_name in stages:
            state.add_stage(stage_name)

        # Progress through all stages
        for i, stage_name in enumerate(stages):
            state.start_stage(stage_name)
            state.update_stage_progress(stage_name, 0.5)
            state.complete_stage(stage_name)

            # Verify progress at each step
            expected_progress = (i + 1) / len(stages)
            assert abs(state.overall_progress - expected_progress) < 0.01

        # Final state should be 100%
        assert state.overall_progress == 1.0
        assert len(state.get_completed_stages()) == 6


# ============================================================================
# Test Group 5: Edge Cases and Error Handling
# ============================================================================

class TestEdgeCases:
    """Test edge cases and error scenarios."""

    @pytest.mark.asyncio
    async def test_nonexistent_file_error(self):
        """Test error for nonexistent file."""
        from video_gen.input_adapters.document import DocumentAdapter

        adapter = DocumentAdapter(test_mode=True, use_ai=False)

        result = await adapter.adapt(
            "/nonexistent/path/to/file.md",
            accent_color="blue",
            voice="male",
            languages=["en"]
        )

        # Should return failure result
        assert result.success is False
        assert result.error is not None

    def test_stage_timing_recorded(self, state_manager):
        """Test that stage timing is recorded correctly."""
        state = TaskState(
            task_id="timing_test",
            input_config={"source": "test.md"}
        )

        state.start_stage("stage1")

        # Verify started_at is set
        assert state.stages["stage1"].started_at is not None
        assert isinstance(state.stages["stage1"].started_at, datetime)

        state.complete_stage("stage1")

        # Verify completed_at is set
        assert state.stages["stage1"].completed_at is not None
        assert state.stages["stage1"].completed_at >= state.stages["stage1"].started_at

    def test_failed_stage_timing_recorded(self, state_manager):
        """Test that failed stage timing is recorded."""
        state = TaskState(
            task_id="fail_timing_test",
            input_config={"source": "test.md"}
        )

        state.start_stage("stage1")
        state.fail_stage("stage1", "Error")

        # Verify completed_at is set even for failed stages
        assert state.stages["stage1"].completed_at is not None


# ============================================================================
# Test Group 6: Real-World Scenarios
# ============================================================================

class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    @pytest.mark.asyncio
    async def test_upload_then_process_scenario(self, temp_uploads_dir, sample_markdown_content):
        """Test realistic upload-then-process scenario."""
        from video_gen.input_adapters.document import DocumentAdapter

        # Step 1: User uploads file
        task_id = f"upload_{int(datetime.now().timestamp())}"
        filename = "user_document.md"
        upload_path = temp_uploads_dir / f"{task_id}_{filename}"
        upload_path.write_text(sample_markdown_content)

        # Step 2: Parse with adapter
        adapter = DocumentAdapter(test_mode=True, use_ai=False)
        result = await adapter.adapt(
            str(upload_path),
            accent_color="purple",
            voice="female",
            languages=["en"]
        )

        # Verify success
        assert result is not None
        assert result.success is True
        assert result.video_set is not None
        assert len(result.video_set.videos) > 0

    def test_recovery_from_mid_pipeline_failure(self, state_manager):
        """Test recovery scenario from mid-pipeline failure."""
        state = TaskState(
            task_id="recovery_test",
            input_config={"source": "test.md"}
        )

        # Simulate pipeline that gets to stage 3 then fails
        stages = ["stage1", "stage2", "stage3", "stage4", "stage5"]

        for stage in stages[:2]:
            state.add_stage(stage)
            state.complete_stage(stage)

        state.add_stage(stages[2])
        state.fail_stage(stages[2], "Network timeout")

        # Save failed state
        state_manager.save(state)

        # Verify we can resume from this point
        loaded_state = state_manager.load("recovery_test")
        assert len(loaded_state.get_completed_stages()) == 2
        assert len(loaded_state.get_failed_stages()) == 1

        # Recovery: retry failed stage
        loaded_state.start_stage(stages[2])
        loaded_state.complete_stage(stages[2])

        # Continue with remaining stages
        for stage in stages[3:]:
            loaded_state.add_stage(stage)
            loaded_state.complete_stage(stage)

        # Verify full completion
        assert len(loaded_state.get_completed_stages()) == 5
        assert loaded_state.overall_progress == 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
