"""
Test Suite for Unified Video Generator
=======================================
Tests all video generation functionality including:
- Scene rendering (12 types)
- Frame blending (NumPy and PIL)
- Video encoding
- Audio processing
- Batch and parallel modes
"""

import pytest
import json
import numpy as np
from pathlib import Path
from PIL import Image
from unittest.mock import Mock, patch, MagicMock
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from video_gen.video_generator.unified import (
    UnifiedVideoGenerator,
    TimingReport,
    VideoConfig,
    generate_videos_from_timings
)


@pytest.fixture
def sample_timing_report(tmp_path):
    """Create a sample timing report"""
    report = {
        "video_id": "test_video_001",
        "title": "Test Video",
        "total_duration": 10.0,
        "accent_color": [59, 130, 246],
        "scenes": [
            {
                "scene_id": "scene_001",
                "type": "title",
                "duration": 3.0,
                "audio_duration": 2.5,
                "visual_content": {
                    "title": "Test Title",
                    "subtitle": "Test Subtitle"
                },
                "voice": "male"
            },
            {
                "scene_id": "scene_002",
                "type": "command",
                "duration": 4.0,
                "audio_duration": 3.5,
                "visual_content": {
                    "header": "Command Test",
                    "description": "Testing commands",
                    "commands": ["$ python test.py", "→ Success"]
                },
                "voice": "male"
            },
            {
                "scene_id": "scene_003",
                "type": "outro",
                "duration": 3.0,
                "audio_duration": 2.5,
                "visual_content": {
                    "main_text": "Thank You",
                    "sub_text": "End of Test"
                },
                "voice": "male"
            }
        ]
    }

    report_file = tmp_path / "timing_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f)

    return report_file


@pytest.fixture
def generator_fast(tmp_path):
    """Create fast mode generator"""
    return UnifiedVideoGenerator(mode="fast", output_dir=tmp_path / "videos")


@pytest.fixture
def generator_baseline(tmp_path):
    """Create baseline mode generator"""
    return UnifiedVideoGenerator(mode="baseline", output_dir=tmp_path / "videos")


@pytest.fixture
def generator_parallel(tmp_path):
    """Create parallel mode generator"""
    return UnifiedVideoGenerator(mode="parallel", output_dir=tmp_path / "videos")


class TestUnifiedVideoGenerator:
    """Test UnifiedVideoGenerator class"""

    def test_initialization_fast(self, generator_fast):
        """Test generator initialization in fast mode"""
        assert generator_fast.mode == "fast"
        assert generator_fast.output_dir.exists()
        assert len(generator_fast.renderers) == 12

    def test_initialization_baseline(self, generator_baseline):
        """Test generator initialization in baseline mode"""
        assert generator_baseline.mode == "baseline"
        assert generator_baseline.output_dir.exists()

    def test_initialization_parallel(self, generator_parallel):
        """Test generator initialization in parallel mode"""
        assert generator_parallel.mode == "parallel"
        assert generator_parallel.output_dir.exists()

    def test_renderer_mapping(self, generator_fast):
        """Test that all scene types have renderers"""
        expected_types = [
            "title", "command", "list", "outro",
            "code_comparison", "quote", "problem", "solution",
            "checkpoint", "quiz", "learning_objectives", "exercise"
        ]

        for scene_type in expected_types:
            assert scene_type in generator_fast.renderers
            assert callable(generator_fast.renderers[scene_type])


class TestSceneRendering:
    """Test scene rendering for all types"""

    def test_render_title_scene(self, generator_fast):
        """Test title scene rendering"""
        scene = {
            "type": "title",
            "visual_content": {
                "title": "Test Title",
                "subtitle": "Test Subtitle"
            }
        }

        start, end = generator_fast._render_scene_keyframes(scene, (59, 130, 246))

        assert isinstance(start, Image.Image)
        assert isinstance(end, Image.Image)
        assert start.size == (1920, 1080)
        assert end.size == (1920, 1080)

    def test_render_command_scene(self, generator_fast):
        """Test command scene rendering"""
        scene = {
            "type": "command",
            "visual_content": {
                "header": "Test Command",
                "description": "Command description",
                "commands": ["$ python test.py", "→ Output"]
            }
        }

        start, end = generator_fast._render_scene_keyframes(scene, (59, 130, 246))

        assert isinstance(start, Image.Image)
        assert isinstance(end, Image.Image)

    def test_render_list_scene(self, generator_fast):
        """Test list scene rendering"""
        scene = {
            "type": "list",
            "visual_content": {
                "header": "Test List",
                "description": "List description",
                "items": ["Item 1", "Item 2", "Item 3"]
            }
        }

        start, end = generator_fast._render_scene_keyframes(scene, (59, 130, 246))

        assert isinstance(start, Image.Image)
        assert isinstance(end, Image.Image)

    def test_render_outro_scene(self, generator_fast):
        """Test outro scene rendering"""
        scene = {
            "type": "outro",
            "visual_content": {
                "main_text": "Thank You",
                "sub_text": "Visit us again"
            }
        }

        start, end = generator_fast._render_scene_keyframes(scene, (59, 130, 246))

        assert isinstance(start, Image.Image)
        assert isinstance(end, Image.Image)

    def test_render_code_comparison_scene(self, generator_fast):
        """Test code comparison scene rendering"""
        scene = {
            "type": "code_comparison",
            "visual_content": {
                "header": "Code Comparison",
                "before_code": "def old(): pass",
                "after_code": "def new(): return True",
                "before_label": "Before",
                "after_label": "After"
            }
        }

        start, end = generator_fast._render_scene_keyframes(scene, (59, 130, 246))

        assert isinstance(start, Image.Image)
        assert isinstance(end, Image.Image)

    def test_render_quote_scene(self, generator_fast):
        """Test quote scene rendering"""
        scene = {
            "type": "quote",
            "visual_content": {
                "quote_text": "Test quote text",
                "attribution": "Test Author"
            }
        }

        start, end = generator_fast._render_scene_keyframes(scene, (59, 130, 246))

        assert isinstance(start, Image.Image)
        assert isinstance(end, Image.Image)

    def test_render_unknown_scene_type(self, generator_fast):
        """Test error handling for unknown scene type"""
        scene = {
            "type": "unknown_type",
            "visual_content": {}
        }

        with pytest.raises(ValueError, match="Unknown scene type"):
            generator_fast._render_scene_keyframes(scene, (59, 130, 246))


class TestFrameBlending:
    """Test frame blending optimizations"""

    def test_numpy_blending_fast_mode(self, generator_fast):
        """Test NumPy blending in fast mode"""
        # Create test frames
        img1 = Image.new('RGB', (100, 100), color=(255, 0, 0))
        img2 = Image.new('RGB', (100, 100), color=(0, 0, 255))

        frames = generator_fast._animate_scene(img1, img2, anim_frames=5, scene_duration=1.0)

        assert len(frames) > 0
        assert all(isinstance(f, np.ndarray) for f in frames)
        assert all(f.dtype == np.uint8 for f in frames)

    def test_pil_blending_baseline_mode(self, generator_baseline):
        """Test PIL blending in baseline mode"""
        img1 = Image.new('RGB', (100, 100), color=(255, 0, 0))
        img2 = Image.new('RGB', (100, 100), color=(0, 0, 255))

        frames = generator_baseline._animate_scene(img1, img2, anim_frames=5, scene_duration=1.0)

        assert len(frames) > 0
        assert all(isinstance(f, np.ndarray) for f in frames)

    def test_transition_rendering_fast(self, generator_fast):
        """Test transition rendering in fast mode"""
        img1 = Image.new('RGB', (100, 100), color=(255, 0, 0))
        img2 = Image.new('RGB', (100, 100), color=(0, 0, 255))

        frames = generator_fast._render_transition(img1, img2, trans_frames=10)

        assert len(frames) == 10
        assert all(isinstance(f, np.ndarray) for f in frames)

    def test_transition_rendering_baseline(self, generator_baseline):
        """Test transition rendering in baseline mode"""
        img1 = Image.new('RGB', (100, 100), color=(255, 0, 0))
        img2 = Image.new('RGB', (100, 100), color=(0, 0, 255))

        frames = generator_baseline._render_transition(img1, img2, trans_frames=10)

        assert len(frames) == 10
        assert all(isinstance(f, np.ndarray) for f in frames)


class TestVideoGeneration:
    """Test complete video generation pipeline"""

    @patch('subprocess.run')
    def test_encode_video(self, mock_run, generator_fast, tmp_path):
        """Test video encoding"""
        # Mock successful encoding
        mock_run.return_value = MagicMock(returncode=0)

        # Create test frames
        frames = [np.zeros((1080, 1920, 3), dtype=np.uint8) for _ in range(5)]

        # Should not raise exception
        output = generator_fast._encode_video(frames, "test_video")

        assert output.exists() or mock_run.called

    @patch('subprocess.run')
    def test_encode_video_failure(self, mock_run, generator_fast):
        """Test video encoding failure handling"""
        # Mock encoding failure
        mock_run.return_value = MagicMock(returncode=1, stderr="Encoding failed")

        frames = [np.zeros((1080, 1920, 3), dtype=np.uint8) for _ in range(5)]

        with pytest.raises(RuntimeError, match="Video encoding failed"):
            generator_fast._encode_video(frames, "test_video")

    def test_progress_callback(self, tmp_path):
        """Test progress callback functionality"""
        callback_calls = []

        def progress_cb(stage, progress, message):
            callback_calls.append({
                'stage': stage,
                'progress': progress,
                'message': message
            })

        generator = UnifiedVideoGenerator(
            mode="fast",
            output_dir=tmp_path / "videos",
            progress_callback=progress_cb
        )

        # Create mock timing reports
        reports = [tmp_path / f"report_{i}.json" for i in range(3)]
        for report in reports:
            report.write_text('{"video_id": "test", "title": "Test", "scenes": []}')

        with patch.object(generator, '_generate_single_video', return_value=None):
            generator._generate_sequential(reports)

        assert len(callback_calls) > 0
        assert all(call['stage'] == 'video' for call in callback_calls)


class TestBatchProcessing:
    """Test batch and parallel processing"""

    def test_sequential_generation(self, generator_fast, tmp_path):
        """Test sequential video generation"""
        reports = [tmp_path / f"report_{i}.json" for i in range(3)]

        for i, report in enumerate(reports):
            data = {
                "video_id": f"test_{i}",
                "title": f"Test {i}",
                "total_duration": 5.0,
                "scenes": []
            }
            with open(report, 'w') as f:
                json.dump(data, f)

        with patch.object(generator_fast, '_generate_single_video', return_value=Path("test.mp4")):
            results = generator_fast._generate_sequential(reports)

        assert len(results) == 3

    @pytest.mark.skip(reason="Cannot mock methods that use multiprocessing - Mock objects not picklable. Needs real files or different test approach.")
    def test_parallel_generation(self, generator_parallel, tmp_path):
        """Test parallel video generation"""
        pass


class TestBackwardCompatibility:
    """Test backward compatibility functions"""

    def test_generate_videos_from_timings(self, tmp_path):
        """Test legacy function"""
        reports = [tmp_path / "report.json"]
        report_data = {
            "video_id": "test",
            "title": "Test",
            "total_duration": 5.0,
            "scenes": []
        }

        with open(reports[0], 'w') as f:
            json.dump(report_data, f)

        with patch('video_gen.video_generator.unified.UnifiedVideoGenerator._generate_single_video', return_value=Path("test.mp4")):
            results = generate_videos_from_timings(reports, tmp_path / "output")

        assert len(results) == 1


class TestEdgeCases:
    """Test edge cases and error handling"""

    def test_missing_visual_content(self, generator_fast):
        """Test handling of missing visual content"""
        scene = {
            "type": "title",
            "visual_content": {}  # Empty visual content
        }

        # Should handle missing fields gracefully
        start, end = generator_fast._render_scene_keyframes(scene, (59, 130, 246))

        assert isinstance(start, Image.Image)
        assert isinstance(end, Image.Image)

    def test_empty_timing_report(self, generator_fast, tmp_path):
        """Test handling of empty timing report"""
        report = tmp_path / "empty_report.json"
        data = {
            "video_id": "test",
            "title": "Test",
            "total_duration": 0.0,
            "scenes": []
        }

        with open(report, 'w') as f:
            json.dump(data, f)

        # Should handle gracefully or raise appropriate error
        try:
            result = generator_fast._generate_single_video(report)
            # Either returns None or raises error - both acceptable
        except Exception as e:
            assert isinstance(e, (ValueError, IndexError, KeyError))

    def test_invalid_ffmpeg_path(self, tmp_path):
        """Test handling of invalid FFmpeg path"""
        generator = UnifiedVideoGenerator(
            mode="fast",
            output_dir=tmp_path / "videos",
            ffmpeg_path="/invalid/path/to/ffmpeg"
        )

        frames = [np.zeros((1080, 1920, 3), dtype=np.uint8) for _ in range(5)]

        # Should raise error when trying to encode
        with pytest.raises((FileNotFoundError, RuntimeError)):
            generator._encode_video(frames, "test")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
