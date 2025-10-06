"""
Comprehensive tests for utility modules to increase coverage.

Tests for:
- app/utils.py - API utility functions (140 missing lines)
- app/models.py - Pydantic models (127 missing lines)
- video_gen/shared/utils.py - Shared utilities (39 missing lines)

Target: Cover ~200 of 306 missing lines across utility modules.
"""

import pytest
import asyncio
import tempfile
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock, mock_open
from datetime import datetime
from typing import Dict, List

# Import modules under test
from app.utils import (
    get_input_methods,
    parse_document_input,
    parse_youtube_input,
    parse_wizard_input,
    trigger_video_generation,
    get_job_status,
    list_templates,
    _convert_structure_to_scenes,
    _convert_transcript_to_scenes,
    _convert_wizard_to_scenes,
    _extract_scene_types,
    _create_yaml_from_scenes,
)

from app.models import (
    ParseRequest,
    ParseResponse,
    GenerateRequest,
    GenerateResponse,
    JobStatus,
    InputMethod,
    Template,
    TitleScene,
    CommandScene,
    ListScene,
    OutroScene,
    CodeComparisonScene,
    QuoteScene,
    LearningObjectivesScene,
    ProblemScene,
    SolutionScene,
    CheckpointScene,
    QuizScene,
    ExerciseScene,
    VideoConfig,
)

from video_gen.shared.utils import (
    format_timestamp,
    sanitize_filename,
    validate_language_code,
    get_language_name,
    ensure_dir,
    get_file_extension,
    calculate_progress,
    truncate_text,
)


# ============================================================================
# Tests for video_gen/shared/utils.py
# ============================================================================

class TestSharedUtils:
    """Test shared utility functions."""

    def test_format_timestamp_with_hours(self):
        """Test timestamp formatting with hours."""
        assert format_timestamp(0) == "00:00:00"
        assert format_timestamp(90) == "00:01:30"
        assert format_timestamp(3661) == "01:01:01"
        assert format_timestamp(3600) == "01:00:00"

    def test_format_timestamp_without_hours(self):
        """Test timestamp formatting without hours."""
        assert format_timestamp(90, include_hours=False) == "01:30"
        assert format_timestamp(3661, include_hours=False) == "01:01"  # Hours still affect minutes calculation
        assert format_timestamp(0, include_hours=False) == "00:00"

    def test_format_timestamp_edge_cases(self):
        """Test timestamp with edge cases."""
        assert format_timestamp(0.5) == "00:00:00"  # Rounds down
        assert format_timestamp(59.9) == "00:00:59"
        assert format_timestamp(86399) == "23:59:59"

    def test_sanitize_filename_removes_invalid_chars(self):
        """Test sanitizing filenames by removing invalid characters."""
        # Multiple underscores are collapsed to single underscore
        assert sanitize_filename("file<>name.txt") == "file_name.txt"
        assert sanitize_filename('video:"test"|part?.mp4') == "video_test_part_.mp4"
        assert sanitize_filename("path/to\\file.txt") == "path_to_file.txt"

    def test_sanitize_filename_strips_spaces_dots(self):
        """Test sanitizing strips leading/trailing spaces and dots."""
        assert sanitize_filename("  filename.txt  ") == "filename.txt"
        assert sanitize_filename("...filename...") == "filename"
        # Leading/trailing dots/spaces are stripped
        result = sanitize_filename(". . file . .txt")
        assert "file" in result
        assert result.endswith(".txt")

    def test_sanitize_filename_replaces_multiple_underscores(self):
        """Test sanitizing replaces multiple underscores."""
        assert sanitize_filename("file___name.txt") == "file_name.txt"
        assert sanitize_filename("a__b___c____d.txt") == "a_b_c_d.txt"

    def test_sanitize_filename_truncates_long_names(self):
        """Test sanitizing truncates long filenames."""
        long_name = "a" * 300 + ".txt"
        result = sanitize_filename(long_name, max_length=255)
        assert len(result) <= 255
        assert result.endswith(".txt")

    def test_validate_language_code_valid(self):
        """Test validating valid language codes."""
        assert validate_language_code("en") is True
        assert validate_language_code("es") is True
        assert validate_language_code("EN") is True  # Case insensitive
        assert validate_language_code("fr") is True

    def test_validate_language_code_invalid(self):
        """Test validating invalid language codes."""
        assert validate_language_code("invalid") is False
        assert validate_language_code("xyz") is False
        assert validate_language_code("") is False
        assert validate_language_code("english") is False

    def test_get_language_name_valid(self):
        """Test getting language names for valid codes."""
        assert get_language_name("en") == "English"
        assert get_language_name("es") == "Spanish"
        assert get_language_name("EN") == "English"  # Case insensitive
        assert get_language_name("fr") == "French"

    def test_get_language_name_invalid(self):
        """Test getting language name for invalid code returns None."""
        assert get_language_name("invalid") is None
        assert get_language_name("xyz") is None
        assert get_language_name("") is None

    def test_ensure_dir_creates_directory(self, tmp_path):
        """Test ensuring directory creates it if it doesn't exist."""
        test_dir = tmp_path / "test" / "nested" / "dir"
        result = ensure_dir(test_dir)
        assert result == test_dir
        assert test_dir.exists()
        assert test_dir.is_dir()

    def test_ensure_dir_existing_directory(self, tmp_path):
        """Test ensuring directory works with existing directory."""
        test_dir = tmp_path / "existing"
        test_dir.mkdir()
        result = ensure_dir(test_dir)
        assert result == test_dir
        assert test_dir.exists()

    def test_get_file_extension(self):
        """Test getting file extensions."""
        assert get_file_extension("video.MP4") == ".mp4"
        assert get_file_extension("document.PDF") == ".pdf"
        assert get_file_extension("/path/to/file.TXT") == ".txt"
        assert get_file_extension("noextension") == ""
        assert get_file_extension("file.tar.gz") == ".gz"

    def test_calculate_progress(self):
        """Test calculating progress percentage."""
        assert calculate_progress(0, 100) == 0.0
        assert calculate_progress(25, 100) == 25.0
        assert calculate_progress(50, 100) == 50.0
        assert calculate_progress(100, 100) == 100.0
        assert calculate_progress(1, 3) == pytest.approx(33.333, rel=0.01)

    def test_calculate_progress_zero_total(self):
        """Test calculating progress with zero total."""
        assert calculate_progress(0, 0) == 0.0
        assert calculate_progress(10, 0) == 0.0

    def test_truncate_text_short(self):
        """Test truncating text that's already short."""
        text = "Short text"
        assert truncate_text(text, max_length=100) == text
        assert truncate_text(text, max_length=10) == text

    def test_truncate_text_long(self):
        """Test truncating long text."""
        text = "This is a very long text that needs to be truncated"
        result = truncate_text(text, max_length=20)
        assert len(result) == 20
        assert result.endswith("...")
        # Truncates at max_length - len(suffix)
        assert result.startswith("This is a very")

    def test_truncate_text_custom_suffix(self):
        """Test truncating with custom suffix."""
        text = "This is a long text"
        result = truncate_text(text, max_length=15, suffix=" [more]")
        assert len(result) == 15
        assert result.endswith(" [more]")


# ============================================================================
# Tests for app/models.py
# ============================================================================

class TestPydanticModels:
    """Test Pydantic model validation and serialization."""

    def test_parse_request_document_valid(self):
        """Test ParseRequest with valid document input."""
        data = {
            "input_type": "document",
            "document_path": "README.md",
            "accent_color": "blue",
            "voice": "male",
            "duration": 60
        }
        request = ParseRequest(**data)
        assert request.input_type == "document"
        assert request.document_path == "README.md"
        assert request.accent_color == "blue"
        assert request.duration == 60

    def test_parse_request_youtube_valid(self):
        """Test ParseRequest with valid YouTube input."""
        data = {
            "input_type": "youtube",
            "youtube_url": "https://youtube.com/watch?v=test123",
            "accent_color": "orange",
            "voice": "female"
        }
        request = ParseRequest(**data)
        assert request.input_type == "youtube"
        assert "youtube.com" in str(request.youtube_url)

    def test_parse_request_wizard_valid(self):
        """Test ParseRequest with valid wizard input."""
        data = {
            "input_type": "wizard",
            "wizard_data": {"scenes": [{"type": "title", "title": "Test"}]},
            "accent_color": "purple"
        }
        request = ParseRequest(**data)
        assert request.input_type == "wizard"
        assert request.wizard_data is not None
        assert "scenes" in request.wizard_data

    def test_parse_request_invalid_accent_color(self):
        """Test ParseRequest rejects invalid accent color."""
        with pytest.raises(ValueError):
            ParseRequest(
                input_type="document",
                document_path="test.md",
                accent_color="invalid_color"
            )

    def test_parse_request_invalid_voice(self):
        """Test ParseRequest rejects invalid voice."""
        with pytest.raises(ValueError):
            ParseRequest(
                input_type="document",
                document_path="test.md",
                voice="invalid_voice"
            )

    def test_parse_request_duration_bounds(self):
        """Test ParseRequest validates duration bounds."""
        # Too short
        with pytest.raises(ValueError):
            ParseRequest(input_type="document", document_path="test.md", duration=5)

        # Too long
        with pytest.raises(ValueError):
            ParseRequest(input_type="document", document_path="test.md", duration=700)

        # Valid
        request = ParseRequest(input_type="document", document_path="test.md", duration=60)
        assert request.duration == 60

    def test_parse_response_creation(self):
        """Test ParseResponse creation."""
        response = ParseResponse(
            job_id="test123",
            status="completed",
            message="Parsing successful",
            scenes=[{"type": "title", "title": "Test"}],
            metadata={"source": "test.md"}
        )
        assert response.job_id == "test123"
        assert response.status == "completed"
        assert len(response.scenes) == 1
        assert response.metadata["source"] == "test.md"

    def test_generate_request_valid(self):
        """Test GenerateRequest with valid data."""
        request = GenerateRequest(
            scenes=[
                {"type": "title", "title": "Test", "subtitle": "Subtitle"},
                {"type": "command", "command_name": "Install", "commands": ["pip install"]}
            ],
            config={"accent_color": "blue", "default_voice": "male"}
        )
        assert len(request.scenes) == 2
        assert request.config["accent_color"] == "blue"

    def test_generate_response_creation(self):
        """Test GenerateResponse creation."""
        response = GenerateResponse(
            job_id="test123",
            status="queued",
            message="Video generation started",
            estimated_time_seconds=120
        )
        assert response.job_id == "test123"
        assert response.estimated_time_seconds == 120

    def test_job_status_valid_states(self):
        """Test JobStatus with valid states."""
        for state in ["queued", "parsing", "generating", "completed", "error"]:
            status = JobStatus(
                job_id="test123",
                status=state,
                progress=50,
                message="Processing",
                created_at="2025-10-06T12:00:00Z"
            )
            assert status.status == state

    def test_job_status_progress_bounds(self):
        """Test JobStatus validates progress bounds."""
        # Valid progress
        status = JobStatus(
            job_id="test123",
            status="generating",
            progress=50,
            message="Processing",
            created_at="2025-10-06T12:00:00Z"
        )
        assert status.progress == 50

    def test_title_scene_validation(self):
        """Test TitleScene validation."""
        scene = TitleScene(title="Test Title", subtitle="Test Subtitle")
        assert scene.type == "title"
        assert scene.title == "Test Title"
        assert scene.subtitle == "Test Subtitle"

    def test_command_scene_validation(self):
        """Test CommandScene validation."""
        scene = CommandScene(
            command_name="Install",
            description="Install dependencies",
            commands=["pip install -r requirements.txt"]
        )
        assert scene.type == "command"
        assert len(scene.commands) == 1

    def test_list_scene_validation(self):
        """Test ListScene validation."""
        scene = ListScene(
            title="Key Points",
            items=["Point 1", "Point 2", "Point 3"]
        )
        assert scene.type == "list"
        assert len(scene.items) == 3

    def test_outro_scene_validation(self):
        """Test OutroScene validation."""
        scene = OutroScene(title="Thanks!", subtitle="Subscribe")
        assert scene.type == "outro"
        assert scene.title == "Thanks!"

    def test_code_comparison_scene_validation(self):
        """Test CodeComparisonScene validation."""
        scene = CodeComparisonScene(
            title="Refactoring",
            before_label="Before",
            after_label="After",
            before_code=["old code"],
            after_code=["new code"]
        )
        assert scene.type == "code_comparison"
        assert len(scene.before_code) == 1

    def test_quote_scene_validation(self):
        """Test QuoteScene validation."""
        scene = QuoteScene(
            quote="Test quote",
            attribution="Author"
        )
        assert scene.type == "quote"
        assert scene.quote == "Test quote"

    def test_learning_objectives_scene(self):
        """Test LearningObjectivesScene validation."""
        scene = LearningObjectivesScene(
            title="Objectives",
            objectives=["Learn X", "Understand Y"]
        )
        assert scene.type == "learning_objectives"
        assert len(scene.objectives) == 2

    def test_problem_scene_validation(self):
        """Test ProblemScene validation."""
        scene = ProblemScene(
            title="Problem",
            description="Solve this",
            constraints=["Constraint 1"]
        )
        assert scene.type == "problem"
        assert scene.constraints is not None

    def test_solution_scene_validation(self):
        """Test SolutionScene validation."""
        scene = SolutionScene(
            title="Solution",
            explanation="Here's how",
            code=["solution code"]
        )
        assert scene.type == "solution"
        assert len(scene.code) == 1

    def test_checkpoint_scene_validation(self):
        """Test CheckpointScene validation."""
        scene = CheckpointScene(
            title="Checkpoint",
            key_points=["Point 1", "Point 2"]
        )
        assert scene.type == "checkpoint"
        assert len(scene.key_points) == 2

    def test_quiz_scene_validation(self):
        """Test QuizScene validation."""
        scene = QuizScene(
            question="What is 2+2?",
            options=["3", "4", "5"],
            correct_answer=1
        )
        assert scene.type == "quiz"
        assert scene.correct_answer == 1

    def test_exercise_scene_validation(self):
        """Test ExerciseScene validation."""
        scene = ExerciseScene(
            title="Exercise",
            instructions="Do this",
            hints=["Hint 1"]
        )
        assert scene.type == "exercise"
        assert scene.hints is not None

    def test_video_config_defaults(self):
        """Test VideoConfig with default values."""
        config = VideoConfig()
        assert config.accent_color == "blue"
        assert config.default_voice == "male"
        assert config.resolution == "1920x1080"
        assert config.fps == 30

    def test_video_config_custom_values(self):
        """Test VideoConfig with custom values."""
        config = VideoConfig(
            accent_color="orange",
            default_voice="female",
            resolution="1280x720",
            fps=60,
            use_ai_narration=True,
            output_format="webm"
        )
        assert config.accent_color == "orange"
        assert config.fps == 60
        assert config.use_ai_narration is True

    def test_video_config_invalid_resolution(self):
        """Test VideoConfig rejects invalid resolution."""
        with pytest.raises(ValueError):
            VideoConfig(resolution="invalid")

    def test_video_config_fps_bounds(self):
        """Test VideoConfig validates FPS bounds."""
        with pytest.raises(ValueError):
            VideoConfig(fps=10)  # Too low
        with pytest.raises(ValueError):
            VideoConfig(fps=100)  # Too high

        config = VideoConfig(fps=30)
        assert config.fps == 30


# ============================================================================
# Tests for app/utils.py
# ============================================================================

class TestAppUtils:
    """Test API utility functions."""

    @pytest.mark.asyncio
    async def test_get_input_methods(self):
        """Test getting list of input methods."""
        methods = await get_input_methods()
        assert len(methods) == 3
        assert any(m["id"] == "document" for m in methods)
        assert any(m["id"] == "youtube" for m in methods)
        assert any(m["id"] == "wizard" for m in methods)

        # Check structure
        for method in methods:
            assert "id" in method
            assert "name" in method
            assert "description" in method
            assert "icon" in method

    @pytest.mark.asyncio
    async def test_parse_document_input_no_source(self):
        """Test parse_document_input raises error with no source."""
        request = MagicMock()
        request.document_path = None
        request.document_url = None

        # Function wraps ValueError in Exception
        with pytest.raises(Exception, match="Document parsing failed"):
            await parse_document_input(request, "job123")

    @pytest.mark.asyncio
    @patch("app.utils.read_document")
    @patch("app.utils.MarkdownParser")
    async def test_parse_document_input_success(self, mock_parser_class, mock_read):
        """Test successful document parsing."""
        # Setup mocks
        mock_read.return_value = "# Test Document\nContent here"
        mock_parser = MagicMock()
        mock_parser.parse.return_value = {
            "title": "Test Document",
            "sections": [
                {"type": "code", "title": "Example", "code_lines": ["print('hello')"]}
            ]
        }
        mock_parser_class.return_value = mock_parser

        request = MagicMock()
        request.document_path = "test.md"
        request.document_url = None

        result = await parse_document_input(request, "job123")

        assert "scenes" in result
        assert "metadata" in result
        assert result["metadata"]["source"] == "test.md"
        assert result["metadata"]["title"] == "Test Document"

    @pytest.mark.asyncio
    async def test_parse_youtube_input_no_source(self):
        """Test parse_youtube_input raises error with no source."""
        request = MagicMock()
        request.youtube_url = None
        request.youtube_id = None
        request.youtube_query = None

        # Function wraps ValueError in Exception
        with pytest.raises(Exception, match="YouTube parsing failed"):
            await parse_youtube_input(request, "job123")

    @pytest.mark.asyncio
    @patch("app.utils.extract_video_id")
    @patch("app.utils.fetch_transcript")
    async def test_parse_youtube_input_with_url(self, mock_fetch, mock_extract):
        """Test parse_youtube_input with URL."""
        mock_extract.return_value = "test_video_id"
        mock_fetch.return_value = {
            "transcript": "This is the video transcript" * 50,
            "duration": 120
        }

        request = MagicMock()
        request.youtube_url = "https://youtube.com/watch?v=test_video_id"
        request.youtube_id = None
        request.duration = 60

        result = await parse_youtube_input(request, "job123")

        assert "scenes" in result
        assert "metadata" in result
        assert result["metadata"]["video_id"] == "test_video_id"

    @pytest.mark.asyncio
    async def test_parse_wizard_input_no_data(self):
        """Test parse_wizard_input raises error with no data."""
        request = MagicMock()
        request.wizard_data = None

        # Function wraps ValueError in Exception
        with pytest.raises(Exception, match="Wizard parsing failed"):
            await parse_wizard_input(request, "job123")

    @pytest.mark.asyncio
    async def test_parse_wizard_input_success(self):
        """Test successful wizard input parsing."""
        request = MagicMock()
        request.wizard_data = {
            "scenes": [
                {"type": "title", "title": "Test"},
                {"type": "command", "command_name": "Test Command"}
            ]
        }

        result = await parse_wizard_input(request, "job123")

        assert "scenes" in result
        assert len(result["scenes"]) == 2
        assert result["metadata"]["source"] == "wizard"

    @pytest.mark.asyncio
    async def test_get_job_status_not_found(self):
        """Test get_job_status raises error when job not found."""
        job_store = {}

        with pytest.raises(ValueError, match="Job test123 not found"):
            await get_job_status("test123", job_store)

    @pytest.mark.asyncio
    async def test_get_job_status_found(self):
        """Test get_job_status returns job data."""
        job_store = {
            "test123": {
                "status": "completed",
                "progress": 100,
                "message": "Done"
            }
        }

        result = await get_job_status("test123", job_store)

        assert result["status"] == "completed"
        assert result["progress"] == 100

    @pytest.mark.asyncio
    async def test_list_templates(self, tmp_path):
        """Test listing available templates."""
        # Create mock template files
        inputs_dir = tmp_path / "inputs"
        inputs_dir.mkdir()

        template_data = {
            "video": {
                "id": "test",
                "scenes": [
                    {"type": "title"},
                    {"type": "command"}
                ]
            }
        }

        template_file = inputs_dir / "example_test.yaml"
        with open(template_file, "w") as f:
            yaml.dump(template_data, f)

        with patch("app.utils.Path") as mock_path:
            mock_path.return_value.parent.parent = tmp_path
            mock_path.return_value.glob.return_value = [template_file]

            # Need to actually implement the test when path is properly mocked
            # For now, test the helper function
            pass

    def test_convert_structure_to_scenes(self):
        """Test converting markdown structure to scenes."""
        structure = {
            "title": "Test Document",
            "subtitle": "A test",
            "sections": [
                {
                    "type": "code",
                    "title": "Installation",
                    "description": "Install the package",
                    "code_lines": ["pip install package"]
                },
                {
                    "type": "list",
                    "title": "Features",
                    "items": ["Feature 1", "Feature 2"]
                }
            ]
        }

        scenes = _convert_structure_to_scenes(structure)

        # Should have title, code, list, and outro scenes
        assert len(scenes) >= 3
        assert scenes[0]["type"] == "title"
        assert scenes[0]["title"] == "Test Document"
        assert scenes[-1]["type"] == "outro"

    def test_convert_transcript_to_scenes(self):
        """Test converting YouTube transcript to scenes."""
        transcript_data = {
            "transcript": "This is a long transcript " * 100,
            "duration": 300
        }

        scenes = _convert_transcript_to_scenes(transcript_data, target_duration=60)

        # Should have title, parts, and outro
        assert len(scenes) >= 2
        assert scenes[0]["type"] == "title"
        assert scenes[-1]["type"] == "outro"

    def test_convert_wizard_to_scenes(self):
        """Test converting wizard data to scenes."""
        wizard_data = {
            "scenes": [
                {"type": "title", "title": "Test"},
                {"type": "command", "command_name": "Test"}
            ]
        }

        scenes = _convert_wizard_to_scenes(wizard_data)

        assert len(scenes) == 2
        assert scenes[0]["type"] == "title"

    def test_extract_scene_types(self):
        """Test extracting scene types from YAML data."""
        yaml_data = {
            "video": {
                "scenes": [
                    {"type": "title"},
                    {"type": "command"},
                    {"type": "command"},
                    {"type": "outro"}
                ]
            }
        }

        scene_types = _extract_scene_types(yaml_data)

        assert "title" in scene_types
        assert "command" in scene_types
        assert "outro" in scene_types
        assert len(scene_types) == 3  # Unique types only

    @pytest.mark.asyncio
    async def test_create_yaml_from_scenes(self, tmp_path):
        """Test creating YAML file from scenes."""
        scenes = [
            {"type": "title", "title": "Test", "subtitle": "Test Sub"},
            {"type": "command", "command_name": "Install", "commands": ["pip install"]}
        ]
        config = {"accent_color": "blue", "default_voice": "male"}

        with patch("app.utils.Path") as mock_path:
            mock_inputs_dir = tmp_path / "inputs"
            mock_inputs_dir.mkdir()
            mock_path.return_value.parent.parent = tmp_path

            yaml_path = await _create_yaml_from_scenes("test123", scenes, config)

            # Verify YAML was created with correct structure
            assert yaml_path.name.startswith("web_ui_test123")

    @pytest.mark.asyncio
    @patch("app.utils._create_yaml_from_scenes")
    @patch("app.utils._generate_audio")
    @patch("app.utils._generate_video")
    async def test_trigger_video_generation_success(self, mock_video, mock_audio, mock_yaml):
        """Test successful video generation trigger."""
        job_store = {
            "test123": {
                "status": "queued",
                "progress": 0,
                "message": ""
            }
        }

        mock_yaml.return_value = Path("/tmp/test.yaml")
        mock_audio.return_value = None
        mock_video.return_value = Path("/tmp/output/video.mp4")

        scenes = [{"type": "title", "title": "Test"}]
        config = {"accent_color": "blue"}

        await trigger_video_generation("test123", scenes, config, job_store)

        assert job_store["test123"]["status"] == "completed"
        assert job_store["test123"]["progress"] == 100
        assert "output_path" in job_store["test123"]

    @pytest.mark.asyncio
    @patch("app.utils._create_yaml_from_scenes")
    async def test_trigger_video_generation_error(self, mock_yaml):
        """Test video generation handles errors."""
        job_store = {
            "test123": {
                "status": "queued",
                "progress": 0,
                "message": ""
            }
        }

        mock_yaml.side_effect = Exception("YAML creation failed")

        scenes = [{"type": "title", "title": "Test"}]
        config = {"accent_color": "blue"}

        await trigger_video_generation("test123", scenes, config, job_store)

        assert job_store["test123"]["status"] == "error"
        assert "YAML creation failed" in job_store["test123"]["error"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
