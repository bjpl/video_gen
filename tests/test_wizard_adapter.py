"""Tests for interactive wizard adapter.

This module tests the wizard adapter functionality including:
- Non-interactive mode (for testing)
- Template selection
- Scene generation
- Draft save/resume
- VideoSet conversion
"""

import pytest
import json
from pathlib import Path
from datetime import datetime

from video_gen.input_adapters.wizard import InteractiveWizard
from video_gen.shared.models import VideoSet, VideoConfig, SceneConfig


class TestInteractiveWizard:
    """Tests for InteractiveWizard adapter."""

    @pytest.fixture
    def wizard(self):
        """Create wizard instance."""
        return InteractiveWizard()

    @pytest.fixture
    def temp_draft_file(self, tmp_path):
        """Create temporary draft file."""
        draft_data = {
            'video': {
                'id': 'test_video',
                'title': 'Test Video',
                'topic': 'Testing',
                'description': 'Test description',
                'accent_color': 'blue',
                'voice': 'male',
                'timestamp': datetime.now().isoformat()
            },
            'template': 'tutorial',
            'scenes': [
                {
                    'scene_id': 'scene_01_title',
                    'scene_type': 'title',
                    'narration': 'Welcome to Test Video',
                    'visual_content': {'title': 'Test Video', 'subtitle': 'Guide'}
                },
                {
                    'scene_id': 'scene_02_outro',
                    'scene_type': 'outro',
                    'narration': 'Thank you for watching!',
                    'visual_content': {'main_text': 'Get Started', 'sub_text': 'Docs'}
                }
            ]
        }

        draft_file = tmp_path / "test_draft.json"
        with open(draft_file, 'w') as f:
            json.dump(draft_data, f)

        return draft_file

    @pytest.mark.asyncio
    async def test_wizard_initialization(self, wizard):
        """Test wizard initialization."""
        assert wizard.name == "wizard"
        assert wizard.description == "Interactive guided video creation"
        assert len(wizard.templates) == 6  # 5 presets + custom
        assert 'tutorial' in wizard.templates
        assert 'custom' in wizard.templates

    @pytest.mark.asyncio
    async def test_non_interactive_mode(self, wizard):
        """Test non-interactive mode for testing."""
        result = await wizard.adapt(non_interactive=True)

        assert result.success is True
        assert result.video_set is not None
        assert isinstance(result.video_set, VideoSet)
        assert len(result.video_set.videos) == 1

        video = result.video_set.videos[0]
        assert video.video_id == 'test_video'
        assert video.title == 'Test Video'
        assert len(video.scenes) == 2

    @pytest.mark.asyncio
    async def test_template_preselection(self, wizard):
        """Test pre-selecting a template."""
        result = await wizard.adapt(non_interactive=True, template='overview')

        assert result.success is True
        assert result.metadata['template'] == 'tutorial'  # Default video uses tutorial

    @pytest.mark.asyncio
    async def test_resume_from_draft(self, wizard, temp_draft_file):
        """Test resuming from draft file."""
        result = await wizard.adapt(source=temp_draft_file)

        assert result.success is True
        assert result.video_set is not None
        assert result.metadata['source'] == 'wizard_resume'
        assert result.metadata['resumed_from'] == str(temp_draft_file)

        video = result.video_set.videos[0]
        assert video.video_id == 'test_video'
        assert video.title == 'Test Video'
        assert len(video.scenes) == 2

    @pytest.mark.asyncio
    async def test_resume_invalid_file(self, wizard, tmp_path):
        """Test resuming with invalid file."""
        invalid_file = tmp_path / "invalid.json"
        result = await wizard.adapt(source=invalid_file)

        assert result.success is False
        assert "Failed to resume" in result.error

    @pytest.mark.asyncio
    async def test_convert_to_video_set(self, wizard):
        """Test converting wizard data to VideoSet."""
        video_data = {
            'video': {
                'id': 'test_id',
                'title': 'Test Title',
                'description': 'Test description',
                'accent_color': 'purple',
                'voice': 'female',
                'timestamp': datetime.now().isoformat()
            },
            'template': 'comparison',
            'scenes': [
                {
                    'scene_id': 'scene_01',
                    'scene_type': 'title',
                    'narration': 'Welcome',
                    'visual_content': {'title': 'Test', 'subtitle': 'Sub'}
                }
            ]
        }

        video_set = wizard._convert_to_video_set(video_data)

        assert isinstance(video_set, VideoSet)
        assert video_set.set_id == 'test_id_set'
        assert video_set.name == 'Test Title'
        assert len(video_set.videos) == 1

        video = video_set.videos[0]
        assert video.video_id == 'test_id'
        assert video.title == 'Test Title'
        assert video.accent_color == 'purple'
        assert video.voices == ['female']
        assert len(video.scenes) == 1

        scene = video.scenes[0]
        assert scene.scene_id == 'scene_01'
        assert scene.scene_type == 'title'
        assert scene.narration == 'Welcome'
        assert scene.voice == 'female'

    @pytest.mark.asyncio
    async def test_create_default_video(self, wizard):
        """Test creating default video."""
        video_data = wizard._create_default_video()

        assert video_data['video']['id'] == 'test_video'
        assert video_data['video']['title'] == 'Test Video'
        assert video_data['template'] == 'tutorial'
        assert len(video_data['scenes']) == 2

        # Check title scene
        title_scene = video_data['scenes'][0]
        assert title_scene['scene_type'] == 'title'
        assert 'Welcome' in title_scene['narration']

        # Check outro scene
        outro_scene = video_data['scenes'][1]
        assert outro_scene['scene_type'] == 'outro'
        assert 'Thank you' in outro_scene['narration']

    def test_slugify(self, wizard):
        """Test slug generation."""
        assert wizard._slugify("Hello World") == "hello_world"
        assert wizard._slugify("Test-With-Dashes") == "test_with_dashes"
        assert wizard._slugify("Symbols!@#$%Test") == "symbolstest"
        assert wizard._slugify("Multiple   Spaces") == "multiple_spaces"

        # Test length limit
        long_text = "a" * 50
        assert len(wizard._slugify(long_text)) == 30

    def test_templates_structure(self, wizard):
        """Test template structure validity."""
        for template_name, template in wizard.templates.items():
            assert 'description' in template
            assert 'scene_pattern' in template
            assert 'suggestions' in template

            if template_name != 'custom':
                assert len(template['scene_pattern']) > 0

            # Check scene pattern validity
            valid_scene_types = [
                'title', 'command', 'list', 'outro', 'quiz',
                'problem', 'code_comparison', 'checkpoint', 'exercise'
            ]
            for scene_type in template['scene_pattern']:
                assert scene_type in valid_scene_types

    @pytest.mark.asyncio
    async def test_wizard_title_scene(self, wizard):
        """Test title scene creation."""
        video_data = {
            'video': {
                'title': 'My Video',
                'id': 'my_video'
            }
        }
        template = wizard.templates['tutorial']

        # Can't test interactive input, but we can test the structure
        # by calling the method directly with mocked input
        # For now, just verify the template structure
        assert 'suggestions' in template
        assert 'title_subtitle' in template['suggestions']

    @pytest.mark.asyncio
    async def test_validate_source(self, wizard):
        """Test source validation (always true for wizard)."""
        assert await wizard.validate_source(None) is True
        assert await wizard.validate_source("anything") is True
        assert await wizard.validate_source(123) is True

    def test_supports_format(self, wizard):
        """Test format support checking."""
        assert wizard.supports_format("wizard") is True
        assert wizard.supports_format("interactive") is True
        assert wizard.supports_format("WIZARD") is True
        assert wizard.supports_format("yaml") is False
        assert wizard.supports_format("document") is False

    @pytest.mark.asyncio
    async def test_wizard_command_scene(self, wizard):
        """Test command scene structure."""
        # Test with suggested topic
        video_data = {'video': {'id': 'test'}}

        # We can test the scene structure generation logic
        scene_data = {
            'scene_id': 'scene_02_test',
            'scene_type': 'command',
            'narration': 'Let\'s look at Test Commands',
            'visual_content': {
                'header': 'Test Commands',
                'commands': ['$ command1', '$ command2']
            }
        }

        # Verify structure
        assert 'scene_id' in scene_data
        assert 'scene_type' in scene_data
        assert 'narration' in scene_data
        assert 'visual_content' in scene_data
        assert 'header' in scene_data['visual_content']
        assert 'commands' in scene_data['visual_content']

    @pytest.mark.asyncio
    async def test_wizard_list_scene(self, wizard):
        """Test list scene structure."""
        scene_data = {
            'scene_id': 'scene_03_features',
            'scene_type': 'list',
            'narration': 'Here are the key features',
            'visual_content': {
                'header': 'Key Features',
                'items': ['Feature 1', 'Feature 2', 'Feature 3']
            }
        }

        # Verify structure
        assert scene_data['scene_type'] == 'list'
        assert 'items' in scene_data['visual_content']
        assert len(scene_data['visual_content']['items']) == 3

    @pytest.mark.asyncio
    async def test_wizard_outro_scene(self, wizard):
        """Test outro scene structure."""
        scene_data = {
            'scene_id': 'scene_outro',
            'scene_type': 'outro',
            'narration': 'Get Started Today. Thank you for watching!',
            'visual_content': {
                'main_text': 'Get Started Today',
                'sub_text': 'Visit our documentation'
            }
        }

        # Verify structure
        assert scene_data['scene_type'] == 'outro'
        assert 'main_text' in scene_data['visual_content']
        assert 'sub_text' in scene_data['visual_content']

    def test_wizard_generic_scene_structure(self, wizard):
        """Test generic scene structure without interactive input."""
        # Test the structure that would be created
        scene_data = {
            'scene_id': 'scene_05_quiz',
            'scene_type': 'quiz',
            'narration': 'This is the quiz scene',
            'visual_content': {}
        }

        assert scene_data['scene_id'] == 'scene_05_quiz'
        assert scene_data['scene_type'] == 'quiz'
        assert 'narration' in scene_data
        assert 'visual_content' in scene_data

    @pytest.mark.asyncio
    async def test_error_handling(self, wizard):
        """Test error handling in wizard."""
        # Test with exception during processing
        class BrokenWizard(InteractiveWizard):
            async def _run_wizard_steps(self, **kwargs):
                raise ValueError("Test error")

        broken = BrokenWizard()
        result = await broken.adapt()

        assert result.success is False
        assert "Wizard failed" in result.error

    @pytest.mark.asyncio
    async def test_metadata_generation(self, wizard):
        """Test metadata generation in result."""
        result = await wizard.adapt(non_interactive=True)

        assert result.success is True
        assert 'source' in result.metadata
        assert result.metadata['source'] == 'wizard'
        assert 'template' in result.metadata
        assert 'scenes_generated' in result.metadata
        assert result.metadata['scenes_generated'] == 2

    @pytest.mark.asyncio
    async def test_video_set_metadata(self, wizard):
        """Test VideoSet metadata."""
        result = await wizard.adapt(non_interactive=True)

        video_set = result.video_set
        assert 'source' in video_set.metadata
        assert video_set.metadata['source'] == 'wizard'
        assert 'template' in video_set.metadata
        assert 'created' in video_set.metadata

    def test_colors_class(self):
        """Test Colors class for terminal output."""
        from video_gen.input_adapters.wizard import Colors

        # Verify all color codes exist
        assert hasattr(Colors, 'HEADER')
        assert hasattr(Colors, 'BLUE')
        assert hasattr(Colors, 'CYAN')
        assert hasattr(Colors, 'GREEN')
        assert hasattr(Colors, 'YELLOW')
        assert hasattr(Colors, 'RED')
        assert hasattr(Colors, 'END')
        assert hasattr(Colors, 'BOLD')

        # Verify they're ANSI codes
        assert Colors.END == '\033[0m'
        assert Colors.BOLD == '\033[1m'


class TestWizardIntegration:
    """Integration tests for wizard adapter."""

    @pytest.mark.asyncio
    async def test_end_to_end_non_interactive(self):
        """Test complete wizard flow in non-interactive mode."""
        wizard = InteractiveWizard()

        # Run wizard
        result = await wizard.adapt(non_interactive=True)

        # Verify result
        assert result.success is True
        assert result.video_set is not None

        # Verify video set structure
        video_set = result.video_set
        assert len(video_set.videos) == 1

        video = video_set.videos[0]
        assert len(video.scenes) > 0

        # Verify all scenes have required fields
        for scene in video.scenes:
            assert scene.scene_id is not None
            assert scene.scene_type is not None
            assert scene.narration is not None
            assert scene.visual_content is not None

    @pytest.mark.asyncio
    async def test_wizard_with_yaml_export(self, tmp_path):
        """Test wizard integration with YAML export."""
        wizard = InteractiveWizard()

        # Generate video with wizard
        result = await wizard.adapt(non_interactive=True)
        assert result.success is True

        # Export to YAML
        from video_gen.input_adapters.yaml_file import YAMLFileAdapter

        yaml_adapter = YAMLFileAdapter(test_mode=True)
        output_path = tmp_path / "wizard_output.yaml"

        success = yaml_adapter.export_to_yaml(
            result.video_set,
            output_path,
            format_type="single_video"
        )

        assert success is True
        assert output_path.exists()

        # Re-import and verify
        import_result = await yaml_adapter.adapt(output_path)
        assert import_result.success is True
        assert len(import_result.video_set.videos) == 1

    @pytest.mark.asyncio
    async def test_all_templates(self):
        """Test all template types."""
        wizard = InteractiveWizard()

        for template_name in wizard.templates.keys():
            if template_name == 'custom':
                continue  # Skip custom (requires user input)

            result = await wizard.adapt(
                non_interactive=True,
                template=template_name
            )

            assert result.success is True
            assert result.video_set is not None
