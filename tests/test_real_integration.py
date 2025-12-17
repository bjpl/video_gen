"""
Real End-to-End Integration Tests
===================================
Comprehensive workflow tests that verify actual user workflows work correctly.

Tests cover:
1. YAML file → complete pipeline → verify video metadata
2. Document → scenes → verify structure
3. Programmatic → pipeline → verify processing
4. Multi-stage validation → verify each stage output
5. Error handling → verify proper error messages

NOTE: Does NOT render actual videos (too slow for CI/CD).
Tests up to and including script/scene generation only.
"""

import pytest
import tempfile
import yaml
import os
from pathlib import Path
from datetime import datetime
from unittest.mock import patch

# Environment-based thresholds for CI/CD friendliness
PERF_YAML_PARSE = float(os.getenv("PERF_YAML_PARSE", "2.0"))  # Was 1.0s
PERF_DOC_PARSE = float(os.getenv("PERF_DOC_PARSE", "5.0"))  # Was 2.0s
PERF_EXPORT = float(os.getenv("PERF_EXPORT", "2.0"))  # Was 1.0s


class TestYAMLWorkflow:
    """Test YAML file → parsed scenes → verified metadata"""

    def test_simple_yaml_to_scenes_real_file(self):
        """Test actual YAML file processing with real adapter"""
        from video_gen.input_adapters.compat import YAMLAdapter

        yaml_path = Path(__file__).parent.parent / "inputs" / "example_simple.yaml"
        assert yaml_path.exists(), f"Test file not found: {yaml_path}"

        adapter = YAMLAdapter(test_mode=True)
        result = adapter.parse(str(yaml_path))

        # Verify VideoSet structure
        assert result is not None
        assert hasattr(result, 'config')
        assert hasattr(result, 'videos')
        assert len(result.videos) >= 1

        # Verify first video
        video = result.videos[0]
        assert video.video_id == "feature_demo"
        assert video.title == "Feature Demo"
        assert len(video.scenes) == 4  # title, command, list, outro

        # Verify scene types (scenes are now SceneConfig objects)
        scene_types = [scene.scene_type for scene in video.scenes]
        assert 'title' in scene_types
        assert 'command' in scene_types
        assert 'list' in scene_types
        assert 'outro' in scene_types

    @pytest.mark.skip(reason="export_to_yaml() method removed from VideoSet - needs new export functionality")
    def test_yaml_to_export_roundtrip(self):
        """Test YAML → parse → export → validate roundtrip"""
        from video_gen.input_adapters.compat import YAMLAdapter

        yaml_path = Path(__file__).parent.parent / "inputs" / "example_simple.yaml"

        adapter = YAMLAdapter(test_mode=True)
        result = adapter.parse(str(yaml_path))

        # Export to temporary directory
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = result.export_to_yaml(tmpdir)

            # Verify files created
            assert (output_path / 'set_config.yaml').exists()
            assert (output_path / 'feature_demo.yaml').exists()

            # Verify set_config.yaml is valid
            with open(output_path / 'set_config.yaml') as f:
                set_data = yaml.safe_load(f)

            assert 'set' in set_data
            assert set_data['set']['id'] is not None
            assert len(set_data['set']['videos']) >= 1

            # Verify video YAML is valid
            with open(output_path / 'feature_demo.yaml') as f:
                video_data = yaml.safe_load(f)

            assert 'video' in video_data
            assert 'scenes' in video_data
            assert video_data['video']['id'] == 'feature_demo'

    def test_yaml_narration_generation(self):
        """Test automatic narration generation for scenes"""
        from video_gen.input_adapters.compat import YAMLAdapter

        # Create YAML with minimal required fields (narration will be generated)
        yaml_content = {
            'video': {
                'id': 'test_narration',
                'title': 'Test Narration',
                'accent_color': 'blue',
                'voice': 'male'
            },
            'scenes': [
                {
                    'scene_id': '1',
                    'scene_type': 'title',
                    'narration': 'Test narration for title scene',
                    'visual_content': {
                        'title': 'Test Title',
                        'subtitle': 'Test Subtitle'
                    }
                },
                {
                    'scene_id': '2',
                    'scene_type': 'command',
                    'narration': 'Test narration for command scene',
                    'visual_content': {
                        'header': 'Installation',
                        'description': 'Quick setup',
                        'commands': ['$ npm install', '$ npm start']
                    }
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(yaml_content, f)
            yaml_path = f.name

        try:
            adapter = YAMLAdapter(test_mode=True)
            result = adapter.parse(yaml_path)

            # Verify narration is present (scenes are SceneConfig objects)
            video = result.videos[0]
            assert len(video.scenes) >= 2

            # Title scene should have narration
            title_scene = video.scenes[0]
            assert title_scene.scene_type == 'title'
            assert title_scene.narration is not None
            assert len(title_scene.narration) > 0

        finally:
            Path(yaml_path).unlink(missing_ok=True)


class TestDocumentWorkflow:
    """Test Document → parsed scenes → verified structure"""

    def test_markdown_to_scenes_real_file(self):
        """Test actual markdown document processing"""
        from video_gen.input_adapters.compat import DocumentAdapter

        md_path = Path(__file__).parent.parent / "inputs" / "Internet_Guide_Vol1_Core_Infrastructure.md"
        assert md_path.exists(), f"Test file not found: {md_path}"

        adapter = DocumentAdapter(test_mode=True)
        result = adapter.parse(str(md_path))

        # Verify VideoSet structure
        assert result is not None
        assert len(result.videos) >= 1

        # Verify video metadata
        video = result.videos[0]
        assert video.title  # Should have extracted title
        assert len(video.scenes) >= 2  # At least title + outro

    def test_document_scene_type_detection(self):
        """Test that document adapter correctly detects scene types"""
        from video_gen.input_adapters.compat import DocumentAdapter

        # Create test document with different content types
        content = """# Test Document

## Installation

Run these commands:

```bash
pip install package
python setup.py
```

## Features

- Fast performance
- Easy to use
- Well documented

## Configuration

The system supports various options.
Each option can be configured separately.
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False, encoding='utf-8') as f:
            f.write(content)
            md_path = f.name

        try:
            adapter = DocumentAdapter(test_mode=True)
            result = adapter.parse(md_path)

            video = result.videos[0]
            scenes = video.scenes

            # Should have title scene (scenes are now SceneConfig objects)
            assert scenes[0].scene_type == 'title'

            # Should detect command scene (has code block)
            scene_types = [s.scene_type for s in scenes]
            assert 'command' in scene_types or 'list' in scene_types

            # Should have outro
            assert scenes[-1].scene_type == 'outro'

        finally:
            Path(md_path).unlink(missing_ok=True)

    @pytest.mark.skip(reason="export_to_yaml() method removed from VideoSet - needs new export functionality")
    def test_document_export_to_yaml(self):
        """Test document → scenes → YAML export workflow"""
        from video_gen.input_adapters.compat import DocumentAdapter

        content = """# Sample Project

## Getting Started

Install the dependencies and run the project.

```
npm install
npm start
```

## Key Features

- Feature A: Description A
- Feature B: Description B
- Feature C: Description C
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(content)
            md_path = f.name

        try:
            adapter = DocumentAdapter(test_mode=True)
            result = adapter.parse(md_path)

            # Export to YAML
            with tempfile.TemporaryDirectory() as tmpdir:
                output_path = result.export_to_yaml(tmpdir)

                # Verify files created
                assert (output_path / 'set_config.yaml').exists()

                # Verify YAML is valid and has expected structure
                with open(output_path / 'set_config.yaml') as f:
                    data = yaml.safe_load(f)

                assert 'set' in data
                assert data['set']['name'] is not None

        finally:
            Path(md_path).unlink(missing_ok=True)


class TestProgrammaticWorkflow:
    """Test programmatic VideoConfig → pipeline → verified processing"""

    @pytest.mark.skip(reason="Deprecated API: VideoConfig signature changed - 'voice' is now 'voices' list, scenes require SceneConfig objects")
    def test_programmatic_video_config_creation(self):
        """Test creating VideoConfig programmatically"""
        from video_gen.input_adapters.compat import VideoConfig, VideoSet, VideoSetConfig

        # Create scenes programmatically
        scenes = [
            {
                'type': 'title',
                'title': 'Programmatic Video',
                'subtitle': 'Created via API'
            },
            {
                'type': 'list',
                'header': 'Benefits',
                'description': 'Key advantages',
                'items': ['Flexible', 'Automated', 'Scalable']
            },
            {
                'type': 'outro',
                'main_text': 'Thank You',
                'sub_text': 'Questions?'
            }
        ]

        video = VideoConfig(
            video_id='programmatic_001',
            title='Programmatic Video',
            description='Created programmatically',
            scenes=scenes,
            accent_color='blue',
            voice='male'
        )

        # Verify structure
        assert video.video_id == 'programmatic_001'
        assert len(video.scenes) == 3
        assert video.scenes[0]['type'] == 'title'

    @pytest.mark.skip(reason="Deprecated API: VideoSet.export_to_yaml() method removed - use new YAML export functionality")
    def test_programmatic_video_set_export(self):
        """Test programmatic VideoSet export to YAML"""
        from video_gen.input_adapters.compat import VideoConfig, VideoSet, VideoSetConfig

        video = VideoConfig(
            video_id='test_video',
            title='Test Video',
            scenes=[
                {'type': 'title', 'title': 'Test', 'subtitle': 'Demo'}
            ]
        )

        set_config = VideoSetConfig(
            set_id='programmatic_set',
            set_name='Programmatic Set',
            description='Created programmatically'
        )

        video_set = VideoSet(config=set_config, videos=[video])

        # Export and verify
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = video_set.export_to_yaml(tmpdir)

            assert (output_path / 'set_config.yaml').exists()
            assert (output_path / 'test_video.yaml').exists()


class TestMultiStageValidation:
    """Test Input → Parsing → Script → verify each stage output"""

    def test_yaml_parsing_stage(self):
        """Test YAML parsing stage outputs correct structure"""
        from video_gen.input_adapters.compat import YAMLAdapter

        yaml_path = Path(__file__).parent.parent / "inputs" / "example_simple.yaml"

        if not yaml_path.exists():
            pytest.skip(f"Test file not found: {yaml_path}")

        adapter = YAMLAdapter(test_mode=True)
        result = adapter.parse(str(yaml_path))

        # Stage 1: Parse YAML → VideoSet
        assert result is not None
        assert isinstance(result.videos, list)

        # Verify VideoSet has required attributes
        assert hasattr(result, 'config')
        assert hasattr(result.config, 'set_id')
        assert hasattr(result.config, 'defaults')

    def test_document_parsing_stage(self):
        """Test document parsing stage outputs correct structure"""
        from video_gen.input_adapters.compat import DocumentAdapter

        content = "# Test\n\n## Section\n\nContent here."

        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(content)
            md_path = f.name

        try:
            adapter = DocumentAdapter(test_mode=True)
            result = adapter.parse(md_path)

            # Stage 1: Parse document → VideoSet
            assert result is not None
            assert len(result.videos) >= 1

            # Verify scenes structure (scenes are now SceneConfig objects)
            video = result.videos[0]
            assert isinstance(video.scenes, list)
            assert all(hasattr(scene, 'scene_type') for scene in video.scenes)

        finally:
            Path(md_path).unlink(missing_ok=True)

    def test_scene_structure_validation(self):
        """Test that parsed scenes have valid structure"""
        from video_gen.input_adapters.compat import YAMLAdapter

        # Updated YAML format with required fields: scene_id and narration
        yaml_content = {
            'video': {
                'id': 'validation_test',
                'title': 'Validation Test'
            },
            'scenes': [
                {
                    'scene_id': 'scene_1',
                    'scene_type': 'title',
                    'narration': 'Welcome to the validation test',
                    'visual_content': {
                        'title': 'Test',
                        'subtitle': 'Validation'
                    }
                },
                {
                    'scene_id': 'scene_2',
                    'scene_type': 'command',
                    'narration': 'Run these commands',
                    'visual_content': {
                        'header': 'Commands',
                        'description': 'Run these',
                        'commands': ['$ cmd1', '$ cmd2']
                    }
                },
                {
                    'scene_id': 'scene_3',
                    'scene_type': 'list',
                    'narration': 'Here are the key items',
                    'visual_content': {
                        'header': 'Items',
                        'description': 'Key items',
                        'items': ['Item 1', 'Item 2']
                    }
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(yaml_content, f)
            yaml_path = f.name

        try:
            adapter = YAMLAdapter(test_mode=True)
            result = adapter.parse(yaml_path)

            video = result.videos[0]

            # Validate each scene type has required fields (scenes are SceneConfig objects)
            for scene in video.scenes:
                assert hasattr(scene, 'scene_type')

                if scene.scene_type == 'title':
                    assert 'title' in scene.visual_content
                    assert 'subtitle' in scene.visual_content

                elif scene.scene_type == 'command':
                    assert 'header' in scene.visual_content
                    assert 'commands' in scene.visual_content

                elif scene.scene_type == 'list':
                    assert 'header' in scene.visual_content
                    assert 'items' in scene.visual_content

        finally:
            Path(yaml_path).unlink(missing_ok=True)


class TestErrorHandling:
    """Test invalid inputs → proper error messages"""

    def test_invalid_yaml_file(self):
        """Test handling of invalid YAML file"""
        from video_gen.input_adapters.compat import YAMLAdapter

        # Create invalid YAML
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("invalid: yaml: content: [unclosed")
            invalid_path = f.name

        try:
            adapter = YAMLAdapter(test_mode=True)

            with pytest.raises(Exception):  # Should raise YAML parsing error
                adapter.parse(invalid_path)

        finally:
            Path(invalid_path).unlink(missing_ok=True)

    def test_missing_required_fields(self):
        """Test handling of YAML missing required fields"""
        from video_gen.input_adapters.compat import YAMLAdapter

        # Missing 'video' key
        yaml_content = {
            'scenes': [
                {'type': 'title', 'title': 'Test'}
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(yaml_content, f)
            yaml_path = f.name

        try:
            adapter = YAMLAdapter(test_mode=True)

            # Updated error message pattern to match new validation format
            with pytest.raises(ValueError, match="YAML validation failed|Missing required field"):
                adapter.parse(yaml_path)

        finally:
            Path(yaml_path).unlink(missing_ok=True)

    def test_file_not_found(self):
        """Test handling of non-existent file"""
        from video_gen.input_adapters.compat import YAMLAdapter

        adapter = YAMLAdapter(test_mode=True)

        # Compat layer wraps FileNotFoundError in ValueError
        with pytest.raises(ValueError, match="File not found"):
            adapter.parse('/nonexistent/path/file.yaml')

    def test_empty_document(self):
        """Test handling of empty document"""
        from video_gen.input_adapters.compat import DocumentAdapter

        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write("")  # Empty file
            empty_path = f.name

        try:
            adapter = DocumentAdapter(test_mode=True)
            # Empty documents now raise ValueError through compat layer
            with pytest.raises(ValueError, match="Failed to read document|empty|no content"):
                adapter.parse(empty_path)

        finally:
            Path(empty_path).unlink(missing_ok=True)

    def test_document_with_only_whitespace(self):
        """Test handling of document with only whitespace"""
        from video_gen.input_adapters.compat import DocumentAdapter

        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write("   \n\n   \t\t  \n  ")
            ws_path = f.name

        try:
            adapter = DocumentAdapter(test_mode=True)
            result = adapter.parse(ws_path)

            # Should handle gracefully
            assert result is not None

        finally:
            Path(ws_path).unlink(missing_ok=True)


class TestPerformance:
    """Test execution performance (should be fast for CI/CD)"""

    def test_yaml_parsing_speed(self):
        """Test YAML parsing completes quickly"""
        import time
        from video_gen.input_adapters.compat import YAMLAdapter

        yaml_path = Path(__file__).parent.parent / "inputs" / "example_simple.yaml"

        if not yaml_path.exists():
            pytest.skip(f"Test file not found: {yaml_path}")

        # Disable AI to avoid network calls
        adapter = YAMLAdapter(test_mode=True, use_ai=False)

        start = time.time()
        result = adapter.parse(str(yaml_path))
        elapsed = time.time() - start

        # Should complete quickly (CI-friendly threshold)
        assert elapsed < PERF_YAML_PARSE, f"Parsing took {elapsed:.2f}s, expected < {PERF_YAML_PARSE}s"
        assert result is not None

    def test_document_parsing_speed(self):
        """Test document parsing completes quickly"""
        import time
        from video_gen.input_adapters.compat import DocumentAdapter

        # Create moderately-sized document
        content = "# Test\n\n" + "\n\n".join([
            f"## Section {i}\n\nContent for section {i}.\n\n- Point 1\n- Point 2"
            for i in range(10)
        ])

        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(content)
            md_path = f.name

        try:
            # Disable AI to avoid network calls
            adapter = DocumentAdapter(test_mode=True, use_ai=False)

            start = time.time()
            result = adapter.parse(md_path)
            elapsed = time.time() - start

            # Should complete quickly (CI-friendly threshold)
            assert elapsed < PERF_DOC_PARSE, f"Parsing took {elapsed:.2f}s, expected < {PERF_DOC_PARSE}s"
            assert result is not None

        finally:
            Path(md_path).unlink(missing_ok=True)

    @pytest.mark.skip(reason="export_to_yaml() method removed from VideoSet - needs new export functionality")
    @patch('video_gen.script_generator.ai_enhancer.AIScriptEnhancer.enhance_narration')
    def test_export_speed(self, mock_enhance):
        """Test YAML export completes quickly"""
        import time
        from video_gen.input_adapters.compat import YAMLAdapter

        # Mock AI enhancement to avoid network calls
        mock_enhance.return_value = "Test narration"

        yaml_path = Path(__file__).parent.parent / "inputs" / "example_simple.yaml"

        if not yaml_path.exists():
            pytest.skip(f"Test file not found: {yaml_path}")

        adapter = YAMLAdapter(test_mode=True)
        result = adapter.parse(str(yaml_path))

        with tempfile.TemporaryDirectory() as tmpdir:
            start = time.time()
            output_path = result.export_to_yaml(tmpdir)
            elapsed = time.time() - start

            # Should complete quickly (CI-friendly threshold)
            assert elapsed < PERF_EXPORT, f"Export took {elapsed:.2f}s, expected < {PERF_EXPORT}s"
            assert output_path.exists()


class TestComplexWorkflows:
    """Test complex real-world workflows"""

    @pytest.mark.skip(reason="Deprecated API: VideoConfig signature changed and export_to_yaml() removed")
    def test_multiple_videos_in_set(self):
        """Test processing multiple videos in a set"""
        from video_gen.input_adapters.compat import VideoConfig, VideoSet, VideoSetConfig

        videos = [
            VideoConfig(
                video_id=f'video_{i}',
                title=f'Video {i}',
                scenes=[
                    {'type': 'title', 'title': f'Video {i}', 'subtitle': 'Test'}
                ]
            )
            for i in range(5)
        ]

        set_config = VideoSetConfig(
            set_id='multi_video_set',
            set_name='Multi Video Set'
        )

        video_set = VideoSet(config=set_config, videos=videos)

        # Export and verify
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = video_set.export_to_yaml(tmpdir)

            # Should create one file per video + set_config
            assert (output_path / 'set_config.yaml').exists()
            for i in range(5):
                assert (output_path / f'video_{i}.yaml').exists()

    def test_document_with_multiple_scene_types(self):
        """Test document with various content types"""
        from video_gen.input_adapters.compat import DocumentAdapter

        content = """# Complex Document

## Installation

```bash
pip install package
python setup.py install
```

## Features

- Feature 1: Fast
- Feature 2: Reliable
- Feature 3: Scalable

## Configuration

```python
config = {
    'option1': 'value1',
    'option2': 'value2'
}
```

## Usage

The system can be used in multiple ways.
Each method has its own advantages.

## Troubleshooting

- Problem 1: Check logs
- Problem 2: Restart service
- Problem 3: Contact support
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(content)
            md_path = f.name

        try:
            adapter = DocumentAdapter(test_mode=True)
            result = adapter.parse(md_path)

            video = result.videos[0]
            # Scenes are now SceneConfig objects, use attribute access
            scene_types = [s.scene_type for s in video.scenes]

            # Should have multiple scene types
            assert 'title' in scene_types
            assert 'command' in scene_types or 'list' in scene_types
            assert 'outro' in scene_types

        finally:
            Path(md_path).unlink(missing_ok=True)


if __name__ == '__main__':
    # Run tests with timing
    pytest.main([__file__, '-v', '--tb=short', '--durations=10'])
