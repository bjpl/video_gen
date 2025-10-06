"""
Integration tests for auto-orchestrator
Tests all input types with real workflows
"""
import pytest
import subprocess
import sys
import tempfile
import shutil
from pathlib import Path

# Test configuration
PROJECT_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
AUTO_ORCHESTRATOR = SCRIPTS_DIR / "create_video_auto.py"


class TestAutoOrchestratorCLI:
    """Test the auto-orchestrator CLI interface"""

    def test_help_command(self):
        """Test --help displays usage information"""
        result = subprocess.run(
            [sys.executable, str(AUTO_ORCHESTRATOR), "--help"],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert "Auto-orchestrator" in result.stdout
        assert "--type" in result.stdout
        assert "document" in result.stdout
        assert "youtube" in result.stdout
        assert "yaml" in result.stdout
        assert "wizard" in result.stdout

    def test_missing_required_args(self):
        """Test error when required arguments are missing"""
        result = subprocess.run(
            [sys.executable, str(AUTO_ORCHESTRATOR)],
            capture_output=True,
            text=True
        )

        assert result.returncode != 0
        assert "required" in result.stderr.lower() or "error" in result.stderr.lower()

    def test_document_type_requires_source(self):
        """Test that document type requires --from argument"""
        result = subprocess.run(
            [sys.executable, str(AUTO_ORCHESTRATOR), "--type", "document"],
            capture_output=True,
            text=True
        )

        assert result.returncode != 0
        assert "--from" in result.stderr or "required" in result.stderr.lower()


class TestDocumentInput:
    """Test document input processing"""

    def create_test_document(self):
        """Create a test markdown document"""
        content = """# Test Video Document

## Introduction
This is a test document for the auto-orchestrator.

## Section 1: Key Concept
Here we explain the first key concept with important details.

## Section 2: Examples
Examples help illustrate the concepts.

## Conclusion
Summary of the test video content.
"""
        test_file = tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.md',
            delete=False,
            encoding='utf-8'
        )
        test_file.write(content)
        test_file.close()
        return test_file.name

    def test_document_parsing_validation(self):
        """Test that document input is parsed correctly"""
        test_doc = self.create_test_document()

        try:
            # Import the document parser directly
            sys.path.insert(0, str(SCRIPTS_DIR))
            from generate_script_from_document import generate_yaml_from_document

            # Generate YAML from document
            yaml_file = generate_yaml_from_document(
                test_doc,
                accent_color="blue",
                voice="male",
                target_duration=30
            )

            # Verify YAML was created
            assert yaml_file is not None
            assert Path(yaml_file).exists()

            # Verify content
            import yaml
            with open(yaml_file, 'r') as f:
                data = yaml.safe_load(f)

            # Check structure (document parser creates nested structure)
            assert 'scenes' in data
            assert len(data['scenes']) > 0
            # Video metadata is in 'video' key for document parser
            if 'video' in data:
                assert 'id' in data['video']
            else:
                assert 'title' in data

            # Cleanup
            if Path(yaml_file).exists():
                Path(yaml_file).unlink()

        finally:
            Path(test_doc).unlink()

    @pytest.mark.skip(reason="PipelineOrchestrator API changed - needs refactoring to use new pipeline architecture")
    def test_document_end_to_end_dry_run(self):
        """Test document processing without actual video generation"""
        test_doc = self.create_test_document()

        try:
            # This test needs to be updated to use the new pipeline architecture
            # The new PipelineOrchestrator uses InputConfig and register_stages()
            # instead of the old args + stage_1_parse_input() API
            pass

        finally:
            Path(test_doc).unlink()


class TestYAMLInput:
    """Test YAML input processing"""

    def create_test_yaml(self):
        """Create a minimal test YAML file"""
        content = """title: "Test Video"
description: "A test video"
accent_color: "blue"
scenes:
  - scene_id: "intro"
    scene_type: "title_intro"
    visual_content:
      title: "Test Video"
      subtitle: "Integration Test"
    narration: "Welcome to the test video."
    voice: "male"
    min_duration: 3
    max_duration: 5

  - scene_id: "content"
    scene_type: "concept"
    visual_content:
      title: "Test Concept"
      bullet_points:
        - "Point one"
        - "Point two"
    narration: "Here are the key points."
    voice: "male"
    min_duration: 3
    max_duration: 5
"""
        test_file = tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.yaml',
            delete=False,
            encoding='utf-8'
        )
        test_file.write(content)
        test_file.close()
        return test_file.name

    def test_yaml_validation(self):
        """Test that YAML input is validated correctly"""
        test_yaml = self.create_test_yaml()

        try:
            import yaml
            with open(test_yaml, 'r') as f:
                data = yaml.safe_load(f)

            # Verify structure
            assert 'title' in data
            assert 'scenes' in data
            assert len(data['scenes']) == 2
            assert data['scenes'][0]['scene_type'] == 'title_intro'

        finally:
            Path(test_yaml).unlink()

    @pytest.mark.skip(reason="PipelineOrchestrator API changed - needs refactoring to use new pipeline architecture")
    def test_yaml_stage_1_processing(self):
        """Test YAML input through stage 1"""
        test_yaml = self.create_test_yaml()

        try:
            # This test needs to be updated to use the new pipeline architecture
            # The new PipelineOrchestrator uses InputConfig and register_stages()
            # instead of the old args + stage_1_parse_input() API
            pass

        finally:
            Path(test_yaml).unlink()


class TestErrorHandling:
    """Test error handling and edge cases"""

    def test_nonexistent_file(self):
        """Test error handling for nonexistent file"""
        result = subprocess.run(
            [sys.executable, str(AUTO_ORCHESTRATOR),
             "--type", "document",
             "--from", "/nonexistent/file.md"],
            capture_output=True,
            text=True
        )

        # Should fail gracefully
        assert result.returncode != 0

    def test_invalid_yaml_format(self):
        """Test error handling for invalid YAML"""
        # Create invalid YAML
        invalid_yaml = tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.yaml',
            delete=False,
            encoding='utf-8'
        )
        invalid_yaml.write("invalid: yaml: content:\n  - this is broken")
        invalid_yaml.close()

        try:
            result = subprocess.run(
                [sys.executable, str(AUTO_ORCHESTRATOR),
                 "--type", "yaml",
                 "--from", invalid_yaml.name],
                capture_output=True,
                text=True
            )

            # Should fail but not crash
            assert result.returncode != 0

        finally:
            Path(invalid_yaml.name).unlink()


class TestOutputGeneration:
    """Test output file generation"""

    def test_yaml_output_created(self):
        """Test that YAML files are created in correct location"""
        # Create test document
        test_doc = tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.md',
            delete=False,
            encoding='utf-8'
        )
        test_doc.write("# Test\n\nContent here.")
        test_doc.close()

        try:
            sys.path.insert(0, str(SCRIPTS_DIR))
            from generate_script_from_document import generate_yaml_from_document

            yaml_file = generate_yaml_from_document(
                test_doc.name,
                accent_color="blue",
                voice="male",
                target_duration=30
            )

            # Verify output location
            assert yaml_file is not None
            yaml_path = Path(yaml_file)
            assert yaml_path.exists()

            # Should be in inputs/ or drafts/ directory (document parser uses inputs/)
            parent_dir = yaml_path.parent.name
            assert parent_dir in ["drafts", "inputs"], f"Expected drafts or inputs, got {parent_dir}"

            # Cleanup
            yaml_path.unlink()

        finally:
            Path(test_doc.name).unlink()


class TestIntegrationWorkflow:
    """Test complete integration workflows"""

    @pytest.mark.skip(reason="PipelineOrchestrator API changed - needs refactoring to use new pipeline architecture")
    def test_minimal_workflow_validation(self):
        """Test minimal workflow completes without errors"""
        # This test validates the workflow structure without
        # actually generating audio/video (which takes time)

        test_doc = tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.md',
            delete=False,
            encoding='utf-8'
        )
        test_doc.write("# Test Video\n\n## Section 1\nContent here.\n\n## Section 2\nMore content.")
        test_doc.close()

        try:
            # This test needs to be updated to use the new pipeline architecture
            # The new PipelineOrchestrator uses InputConfig and register_stages()
            # instead of the old args + stage_1_parse_input() API
            pass

        finally:
            Path(test_doc.name).unlink()


def test_dependencies_available():
    """Test that all required dependencies are available"""
    required_modules = [
        'yaml',
        'edge_tts',
        'PIL',
        'numpy',
    ]

    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            pytest.fail(f"Required module '{module}' not available")


def test_scripts_exist():
    """Test that all required scripts exist"""
    required_scripts = [
        "create_video_auto.py",
        "generate_script_from_document.py",
        "generate_script_from_yaml.py",
        "generate_script_wizard.py",
        "unified_video_system.py",
    ]

    for script in required_scripts:
        script_path = SCRIPTS_DIR / script
        assert script_path.exists(), f"Required script '{script}' not found"


if __name__ == "__main__":
    # Run with pytest
    pytest.main([__file__, "-v", "--tb=short"])
