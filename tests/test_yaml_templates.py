"""
Tests for YAML template system.

This module tests the template loading, variable substitution,
and template merging functionality of the YAMLFileAdapter.
"""

import pytest
import tempfile
from pathlib import Path
import yaml

from video_gen.input_adapters.yaml_file import YAMLFileAdapter


class TestTemplateLoading:
    """Test template loading functionality."""

    @pytest.fixture
    def adapter(self):
        """Create a YAML adapter instance."""
        return YAMLFileAdapter(test_mode=True)

    def test_list_templates(self, adapter):
        """Test listing available templates."""
        templates = adapter.list_templates()

        assert len(templates) >= 5, "Should have at least 5 templates"

        template_names = [t["name"] for t in templates]
        assert "tutorial" in template_names
        assert "presentation" in template_names
        assert "intro" in template_names
        assert "course_lesson" in template_names
        assert "documentation" in template_names

        # Check structure
        for template in templates:
            assert "name" in template
            assert "description" in template
            assert isinstance(template["name"], str)
            assert isinstance(template["description"], str)

    def test_load_template(self, adapter):
        """Test loading a single template."""
        template_data = adapter._load_template("tutorial")

        assert isinstance(template_data, dict)
        assert "video_id" in template_data
        assert "title" in template_data
        assert "scenes" in template_data
        assert isinstance(template_data["scenes"], list)
        assert len(template_data["scenes"]) > 0

    def test_load_nonexistent_template(self, adapter):
        """Test loading a template that doesn't exist."""
        with pytest.raises(ValueError, match="Template.*not found"):
            adapter._load_template("nonexistent_template")

    def test_template_caching(self, adapter):
        """Test that templates are cached after first load."""
        # Load template twice
        template1 = adapter._load_template("tutorial")
        template2 = adapter._load_template("tutorial")

        # Should be equal but different objects (due to copy())
        assert template1 == template2
        # Verify it was cached
        assert "tutorial" in adapter._template_cache


class TestVariableSubstitution:
    """Test variable substitution functionality."""

    @pytest.fixture
    def adapter(self):
        """Create a YAML adapter instance."""
        return YAMLFileAdapter(test_mode=True)

    def test_simple_substitution(self, adapter):
        """Test simple variable substitution."""
        text = "Hello ${name}!"
        variables = {"name": "World"}
        result = adapter._substitute_variables(text, variables)
        assert result == "Hello World!"

    def test_substitution_with_default(self, adapter):
        """Test variable substitution with default value."""
        text = "Color: ${color|blue}"

        # With variable provided
        result1 = adapter._substitute_variables(text, {"color": "red"})
        assert result1 == "Color: red"

        # Without variable (uses default)
        result2 = adapter._substitute_variables(text, {})
        assert result2 == "Color: blue"

    def test_multiple_substitutions(self, adapter):
        """Test multiple variable substitutions in one string."""
        text = "${greeting} ${name}, welcome to ${place}!"
        variables = {
            "greeting": "Hello",
            "name": "Alice",
            "place": "Wonderland"
        }
        result = adapter._substitute_variables(text, variables)
        assert result == "Hello Alice, welcome to Wonderland!"

    def test_substitution_with_missing_variable(self, adapter):
        """Test substitution when variable is missing (no default)."""
        text = "Hello ${name}!"
        result = adapter._substitute_variables(text, {})
        assert result == "Hello !"  # Empty string when no default

    def test_recursive_substitution(self, adapter):
        """Test recursive substitution in nested data structures."""
        data = {
            "title": "${project_name} Documentation",
            "description": "Guide for ${project_name}",
            "nested": {
                "field": "${project_name} - ${version}"
            },
            "list": ["${project_name}", "version ${version}"]
        }
        variables = {
            "project_name": "MyApp",
            "version": "1.0"
        }

        result = adapter._substitute_all_variables(data, variables)

        assert result["title"] == "MyApp Documentation"
        assert result["description"] == "Guide for MyApp"
        assert result["nested"]["field"] == "MyApp - 1.0"
        assert result["list"][0] == "MyApp"
        assert result["list"][1] == "version 1.0"

    def test_non_string_values(self, adapter):
        """Test that non-string values are preserved."""
        data = {
            "string": "${name}",
            "number": 42,
            "boolean": True,
            "null": None,
            "list": [1, 2, 3]
        }
        variables = {"name": "test"}

        result = adapter._substitute_all_variables(data, variables)

        assert result["string"] == "test"
        assert result["number"] == 42
        assert result["boolean"] is True
        assert result["null"] is None
        assert result["list"] == [1, 2, 3]


class TestTemplateMerging:
    """Test template merging functionality."""

    @pytest.fixture
    def adapter(self):
        """Create a YAML adapter instance."""
        return YAMLFileAdapter(test_mode=True)

    def test_simple_merge(self, adapter):
        """Test simple dictionary merge."""
        base = {"a": 1, "b": 2, "c": 3}
        override = {"b": 20, "d": 4}

        result = adapter._deep_merge(base, override)

        assert result == {"a": 1, "b": 20, "c": 3, "d": 4}

    def test_nested_merge(self, adapter):
        """Test nested dictionary merge."""
        base = {
            "settings": {
                "color": "blue",
                "size": "medium",
                "nested": {"value": 1}
            }
        }
        override = {
            "settings": {
                "color": "red",
                "nested": {"value": 2, "new": 3}
            }
        }

        result = adapter._deep_merge(base, override)

        assert result["settings"]["color"] == "red"
        assert result["settings"]["size"] == "medium"
        assert result["settings"]["nested"]["value"] == 2
        assert result["settings"]["nested"]["new"] == 3

    def test_list_extension(self, adapter):
        """Test that lists are extended (not replaced)."""
        base = {"items": [1, 2, 3]}
        override = {"items": [4, 5]}

        result = adapter._deep_merge(base, override)

        assert result["items"] == [1, 2, 3, 4, 5]

    def test_merge_template_with_variables(self, adapter):
        """Test full template merge with variable substitution."""
        template = {
            "video_id": "${video_id}",
            "title": "${title}",
            "accent_color": "${accent_color|blue}",
            "scenes": [
                {
                    "scene_id": "title",
                    "narration": "Welcome to ${title}"
                }
            ]
        }

        override = {
            "variables": {
                "video_id": "my_video",
                "title": "My Tutorial",
                "accent_color": "red"
            },
            "description": "Custom description",
            "scenes": [
                {
                    "scene_id": "outro",
                    "narration": "Thanks for watching!"
                }
            ]
        }

        result = adapter._merge_template(template, override)

        # Check substitution happened
        assert result["video_id"] == "my_video"
        assert result["title"] == "My Tutorial"
        assert result["accent_color"] == "red"

        # Check merge happened
        assert "description" in result
        assert result["description"] == "Custom description"

        # Check lists were extended
        assert len(result["scenes"]) == 2
        assert result["scenes"][0]["narration"] == "Welcome to My Tutorial"
        assert result["scenes"][1]["narration"] == "Thanks for watching!"


class TestTemplateIntegration:
    """Test end-to-end template usage."""

    @pytest.fixture
    def adapter(self):
        """Create a YAML adapter instance."""
        return YAMLFileAdapter(test_mode=True)

    @pytest.mark.asyncio
    async def test_load_yaml_with_template(self, adapter):
        """Test loading a YAML file that uses a template."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml_content = """
template: tutorial
variables:
  video_id: python_basics
  title: Python Basics Tutorial
  topic: Python Programming
  subtitle: Learn the Fundamentals
  accent_color: green
  objectives:
    - Understand Python syntax
    - Write simple programs
    - Debug common errors
  objectives_narration: Master the fundamentals of Python programming.
  concepts:
    - Variables and data types
    - Control flow
    - Functions
  concepts_narration: These are the building blocks of Python.
  examples:
    - 'print("Hello, World!")'
    - 'x = 42'
    - 'def greet(name): print("Hello")'
  example_narration: See how easy Python is to use.
  problem_description: How do you handle errors in Python?
  problem_narration: Error handling is crucial for robust programs.
  solution_description: Use try-except blocks to catch exceptions.
  solution_narration: Python provides elegant error handling.
  solution_steps:
    - Wrap risky code in try block
    - Catch exceptions with except
    - Clean up with finally
  checkpoint_narration: You've learned the core concepts.
  checkpoint_summary: Variables, functions, and error handling
  next_steps: Continue to the next module
"""
            f.write(yaml_content)
            yaml_path = f.name

        try:
            result = await adapter.adapt(yaml_path)

            assert result.success
            assert result.video_set is not None
            assert len(result.video_set.videos) == 1

            video = result.video_set.videos[0]
            assert video.video_id == "python_basics"
            assert video.title == "Python Basics Tutorial"
            assert video.accent_color == "green"

            # Check that template structure was preserved
            assert len(video.scenes) >= 8  # Tutorial template has 8 scenes

            # Check variable substitution worked
            title_scene = video.scenes[0]
            assert "Python Programming" in title_scene.narration  # ${topic} was substituted

        finally:
            Path(yaml_path).unlink()

    @pytest.mark.asyncio
    async def test_template_with_overrides(self, adapter):
        """Test that template can be overridden with custom values."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml_content = """
template: intro
variables:
  video_id: product_intro
  title: Amazing Product
  tagline: The Best Tool Ever
  hook: Are you tired of complicated tools?
  hook_title: Simplify Your Workflow
  overview_narration: We offer three key benefits.
  features:
    - Easy to use
    - Fast performance
    - Great support
  cta_message: Sign up today!

# Override some template values
accent_color: purple
voice: female
"""
            f.write(yaml_content)
            yaml_path = f.name

        try:
            result = await adapter.adapt(yaml_path)

            assert result.success
            video = result.video_set.videos[0]

            # Check overrides worked
            assert video.accent_color == "purple"
            assert video.voices == ["female"]

            # Check template was used
            assert video.video_id == "product_intro"
            assert video.title == "Amazing Product"

        finally:
            Path(yaml_path).unlink()

    @pytest.mark.asyncio
    async def test_invalid_template_name(self, adapter):
        """Test error handling for invalid template."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml_content = """
template: nonexistent_template
variables:
  video_id: test
"""
            f.write(yaml_content)
            yaml_path = f.name

        try:
            result = await adapter.adapt(yaml_path)

            assert not result.success
            assert "Template error" in result.error
            assert "not found" in result.error

        finally:
            Path(yaml_path).unlink()

    @pytest.mark.asyncio
    async def test_template_with_custom_scenes(self, adapter):
        """Test adding custom scenes to template."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml_content = """
template: presentation
variables:
  video_id: sales_pitch
  title: Q4 Sales Results
  presenter: John Doe
  subtitle: Outstanding Performance
  opening_line: Let me share our amazing results.
  accent_color: orange
  sections:
    - Revenue growth
    - Market expansion
    - Customer satisfaction
  agenda_narration: We'll cover three key areas.
  problem_description: Competition is increasing.
  problem_narration: We face new challenges.
  solution_description: Our innovative strategy.
  solution_narration: Here's how we'll win.
  key_points:
    - 40% revenue increase
    - Entered 5 new markets
    - 95% satisfaction rate
  key_points_narration: These numbers speak for themselves.
  closing_line: Let's keep up the momentum.
  cta_title: Action Items
  cta_message: Let's execute on these plans.
  contact_info: john@company.com

# Add custom scene
scenes:
  - scene_id: custom_demo
    scene_type: command
    narration: Let me show you a live demo of our new feature.
    visual_content:
      header: Live Demo
      commands:
        - npm install our-product
        - our-product --demo
"""
            f.write(yaml_content)
            yaml_path = f.name

        try:
            result = await adapter.adapt(yaml_path)

            assert result.success
            video = result.video_set.videos[0]

            # Check template scenes exist
            scene_ids = [scene.scene_id for scene in video.scenes]
            assert "title" in scene_ids  # From template
            assert "agenda" in scene_ids  # From template

            # Check custom scene was added
            assert "custom_demo" in scene_ids
            custom_scene = next(s for s in video.scenes if s.scene_id == "custom_demo")
            assert custom_scene.scene_type == "command"
            assert "live demo" in custom_scene.narration.lower()

        finally:
            Path(yaml_path).unlink()


class TestEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.fixture
    def adapter(self):
        """Create a YAML adapter instance."""
        return YAMLFileAdapter(test_mode=True)

    def test_empty_variables(self, adapter):
        """Test template merge with no variables."""
        template = {"title": "${title|Default Title}"}
        override = {"variables": {}}

        result = adapter._merge_template(template, override)
        assert result["title"] == "Default Title"

    def test_missing_default_value(self, adapter):
        """Test variable without value and without default."""
        text = "Hello ${name}"
        result = adapter._substitute_variables(text, {})
        assert result == "Hello "  # Empty string

    def test_special_characters_in_variables(self, adapter):
        """Test variables with special characters."""
        text = "Path: ${file_path}"
        variables = {"file_path": "/usr/local/bin/app"}
        result = adapter._substitute_variables(text, variables)
        assert result == "Path: /usr/local/bin/app"

    def test_numeric_variable_values(self, adapter):
        """Test numeric values in variables."""
        text = "Version: ${version}, Count: ${count}"
        variables = {"version": 1.5, "count": 42}
        result = adapter._substitute_variables(text, variables)
        assert result == "Version: 1.5, Count: 42"

    def test_none_variable_value(self, adapter):
        """Test None values in variables."""
        text = "Value: ${value|default}"

        # None should use default
        result1 = adapter._substitute_variables(text, {"value": None})
        assert result1 == "Value: default"

        # Explicit empty string
        result2 = adapter._substitute_variables(text, {"value": ""})
        assert result2 == "Value: "


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
