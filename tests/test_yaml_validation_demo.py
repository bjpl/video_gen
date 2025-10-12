"""
Demonstration of YAML schema validation with real-world examples.

This file shows how validation catches common errors with clear messages.
"""

import pytest
import tempfile
from pathlib import Path
from video_gen.input_adapters.yaml_file import YAMLFileAdapter


@pytest.fixture
def adapter():
    """Create adapter in test mode."""
    return YAMLFileAdapter(test_mode=True)


@pytest.fixture
def temp_yaml_file():
    """Create temporary YAML file for testing."""
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False, encoding='utf-8')
    yield temp_file
    temp_file.close()
    Path(temp_file.name).unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_comprehensive_error_reporting(adapter, temp_yaml_file):
    """
    DEMO: Show how validation catches multiple errors at once.

    This YAML has several issues:
    - Missing title
    - video_id is wrong type (number)
    - description is too long
    - Scene missing scene_id
    - Scene has invalid scene_type
    - Scene narration is wrong type
    - Duration constraints violated
    """
    yaml_content = """
video_id: 123
description: """ + ("x" * 5001) + """
scenes:
  - scene_type: invalid_type
    narration: 456
    min_duration: 20
    max_duration: 10
"""
    temp_yaml_file.write(yaml_content)
    temp_yaml_file.flush()

    result = await adapter.adapt(temp_yaml_file.name)

    # Validation should fail
    assert result.success is False

    # All errors should be reported together
    print("\n" + "="*70)
    print("COMPREHENSIVE ERROR REPORT:")
    print("="*70)
    print(result.error)
    print("="*70)

    # Check that specific errors are present
    assert "Missing required field 'title'" in result.error
    assert "video_id: Must be a string" in result.error
    assert "description: Too long" in result.error
    assert "Missing required field 'scene_id'" in result.error
    assert "Invalid type 'invalid_type'" in result.error
    assert "narration: Must be a string" in result.error
    assert "min_duration (20) cannot be greater than max_duration (10)" in result.error


@pytest.mark.asyncio
async def test_helpful_scene_type_validation(adapter, temp_yaml_file):
    """
    DEMO: Show helpful error message for invalid scene_type.

    When user provides invalid scene_type, error shows all valid options.
    """
    yaml_content = """
video_id: test_video
title: Test Video
scenes:
  - scene_id: scene_1
    scene_type: tutorial
    narration: "This is a tutorial"
"""
    temp_yaml_file.write(yaml_content)
    temp_yaml_file.flush()

    result = await adapter.adapt(temp_yaml_file.name)

    print("\n" + "="*70)
    print("HELPFUL SCENE_TYPE ERROR:")
    print("="*70)
    print(result.error)
    print("="*70)

    assert result.success is False
    assert "Invalid type 'tutorial'" in result.error
    assert "Must be one of:" in result.error
    # All valid types should be listed
    assert "title" in result.error
    assert "command" in result.error
    assert "list" in result.error


@pytest.mark.asyncio
async def test_context_in_video_set_errors(adapter, temp_yaml_file):
    """
    DEMO: Show how errors include context for video_set format.

    When multiple videos have errors, context shows which video is problematic.
    """
    yaml_content = """
videos:
  - video_id: video_1
    scenes:
      - scene_id: scene_1
        scene_type: title
        narration: "Test"
  - video_id: video_2
    title: Video 2
    scenes: []
  - video_id: 123
    title: Video 3
    scenes:
      - scene_type: title
        narration: "Test"
"""
    temp_yaml_file.write(yaml_content)
    temp_yaml_file.flush()

    result = await adapter.adapt(temp_yaml_file.name)

    print("\n" + "="*70)
    print("VIDEO_SET ERROR CONTEXT:")
    print("="*70)
    print(result.error)
    print("="*70)

    assert result.success is False
    # Errors should show which video has problems
    assert "videos[0]" in result.error  # Missing title
    assert "videos[1]" in result.error  # Empty scenes
    assert "videos[2]" in result.error  # Wrong type video_id and missing scene_id


@pytest.mark.asyncio
async def test_clear_error_for_empty_structures(adapter, temp_yaml_file):
    """
    DEMO: Show clear errors for empty lists.
    """
    yaml_content = """
video_id: test_video
title: Test Video
scenes: []
"""
    temp_yaml_file.write(yaml_content)
    temp_yaml_file.flush()

    result = await adapter.adapt(temp_yaml_file.name)

    print("\n" + "="*70)
    print("EMPTY SCENES ERROR:")
    print("="*70)
    print(result.error)
    print("="*70)

    assert result.success is False
    assert "Cannot be empty (must contain at least one scene)" in result.error


@pytest.mark.asyncio
async def test_valid_yaml_passes_validation(adapter, temp_yaml_file):
    """
    DEMO: Show that valid YAML passes all validation checks.
    """
    yaml_content = """
video_id: tutorial_video
title: Getting Started Tutorial
description: A comprehensive introduction to the system
accent_color: blue
voice: male
scenes:
  - scene_id: intro
    scene_type: title
    narration: "Welcome to this tutorial"
    visual_content:
      title: "Getting Started"
      subtitle: "Your first steps"
    min_duration: 3.0
    max_duration: 5.0

  - scene_id: content
    scene_type: list
    narration: "Here are the key concepts"
    visual_content:
      header: "Key Concepts"
      items:
        - "Concept 1"
        - "Concept 2"
        - "Concept 3"

  - scene_id: outro
    scene_type: outro
    narration: "Thanks for watching"
"""
    temp_yaml_file.write(yaml_content)
    temp_yaml_file.flush()

    result = await adapter.adapt(temp_yaml_file.name)

    print("\n" + "="*70)
    print("VALID YAML - SUCCESS:")
    print("="*70)
    print(f"Success: {result.success}")
    print(f"Video ID: {result.video_set.videos[0].video_id}")
    print(f"Title: {result.video_set.videos[0].title}")
    print(f"Scenes: {len(result.video_set.videos[0].scenes)}")
    print("="*70)

    assert result.success is True
    assert result.error is None
    assert len(result.video_set.videos) == 1
    assert result.video_set.videos[0].video_id == "tutorial_video"
    assert len(result.video_set.videos[0].scenes) == 3


if __name__ == "__main__":
    """Run demos to see validation in action."""
    pytest.main([__file__, "-v", "-s"])
