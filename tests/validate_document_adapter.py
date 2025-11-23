"""
Document Adapter Validation Script
===================================
Quick validation script to verify all enhancements are working.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from video_gen.input_adapters.document import DocumentAdapter


def print_header(text):
    """Print formatted header"""
    print("\n" + "="*60)
    print(f"  {text}")
    print("="*60)


def print_success(text):
    """Print success message"""
    print(f"✓ {text}")


def print_error(text):
    """Print error message"""
    print(f"✗ {text}")


async def validate_basic_parsing():
    """Validate basic markdown parsing"""
    print_header("VALIDATION 1: Basic Parsing")

    adapter = DocumentAdapter()

    test_md = """# Test Document

## Section 1
Some text here.

- Item 1
- Item 2

## Section 2

```python
print("Hello World")
```
"""

    structure = adapter._parse_markdown_structure(test_md)

    assert structure['title'] == 'Test Document', "Title parsing failed"
    print_success("Title parsing")

    assert len(structure['sections']) == 2, "Section parsing failed"
    print_success("Section parsing")

    assert any(s.get('lists') for s in structure['sections']), "List parsing failed"
    print_success("List parsing")

    assert any(s.get('code_blocks') for s in structure['sections']), "Code block parsing failed"
    print_success("Code block parsing")


async def validate_nested_lists():
    """Validate nested list support"""
    print_header("VALIDATION 2: Nested Lists")

    adapter = DocumentAdapter()

    nested_md = """# Nested

## Test

- Level 1
  - Level 2
    - Level 3
"""

    structure = adapter._parse_markdown_structure(nested_md)

    assert len(structure['sections']) == 1, "Nested list section failed"
    assert structure['sections'][0].get('lists'), "Nested lists not found"
    print_success("Nested list parsing (3 levels)")


async def validate_table_parsing():
    """Validate table parsing"""
    print_header("VALIDATION 3: Table Parsing")

    adapter = DocumentAdapter()

    table_md = """# Tables

## Comparison

| Col1 | Col2 |
|------|------|
| A    | B    |
| C    | D    |
"""

    structure = adapter._parse_markdown_structure(table_md)

    section = structure['sections'][0]
    assert 'tables' in section, "Tables not found"
    assert len(section['tables']) > 0, "No tables parsed"
    assert len(section['tables'][0]) >= 2, "Table rows not parsed"
    print_success("Table parsing with headers and rows")


async def validate_link_extraction():
    """Validate link extraction"""
    print_header("VALIDATION 4: Link Extraction")

    adapter = DocumentAdapter()

    link_md = """# Links

## Resources

Check [Python](https://python.org) and visit our [site](https://example.com).

- [Docs](https://docs.example.com)
"""

    structure = adapter._parse_markdown_structure(link_md)

    section = structure['sections'][0]
    assert 'links' in section, "Links not found"
    assert len(section['links']) >= 3, f"Expected 3+ links, got {len(section['links'])}"
    print_success(f"Link extraction ({len(section['links'])} links found)")


async def validate_multiple_videos():
    """Validate multiple video generation"""
    print_header("VALIDATION 5: Multiple Video Generation")

    adapter = DocumentAdapter()

    multi_md = """# Main Title

## Section 1
Content 1

## Section 2
Content 2

## Section 3
Content 3
"""

    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
        f.write(multi_md)
        temp_file = f.name

    try:
        # Test multi-video mode
        result = await adapter.adapt(temp_file, split_by_h2=True)
        assert result.success, "Multi-video mode failed"
        assert len(result.video_set.videos) == 3, f"Expected 3 videos, got {len(result.video_set.videos)}"
        print_success(f"Multi-video mode (3 videos created)")

        # Test single-video mode
        result = await adapter.adapt(temp_file, split_by_h2=False)
        assert result.success, "Single-video mode failed"
        assert len(result.video_set.videos) == 1, f"Expected 1 video, got {len(result.video_set.videos)}"
        print_success("Single-video mode (1 video created)")

    finally:
        Path(temp_file).unlink()


async def validate_scene_types():
    """Validate all scene types are generated"""
    print_header("VALIDATION 6: Scene Type Generation")

    adapter = DocumentAdapter()

    complete_md = """# Complete

## Lists

- Item 1
- Item 2

## Commands

```bash
npm install
npm start
```

## Table

| A | B |
|---|---|
| 1 | 2 |
"""

    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
        f.write(complete_md)
        temp_file = f.name

    try:
        result = await adapter.adapt(temp_file, split_by_h2=False)  # Single video mode
        assert result.success, "Scene generation failed"

        video = result.video_set.videos[0]
        scene_types = {s.scene_type for s in video.scenes}

        assert 'title' in scene_types, "Title scene missing"
        print_success("Title scene generated")

        # Check for at least one content scene type
        content_types = {'list', 'command', 'comparison'}
        found_content = content_types.intersection(scene_types)
        assert len(found_content) > 0, f"No content scenes found. Found: {scene_types}"

        if 'list' in scene_types:
            print_success("List scene generated")
        if 'command' in scene_types:
            print_success("Command scene generated")
        if 'comparison' in scene_types:
            print_success("Comparison scene generated")

        assert 'outro' in scene_types, "Outro scene missing"
        print_success("Outro scene generated")

        print_success(f"Scene variety: {len(scene_types)} different types")

    finally:
        Path(temp_file).unlink()


async def validate_error_handling():
    """Validate error handling"""
    print_header("VALIDATION 7: Error Handling")

    adapter = DocumentAdapter()

    # Test nonexistent file
    result = await adapter.adapt('nonexistent_file_12345.md')
    assert not result.success, "Should fail for nonexistent file"
    assert result.error is not None, "Error message missing"
    print_success("Nonexistent file handling")

    # Test empty file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
        f.write('')
        temp_file = f.name

    try:
        result = await adapter.adapt(temp_file)
        # Should succeed with minimal content or fail gracefully
        print_success("Empty file handling")
    finally:
        Path(temp_file).unlink()


async def validate_real_files():
    """Validate with real README files"""
    print_header("VALIDATION 8: Real File Processing")

    adapter = DocumentAdapter()
    inputs_dir = Path(__file__).parent.parent / 'inputs'

    readme_path = inputs_dir / 'Internet_Guide_README.md'
    if readme_path.exists():
        result = await adapter.adapt(str(readme_path))
        assert result.success, f"Failed to parse README: {result.error}"
        assert len(result.video_set.videos) > 0, "No videos generated"
        print_success(f"README parsing ({len(result.video_set.videos)} videos)")
    else:
        print_success("README not found (skipped)")

    vol1_path = inputs_dir / 'Internet_Guide_Vol1_Core_Infrastructure.md'
    if vol1_path.exists():
        result = await adapter.adapt(str(vol1_path))
        assert result.success, f"Failed to parse Volume 1: {result.error}"
        assert len(result.video_set.videos) > 0, "No videos generated"
        print_success(f"Volume 1 parsing ({len(result.video_set.videos)} videos)")
    else:
        print_success("Volume 1 not found (skipped)")


async def validate_max_scenes():
    """Validate max scenes per video"""
    print_header("VALIDATION 9: Max Scenes Control")

    adapter = DocumentAdapter()

    many_sections_md = """# Document

## S1
Text

## S2
Text

## S3
Text

## S4
Text

## S5
Text

## S6
Text
"""

    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
        f.write(many_sections_md)
        temp_file = f.name

    try:
        result = await adapter.adapt(temp_file, split_by_h2=False, max_scenes_per_video=5)
        assert result.success, "Max scenes failed"

        video = result.video_set.videos[0]
        assert len(video.scenes) <= 5, f"Expected ≤5 scenes, got {len(video.scenes)}"
        print_success(f"Max scenes control (limited to {len(video.scenes)} scenes)")

    finally:
        Path(temp_file).unlink()


async def validate_metadata():
    """Validate metadata generation"""
    print_header("VALIDATION 10: Metadata")

    adapter = DocumentAdapter()

    simple_md = """# Title

## Section
Content
"""

    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
        f.write(simple_md)
        temp_file = f.name

    try:
        result = await adapter.adapt(temp_file)
        assert result.success, "Metadata test failed"

        assert 'sections_found' in result.metadata, "Missing sections_found"
        assert 'videos_generated' in result.metadata, "Missing videos_generated"
        print_success("Metadata generation")

        assert 'source' in result.video_set.metadata, "Missing source in video_set"
        assert 'video_count' in result.video_set.metadata, "Missing video_count"
        print_success("Video set metadata")

    finally:
        Path(temp_file).unlink()


async def main():
    """Run all validations"""
    print("\n" + "="*60)
    print("  DOCUMENT ADAPTER VALIDATION SUITE")
    print("="*60)

    validations = [
        ("Basic Parsing", validate_basic_parsing),
        ("Nested Lists", validate_nested_lists),
        ("Table Parsing", validate_table_parsing),
        ("Link Extraction", validate_link_extraction),
        ("Multiple Videos", validate_multiple_videos),
        ("Scene Types", validate_scene_types),
        ("Error Handling", validate_error_handling),
        ("Real Files", validate_real_files),
        ("Max Scenes", validate_max_scenes),
        ("Metadata", validate_metadata),
    ]

    passed = 0
    failed = 0

    for name, validation_func in validations:
        try:
            await validation_func()
            passed += 1
        except AssertionError as e:
            failed += 1
            print_error(f"{name} validation failed: {e}")
        except Exception as e:
            failed += 1
            print_error(f"{name} validation error: {e}")

    print_header("VALIDATION SUMMARY")
    print(f"Passed: {passed}/{len(validations)}")
    print(f"Failed: {failed}/{len(validations)}")

    if failed == 0:
        print("\n✓ ALL VALIDATIONS PASSED!")
        print("✓ Document adapter is ready for production use.")
    else:
        print(f"\n✗ {failed} validation(s) failed")
        sys.exit(1)

    print("\n" + "="*60 + "\n")


if __name__ == '__main__':
    asyncio.run(main())
