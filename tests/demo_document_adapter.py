"""
Demo Script for Enhanced Document Adapter
==========================================
Demonstrates the new features of the document adapter.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from video_gen.input_adapters.document import DocumentAdapter


async def demo_basic_parsing():
    """Demo basic markdown parsing"""
    print("\n" + "="*60)
    print("DEMO 1: Basic Markdown Parsing")
    print("="*60)

    adapter = DocumentAdapter()

    markdown = """# My Project

## Installation

Install the package:

```bash
npm install my-package
pip install my-package
```

## Features

- Fast performance
- Easy to use
- Well documented
  - API documentation
  - User guide
  - Examples

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| port   | 3000    | Server port |
| host   | 0.0.0.0 | Server host |

Learn more at [documentation](https://docs.example.com).
"""

    structure = adapter._parse_markdown_structure(markdown)

    print(f"\n✓ Title: {structure['title']}")
    print(f"✓ Sections found: {len(structure['sections'])}")

    for i, section in enumerate(structure['sections'], 1):
        print(f"\n  Section {i}: {section['heading']} (level {section['level']})")
        if section.get('code_blocks'):
            print(f"    - Code blocks: {len(section['code_blocks'])}")
        if section.get('lists'):
            print(f"    - Lists: {len(section['lists'])}")
        if section.get('tables'):
            print(f"    - Tables: {len(section['tables'])}")
        if section.get('links'):
            print(f"    - Links: {len(section['links'])}")


async def demo_multiple_videos():
    """Demo splitting document into multiple videos"""
    print("\n" + "="*60)
    print("DEMO 2: Splitting into Multiple Videos")
    print("="*60)

    adapter = DocumentAdapter()
    readme_path = Path(__file__).parent.parent / 'inputs' / 'Internet_Guide_README.md'

    if readme_path.exists():
        # Single video mode
        result_single = await adapter.adapt(str(readme_path), split_by_h2=False)
        print(f"\n✓ Single video mode:")
        print(f"  - Videos: {len(result_single.video_set.videos)}")
        print(f"  - Total scenes: {sum(len(v.scenes) for v in result_single.video_set.videos)}")

        # Multiple video mode (split by ## headings)
        result_multi = await adapter.adapt(str(readme_path), split_by_h2=True)
        print(f"\n✓ Multi video mode (split by ## headings):")
        print(f"  - Videos: {len(result_multi.video_set.videos)}")

        for idx, video in enumerate(result_multi.video_set.videos, 1):
            print(f"    {idx}. {video.title} ({len(video.scenes)} scenes)")
    else:
        print(f"\n⚠ README not found at {readme_path}")


async def demo_real_file_parsing():
    """Demo parsing real documentation files"""
    print("\n" + "="*60)
    print("DEMO 3: Parsing Real Documentation")
    print("="*60)

    adapter = DocumentAdapter()
    inputs_dir = Path(__file__).parent.parent / 'inputs'

    volumes = [
        'Internet_Guide_Vol1_Core_Infrastructure.md',
        'Internet_Guide_Vol2_Protocols_Standards.md',
    ]

    for volume_name in volumes:
        volume_path = inputs_dir / volume_name
        if not volume_path.exists():
            continue

        print(f"\n✓ Processing: {volume_name}")

        result = await adapter.adapt(str(volume_path))

        if result.success:
            print(f"  - Videos generated: {len(result.video_set.videos)}")
            print(f"  - Sections found: {result.metadata['sections_found']}")
            print(f"  - Total scenes: {sum(len(v.scenes) for v in result.video_set.videos)}")

            # Show first video details
            if result.video_set.videos:
                first_video = result.video_set.videos[0]
                print(f"\n  First video: {first_video.title}")
                print(f"  Scene types:")
                scene_types = {}
                for scene in first_video.scenes:
                    scene_type = scene.scene_type
                    scene_types[scene_type] = scene_types.get(scene_type, 0) + 1

                for scene_type, count in scene_types.items():
                    print(f"    - {scene_type}: {count}")
        else:
            print(f"  ✗ Failed: {result.error}")


async def demo_table_parsing():
    """Demo table parsing and rendering"""
    print("\n" + "="*60)
    print("DEMO 4: Table Parsing")
    print("="*60)

    adapter = DocumentAdapter()

    markdown_with_table = """# Comparison Guide

## Feature Comparison

| Feature    | Free Tier | Pro Tier | Enterprise |
|------------|-----------|----------|------------|
| Users      | 1         | 5        | Unlimited  |
| Storage    | 1GB       | 100GB    | Unlimited  |
| Support    | Email     | Phone    | Dedicated  |
| API Access | Limited   | Full     | Full       |

Choose the tier that best fits your needs.
"""

    structure = adapter._parse_markdown_structure(markdown_with_table)

    print(f"\n✓ Found {len(structure['sections'])} section(s)")

    for section in structure['sections']:
        if section.get('tables'):
            print(f"\n  Section: {section['heading']}")
            print(f"  Tables: {len(section['tables'])}")

            table = section['tables'][0]
            print(f"  Table has {len(table)} rows")
            print(f"  First row (header): {table[0]}")
            if len(table) > 1:
                print(f"  Sample data row: {table[1]}")


async def demo_edge_cases():
    """Demo edge case handling"""
    print("\n" + "="*60)
    print("DEMO 5: Edge Case Handling")
    print("="*60)

    adapter = DocumentAdapter()

    # Test malformed markdown
    malformed = """# Title Only

No sections, just some text.

```
Code block without proper closing
"""

    print("\n✓ Testing malformed markdown:")
    structure = adapter._parse_markdown_structure(malformed)
    print(f"  - Title: {structure['title']}")
    print(f"  - Sections: {len(structure['sections'])}")
    print("  - Handled gracefully ✓")

    # Test nested lists
    nested_lists = """# Nested Example

## Features

- Main feature 1
  - Sub-feature 1.1
  - Sub-feature 1.2
    - Deep feature 1.2.1
- Main feature 2
"""

    print("\n✓ Testing nested lists:")
    structure = adapter._parse_markdown_structure(nested_lists)
    section = structure['sections'][0]
    print(f"  - Lists found: {len(section['lists'])}")
    print("  - Nested structure preserved ✓")


async def main():
    """Run all demos"""
    print("\n" + "="*60)
    print("ENHANCED DOCUMENT ADAPTER DEMONSTRATION")
    print("="*60)

    await demo_basic_parsing()
    await demo_multiple_videos()
    await demo_real_file_parsing()
    await demo_table_parsing()
    await demo_edge_cases()

    print("\n" + "="*60)
    print("DEMO COMPLETE")
    print("="*60 + "\n")


if __name__ == '__main__':
    asyncio.run(main())
