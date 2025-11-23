#!/usr/bin/env python3
"""
Demonstration script for YAML template system.

This script shows how to:
1. List available templates
2. Load a template
3. Create a video using a template
"""

import asyncio
from pathlib import Path
import sys
import tempfile

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from video_gen.input_adapters.yaml_file import YAMLFileAdapter


async def demo_list_templates():
    """Demonstrate listing available templates."""
    print("=" * 60)
    print("DEMO 1: Listing Available Templates")
    print("=" * 60)

    adapter = YAMLFileAdapter()
    templates = adapter.list_templates()

    print(f"\nFound {len(templates)} templates:\n")
    for template in templates:
        print(f"  • {template['name']}")
        print(f"    {template['description']}\n")


async def demo_load_template():
    """Demonstrate loading a template."""
    print("=" * 60)
    print("DEMO 2: Loading a Template")
    print("=" * 60)

    adapter = YAMLFileAdapter()

    print("\nLoading 'tutorial' template...")
    template_data = adapter._load_template("tutorial")

    print(f"\nTemplate structure:")
    print(f"  Video ID: {template_data.get('video_id')}")
    print(f"  Title: {template_data.get('title')}")
    print(f"  Scenes: {len(template_data.get('scenes', []))}")

    print(f"\nFirst scene:")
    first_scene = template_data['scenes'][0]
    print(f"  ID: {first_scene['scene_id']}")
    print(f"  Type: {first_scene['scene_type']}")
    print(f"  Narration preview: {first_scene['narration'][:80]}...")


async def demo_use_template():
    """Demonstrate using a template to create a video configuration."""
    print("=" * 60)
    print("DEMO 3: Using a Template")
    print("=" * 60)

    adapter = YAMLFileAdapter(test_mode=True)

    # Create a temporary YAML file using the intro template
    yaml_content = """
template: intro

variables:
  video_id: product_demo
  title: Amazing Video Tool
  tagline: Create Videos in Minutes
  hook: Want to create professional videos quickly?
  hook_title: Save Time on Video Production
  overview_narration: Our tool offers three key benefits that will transform your workflow.
  features:
    - Lightning-fast generation
    - Professional quality
    - Easy to customize
  cta_message: Try it free today!

# Customize the template
accent_color: cyan
voice: female
"""

    # Write to temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(yaml_content)
        yaml_path = f.name

    try:
        print("\nProcessing template-based YAML...")
        result = await adapter.adapt(yaml_path)

        if result.success:
            print(f"✓ Successfully created video configuration")
            print(f"\nVideo details:")
            video = result.video_set.videos[0]
            print(f"  Video ID: {video.video_id}")
            print(f"  Title: {video.title}")
            print(f"  Accent Color: {video.accent_color}")
            print(f"  Voice: {video.voices[0]}")
            print(f"  Scenes: {len(video.scenes)}")

            print(f"\nScene breakdown:")
            for i, scene in enumerate(video.scenes, 1):
                print(f"  {i}. {scene.scene_id} ({scene.scene_type})")

            print(f"\nFirst scene narration:")
            print(f"  {video.scenes[0].narration[:100]}...")

        else:
            print(f"✗ Failed: {result.error}")

    finally:
        Path(yaml_path).unlink()


async def demo_variable_substitution():
    """Demonstrate variable substitution."""
    print("=" * 60)
    print("DEMO 4: Variable Substitution")
    print("=" * 60)

    adapter = YAMLFileAdapter()

    print("\nExample variable placeholders:")
    examples = [
        ("${title}", {"title": "My Video"}, "Simple variable"),
        ("${color|blue}", {}, "Variable with default (no value)"),
        ("${color|blue}", {"color": "red"}, "Variable with default (with value)"),
        ("Hello ${name}!", {"name": "World"}, "Variable in text"),
        ("${greeting} ${name}!", {"greeting": "Hi", "name": "Alice"}, "Multiple variables"),
    ]

    for text, variables, description in examples:
        result = adapter._substitute_variables(text, variables)
        print(f"\n  {description}:")
        print(f"    Input:     {text}")
        print(f"    Variables: {variables}")
        print(f"    Result:    {result}")


async def main():
    """Run all demonstrations."""
    print("\n")
    print("╔════════════════════════════════════════════════════════════╗")
    print("║         YAML Template System Demonstration                 ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print("\n")

    await demo_list_templates()
    print("\n")

    await demo_load_template()
    print("\n")

    await demo_variable_substitution()
    print("\n")

    await demo_use_template()
    print("\n")

    print("=" * 60)
    print("All demonstrations completed successfully!")
    print("=" * 60)
    print("\nNext steps:")
    print("  1. Check out examples/template_usage_example.yaml")
    print("  2. Explore templates in video_gen/input_adapters/templates/")
    print("  3. Create your own custom templates")
    print("\n")


if __name__ == "__main__":
    asyncio.run(main())
