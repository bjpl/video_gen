"""
Document to Programmatic Bridge
================================
Parse raw markdown/GitHub README and convert to programmatic video sets.

This bridges the document parser with the programmatic API, allowing:
- Direct markdown → VideoSetBuilder
- GitHub README → Video set
- No manual structuring needed
- Combine automatic parsing with programmatic control

Usage:
    # Simple: Parse and generate
    from document_to_programmatic import parse_document_to_builder

    builder = parse_document_to_builder('README.md')
    builder.export_to_yaml('sets/my_readme_video')

    # Advanced: Parse, then customize
    builder = parse_document_to_builder('README.md')
    builder.add_video(...)  # Add more videos programmatically
    builder.export_to_yaml('sets/enhanced_readme')
"""

import sys
sys.path.append('.')

from generate_script_from_document import MarkdownParser, read_document
from python_set_builder import VideoSetBuilder
from typing import Optional, Dict, Any


def parse_document_to_builder(
    source: str,
    set_id: Optional[str] = None,
    set_name: Optional[str] = None,
    **builder_kwargs
) -> VideoSetBuilder:
    """
    Parse a document and create a VideoSetBuilder.

    Args:
        source: Path to markdown file or GitHub URL
        set_id: Optional set ID (auto-generated if not provided)
        set_name: Optional set name (auto-generated if not provided)
        **builder_kwargs: Additional VideoSetBuilder parameters

    Returns:
        VideoSetBuilder with video from parsed document

    Example:
        # Parse GitHub README
        builder = parse_document_to_builder(
            'https://github.com/user/repo/blob/main/README.md',
            set_id='repo_demo',
            defaults={'accent_color': 'blue', 'voice': 'male'}
        )

        # Add more videos programmatically
        builder.add_video(...)

        # Export
        builder.export_to_yaml('sets/repo_demo')
    """

    # Read document
    print(f"Reading document: {source}")
    content = read_document(source)

    # Parse structure
    parser = MarkdownParser()
    structure = parser.parse(content)

    # Generate IDs if not provided
    if not set_id:
        import re
        # Extract from filename or title
        if source.startswith('http'):
            set_id = source.split('/')[-1].replace('.md', '').lower()
        else:
            set_id = source.replace('.md', '').replace('/', '_').lower()

        # Clean up
        set_id = re.sub(r'[^a-z0-9_-]', '_', set_id)

    if not set_name:
        set_name = structure.get('title', set_id).title()

    print(f"Creating video set: {set_name}")

    # Create builder
    builder = VideoSetBuilder(
        set_id=set_id,
        set_name=set_name,
        **builder_kwargs
    )

    # Convert parsed structure to video
    scenes = _structure_to_scenes(builder, structure)

    builder.add_video(
        video_id=f"{set_id}_main",
        title=structure.get('title', 'Documentation'),
        description=f"Video generated from {source}",
        scenes=scenes
    )

    print(f"✓ Parsed {len(structure.get('sections', []))} sections → {len(scenes)} scenes")

    return builder


def _structure_to_scenes(builder: VideoSetBuilder, structure: Dict) -> list:
    """Convert parsed markdown structure to scenes"""

    scenes = []

    # Title scene from document title
    if structure.get('title'):
        scenes.append(
            builder.create_title_scene(
                structure['title'],
                "Documentation Overview"
            )
        )

    # Process sections
    for section in structure.get('sections', []):
        scene = _section_to_scene(builder, section)
        if scene:
            scenes.append(scene)

    # Outro scene
    scenes.append(
        builder.create_outro_scene(
            "Learn More",
            "See full documentation"
        )
    )

    return scenes


def _section_to_scene(builder: VideoSetBuilder, section: Dict):
    """Convert a section to appropriate scene type"""

    header = section.get('header', 'Section')

    # Has code blocks → command scene
    if section.get('code_blocks'):
        commands = []
        for code_block in section['code_blocks']:
            # Split code block into lines
            code_lines = code_block.strip().split('\n')
            commands.extend(code_lines[:10])  # Limit to 10 lines

        return builder.create_command_scene(
            header,
            section.get('content', '')[:50],  # Use first 50 chars as description
            commands
        )

    # Has list items → list scene
    elif section.get('list_items'):
        items = []
        for item in section['list_items'][:6]:  # Max 6 items
            # Simple string items
            items.append(item)

        return builder.create_list_scene(
            header,
            f"{len(items)} Key Points",
            items
        )

    # Has paragraph content → command scene with description
    elif section.get('content'):
        # Create a descriptive command scene
        return builder.create_command_scene(
            header,
            section['content'][:100],  # First 100 chars
            []  # No commands, just descriptive
        )

    return None


def parse_document_to_set(
    source: str,
    output_dir: str = 'sets',
    **kwargs
) -> str:
    """
    Parse document and export to set (complete workflow).

    Args:
        source: Document path or URL
        output_dir: Where to save the set (default: 'sets')
        **kwargs: VideoSetBuilder parameters

    Returns:
        Path to exported set directory

    Example:
        # One function call!
        set_path = parse_document_to_set(
            'https://github.com/fastapi/fastapi/blob/master/README.md',
            defaults={'accent_color': 'green', 'voice': 'female'}
        )

        # Then generate
        # python generate_video_set.py {set_path}
    """

    builder = parse_document_to_builder(source, **kwargs)

    # Export
    set_path = builder.export_to_yaml(output_dir)

    print(f"\n✓ Document parsed and exported!")
    print(f"  → {set_path}")
    print(f"\nNext steps:")
    print(f"  cd scripts")
    print(f"  python generate_video_set.py ../{set_path}")
    print(f"  python generate_videos_from_set.py ../output/{builder.set_id}")

    return str(set_path)


# Convenience function for GitHub
def github_readme_to_video(
    github_url: str,
    set_id: Optional[str] = None,
    **kwargs
) -> VideoSetBuilder:
    """
    Convert GitHub README directly to video.

    Args:
        github_url: GitHub repository URL or README URL
        set_id: Optional set ID
        **kwargs: VideoSetBuilder parameters

    Example:
        # From repo URL
        builder = github_readme_to_video(
            'https://github.com/fastapi/fastapi',
            accent_color='green'
        )

        # From README URL
        builder = github_readme_to_video(
            'https://github.com/fastapi/fastapi/blob/master/README.md'
        )
    """

    # If repo URL, append /blob/main/README.md
    if '/blob/' not in github_url:
        # Try main branch
        readme_url = f"{github_url}/blob/main/README.md"
        print(f"Attempting: {readme_url}")
    else:
        readme_url = github_url

    return parse_document_to_builder(readme_url, set_id=set_id, **kwargs)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description='Parse documents into programmatic video sets',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Local file
  python document_to_programmatic.py README.md

  # GitHub URL
  python document_to_programmatic.py https://github.com/user/repo/blob/main/README.md

  # With options
  python document_to_programmatic.py README.md --accent-color purple --voice female

  # GitHub repo (auto-adds README.md)
  python document_to_programmatic.py https://github.com/fastapi/fastapi
        """
    )

    parser.add_argument('source', help='Document path or GitHub URL')
    parser.add_argument('--set-id', help='Set ID (auto-generated if not provided)')
    parser.add_argument('--set-name', help='Set name (auto-generated if not provided)')
    parser.add_argument('--accent-color', default='blue', help='Accent color')
    parser.add_argument('--voice', default='male', help='Voice')
    parser.add_argument('--output', default='../sets', help='Output directory')

    args = parser.parse_args()

    # Build kwargs
    kwargs = {
        'defaults': {
            'accent_color': args.accent_color,
            'voice': args.voice
        }
    }

    if args.set_id:
        kwargs['set_id'] = args.set_id
    if args.set_name:
        kwargs['set_name'] = args.set_name

    # Parse and export
    set_path = parse_document_to_set(
        args.source,
        output_dir=args.output,
        **kwargs
    )

    print(f"\n✅ Ready to generate!")
