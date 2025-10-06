"""
Input Adapter Examples
======================
Practical examples of using all input adapters.

Run this file to see examples in action:
    python app/input_adapters/examples.py
"""

from pathlib import Path
import tempfile


def example_document_adapter():
    """Example: Parse a markdown document"""
    logger.info("\n" + "="*80)
    logger.info("EXAMPLE 1: Document Adapter")
    logger.info("="*80 + "\n")

    from . import DocumentAdapter

    # Create sample markdown
    markdown_content = """# My Project

This is a sample project documentation.

## Installation

Install the dependencies:

```bash
npm install
npm start
```

## Features

- Fast performance
- Easy to use
- Well documented
- Active community

## Getting Started

Follow these steps to get started with the project.
"""

    # Save to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
        f.write(markdown_content)
        temp_file = f.name

    # Parse document
    adapter = DocumentAdapter(max_scenes=6)
    video_set = adapter.parse(
        temp_file,
        set_id='my_project_demo',
        set_name='My Project Demo',
        accent_color='blue',
        voice='male'
    )

    logger.info(f"✓ Parsed document into video set")
    logger.info(f"  Set ID: {video_set.config.set_id}")
    logger.info(f"  Set Name: {video_set.config.set_name}")
    logger.info(f"  Videos: {len(video_set.videos)}")
    logger.info(f"  Scenes: {len(video_set.videos[0].scenes)}")

    # Show scenes
    logger.info("\nScenes:")
    for i, scene in enumerate(video_set.videos[0].scenes, 1):
        logger.info(f"  {i}. {scene['type'].upper()}: {scene.get('title') or scene.get('header', 'N/A')}")

    # Clean up
    Path(temp_file).unlink()

    return video_set


def example_yaml_adapter():
    """Example: Parse YAML configuration"""
    logger.info("\n" + "="*80)
    logger.info("EXAMPLE 2: YAML Adapter")
    logger.info("="*80 + "\n")

    from . import YAMLAdapter
    import yaml

    # Create sample YAML
    yaml_data = {
        'video': {
            'id': 'demo_video',
            'title': 'Demo Video',
            'description': 'Example video from YAML',
            'accent_color': 'purple',
            'voice': 'female',
            'target_duration': 60
        },
        'scenes': [
            {
                'type': 'title',
                'title': 'Welcome',
                'subtitle': 'To Our Demo'
            },
            {
                'type': 'command',
                'header': 'Quick Start',
                'description': 'Get started in seconds',
                'commands': [
                    '$ pip install demo-package',
                    '$ demo-package init',
                    '$ demo-package run'
                ]
            },
            {
                'type': 'list',
                'header': 'Key Features',
                'description': 'What makes us special',
                'items': [
                    'Lightning fast',
                    'Easy to use',
                    'Fully customizable',
                    'Great documentation'
                ]
            },
            {
                'type': 'outro',
                'main_text': 'Get Started Today',
                'sub_text': 'Visit our website'
            }
        ]
    }

    # Save to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(yaml_data, f)
        temp_file = f.name

    # Parse YAML
    adapter = YAMLAdapter()
    video_set = adapter.parse(temp_file)

    logger.info(f"✓ Parsed YAML into video set")
    logger.info(f"  Set ID: {video_set.config.set_id}")
    logger.info(f"  Videos: {len(video_set.videos)}")
    logger.info(f"  Scenes: {len(video_set.videos[0].scenes)}")

    # Show configuration
    logger.info("\nConfiguration:")
    logger.info(f"  Accent Color: {video_set.config.defaults['accent_color']}")
    logger.info(f"  Voice: {video_set.config.defaults['voice']}")
    logger.info(f"  Duration: {video_set.config.defaults['target_duration']}s")

    # Clean up
    Path(temp_file).unlink()

    return video_set


def example_programmatic_adapter():
    """Example: Create video set programmatically"""
    logger.info("\n" + "="*80)
    logger.info("EXAMPLE 3: Programmatic Adapter")
    logger.info("="*80 + "\n")

    from . import ProgrammaticAdapter, create_title_scene, create_list_scene, create_outro_scene

    adapter = ProgrammaticAdapter()

    # Create video set from dictionary
    video_set_data = {
        'set': {
            'id': 'tutorial_series',
            'name': 'Tutorial Series',
            'description': 'Comprehensive tutorial collection',
            'defaults': {
                'accent_color': 'green',
                'voice': 'male',
                'target_duration': 90
            }
        },
        'videos': [
            {
                'video_id': 'intro',
                'title': 'Introduction',
                'description': 'Series introduction',
                'scenes': [
                    create_title_scene(
                        'Tutorial Series',
                        'Introduction',
                        narration='Welcome to our comprehensive tutorial series.'
                    ),
                    create_list_scene(
                        'What You Will Learn',
                        'Course Overview',
                        [
                            'Fundamentals',
                            'Advanced techniques',
                            'Best practices',
                            'Real-world examples'
                        ],
                        narration='This course covers everything you need to know.'
                    ),
                    create_outro_scene(
                        'Let\'s Begin',
                        'Next: Fundamentals',
                        narration='Let\'s get started with the fundamentals.'
                    )
                ]
            }
        ]
    }

    video_set = adapter.create_from_dict(video_set_data)

    logger.info(f"✓ Created video set programmatically")
    logger.info(f"  Set ID: {video_set.config.set_id}")
    logger.info(f"  Set Name: {video_set.config.set_name}")
    logger.info(f"  Videos: {len(video_set.videos)}")

    # Show video details
    video = video_set.videos[0]
    logger.info(f"\nVideo: {video.title}")
    logger.info(f"  Scenes: {len(video.scenes)}")
    for i, scene in enumerate(video.scenes, 1):
        narration = scene.get('narration', 'No narration')
        logger.info(f"  {i}. {scene['type']}: {narration[:50]}...")

    return video_set


def example_factory_pattern():
    """Example: Using adapter factory"""
    logger.info("\n" + "="*80)
    logger.info("EXAMPLE 4: Factory Pattern")
    logger.info("="*80 + "\n")

    from . import get_adapter

    # Create sample markdown
    markdown = """# Quick Guide

## Step 1
First step instructions.

## Step 2
Second step instructions.
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
        f.write(markdown)
        temp_file = f.name

    # Get adapter using factory
    adapter = get_adapter('document', max_scenes=4, target_duration=45)

    logger.info(f"✓ Created adapter via factory: {adapter.__class__.__name__}")

    # Parse
    video_set = adapter.parse(
        temp_file,
        accent_color='orange',
        voice='female'
    )

    logger.info(f"  Set ID: {video_set.config.set_id}")
    logger.info(f"  Accent Color: {video_set.config.defaults['accent_color']}")
    logger.info(f"  Voice: {video_set.config.defaults['voice']}")

    # Clean up
    Path(temp_file).unlink()

    return video_set


def example_export_workflow():
    """Example: Complete export workflow"""
    logger.info("\n" + "="*80)
    logger.info("EXAMPLE 5: Export Workflow")
    logger.info("="*80 + "\n")

    from . import DocumentAdapter
    import yaml

    # Create document
    markdown = """# Export Demo

This demonstrates the complete export workflow.

## Features
- Feature 1
- Feature 2
- Feature 3
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
        f.write(markdown)
        temp_file = f.name

    # Parse
    adapter = DocumentAdapter()
    video_set = adapter.parse(temp_file, set_id='export_demo')

    logger.info(f"✓ Parsed document")

    # Export to temp directory
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = video_set.export_to_yaml(tmpdir)

        logger.info(f"✓ Exported to: {output_path}")

        # Verify files
        files = list(output_path.glob('*.yaml'))
        logger.info(f"  Files created: {len(files)}")
        for file in files:
            logger.info(f"    - {file.name}")

        # Load and verify
        with open(output_path / 'set_config.yaml') as f:
            config = yaml.safe_load(f)

        logger.info(f"\n✓ Verified set_config.yaml:")
        logger.info(f"  Set ID: {config['set']['id']}")
        logger.info(f"  Videos: {len(config['set']['videos'])}")

    # Clean up
    Path(temp_file).unlink()


def example_custom_adapter():
    """Example: Creating a custom adapter"""
    logger.info("\n" + "="*80)
    logger.info("EXAMPLE 6: Custom Adapter")
    logger.info("="*80 + "\n")

    from . import BaseInputAdapter, VideoSet, VideoConfig

    class CSVAdapter(BaseInputAdapter):
        """Custom adapter for CSV files"""

        def parse(self, source: str, **options) -> VideoSet:
            # Simulate reading CSV
            data = [
                ['Feature 1', 'Description 1'],
                ['Feature 2', 'Description 2'],
                ['Feature 3', 'Description 3']
            ]

            # Create scenes from CSV rows
            scenes = [
                self.create_scene(
                    scene_type='title',
                    visual_content={
                        'title': 'CSV Data',
                        'subtitle': 'Imported from CSV'
                    }
                )
            ]

            # Add list scene with CSV data
            items = [f"{row[0]}: {row[1]}" for row in data]
            scenes.append(
                self.create_scene(
                    scene_type='list',
                    visual_content={
                        'header': 'Features from CSV',
                        'description': 'Data imported',
                        'items': items
                    }
                )
            )

            scenes.append(
                self.create_scene(
                    scene_type='outro',
                    visual_content={
                        'main_text': 'Data Imported',
                        'sub_text': 'From CSV File'
                    }
                )
            )

            # Create video
            video = VideoConfig(
                video_id='csv_import',
                title='CSV Import',
                description='Data from CSV file',
                scenes=scenes
            )

            # Return video set
            return self.create_video_set(
                set_id='csv_data',
                set_name='CSV Data',
                videos=[video],
                description='Imported from CSV'
            )

    # Use custom adapter
    adapter = CSVAdapter()
    video_set = adapter.parse('data.csv')  # Source not actually read in this example

    logger.info(f"✓ Created custom CSV adapter")
    logger.info(f"  Adapter: {adapter.__class__.__name__}")
    logger.info(f"  Videos: {len(video_set.videos)}")
    logger.info(f"  Scenes: {len(video_set.videos[0].scenes)}")

    return video_set


def run_all_examples():
    """Run all examples"""
    logger.info("\n" + "="*80)
    logger.info("INPUT ADAPTER EXAMPLES")
    logger.info("="*80)

    try:
        # Run examples
        example_document_adapter()
        example_yaml_adapter()
        example_programmatic_adapter()
        example_factory_pattern()
        example_export_workflow()
        example_custom_adapter()

        logger.info("\n" + "="*80)
        logger.info("✓ ALL EXAMPLES COMPLETED SUCCESSFULLY")
        logger.info("="*80 + "\n")

    except Exception as e:
        logger.info(f"\n❌ Error running examples: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    run_all_examples()
