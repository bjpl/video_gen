"""
Example: Parse Documents Programmatically
==========================================
Shows how to parse raw markdown/GitHub READMEs and convert to videos
programmatically, with optional customization.
"""

import sys
sys.path.append('.')

from document_to_programmatic import (
    parse_document_to_builder,
    github_readme_to_video,
    parse_document_to_set
)


def example_1_simple_parse():
    """Example 1: Parse local markdown → auto-generate video"""

    print("\n" + "="*80)
    print("EXAMPLE 1: Simple Parse - Local Markdown")
    print("="*80 + "\n")

    # Just parse and export - that's it!
    set_path = parse_document_to_set(
        '../README.md',
        output_dir='../sets'
    )

    print("\nDone! Now run:")
    print(f"  cd scripts")
    print(f"  python generate_video_set.py ../{set_path}")


def example_2_github_readme():
    """Example 2: Parse GitHub README → video"""

    print("\n" + "="*80)
    print("EXAMPLE 2: GitHub README to Video")
    print("="*80 + "\n")

    # Parse GitHub README directly
    builder = github_readme_to_video(
        'https://github.com/fastapi/fastapi',  # Just the repo URL!
        set_id='fastapi_demo',
        defaults={
            'accent_color': 'green',
            'voice': 'male'
        }
    )

    # Export
    builder.export_to_yaml('../sets/fastapi_demo')

    print("\n✓ FastAPI README parsed and ready!")


def example_3_parse_and_customize():
    """Example 3: Parse → customize → export"""

    print("\n" + "="*80)
    print("EXAMPLE 3: Parse + Customize")
    print("="*80 + "\n")

    # Step 1: Parse document
    builder = parse_document_to_builder(
        '../README.md',
        set_id='readme_enhanced',
        set_name='Enhanced README Video',
        defaults={'accent_color': 'purple', 'voice': 'female'}
    )

    print("✓ Document parsed")

    # Step 2: Add custom intro
    builder.videos[0].scenes.insert(0,
        builder.create_title_scene(
            "Welcome!",
            "Enhanced Tutorial",
            narration="Welcome to this enhanced tutorial. We've automatically parsed the documentation and added custom touches for better flow."
        )
    )

    # Step 3: Add additional videos programmatically
    builder.add_video(
        video_id='bonus_tips',
        title='Bonus Tips',
        scenes=[
            builder.create_title_scene("Bonus Tips", "Extra Content"),
            builder.create_list_scene(
                "Pro Tips",
                "Advanced Techniques",
                [
                    ("Tip 1", "Use virtual environments"),
                    ("Tip 2", "Write tests first"),
                    ("Tip 3", "Document as you code")
                ]
            ),
            builder.create_outro_scene("Happy Coding!", "bonus.md")
        ]
    )

    # Step 4: Export
    builder.export_to_yaml('../sets/readme_enhanced')

    print("✓ Customized and exported!")


def example_4_batch_parse_multiple():
    """Example 4: Parse multiple documents into one set"""

    print("\n" + "="*80)
    print("EXAMPLE 4: Batch Parse Multiple Documents")
    print("="*80 + "\n")

    from python_set_builder import VideoSetBuilder

    # Create builder
    builder = VideoSetBuilder(
        set_id='documentation_suite',
        set_name='Complete Documentation Suite',
        defaults={'accent_color': 'blue', 'voice': 'male'}
    )

    # Parse multiple documents
    documents = [
        ('../README.md', 'Overview'),
        ('../GETTING_STARTED.md', 'Getting Started'),
        ('../AI_NARRATION_QUICKSTART.md', 'AI Narration')
    ]

    for doc_path, doc_title in documents:
        try:
            # Parse document
            temp_builder = parse_document_to_builder(doc_path)

            # Extract the video (first one)
            if temp_builder.videos:
                video = temp_builder.videos[0]

                # Customize and add to main builder
                video.video_id = doc_path.split('/')[-1].replace('.md', '').lower()
                video.title = doc_title

                # Add to main set
                builder.videos.append(video)

                print(f"  ✓ Parsed: {doc_title}")

        except Exception as e:
            print(f"  ⚠️  Skipped {doc_path}: {e}")

    # Export all as one set
    builder.export_to_yaml('../sets/documentation_suite')

    print(f"\n✓ Created set with {len(builder.videos)} videos!")


def example_5_parse_and_add_content():
    """Example 5: Parse base content, then add programmatic content"""

    print("\n" + "="*80)
    print("EXAMPLE 5: Parse + Add Dynamic Content")
    print("="*80 + "\n")

    # Step 1: Parse README for base content
    builder = parse_document_to_builder(
        '../README.md',
        set_id='hybrid_content',
        defaults={'accent_color': 'orange'}
    )

    print("✓ Base content from README")

    # Step 2: Add content from database (simulated)
    features_from_db = [
        {'name': 'GPU Encoding', 'description': '128x faster', 'benefit': 'Save time'},
        {'name': 'Neural TTS', 'description': '4 voice options', 'benefit': 'Professional sound'},
        {'name': 'Perfect Sync', 'description': 'Audio-first design', 'benefit': 'No drift'}
    ]

    # Create feature showcase videos
    for feature in features_from_db:
        builder.add_video(
            video_id=f"feature_{feature['name'].lower().replace(' ', '_')}",
            title=f"Feature: {feature['name']}",
            scenes=[
                builder.create_title_scene(
                    feature['name'],
                    feature['description']
                ),
                builder.create_list_scene(
                    "Benefits",
                    "Why This Matters",
                    [(feature['benefit'], feature['description'])]
                ),
                builder.create_outro_scene(
                    "Try It Now",
                    "docs.example.com"
                )
            ]
        )

    print(f"✓ Added {len(features_from_db)} feature videos from database")

    # Export
    builder.export_to_yaml('../sets/hybrid_content')

    print(f"\n✓ Hybrid set created: README + {len(features_from_db)} dynamic videos")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Document parsing examples')
    parser.add_argument(
        '--example',
        type=int,
        choices=[1, 2, 3, 4, 5],
        help='Run specific example (1-5)'
    )

    args = parser.parse_args()

    examples = {
        1: example_1_simple_parse,
        2: example_2_github_readme,
        3: example_3_parse_and_customize,
        4: example_4_batch_parse_multiple,
        5: example_5_parse_and_add_content
    }

    if args.example:
        examples[args.example]()
    else:
        # Run all examples
        print("\nRunning all examples...\n")
        for i in range(1, 6):
            try:
                examples[i]()
            except Exception as e:
                print(f"\n⚠️  Example {i} error: {e}\n")

    print("\n" + "="*80)
    print("✓ Examples complete!")
    print("="*80 + "\n")
