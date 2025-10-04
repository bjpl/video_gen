"""
Multilingual Video Generation Examples
=======================================
Complete examples showing different multilingual workflows.

Examples:
1. Simple bilingual (EN/ES) from scratch
2. Auto-translate GitHub README to 5 languages
3. Manual translation with custom content
4. Hybrid: Auto-translate + manual refinement
5. Parse YouTube → multilingual summaries
"""

import sys
import asyncio
sys.path.append('..')

from multilingual_builder import MultilingualVideoSet
from python_set_builder import VideoSetBuilder
from document_to_programmatic import github_readme_to_video


async def example_1_simple_bilingual():
    """
    Example 1: Simple EN/ES bilingual video from scratch
    ====================================================
    Manual translation, full control.
    """

    print("\n" + "="*80)
    print("EXAMPLE 1: Simple Bilingual (EN/ES)")
    print("="*80 + "\n")

    from multilingual_builder import MultilingualVideoSet

    # Create bilingual set
    ml = MultilingualVideoSet(
        base_id="python_intro_bilingual",
        base_name="Python Introduction",
        languages=['en', 'es'],
        source_language='en'
    )

    # Add English version
    ml.add_video_source(
        video_id='introduction',
        title='Python Introduction',
        description='Learn Python basics',
        scenes=[
            {
                'scene_type': 'title',
                'visual_content': {
                    'title': 'Python Programming',
                    'subtitle': 'Introduction'
                },
                'narration': 'Welcome to Python programming. This tutorial covers the essentials.',
                'min_duration': 3.0,
                'max_duration': 8.0
            },
            {
                'scene_type': 'command',
                'visual_content': {
                    'header': 'Installation',
                    'description': 'Quick Setup',
                    'commands': [
                        '$ python --version',
                        '$ pip install numpy',
                        '→ Ready to code!'
                    ]
                },
                'narration': 'First, check your Python version. Then install NumPy. You are ready to start coding.',
                'min_duration': 6.0,
                'max_duration': 12.0
            },
            {
                'scene_type': 'list',
                'visual_content': {
                    'header': 'Key Features',
                    'description': 'Why Python',
                    'items': [
                        ('Easy to Learn', 'Simple syntax'),
                        ('Powerful', 'Rich libraries'),
                        ('Versatile', 'Many applications')
                    ]
                },
                'narration': 'Python has three key features. Easy to learn with simple syntax. Powerful with rich libraries. Versatile for many applications.',
                'min_duration': 8.0,
                'max_duration': 15.0
            },
            {
                'scene_type': 'outro',
                'visual_content': {
                    'main_text': 'Start Coding!',
                    'sub_text': 'python.org'
                },
                'narration': 'You are ready to start coding in Python. Visit python dot org for more resources.',
                'min_duration': 3.0,
                'max_duration': 8.0
            }
        ],
        source_lang='en'
    )

    # Auto-translate to Spanish
    paths = await ml.auto_translate_and_export('../sets')

    print(f"\n✓ Example 1 complete!")
    print(f"  Generated: {len(paths)} language versions")
    for lang, path in paths.items():
        print(f"    • {get_language_name(lang)}: {path}")


async def example_2_github_multilingual():
    """
    Example 2: Auto-translate GitHub README to 5 languages
    =======================================================
    Parse GitHub, auto-translate everything.
    """

    print("\n" + "="*80)
    print("EXAMPLE 2: GitHub README → 5 Languages")
    print("="*80 + "\n")

    # Note: This would use real GitHub URL
    # For demo, using local README
    from document_to_programmatic import parse_document_to_builder

    # Parse README
    builder = parse_document_to_builder('../README.md')

    source_video = builder.videos[0]

    # Convert to source content
    source_content = {
        'video_id': source_video.video_id,
        'title': source_video.title,
        'description': source_video.description,
        'scenes': []
    }

    for scene in source_video.scenes:
        scene_dict = {
            'scene_type': scene.scene_type,
            'visual_content': scene.visual_content,
            'narration': scene.narration,
            'voice': scene.voice,
            'min_duration': scene.min_duration,
            'max_duration': scene.max_duration
        }
        source_content['scenes'].append(scene_dict)

    # Create multilingual set for 5 languages
    ml = MultilingualVideoSet(
        base_id="readme_multilingual",
        base_name="Video System Documentation",
        languages=['en', 'es', 'fr', 'de', 'pt'],  # 5 languages!
        translation_method='claude'
    )

    ml.add_video_source(
        video_id=source_content['video_id'],
        title=source_content['title'],
        description=source_content['description'],
        scenes=source_content['scenes']
    )

    # Auto-translate all
    paths = await ml.auto_translate_and_export('../sets')

    print(f"\n✓ Example 2 complete!")
    print(f"  Generated: {len(paths)} language versions from README")


async def example_3_manual_translations():
    """
    Example 3: Manual translations with full control
    =================================================
    Provide exact translations for each language.
    """

    print("\n" + "="*80)
    print("EXAMPLE 3: Manual Translations (Full Control)")
    print("="*80 + "\n")

    # Create multilingual set
    ml = MultilingualVideoSet(
        base_id="manual_translation_demo",
        base_name="Manual Translation Demo",
        languages=['en', 'es', 'fr']
    )

    # English version
    ml.add_video_manual(
        lang='en',
        video_id='greeting',
        title='Hello World',
        description='Simple greeting program',
        scenes=[
            ml.builders['en'].create_title_scene(
                'Hello World',
                'Your First Program',
                narration='Hello World. Your first program in any language.'
            ),
            ml.builders['en'].create_outro_scene(
                'Great Job!',
                'Next: Variables',
                narration='Great job! Next lesson covers variables.'
            )
        ]
    )

    # Spanish version (manual translation)
    ml.add_video_manual(
        lang='es',
        video_id='greeting',
        title='Hola Mundo',
        description='Programa de saludo simple',
        scenes=[
            ml.builders['es'].create_title_scene(
                'Hola Mundo',
                'Tu Primer Programa',
                narration='Hola Mundo. Tu primer programa en cualquier idioma.'
            ),
            ml.builders['es'].create_outro_scene(
                '¡Excelente!',
                'Próximo: Variables',
                narration='¡Excelente! La próxima lección cubre variables.'
            )
        ]
    )

    # French version (manual translation)
    ml.add_video_manual(
        lang='fr',
        video_id='greeting',
        title='Bonjour le Monde',
        description='Programme de salutation simple',
        scenes=[
            ml.builders['fr'].create_title_scene(
                'Bonjour le Monde',
                'Votre Premier Programme',
                narration='Bonjour le monde. Votre premier programme dans n\'importe quelle langue.'
            ),
            ml.builders['fr'].create_outro_scene(
                'Excellent!',
                'Suivant: Variables',
                narration='Excellent! La prochaine leçon couvre les variables.'
            )
        ]
    )

    # Export all
    paths = ml.export_all_languages('../sets')

    print(f"\n✓ Example 3 complete!")
    print(f"  Generated: {len(paths)} manually translated versions")


async def example_4_hybrid_approach():
    """
    Example 4: Hybrid - Auto-translate + Manual refinement
    =======================================================
    Auto-translate, then manually refine key sections.
    """

    print("\n" + "="*80)
    print("EXAMPLE 4: Hybrid (Auto + Manual Refinement)")
    print("="*80 + "\n")

    # Start with auto-translation
    ml = MultilingualVideoSet(
        base_id="hybrid_demo",
        base_name="Hybrid Demo",
        languages=['en', 'es'],
        translation_method='claude'
    )

    # Add English source
    ml.add_video_source(
        video_id='tutorial',
        title='Advanced Tutorial',
        description='Deep dive',
        scenes=[
            {
                'scene_type': 'title',
                'visual_content': {'title': 'Advanced Tutorial', 'subtitle': 'Deep Dive'},
                'narration': 'Welcome to the advanced tutorial.'
            },
            {
                'scene_type': 'command',
                'visual_content': {
                    'header': 'Setup',
                    'description': 'Configuration',
                    'commands': ['$ config --advanced']
                },
                'narration': 'Configure your environment for advanced features.'
            }
        ]
    )

    # Auto-translate
    print("Auto-translating to Spanish...")
    await ml.auto_translate_and_export('../sets')

    # Now manually refine the Spanish intro (if needed)
    # You can access and modify the Spanish builder directly
    spanish_builder = ml.builders['es']

    # Replace first scene with refined translation
    if spanish_builder.videos:
        video = spanish_builder.videos[0]
        # You can modify scenes here for refinement
        print("  (Spanish version can be refined manually if needed)")

    print(f"\n✓ Example 4 complete!")
    print(f"  Auto-translated, ready for manual refinement if needed")


async def example_5_batch_translation():
    """
    Example 5: Batch translate multiple videos
    ===========================================
    Create tutorial series in multiple languages.
    """

    print("\n" + "="*80)
    print("EXAMPLE 5: Batch Translation (Tutorial Series)")
    print("="*80 + "\n")

    # Create multilingual set
    ml = MultilingualVideoSet(
        base_id="python_course_multilingual",
        base_name="Python Course",
        languages=['en', 'es', 'fr'],
        translation_method='claude'
    )

    # Define course content in English
    lessons = [
        {
            'video_id': 'lesson_01',
            'title': 'Variables',
            'description': 'Learn about variables',
            'scenes': [
                {
                    'scene_type': 'title',
                    'visual_content': {'title': 'Lesson 1', 'subtitle': 'Variables'},
                    'narration': 'Lesson one. Variables. Learn how to store data.'
                },
                {
                    'scene_type': 'command',
                    'visual_content': {
                        'header': 'Creating Variables',
                        'description': 'Basic Syntax',
                        'commands': ['x = 10', 'print(x)']
                    },
                    'narration': 'Create a variable with assignment. Print to see the value.'
                },
                {
                    'scene_type': 'outro',
                    'visual_content': {'main_text': 'Great!', 'sub_text': 'Next: Functions'},
                    'narration': 'Great job! You understand variables. Next: functions.'
                }
            ]
        },
        {
            'video_id': 'lesson_02',
            'title': 'Functions',
            'description': 'Learn about functions',
            'scenes': [
                {
                    'scene_type': 'title',
                    'visual_content': {'title': 'Lesson 2', 'subtitle': 'Functions'},
                    'narration': 'Lesson two. Functions. Learn to create reusable code.'
                },
                {
                    'scene_type': 'command',
                    'visual_content': {
                        'header': 'Defining Functions',
                        'description': 'Basic Syntax',
                        'commands': ['def greet(name):', '    print(f"Hello {name}")']
                    },
                    'narration': 'Define a function with def. Add parameters. Call it anytime.'
                },
                {
                    'scene_type': 'outro',
                    'visual_content': {'main_text': 'Excellent!', 'sub_text': 'Next: Classes'},
                    'narration': 'Excellent! You can create functions. Next: classes.'
                }
            ]
        }
    ]

    # Add all lessons
    for lesson in lessons:
        ml.add_video_source(
            video_id=lesson['video_id'],
            title=lesson['title'],
            description=lesson['description'],
            scenes=lesson['scenes']
        )

    # Auto-translate all lessons to all languages
    paths = await ml.auto_translate_and_export('../sets')

    print(f"\n✓ Example 5 complete!")
    print(f"  Generated: {len(lessons)} lessons × {len(paths)} languages = {len(lessons) * len(paths)} total videos")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Run multilingual examples')
    parser.add_argument(
        '--example',
        type=int,
        choices=[1, 2, 3, 4, 5],
        help='Run specific example (1-5)'
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Run all examples'
    )

    args = parser.parse_args()

    examples = {
        1: example_1_simple_bilingual,
        2: example_2_github_multilingual,
        3: example_3_manual_translations,
        4: example_4_hybrid_approach,
        5: example_5_batch_translation
    }

    if args.all:
        print("\nRunning all multilingual examples...\n")
        for i in range(1, 6):
            try:
                asyncio.run(examples[i]())
            except Exception as e:
                print(f"\n⚠️  Example {i} error: {e}\n")
    elif args.example:
        asyncio.run(examples[args.example]())
    else:
        parser.print_help()
        print("\nAvailable examples:")
        print("  1. Simple bilingual (EN/ES)")
        print("  2. GitHub README → 5 languages")
        print("  3. Manual translations")
        print("  4. Hybrid (auto + manual)")
        print("  5. Batch translation (tutorial series)")


if __name__ == "__main__":
    main()
