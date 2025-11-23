"""
Reverse Translation Examples - Any Language → English
======================================================
Examples showing translation FROM other languages INTO English
(and any language to any language).

Examples:
1. Spanish → English
2. French → English + Spanish
3. Japanese → English + Spanish + French
4. Multi-source: ES → EN, FR → EN (combine into one English set)
"""

import sys
import asyncio
sys.path.append('..')

from multilingual_builder import MultilingualVideoSet


async def example_1_spanish_to_english():
    """
    Example 1: Spanish → English
    =============================
    You have Spanish content, want English video.
    """

    print("\n" + "="*80)
    print("EXAMPLE 1: Spanish → English")
    print("="*80 + "\n")

    # Create bilingual set with SPANISH as source!
    ml = MultilingualVideoSet(
        base_id="tutorial_es_to_en",
        base_name="Tutorial",
        languages=['es', 'en'],  # Spanish and English
        source_language='es',    # Source is SPANISH!
        translation_method='claude'
    )

    # Add content in SPANISH
    ml.add_video_source(
        video_id='introduccion',
        title='Introducción a Python',
        description='Aprende Python desde cero',
        scenes=[
            {
                'scene_type': 'title',
                'visual_content': {
                    'title': 'Programación en Python',
                    'subtitle': 'Introducción'
                },
                'narration': 'Bienvenido a la programación en Python. Este tutorial cubre los fundamentos esenciales.',
                'min_duration': 3.0,
                'max_duration': 8.0
            },
            {
                'scene_type': 'command',
                'visual_content': {
                    'header': 'Instalación',
                    'description': 'Configuración Rápida',
                    'commands': [
                        '$ python --version',
                        '$ pip install numpy',
                        '→ ¡Listo para programar!'
                    ]
                },
                'narration': 'Primero, verifica tu versión de Python. Luego instala NumPy. Estás listo para comenzar a programar.',
                'min_duration': 6.0,
                'max_duration': 12.0
            },
            {
                'scene_type': 'outro',
                'visual_content': {
                    'main_text': '¡Comienza a Programar!',
                    'sub_text': 'python.org'
                },
                'narration': 'Estás listo para comenzar a programar en Python. Visita python punto org para más recursos.',
                'min_duration': 3.0,
                'max_duration': 8.0
            }
        ],
        source_lang='es'  # SPANISH source
    )

    # Auto-translate Spanish → English
    paths = await ml.auto_translate_and_export('../sets')

    print(f"\n✓ Example 1 complete!")
    print(f"  Source: Spanish")
    print(f"  Generated: Spanish (original) + English (translated)")
    for lang, path in paths.items():
        print(f"    • {lang.upper()}: {path}")


async def example_2_french_to_multi():
    """
    Example 2: French → English + Spanish
    ======================================
    You have French content, want English AND Spanish.
    """

    print("\n" + "="*80)
    print("EXAMPLE 2: French → English + Spanish")
    print("="*80 + "\n")

    ml = MultilingualVideoSet(
        base_id="cours_fr_to_multi",
        base_name="Cours Python",
        languages=['fr', 'en', 'es'],  # French, English, Spanish
        source_language='fr',          # Source is FRENCH!
        translation_method='claude'
    )

    # Add content in FRENCH
    ml.add_video_source(
        video_id='introduction',
        title='Introduction à Python',
        description='Apprenez Python',
        scenes=[
            {
                'scene_type': 'title',
                'visual_content': {
                    'title': 'Programmation Python',
                    'subtitle': 'Introduction'
                },
                'narration': 'Bienvenue à la programmation Python. Ce tutoriel couvre les bases essentielles.'
            },
            {
                'scene_type': 'list',
                'visual_content': {
                    'header': 'Caractéristiques Principales',
                    'description': 'Pourquoi Python',
                    'items': [
                        ('Facile à Apprendre', 'Syntaxe simple'),
                        ('Puissant', 'Bibliothèques riches'),
                        ('Polyvalent', 'Nombreuses applications')
                    ]
                },
                'narration': 'Python a trois caractéristiques principales. Facile à apprendre avec une syntaxe simple. Puissant avec des bibliothèques riches. Polyvalent pour de nombreuses applications.'
            }
        ],
        source_lang='fr'
    )

    # Auto-translate French → English AND Spanish
    paths = await ml.auto_translate_and_export('../sets')

    print(f"\n✓ Example 2 complete!")
    print(f"  Source: French")
    print(f"  Generated: French (original) + English + Spanish (both translated)")


async def example_3_japanese_to_global():
    """
    Example 3: Japanese → English + Spanish + French
    =================================================
    You have Japanese content, want Western markets.
    """

    print("\n" + "="*80)
    print("EXAMPLE 3: Japanese → English + Spanish + French")
    print("="*80 + "\n")

    ml = MultilingualVideoSet(
        base_id="tutorial_ja_to_western",
        base_name="Python チュートリアル",
        languages=['ja', 'en', 'es', 'fr'],  # Japanese source + 3 targets
        source_language='ja',                 # Source is JAPANESE!
        translation_method='claude'
    )

    # Add content in JAPANESE
    ml.add_video_source(
        video_id='intro',
        title='Python入門',
        description='Pythonの基礎を学ぶ',
        scenes=[
            {
                'scene_type': 'title',
                'visual_content': {
                    'title': 'Pythonプログラミング',
                    'subtitle': '入門'
                },
                'narration': 'Pythonプログラミングへようこそ。このチュートリアルでは基本を学びます。'
            },
            {
                'scene_type': 'outro',
                'visual_content': {
                    'main_text': 'コーディング開始！',
                    'sub_text': 'python.org'
                },
                'narration': 'Pythonでコーディングを始める準備ができました。'
            }
        ],
        source_lang='ja'
    )

    # Auto-translate Japanese → EN, ES, FR
    paths = await ml.auto_translate_and_export('../sets')

    print(f"\n✓ Example 3 complete!")
    print(f"  Source: Japanese")
    print(f"  Generated: Japanese + English + Spanish + French")


async def example_4_multi_source_to_english():
    """
    Example 4: Multiple sources → English
    ======================================
    Combine Spanish + French content → English set
    """

    print("\n" + "="*80)
    print("EXAMPLE 4: Multi-Source (ES + FR) → English")
    print("="*80 + "\n")

    from python_set_builder import VideoSetBuilder

    # Create English set
    en_builder = VideoSetBuilder(
        "combined_en",
        "Combined English Set"
    )

    # Parse Spanish content → translate to English
    ml_es = MultilingualVideoSet(
        "temp_es",
        "Temp",
        languages=['es', 'en'],
        source_language='es'
    )

    ml_es.add_video_source(
        video_id='video_1_es',
        title='Tutorial en Español',
        description='Contenido español',
        scenes=[{
            'scene_type': 'title',
            'visual_content': {'title': 'Hola', 'subtitle': 'Tutorial'},
            'narration': 'Hola. Este es un tutorial en español.'
        }],
        source_lang='es'
    )

    # Parse French content → translate to English
    ml_fr = MultilingualVideoSet(
        "temp_fr",
        "Temp",
        languages=['fr', 'en'],
        source_language='fr'
    )

    ml_fr.add_video_source(
        video_id='video_2_fr',
        title='Tutoriel en Français',
        description='Contenu français',
        scenes=[{
            'scene_type': 'title',
            'visual_content': {'title': 'Bonjour', 'subtitle': 'Tutoriel'},
            'narration': 'Bonjour. Ceci est un tutoriel en français.'
        }],
        source_lang='fr'
    )

    # Translate both to English
    await ml_es.auto_translate_and_export('../sets')
    await ml_fr.auto_translate_and_export('../sets')

    # Combine English versions
    en_builder.videos.extend(ml_es.builders['en'].videos)
    en_builder.videos.extend(ml_fr.builders['en'].videos)

    en_builder.export_to_yaml('../sets/combined_english')

    print(f"\n✓ Example 4 complete!")
    print(f"  Combined Spanish + French content into unified English set")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Reverse translation examples')
    parser.add_argument(
        '--example',
        type=int,
        choices=[1, 2, 3, 4],
        help='Run specific example (1-4)'
    )

    args = parser.parse_args()

    examples = {
        1: example_1_spanish_to_english,
        2: example_2_french_to_multi,
        3: example_3_japanese_to_global,
        4: example_4_multi_source_to_english
    }

    if args.example:
        print(f"\nRunning Example {args.example}...")
        asyncio.run(examples[args.example]())
    else:
        parser.print_help()
        print("\nAvailable examples:")
        print("  1. Spanish → English")
        print("  2. French → English + Spanish")
        print("  3. Japanese → English + Spanish + French")
        print("  4. Multi-source (ES + FR) → English")
        print("\nNote: These demonstrate the concept")
        print("      (Translation requires API key to actually run)")


if __name__ == "__main__":
    main()
