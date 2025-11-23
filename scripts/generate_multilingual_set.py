"""
Generate Multilingual Video Sets
=================================
Command-line tool to generate videos in multiple languages from a single source.

This tool can:
- Parse English content (markdown, GitHub, YouTube)
- Auto-translate to multiple languages
- Generate language-specific video sets
- Batch process all languages

Usage:
    # From markdown
    python generate_multilingual_set.py --source README.md --languages en es fr

    # From GitHub
    python generate_multilingual_set.py --github https://github.com/user/repo --languages en es fr de

    # From YouTube
    python generate_multilingual_set.py --youtube https://youtube.com/watch?v=ID --languages en es

    # From existing YAML
    python generate_multilingual_set.py --yaml inputs/tutorial.yaml --languages en es fr pt
"""

import os
import sys
import asyncio
import argparse
from pathlib import Path
import logging

# Setup logging
logger = logging.getLogger(__name__)


sys.path.append('.')

from multilingual_builder import MultilingualVideoSet
from document_to_programmatic import parse_document_to_builder, read_document, MarkdownParser
from python_set_builder import VideoSetBuilder
from language_config import list_available_languages, get_language_name

# YouTube import is optional
try:
    from youtube_to_programmatic import parse_youtube_to_builder
    HAS_YOUTUBE = True
except ImportError:
    HAS_YOUTUBE = False
    logger.warning("⚠️  YouTube support requires additional setup")


async def generate_from_document(
    source_file: str,
    languages: list,
    base_id: str = None,
    source_lang: str = 'en',
    translation_method: str = 'claude'
):
    """Generate multilingual videos from document"""

    logger.info(f"\n{'='*80}")
    logger.info(f"GENERATING MULTILINGUAL VIDEOS FROM DOCUMENT")
    logger.info(f"{'='*80}\n")

    # Parse document
    logger.info(f"Parsing: {source_file}")
    builder = parse_document_to_builder(source_file)

    # Get source video
    if not builder.videos:
        logger.error("❌ No videos generated from document")
        return

    source_video = builder.videos[0]

    # Extract content
    source_content = {
        'video_id': source_video.video_id,
        'title': source_video.title,
        'description': source_video.description,
        'scenes': []
    }

    # Convert scenes to dictionaries
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

    # Create multilingual set
    if not base_id:
        base_id = source_video.video_id

    ml = MultilingualVideoSet(
        base_id=base_id,
        base_name=source_video.title,
        languages=languages,
        source_language=source_lang,
        translation_method=translation_method
    )

    # Add source video
    ml.add_video_source(
        video_id=source_content['video_id'],
        title=source_content['title'],
        description=source_content['description'],
        scenes=source_content['scenes'],
        source_lang=source_lang
    )

    # Auto-translate and export
    paths = await ml.auto_translate_and_export()

    logger.info(f"\n✅ Multilingual sets created successfully!")

    return paths


async def generate_from_github(
    github_url: str,
    languages: list,
    base_id: str = None,
    source_lang: str = 'en',
    translation_method: str = 'claude'
):
    """Generate multilingual videos from GitHub README"""

    logger.info(f"\n{'='*80}")
    logger.info(f"GENERATING MULTILINGUAL VIDEOS FROM GITHUB")
    logger.info(f"{'='*80}\n")

    # Import here to avoid circular dependency
    from document_to_programmatic import github_readme_to_video

    # Parse GitHub README
    logger.info(f"Parsing: {github_url}")
    builder = github_readme_to_video(github_url)

    if not builder.videos:
        logger.error("❌ No videos generated from GitHub README")
        return

    source_video = builder.videos[0]

    # Extract content
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

    # Create multilingual set
    if not base_id:
        base_id = source_video.video_id

    ml = MultilingualVideoSet(
        base_id=base_id,
        base_name=source_video.title,
        languages=languages,
        source_language=source_lang,
        translation_method=translation_method
    )

    ml.add_video_source(
        video_id=source_content['video_id'],
        title=source_content['title'],
        description=source_content['description'],
        scenes=source_content['scenes'],
        source_lang=source_lang
    )

    paths = await ml.auto_translate_and_export()

    logger.info(f"\n✅ Multilingual sets created from GitHub README!")

    return paths


async def generate_from_youtube(
    youtube_url: str,
    languages: list,
    base_id: str = None,
    source_lang: str = 'en',
    target_duration: int = 60,
    translation_method: str = 'claude'
):
    """Generate multilingual videos from YouTube"""

    if not HAS_YOUTUBE:
        logger.error("❌ YouTube support not available")
        logger.info("   Install: pip install youtube-transcript-api")
        return None

    logger.info(f"\n{'='*80}")
    logger.info(f"GENERATING MULTILINGUAL VIDEOS FROM YOUTUBE")
    logger.info(f"{'='*80}\n")

    # Parse YouTube
    logger.info(f"Parsing: {youtube_url}")
    builder = parse_youtube_to_builder(youtube_url, target_duration=target_duration)

    if not builder.videos:
        logger.error("❌ No videos generated from YouTube")
        return

    source_video = builder.videos[0]

    # Extract content
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

    # Create multilingual set
    if not base_id:
        base_id = source_video.video_id

    ml = MultilingualVideoSet(
        base_id=base_id,
        base_name=source_video.title,
        languages=languages,
        source_language=source_lang,
        translation_method=translation_method
    )

    ml.add_video_source(
        video_id=source_content['video_id'],
        title=source_content['title'],
        description=source_content['description'],
        scenes=source_content['scenes'],
        source_lang=source_lang
    )

    paths = await ml.auto_translate_and_export()

    logger.info(f"\n✅ Multilingual sets created from YouTube!")

    return paths


def main():
    parser = argparse.ArgumentParser(
        description='Generate multilingual video sets from various sources',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # From English markdown to Spanish + French
  python generate_multilingual_set.py --source README.md --languages en es fr

  # From Spanish markdown to English (REVERSE!)
  python generate_multilingual_set.py --source README_ES.md --languages es en --source-lang es

  # From GitHub README
  python generate_multilingual_set.py --github https://github.com/django/django --languages en es fr de pt

  # From French GitHub → English + Spanish
  python generate_multilingual_set.py --github https://github.com/user/repo --languages fr en es --source-lang fr

  # From YouTube video
  python generate_multilingual_set.py --youtube https://youtube.com/watch?v=ID --languages en es fr

  # List supported languages
  python generate_multilingual_set.py --list-languages

  # Specify translation method
  python generate_multilingual_set.py --source README.md --languages en es --method claude
        """
    )

    # Input sources (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=False)
    input_group.add_argument('--source', help='Local markdown file')
    input_group.add_argument('--github', help='GitHub repository or README URL')
    input_group.add_argument('--youtube', help='YouTube video URL')

    # Configuration
    parser.add_argument(
        '--languages',
        nargs='+',
        default=['en', 'es'],
        help='Target language codes (e.g., en es fr de)'
    )

    parser.add_argument(
        '--source-lang',
        default='en',
        help='Source language code (default: en). Can be any supported language!'
    )

    parser.add_argument(
        '--base-id',
        help='Base set identifier (auto-generated if not provided)'
    )

    parser.add_argument(
        '--method',
        choices=['claude', 'google'],
        default='claude',
        help='Translation method (default: claude)'
    )

    parser.add_argument(
        '--duration',
        type=int,
        default=60,
        help='Target duration for YouTube summaries (default: 60)'
    )

    parser.add_argument(
        '--output',
        default='../sets',
        help='Output directory (default: ../sets)'
    )

    # Utility functions
    parser.add_argument(
        '--list-languages',
        action='store_true',
        help='List all supported languages'
    )

    args = parser.parse_args()

    # List languages
    if args.list_languages:
        logger.info("\nSupported Languages:")
        logger.info("=" * 80)

        for lang in list_available_languages():
            name = get_language_name(lang)
            name_local = get_language_name(lang, local=True)
            logger.info(f"  {lang.upper():<5} {name:<20} ({name_local})")

        logger.info("=" * 80)
        logger.info(f"\nTotal: {len(list_available_languages())} languages supported")
        logger.info(f"\nUsage: --languages en es fr de pt it")
        return

    # Validate input
    if not any([args.source, args.github, args.youtube]):
        logger.error("❌ Please provide an input source:")
        logger.info("   --source README.md")
        logger.info("   --github https://github.com/user/repo")
        logger.info("   --youtube https://youtube.com/watch?v=ID")
        logger.info("\nOr use --list-languages to see supported languages")
        sys.exit(1)

    # Validate languages
    available_langs = list_available_languages()
    for lang in args.languages:
        if lang not in available_langs:
            logger.warning(f"⚠️  Warning: '{lang}' may not be fully supported")
            logger.info(f"   Use --list-languages to see all supported languages")

    # Generate based on source
    if args.source:
        asyncio.run(generate_from_document(
            args.source,
            args.languages,
            args.base_id,
            args.source_lang,
            args.method
        ))

    elif args.github:
        asyncio.run(generate_from_github(
            args.github,
            args.languages,
            args.base_id,
            args.source_lang,
            args.method
        ))

    elif args.youtube:
        asyncio.run(generate_from_youtube(
            args.youtube,
            args.languages,
            args.base_id,
            args.source_lang,
            args.duration,
            args.method
        ))


if __name__ == "__main__":
    main()
