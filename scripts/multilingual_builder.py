"""
Multilingual Video Builder
===========================
Generate the same video in multiple languages automatically.

Features:
- Define content once in source language
- Auto-translate to multiple languages
- Language-specific TTS voices
- Organized output per language
- Batch generation support

Usage:
    from multilingual_builder import MultilingualVideoSet

    # Create multilingual set
    ml = MultilingualVideoSet(
        base_id="python_tutorial",
        base_name="Python Tutorial",
        languages=['en', 'es', 'fr']
    )

    # Add video in English
    ml.add_video('en', {
        'video_id': 'intro',
        'title': 'Introduction',
        'scenes': [...]
    })

    # Auto-translate and generate
    await ml.auto_translate_and_export()

    # Result: Sets for en, es, fr ready to generate!
"""

import sys
import asyncio
from typing import List, Dict, Optional, Any
from pathlib import Path
import logging

# Setup logging
logger = logging.getLogger(__name__)


sys.path.append('.')

from python_set_builder import VideoSetBuilder, SceneConfig, VideoConfig
from translation_service import TranslationService
from language_config import get_voice_for_language, get_language_name, LANGUAGE_INFO


class MultilingualVideoSet:
    """Build same video in multiple languages"""

    def __init__(
        self,
        base_id: str,
        base_name: str,
        languages: List[str],
        source_language: str = 'en',
        translation_method: str = 'claude',
        **builder_defaults
    ):
        """
        Initialize multilingual video set.

        Args:
            base_id: Base identifier for the set
            base_name: Base name (will be localized)
            languages: List of language codes (e.g., ['en', 'es', 'fr'])
            source_language: Source language code (default: 'en')
            translation_method: 'claude', 'google', or 'manual'
            **builder_defaults: Default settings for all builders
        """
        self.base_id = base_id
        self.base_name = base_name
        self.languages = languages
        self.source_language = source_language

        # Initialize builders for each language
        self.builders = {}
        for lang in languages:
            # Get language-specific defaults
            lang_defaults = builder_defaults.get('defaults', {}).copy()

            # Set language-specific voice
            if 'voice' not in lang_defaults:
                # Auto-select voice for language
                gender = builder_defaults.get('defaults', {}).get('voice', 'male')
                if gender not in ['male', 'female', 'male_warm', 'female_friendly']:
                    gender = 'male'

                lang_defaults['voice_override'] = get_voice_for_language(
                    lang,
                    gender='male' if 'male' in gender else 'female'
                )

            # Create builder for this language
            self.builders[lang] = VideoSetBuilder(
                set_id=f"{base_id}_{lang}",
                set_name=f"{base_name} ({get_language_name(lang)})",
                defaults=lang_defaults,
                **{k: v for k, v in builder_defaults.items() if k != 'defaults'}
            )

        # Translation service
        self.translator = TranslationService(preferred_method=translation_method)

        # Source content storage
        self.source_videos = []

    def add_video_source(
        self,
        video_id: str,
        title: str,
        description: str,
        scenes: List[Dict[str, Any]],
        source_lang: Optional[str] = None
    ):
        """
        Add video in source language.

        Args:
            video_id: Video identifier
            title: Video title (in source language)
            description: Video description
            scenes: List of scene dictionaries
            source_lang: Source language (uses self.source_language if not provided)
        """
        if source_lang is None:
            source_lang = self.source_language

        self.source_videos.append({
            'video_id': video_id,
            'title': title,
            'description': description,
            'scenes': scenes,
            'source_lang': source_lang
        })

    def add_video_manual(
        self,
        lang: str,
        video_id: str,
        title: str,
        description: str,
        scenes: List[SceneConfig]
    ):
        """
        Add video with manual translation for specific language.

        Args:
            lang: Language code
            video_id: Video identifier
            title: Video title (in target language)
            description: Video description
            scenes: List of SceneConfig objects
        """
        if lang not in self.builders:
            raise ValueError(f"Language '{lang}' not in configured languages")

        self.builders[lang].add_video(
            video_id=video_id,
            title=title,
            description=description,
            scenes=scenes
        )

    async def auto_translate_and_export(self, output_dir: str = 'sets'):
        """
        Auto-translate source videos to all languages and export.

        Args:
            output_dir: Base directory for output

        Returns:
            Dictionary mapping language codes to export paths
        """
        logger.info(f"\n{'='*80}")
        logger.info(f"MULTILINGUAL VIDEO GENERATION")
        logger.info(f"{'='*80}\n")

        logger.info(f"Base Set: {self.base_name}")
        logger.info(f"Languages: {', '.join([get_language_name(l) for l in self.languages])}")
        logger.info(f"Source Videos: {len(self.source_videos)}")
        logger.info(f"Translation Method: {self.translator.preferred_method}")
        logger.info()

        exported_paths = {}

        # Process each language
        for lang in self.languages:
            logger.info(f"{'─'*80}")
            logger.info(f"Generating: {get_language_name(lang)} ({lang.upper()})")
            logger.info(f"{'─'*80}\n")

            # Process each source video
            for source_video in self.source_videos:
                video_id = source_video['video_id']
                title = source_video['title']
                description = source_video['description']
                scenes = source_video['scenes']
                source_lang = source_video['source_lang']

                logger.info(f"  [{lang.upper()}] Translating: {title}")

                # If this is the source language, use as-is
                if lang == source_lang:
                    self.builders[lang].add_video(
                        video_id=video_id,
                        title=title,
                        description=description,
                        scenes=self._dicts_to_scene_configs(self.builders[lang], scenes)
                    )
                    logger.info(f"    ✓ Source language (no translation needed)")
                    continue

                # Translate title and description
                title_trans = await self.translator.translate(
                    title, lang, source_lang, context_type='title'
                )
                desc_trans = await self.translator.translate(
                    description, lang, source_lang, context_type='technical'
                )

                logger.info(f"    → Title: {title_trans}")

                # Translate scenes
                translated_scenes = []
                for i, scene_data in enumerate(scenes):
                    logger.info(f"    Translating scene {i+1}/{len(scenes)}...", end=' ')

                    translated_scene = await self._translate_scene(
                        scene_data, lang, source_lang
                    )

                    translated_scenes.append(translated_scene)
                    logger.info("✓")

                # Add to language-specific builder
                self.builders[lang].add_video(
                    video_id=video_id,
                    title=title_trans,
                    description=desc_trans,
                    scenes=self._dicts_to_scene_configs(self.builders[lang], translated_scenes)
                )

                logger.info(f"    ✓ Video translated and added\n")

            # Export this language
            export_path = Path(output_dir) / f"{self.base_id}_{lang}"
            self.builders[lang].export_to_yaml(str(export_path))

            exported_paths[lang] = str(export_path)

            logger.info(f"  ✓ {get_language_name(lang)} set exported to: {export_path}\n")

        logger.info(f"{'='*80}")
        logger.info(f"✓ MULTILINGUAL GENERATION COMPLETE")
        logger.info(f"{'='*80}\n")

        logger.info(f"Generated {len(self.languages)} language versions:")
        for lang in self.languages:
            logger.info(f"  • {get_language_name(lang):<15} ({lang.upper()}) → {exported_paths[lang]}")

        logger.info(f"\nNext steps:")
        logger.info(f"  Generate all languages:")
        logger.info(f"    python generate_all_sets.py")
        logger.info(f"  Or generate specific language:")
        logger.info(f"    python generate_video_set.py {exported_paths[self.languages[0]]}")

        return exported_paths

    async def _translate_scene(
        self,
        scene_data: Dict,
        target_lang: str,
        source_lang: str
    ) -> Dict:
        """Translate a single scene"""
        translated = {}

        # Copy scene type and ID
        translated['scene_type'] = scene_data['scene_type']
        if 'scene_id' in scene_data:
            translated['scene_id'] = scene_data['scene_id']

        # Translate narration
        if 'narration' in scene_data:
            translated['narration'] = await self.translator.translate(
                scene_data['narration'],
                target_lang,
                source_lang,
                context_type='narration'
            )

        # Translate visual content
        if 'visual_content' in scene_data:
            translated['visual_content'] = await self._translate_visual_content(
                scene_data['visual_content'],
                target_lang,
                source_lang
            )

        # Copy other fields
        for key in ['voice', 'min_duration', 'max_duration']:
            if key in scene_data:
                translated[key] = scene_data[key]

        return translated

    async def _translate_visual_content(
        self,
        visual_content: Dict,
        target_lang: str,
        source_lang: str
    ) -> Dict:
        """Translate visual content fields"""
        translated = {}

        # Text fields to translate
        text_fields = ['title', 'subtitle', 'header', 'description', 'main_text', 'sub_text']

        for field in text_fields:
            if field in visual_content:
                translated[field] = await self.translator.translate(
                    visual_content[field],
                    target_lang,
                    source_lang,
                    context_type='title'
                )

        # List items
        if 'items' in visual_content:
            translated_items = []
            for item in visual_content['items']:
                if isinstance(item, tuple) and len(item) == 2:
                    title_trans = await self.translator.translate(
                        item[0], target_lang, source_lang, context_type='title'
                    )
                    desc_trans = await self.translator.translate(
                        item[1], target_lang, source_lang, context_type='technical'
                    )
                    translated_items.append((title_trans, desc_trans))
                elif isinstance(item, dict):
                    item_trans = {}
                    if 'title' in item:
                        item_trans['title'] = await self.translator.translate(
                            item['title'], target_lang, source_lang, context_type='title'
                        )
                    if 'description' in item:
                        item_trans['description'] = await self.translator.translate(
                            item['description'], target_lang, source_lang, context_type='technical'
                        )
                    translated_items.append(item_trans)
                else:
                    trans = await self.translator.translate(
                        str(item), target_lang, source_lang, context_type='title'
                    )
                    translated_items.append(trans)

            translated['items'] = translated_items

        # Commands (translate comments only)
        if 'commands' in visual_content:
            translated_commands = []
            for cmd in visual_content['commands']:
                if isinstance(cmd, str) and cmd.strip().startswith('#'):
                    trans = await self.translator.translate(
                        cmd, target_lang, source_lang, context_type='technical'
                    )
                    translated_commands.append(trans)
                else:
                    translated_commands.append(cmd)

            translated['commands'] = translated_commands

        return translated

    def _dicts_to_scene_configs(self, builder: VideoSetBuilder, scene_dicts: List[Dict]) -> List[SceneConfig]:
        """Convert scene dictionaries to SceneConfig objects"""
        scene_configs = []

        for scene_dict in scene_dicts:
            scene_type = scene_dict['scene_type']
            visual_content = scene_dict.get('visual_content', {})

            # Create scene using builder helpers
            if scene_type == 'title':
                scene = builder.create_title_scene(
                    visual_content.get('title', ''),
                    visual_content.get('subtitle', ''),
                    narration=scene_dict.get('narration'),
                    voice=scene_dict.get('voice')
                )
            elif scene_type == 'command':
                scene = builder.create_command_scene(
                    visual_content.get('header', ''),
                    visual_content.get('description', ''),
                    visual_content.get('commands', []),
                    narration=scene_dict.get('narration'),
                    voice=scene_dict.get('voice')
                )
            elif scene_type == 'list':
                scene = builder.create_list_scene(
                    visual_content.get('header', ''),
                    visual_content.get('description', ''),
                    visual_content.get('items', []),
                    narration=scene_dict.get('narration'),
                    voice=scene_dict.get('voice')
                )
            elif scene_type == 'outro':
                scene = builder.create_outro_scene(
                    visual_content.get('main_text', ''),
                    visual_content.get('sub_text', ''),
                    narration=scene_dict.get('narration'),
                    voice=scene_dict.get('voice')
                )
            else:
                # Generic scene
                scene = SceneConfig(
                    scene_type=scene_type,
                    visual_content=visual_content,
                    narration=scene_dict.get('narration'),
                    voice=scene_dict.get('voice')
                )

            # Copy duration settings
            if 'min_duration' in scene_dict:
                scene.min_duration = scene_dict['min_duration']
            if 'max_duration' in scene_dict:
                scene.max_duration = scene_dict['max_duration']

            scene_configs.append(scene)

        return scene_configs

    def export_language(self, lang: str, output_dir: str = 'sets') -> str:
        """Export a specific language"""
        if lang not in self.builders:
            raise ValueError(f"Language '{lang}' not configured")

        export_path = Path(output_dir) / f"{self.base_id}_{lang}"
        self.builders[lang].export_to_yaml(str(export_path))

        return str(export_path)

    def export_all_languages(self, output_dir: str = 'sets') -> Dict[str, str]:
        """Export all languages"""
        paths = {}

        for lang in self.languages:
            paths[lang] = self.export_language(lang, output_dir)

        return paths


# Convenience function for simple use case
async def generate_multilingual_from_source(
    source_content: Dict,
    languages: List[str],
    base_id: str,
    base_name: str,
    source_lang: str = 'en',
    output_dir: str = 'sets'
) -> Dict[str, str]:
    """
    Generate multilingual videos from source content in one function call.

    Args:
        source_content: Content in source language
        languages: Target languages
        base_id: Set identifier
        base_name: Set name
        source_lang: Source language code
        output_dir: Output directory

    Returns:
        Dictionary mapping language codes to export paths

    Example:
        paths = await generate_multilingual_from_source(
            source_content={
                'video_id': 'intro',
                'title': 'Introduction',
                'scenes': [...]
            },
            languages=['en', 'es', 'fr'],
            base_id='tutorial',
            base_name='Tutorial'
        )
    """
    ml = MultilingualVideoSet(base_id, base_name, languages, source_lang)

    ml.add_video_source(
        video_id=source_content['video_id'],
        title=source_content['title'],
        description=source_content.get('description', ''),
        scenes=source_content['scenes'],
        source_lang=source_lang
    )

    return await ml.auto_translate_and_export(output_dir)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description='Multilingual video builder',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show supported languages
  python multilingual_builder.py --list-languages

  # Test translation
  python multilingual_builder.py --test-translation "Hello world" --target es fr de
        """
    )

    parser.add_argument('--list-languages', action='store_true', help='List supported languages')
    parser.add_argument('--test-translation', help='Test text to translate')
    parser.add_argument('--target', nargs='+', default=['es'], help='Target languages')

    args = parser.parse_args()

    if args.list_languages:
        from language_config import list_available_languages

        logger.info("\nSupported Languages:")
        logger.info("=" * 80)

        for lang in list_available_languages():
            name = get_language_name(lang)
            name_local = get_language_name(lang, local=True)
            logger.info(f"  {lang.upper():<5} {name:<20} {name_local}")

        logger.info("=" * 80)
        logger.info(f"Total: {len(list_available_languages())} languages\n")

    elif args.test_translation:
        async def test():
            translator = TranslationService()

            logger.info(f"\nSource (EN): {args.test_translation}\n")

            for lang in args.target:
                translation = await translator.translate(
                    args.test_translation,
                    lang,
                    'en',
                    context_type='narration'
                )
                logger.info(f"{lang.upper()}: {translation}")

        asyncio.run(test())

    else:
        parser.print_help()
