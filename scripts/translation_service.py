"""
Translation Service - High-Quality Content Translation
=======================================================
Translate video content with multiple translation providers:
- Claude API (highest quality, context-aware)
- Google Translate (fallback, free)
- Manual translations (full control)

Supports:
- Technical content translation
- Context preservation
- TTS-optimized output
- Batch translation
- Caching for efficiency
"""

import os
import sys
import json
from typing import Dict, List, Optional
from pathlib import Path

# Try importing translation libraries
try:
    from anthropic import Anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False
    print("⚠️  anthropic not installed: pip install anthropic")

try:
    from googletrans import Translator
    HAS_GOOGLE_TRANS = True
except (ImportError, AttributeError) as e:
    HAS_GOOGLE_TRANS = False
    # AttributeError happens when googletrans is installed but incompatible with httpcore
    # This is expected - we'll use Claude API instead


class TranslationService:
    """Translate video content with quality optimization"""

    def __init__(self, preferred_method='claude', cache_dir='.translation_cache'):
        """
        Initialize translation service.

        Args:
            preferred_method: 'claude', 'google', or 'manual'
            cache_dir: Directory for translation cache
        """
        self.preferred_method = preferred_method
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)

        # Initialize providers
        self.anthropic_client = None
        self.google_translator = None

        if preferred_method == 'claude' and HAS_ANTHROPIC:
            api_key = os.getenv('ANTHROPIC_API_KEY')
            if api_key:
                self.anthropic_client = Anthropic(api_key=api_key)
            else:
                print("⚠️  ANTHROPIC_API_KEY not set")
                if not HAS_GOOGLE_TRANS:
                    raise ValueError("No translation method available. Set ANTHROPIC_API_KEY or install googletrans.")
                self.preferred_method = 'google'

        if self.preferred_method == 'google' or not self.anthropic_client:
            if HAS_GOOGLE_TRANS:
                self.google_translator = Translator()
            else:
                if not self.anthropic_client:
                    raise ValueError("No translation method available. Install googletrans or set ANTHROPIC_API_KEY for Claude API.")

    def _get_cache_key(self, text, source_lang, target_lang):
        """Generate cache key"""
        import hashlib
        content = f"{text}:{source_lang}:{target_lang}"
        return hashlib.md5(content.encode()).hexdigest()

    def _load_from_cache(self, cache_key):
        """Load translation from cache"""
        cache_file = self.cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            with open(cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return None

    def _save_to_cache(self, cache_key, translation):
        """Save translation to cache"""
        cache_file = self.cache_dir / f"{cache_key}.json"
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(translation, f, ensure_ascii=False, indent=2)

    async def translate_with_claude(self, text, target_lang, source_lang='en', context_type='narration'):
        """
        Translate using Claude API for highest quality.

        Args:
            text: Text to translate
            target_lang: Target language code
            source_lang: Source language code
            context_type: Type of content (narration, title, command, etc.)

        Returns:
            Translated text
        """
        if not self.anthropic_client:
            raise ValueError("Claude API not available")

        # Contextual prompts for better translation
        context_prompts = {
            'narration': """You are translating video narration for text-to-speech.

Requirements:
- Natural, spoken language (not written formal)
- Maintain pacing appropriate for TTS
- Preserve technical terms accuracy
- Keep sentence structure TTS-friendly
- Avoid overly complex constructions

Translate the following narration to {target_lang}.
Provide ONLY the translation, no explanation or commentary.""",

            'title': """You are translating video titles and headings.

Requirements:
- Concise and impactful
- Preserve emphasis and tone
- Use standard terminology for target language
- Keep short (video title constraints)

Translate the following title to {target_lang}.
Provide ONLY the translation.""",

            'technical': """You are translating technical documentation for developers.

Requirements:
- Preserve technical accuracy
- Use standard technical terminology in target language
- Keep code examples unchanged
- Maintain clarity for technical audience

Translate the following technical content to {target_lang}.
Provide ONLY the translation."""
        }

        prompt_template = context_prompts.get(context_type, context_prompts['narration'])
        prompt = prompt_template.format(target_lang=target_lang)

        # Call Claude API
        response = self.anthropic_client.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=2000,
            temperature=0.3,  # Lower for consistency
            messages=[
                {
                    "role": "user",
                    "content": f"{prompt}\n\nSource ({source_lang}):\n{text}"
                }
            ]
        )

        return response.content[0].text.strip()

    def translate_with_google(self, text, target_lang, source_lang='en'):
        """
        Translate using Google Translate (free, lower quality).

        Args:
            text: Text to translate
            target_lang: Target language code
            source_lang: Source language code

        Returns:
            Translated text
        """
        if not self.google_translator:
            raise ValueError("Google Translate not available")

        result = self.google_translator.translate(
            text,
            src=source_lang,
            dest=target_lang
        )

        return result.text

    async def translate(
        self,
        text: str,
        target_lang: str,
        source_lang: str = 'en',
        context_type: str = 'narration',
        use_cache: bool = True
    ) -> str:
        """
        Translate text using best available method.

        Args:
            text: Text to translate
            target_lang: Target language code
            source_lang: Source language code
            context_type: Type of content
            use_cache: Whether to use/save cache

        Returns:
            Translated text
        """
        # Same language, return as-is
        if source_lang == target_lang:
            return text

        # Check cache
        if use_cache:
            cache_key = self._get_cache_key(text, source_lang, target_lang)
            cached = self._load_from_cache(cache_key)
            if cached:
                return cached['translation']

        # Translate
        if self.preferred_method == 'claude' and self.anthropic_client:
            translation = await self.translate_with_claude(
                text, target_lang, source_lang, context_type
            )
        elif self.google_translator:
            translation = self.translate_with_google(
                text, target_lang, source_lang
            )
        else:
            raise ValueError("No translation service available")

        # Save to cache
        if use_cache:
            self._save_to_cache(cache_key, {
                'text': text,
                'source_lang': source_lang,
                'target_lang': target_lang,
                'translation': translation,
                'method': self.preferred_method
            })

        return translation

    async def translate_batch(
        self,
        texts: List[str],
        target_lang: str,
        source_lang: str = 'en',
        context_type: str = 'narration'
    ) -> List[str]:
        """
        Translate multiple texts efficiently.

        Args:
            texts: List of texts to translate
            target_lang: Target language code
            source_lang: Source language code
            context_type: Type of content

        Returns:
            List of translated texts
        """
        translations = []

        for text in texts:
            translation = await self.translate(
                text, target_lang, source_lang, context_type
            )
            translations.append(translation)

        return translations

    async def translate_scene_content(
        self,
        scene_data: Dict,
        target_lang: str,
        source_lang: str = 'en'
    ) -> Dict:
        """
        Translate all content in a scene.

        Args:
            scene_data: Scene data dictionary
            target_lang: Target language code
            source_lang: Source language code

        Returns:
            Scene data with translated content
        """
        translated = scene_data.copy()

        # Translate narration
        if 'narration' in scene_data:
            translated['narration'] = await self.translate(
                scene_data['narration'],
                target_lang,
                source_lang,
                context_type='narration'
            )

        # Translate visual content based on scene type
        if 'visual_content' in scene_data:
            vc = scene_data['visual_content'].copy()

            # Title/subtitle
            if 'title' in vc:
                vc['title'] = await self.translate(
                    vc['title'], target_lang, source_lang, context_type='title'
                )
            if 'subtitle' in vc:
                vc['subtitle'] = await self.translate(
                    vc['subtitle'], target_lang, source_lang, context_type='title'
                )

            # Headers/descriptions
            if 'header' in vc:
                vc['header'] = await self.translate(
                    vc['header'], target_lang, source_lang, context_type='title'
                )
            if 'description' in vc:
                vc['description'] = await self.translate(
                    vc['description'], target_lang, source_lang, context_type='title'
                )

            # Main text (outro)
            if 'main_text' in vc:
                vc['main_text'] = await self.translate(
                    vc['main_text'], target_lang, source_lang, context_type='title'
                )
            if 'sub_text' in vc:
                vc['sub_text'] = await self.translate(
                    vc['sub_text'], target_lang, source_lang, context_type='title'
                )

            # List items
            if 'items' in vc and isinstance(vc['items'], list):
                translated_items = []
                for item in vc['items']:
                    if isinstance(item, tuple) and len(item) == 2:
                        title_trans = await self.translate(
                            item[0], target_lang, source_lang, context_type='title'
                        )
                        desc_trans = await self.translate(
                            item[1], target_lang, source_lang, context_type='technical'
                        )
                        translated_items.append((title_trans, desc_trans))
                    else:
                        trans = await self.translate(
                            str(item), target_lang, source_lang, context_type='title'
                        )
                        translated_items.append(trans)
                vc['items'] = translated_items

            # Commands (mostly untranslated, but translate comments)
            if 'commands' in vc and isinstance(vc['commands'], list):
                translated_commands = []
                for cmd in vc['commands']:
                    if cmd.strip().startswith('#'):
                        # Translate comments
                        trans = await self.translate(
                            cmd, target_lang, source_lang, context_type='technical'
                        )
                        translated_commands.append(trans)
                    else:
                        # Keep commands as-is
                        translated_commands.append(cmd)
                vc['commands'] = translated_commands

            translated['visual_content'] = vc

        return translated


# Convenience function
async def translate_to_language(text, target_lang, source_lang='en', method='claude'):
    """
    Quick translation function.

    Example:
        >>> translated = await translate_to_language("Hello world", "es")
        >>> print(translated)
        "Hola mundo"
    """
    service = TranslationService(preferred_method=method)
    return await service.translate(text, target_lang, source_lang)


if __name__ == "__main__":
    import asyncio

    async def test_translation():
        """Test translation service"""
        service = TranslationService(preferred_method='claude')

        # Test translation
        text = "Welcome to Python programming. This tutorial covers variables, functions, and classes."

        print("Testing translation service...")
        print(f"Source (EN): {text}\n")

        for lang in ['es', 'fr', 'de', 'pt']:
            try:
                translation = await service.translate(text, lang, context_type='narration')
                print(f"{lang.upper()}: {translation}")
            except Exception as e:
                print(f"{lang.upper()}: Error - {e}")

    asyncio.run(test_translation())
