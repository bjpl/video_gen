"""
Translation Stage - Translates video content to target languages.

Supports:
- Claude API for high-quality translation (primary)
- Google Translate as fallback
- Batch translation for efficiency
- Language detection
"""

import os
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
import anthropic

from ..pipeline.stage import Stage, StageResult
from ..shared.models import VideoConfig, SceneConfig
from ..shared.config import config
from ..shared.exceptions import TranslationError


logger = logging.getLogger(__name__)

# Optional Google Translate fallback (disabled due to dependency conflicts)
try:
    from googletrans import Translator
    GOOGLE_TRANSLATE_AVAILABLE = True
except ImportError:
    GOOGLE_TRANSLATE_AVAILABLE = False
    logger.warning("googletrans not available - Claude API only mode")


class TranslationStage(Stage):
    """
    Translates video content to target languages.

    Features:
    - Claude API for context-aware translation (primary)
    - Optional Google Translate fallback (if installed)
    - Batch processing for efficiency
    - Preserves formatting and structure
    """

    def __init__(self, event_emitter=None):
        super().__init__("translation", event_emitter)

        # Initialize Claude client
        self.anthropic_api_key = config.get_api_key("anthropic")
        self.claude_client = None
        if self.anthropic_api_key:
            try:
                self.claude_client = anthropic.Anthropic(api_key=self.anthropic_api_key)
                self.logger.info("Claude API initialized for translation")
            except Exception as e:
                self.logger.warning(f"Failed to initialize Claude API: {e}")
        else:
            raise TranslationError(
                "Translation requires Anthropic API key (ANTHROPIC_API_KEY environment variable)",
                stage=self.name,
                details={"missing": "ANTHROPIC_API_KEY"}
            )

        # Initialize Google Translate fallback (optional)
        self.google_translator = None
        if GOOGLE_TRANSLATE_AVAILABLE:
            try:
                self.google_translator = Translator()
                self.logger.info("Google Translate fallback enabled")
            except Exception as e:
                self.logger.warning(f"Google Translate initialization failed: {e}")

    async def execute(self, context: Dict[str, Any]) -> StageResult:
        """Execute translation for all target languages."""

        # Validate context
        self.validate_context(context, ["video_config", "target_languages"])
        video_config: VideoConfig = context["video_config"]
        target_languages: List[str] = context["target_languages"]
        source_language: str = context.get("source_language", "en")

        self.logger.info(
            f"Translating video '{video_config.video_id}' from {source_language} "
            f"to {len(target_languages)} languages"
        )

        # Translate for each target language
        translated_configs = {}
        total_languages = len(target_languages)

        for idx, target_lang in enumerate(target_languages):
            # Skip if source language equals target
            if source_language == target_lang:
                self.logger.info(f"Skipping translation for source language: {target_lang}")
                translated_configs[target_lang] = video_config
                continue

            progress = idx / total_languages
            await self.emit_progress(
                context.get("task_id", "translation"),
                progress,
                f"Translating to {target_lang} ({idx+1}/{total_languages})"
            )

            try:
                # Translate video config
                translated_config = await self._translate_video_config(
                    video_config,
                    source_language,
                    target_lang
                )
                translated_configs[target_lang] = translated_config

                self.logger.info(
                    f"Successfully translated to {target_lang}: "
                    f"{len(translated_config.scenes)} scenes"
                )

            except Exception as e:
                raise TranslationError(
                    f"Failed to translate to {target_lang}: {e}",
                    stage=self.name,
                    details={"target_language": target_lang, "error": str(e)}
                )

        self.logger.info(
            f"Translation complete: {len(translated_configs)} language versions created"
        )

        return StageResult(
            success=True,
            stage_name=self.name,
            artifacts={
                "translated_configs": translated_configs,
                "source_language": source_language,
                "target_languages": target_languages,
            },
            metadata={
                "languages_translated": len(translated_configs),
                "source_language": source_language,
                "target_languages": target_languages,
            }
        )

    async def _translate_video_config(
        self,
        video_config: VideoConfig,
        source_lang: str,
        target_lang: str
    ) -> VideoConfig:
        """Translate entire video configuration to target language."""

        # Create new config for target language
        translated_config = VideoConfig(
            video_id=f"{video_config.video_id}_{target_lang}",
            title=await self._translate_text(video_config.title, source_lang, target_lang),
            description=await self._translate_text(video_config.description, source_lang, target_lang),
            scenes=[],
            accent_color=video_config.accent_color,
            version=video_config.version,
            voices=video_config.voices,
        )

        # Translate each scene
        for scene in video_config.scenes:
            translated_scene = await self._translate_scene(scene, source_lang, target_lang)
            translated_config.scenes.append(translated_scene)

        return translated_config

    async def _translate_scene(
        self,
        scene: SceneConfig,
        source_lang: str,
        target_lang: str
    ) -> SceneConfig:
        """Translate a single scene to target language."""

        # Translate narration
        translated_narration = await self._translate_text(
            scene.narration,
            source_lang,
            target_lang
        )

        # Translate visual content fields (scene-type specific)
        translated_visual = await self._translate_visual_content(
            scene.visual_content,
            scene.scene_type,
            source_lang,
            target_lang
        )

        # Create translated scene
        translated_scene = SceneConfig(
            scene_id=f"{scene.scene_id}_{target_lang}",
            scene_type=scene.scene_type,
            narration=translated_narration,
            visual_content=translated_visual,
            voice=scene.voice,
            min_duration=scene.min_duration,
            max_duration=scene.max_duration,
        )

        return translated_scene

    async def _translate_visual_content(
        self,
        visual_content: Dict[str, Any],
        scene_type: str,
        source_lang: str,
        target_lang: str
    ) -> Dict[str, Any]:
        """Translate visual content fields based on scene type."""

        translated = visual_content.copy()

        # Define translatable fields per scene type
        translatable_fields = {
            "title": ["title", "subtitle"],
            "command": ["title", "description"],
            "list": ["title", "items"],
            "outro": ["message", "cta"],
            "quote": ["quote_text", "attribution"],
            "learning_objectives": ["title", "objectives"],
            "problem": ["title", "problem_text"],
            "solution": ["explanation"],
            "exercise": ["title", "instructions", "hints"],
            "checkpoint": ["learned_topics", "next_topics"],
            "quiz": ["question", "options", "answer"],
        }

        fields = translatable_fields.get(scene_type, [])

        for field in fields:
            if field in translated:
                value = translated[field]

                # Handle different value types
                if isinstance(value, str):
                    translated[field] = await self._translate_text(value, source_lang, target_lang)
                elif isinstance(value, list):
                    translated[field] = [
                        await self._translate_text(item, source_lang, target_lang)
                        for item in value
                        if isinstance(item, str)
                    ]

        return translated

    async def _translate_text(
        self,
        text: str,
        source_lang: str,
        target_lang: str
    ) -> str:
        """Translate text using Claude API (primary) or Google Translate (optional fallback)."""

        if not text or not text.strip():
            return text

        # Try Claude API first
        if self.claude_client:
            try:
                return await self._translate_with_claude(text, source_lang, target_lang)
            except Exception as e:
                self.logger.warning(
                    f"Claude translation failed: {e}"
                )

        # Fallback to Google Translate if available
        if self.google_translator:
            try:
                return await self._translate_with_google(text, source_lang, target_lang)
            except Exception as e:
                self.logger.error(f"Google Translate also failed: {e}")

        # If no translation method succeeded, raise error
        raise TranslationError(
            f"Failed to translate text from {source_lang} to {target_lang}",
            stage=self.name,
            details={"text_preview": text[:100], "claude_available": bool(self.claude_client)}
        )

    async def _translate_with_claude(
        self,
        text: str,
        source_lang: str,
        target_lang: str
    ) -> str:
        """Translate text using Claude API for high-quality, context-aware translation."""

        prompt = f"""Translate the following text from {source_lang} to {target_lang}.

Requirements:
- Maintain the original meaning and tone
- Preserve formatting (line breaks, punctuation)
- Use natural, native-speaker phrasing
- Keep technical terms accurate
- Do NOT add explanations or commentary

Text to translate:
{text}

Translation:"""

        response = self.claude_client.messages.create(
            model="claude-sonnet-4-20250514",  # Latest Sonnet model
            max_tokens=4096,
            temperature=0.3,  # Lower temperature for more consistent translation
            messages=[{
                "role": "user",
                "content": prompt
            }]
        )

        translated = response.content[0].text.strip()
        return translated

    async def _translate_with_google(
        self,
        text: str,
        source_lang: str,
        target_lang: str
    ) -> str:
        """Translate text using Google Translate as fallback (if available)."""

        if not self.google_translator:
            raise Exception("Google Translate not available")

        # Google Translate uses different language codes
        lang_code_map = {
            "en": "en",
            "es": "es",
            "fr": "fr",
            "de": "de",
            "it": "it",
            "pt": "pt",
            "nl": "nl",
            "ru": "ru",
            "ja": "ja",
            "zh": "zh-cn",
            "ko": "ko",
            "ar": "ar",
            "hi": "hi",
            "tr": "tr",
            "pl": "pl",
            "sv": "sv",
            "no": "no",
            "da": "da",
            "fi": "fi",
            "el": "el",
            "he": "he",
            "th": "th",
            "vi": "vi",
            "id": "id",
            "ms": "ms",
            "tl": "tl",
            "cs": "cs",
            "hu": "hu",
        }

        source = lang_code_map.get(source_lang, source_lang)
        target = lang_code_map.get(target_lang, target_lang)

        result = self.google_translator.translate(
            text,
            src=source,
            dest=target
        )

        return result.text
