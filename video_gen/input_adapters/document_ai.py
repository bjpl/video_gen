"""AI enhancement functionality for document processing.

This module handles all AI-related operations for document processing:
- Narration enhancement using AI
- Slide content enhancement
- AI-powered content optimization
"""

import logging
from typing import Optional, Dict, Any
import re


class DocumentAIEnhancer:
    """AI enhancement helper for document adapter."""

    def __init__(self, ai_enhancer=None, use_ai: bool = True):
        """Initialize AI enhancer.

        Args:
            ai_enhancer: AIScriptEnhancer instance or None
            use_ai: Whether to use AI enhancement
        """
        self.ai_enhancer = ai_enhancer
        self.use_ai = use_ai and ai_enhancer is not None
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    async def enhance_slide_content(
        self,
        content: str,
        context_type: str,
        scene_position: int = 0,
        total_scenes: int = 1
    ) -> str:
        """Enhance slide content (titles, headers, descriptions) using AI.

        Args:
            content: Original content text
            context_type: Type of content (title, subtitle, header, description, etc.)
            scene_position: Position of scene in video (0-indexed)
            total_scenes: Total number of scenes

        Returns:
            Enhanced content text - KEPT SHORT for on-screen display
        """
        # Clean markdown artifacts from content FIRST
        content = re.sub(r'\*\*([^*]+)\*\*', r'\1', content)  # **bold**
        content = re.sub(r'\*([^*]+)\*', r'\1', content)  # *italic*
        content = re.sub(r'`([^`]+)`', r'\1', content)  # `code`
        content = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', content)  # [text](url)
        content = content.strip()

        # For slide display text, DON'T use AI enhancement - keep it short and clean
        # AI enhancement is designed for narration (long paragraphs), not slide titles
        # This prevents titles like "How the Internet Works" from becoming long paragraphs
        if context_type in ("title", "subtitle", "header", "outro_main", "outro_sub"):
            # Just clean and limit length
            max_lengths = {
                "title": 60,
                "subtitle": 80,
                "header": 70,
                "outro_main": 50,
                "outro_sub": 60
            }
            max_len = max_lengths.get(context_type, 100)
            if len(content) > max_len:
                content = content[:max_len].rsplit(' ', 1)[0] + '...'
            return content

        # For descriptions, allow AI but with strict length control
        if not self.use_ai or not self.ai_enhancer:
            return content[:150]  # Limit to 150 chars

        try:
            # Create context for AI enhancement
            context = {
                'scene_position': scene_position,
                'total_scenes': total_scenes,
                'content_type': context_type,
                'max_length': 150  # Force AI to keep descriptions short
            }

            # Use AI to enhance the description only (not titles/headers)
            enhanced = await self.ai_enhancer.enhance_script(
                script=content,
                scene_type=context_type,
                context=context
            )

            # Enforce length limit even if AI ignores it
            if len(enhanced) > 150:
                enhanced = enhanced[:150].rsplit(' ', 1)[0] + '...'

            return enhanced

        except Exception as e:
            self.logger.warning(f"Slide content AI enhancement failed: {e}, using original")
            return content[:150]

    async def enhance_narration(
        self,
        narration: str,
        scene_type: str,
        scene_data: Dict[str, Any],
        scene_position: int = 0,
        total_scenes: int = 1
    ) -> str:
        """Enhance narration using AI.

        Args:
            narration: Original narration text
            scene_type: Type of scene
            scene_data: Scene visual content data
            scene_position: Position of scene in video (0-indexed)
            total_scenes: Total number of scenes

        Returns:
            Enhanced narration text
        """
        if not self.use_ai or not self.ai_enhancer:
            return narration

        try:
            # Create context for AI enhancement
            context = {
                'scene_position': scene_position,
                'total_scenes': total_scenes,
                **scene_data
            }

            # Use AI to enhance the narration
            enhanced = await self.ai_enhancer.enhance_script(
                script=narration,
                scene_type=scene_type,
                context=context
            )

            return enhanced

        except Exception as e:
            self.logger.warning(f"Narration AI enhancement failed: {e}, using original")
            return narration


__all__ = ['DocumentAIEnhancer']
