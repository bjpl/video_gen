"""AI-powered script enhancement using Claude API.

This module uses Claude AI to enhance, refine, and improve narration scripts
for better engagement and clarity.

Enhancements (Oct 9, 2025 - Plan B):
- Scene-position awareness for better narrative flow
- Cost tracking and usage metrics
- Quality validation checks
"""

from typing import Optional, Dict, Any, List
import logging

from ..shared.config import config
from ..exceptions import ScriptGenerationError


logger = logging.getLogger(__name__)


class AIUsageMetrics:
    """Track AI API usage and costs."""

    def __init__(self):
        self.total_api_calls = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost_usd = 0.0
        self.successful_enhancements = 0
        self.failed_enhancements = 0

    def record_call(self, input_tokens: int, output_tokens: int, success: bool = True):
        """Record an API call."""
        self.total_api_calls += 1
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens

        # Sonnet 4.5 pricing (approximate): $3/M input, $15/M output
        self.total_cost_usd += (input_tokens / 1_000_000 * 3.0) + (output_tokens / 1_000_000 * 15.0)

        if success:
            self.successful_enhancements += 1
        else:
            self.failed_enhancements += 1

    def get_summary(self) -> Dict[str, Any]:
        """Get usage summary."""
        return {
            "api_calls": self.total_api_calls,
            "input_tokens": self.total_input_tokens,
            "output_tokens": self.total_output_tokens,
            "estimated_cost_usd": round(self.total_cost_usd, 4),
            "successful": self.successful_enhancements,
            "failed": self.failed_enhancements,
            "success_rate": (self.successful_enhancements / self.total_api_calls * 100) if self.total_api_calls > 0 else 0
        }


class AIScriptEnhancer:
    """AI-powered script enhancer using Claude.

    This class uses the Claude API to enhance narration scripts, improving
    clarity, engagement, and educational value.

    Features:
    - Scene-position aware prompts for better narrative flow
    - Cost tracking and usage metrics
    - Quality validation checks
    """

    def __init__(self, api_key: Optional[str] = None):
        """Initialize the AI enhancer.

        Args:
            api_key: Optional Anthropic API key (uses config if not provided)
        """
        self.api_key = api_key or config.get_api_key("anthropic")

        if not self.api_key:
            raise ScriptGenerationError("Anthropic API key not configured")

        # Initialize usage tracking
        self.metrics = AIUsageMetrics()

    async def enhance_script(
        self,
        script: str,
        scene_type: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> str:
        """Enhance narration script using Claude.

        Args:
            script: Original narration script
            scene_type: Type of scene (for context)
            context: Optional context (topic, audience, scene_position, total_scenes, etc.)
            **kwargs: Additional enhancement parameters

        Returns:
            Enhanced narration script
        """
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=self.api_key)

            # Extract scene position information (NEW - Plan B enhancement)
            scene_position = context.get('scene_position', 0) if context else 0
            total_scenes = context.get('total_scenes', 1) if context else 1
            scene_number = scene_position + 1  # Convert 0-indexed to 1-indexed

            # Determine position context for better narrative flow
            if scene_number == 1:
                position_context = "This is the OPENING scene - set the tone and hook the viewer."
            elif scene_number == total_scenes:
                position_context = "This is the FINAL scene - provide closure and call-to-action."
            elif scene_number == 2:
                position_context = "This is the second scene - transition smoothly from the intro."
            elif scene_number == total_scenes - 1:
                position_context = "This is the second-to-last scene - prepare for conclusion."
            else:
                position_context = f"This is scene {scene_number} of {total_scenes} - maintain narrative flow."

            # Build enhancement prompt - optimized for technical/educational content
            scene_context = {
                'title': 'opening/header slide',
                'list': 'bulleted list of topics/concepts',
                'command': 'technical commands/code',
                'outro': 'closing/call-to-action',
                'quiz': 'educational quiz question',
                'problem': 'technical problem/challenge',
                'code_comparison': 'before/after code comparison',
                'checkpoint': 'learning progress review',
                'exercise': 'practice instructions'
            }.get(scene_type or 'general', 'general content')

            prompt = f"""You are a professional narrator for technical educational videos. Enhance this narration to be clear, engaging, and natural-sounding.

Original narration: "{script}"

Scene Context: This is for a {scene_context} in an educational video about technical topics.
Position Context: {position_context}

Enhancement Guidelines:
- Make it sound natural when spoken aloud (this will be voice narration)
- Keep it concise and clear (viewers are watching, not reading)
- Maintain all technical accuracy and key information
- Use conversational but professional tone
- Keep similar length (±30% - target 50-150 words for most scenes)
- {"Use appropriate opening hooks and enthusiasm" if scene_number == 1 else ""}
- {"Include appropriate closing and call-to-action" if scene_number == total_scenes else ""}
- {"Use transition language to connect with previous scene" if scene_number > 1 else ""}
- Avoid jargon unless necessary for technical content

Quality Requirements:
- Must be 20-200 words (strict limit)
- No markdown formatting or special characters
- Natural speech patterns and pacing
- Clear pronunciation-friendly language

Return ONLY the enhanced narration text - no explanations, no quotes, just the narration."""

            response = client.messages.create(
                model="claude-sonnet-4-5-20250929",  # Sonnet 4.5
                max_tokens=500,
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )

            enhanced = response.content[0].text.strip()

            # Quality validation FIRST (NEW - Plan B enhancement)
            validation_result = self._validate_enhanced_script(enhanced, script)
            if not validation_result['valid']:
                logger.warning(f"Enhanced script failed validation: {validation_result['reason']}, using original")
                # Record as failed call
                usage = response.usage
                self.metrics.record_call(
                    input_tokens=usage.input_tokens,
                    output_tokens=usage.output_tokens,
                    success=False
                )
                return script

            # Track usage metrics AFTER validation passes
            usage = response.usage
            self.metrics.record_call(
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                success=True
            )

            logger.debug(f"AI enhancement successful: {len(enhanced)} chars (original: {len(script)} chars)")

            return enhanced

        except Exception as e:
            # If AI enhancement fails, return original
            logger.warning(f"AI enhancement failed: {e}, using original narration")
            self.metrics.record_call(0, 0, success=False)  # Record failure
            return script

    def _validate_enhanced_script(self, enhanced: str, original: str) -> Dict[str, Any]:
        """Validate enhanced script quality.

        Args:
            enhanced: Enhanced script
            original: Original script

        Returns:
            Dictionary with 'valid' (bool) and 'reason' (str) keys
        """
        # Length validation (20-200 words)
        word_count = len(enhanced.split())
        if word_count < 20:
            return {'valid': False, 'reason': f'Too short ({word_count} words)'}
        if word_count > 200:
            return {'valid': False, 'reason': f'Too long ({word_count} words)'}

        # Length change validation (should be within ±50% of original)
        len_ratio = len(enhanced) / len(original) if len(original) > 0 else 0
        if len_ratio > 1.5 or len_ratio < 0.5:
            return {'valid': False, 'reason': f'Length changed too much ({len_ratio:.1f}x)'}

        # Content validation (should not be empty or just whitespace)
        if not enhanced.strip():
            return {'valid': False, 'reason': 'Empty or whitespace only'}

        # Format validation (should not contain markdown formatting)
        # Note: Allow parentheses and brackets - they're normal in speech
        if any(marker in enhanced for marker in ['**', '__', '##', '```', '](', '[!', '```']):
            return {'valid': False, 'reason': 'Contains markdown formatting'}

        return {'valid': True, 'reason': 'Passed all checks'}

    # Alias method for backward compatibility
    async def enhance(self, script: str, scene_type: Optional[str] = None, context: Optional[Dict[str, Any]] = None, **kwargs) -> str:
        """Alias for enhance_script (backward compatibility)."""
        return await self.enhance_script(script, scene_type, context, **kwargs)

    async def translate_script(
        self,
        script: str,
        target_language: str,
        **kwargs
    ) -> str:
        """Translate script to target language using Claude.

        Args:
            script: Original script
            target_language: Target language code
            **kwargs: Additional translation parameters

        Returns:
            Translated script
        """
        # TODO: Implement translation
        raise NotImplementedError("Translation not yet implemented")

    async def improve_clarity(
        self,
        script: str,
        **kwargs
    ) -> str:
        """Improve script clarity and readability.

        Args:
            script: Original script
            **kwargs: Additional parameters

        Returns:
            Improved script
        """
        # TODO: Implement clarity improvement
        raise NotImplementedError("Clarity improvement not yet implemented")
