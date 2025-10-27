"""
Script Generation Stage - Generates narration scripts for all scenes.
"""

from typing import Dict, Any

from ..pipeline.stage import Stage, StageResult
from ..shared.models import VideoConfig
from ..script_generator import NarrationGenerator, AIScriptEnhancer
from ..shared.config import config
from ..shared.exceptions import StageError


class ScriptGenerationStage(Stage):
    """
    Generates narration scripts for all scenes.

    - Creates narration text from content
    - Optionally enhances with AI
    - Ensures appropriate pacing and length
    - Adds engagement and clarity
    """

    def __init__(self, event_emitter=None):
        super().__init__("script_generation", event_emitter)
        self.narration_generator = NarrationGenerator()
        # Initialize AI enhancer if ANTHROPIC_API_KEY is available
        import os
        has_anthropic_key = os.getenv("ANTHROPIC_API_KEY") or (hasattr(config, "anthropic_api_key") and config.anthropic_api_key)
        has_openai_key = hasattr(config, "openai_api_key") and config.openai_api_key
        self.ai_enhancer = AIScriptEnhancer() if (has_anthropic_key or has_openai_key) else None

    async def execute(self, context: Dict[str, Any]) -> StageResult:
        """Execute script generation."""

        # Validate context
        self.validate_context(context, ["video_config"])
        video_config: VideoConfig = context["video_config"]

        # Check if AI narration is enabled (from input_config object in context)
        input_config = context.get("input_config")
        use_ai = (input_config.use_ai_narration if input_config and hasattr(input_config, 'use_ai_narration') else False) or getattr(config, "enhance_scripts", False)

        if use_ai:
            self.logger.info(f"✨ Generating AI-enhanced scripts for {len(video_config.scenes)} scenes")
        else:
            self.logger.info(f"Generating template scripts for {len(video_config.scenes)} scenes")

        # Generate scripts for each scene
        for i, scene in enumerate(video_config.scenes):
            progress = i / len(video_config.scenes)
            await self.emit_progress(
                context["task_id"],
                progress,
                f"Generating script for scene {i+1}/{len(video_config.scenes)}"
            )

            try:
                # Generate base narration (pass the scene object, not scene.content)
                narration = await self.narration_generator.generate(
                    scene,  # Pass the scene object
                    scene_type=scene.scene_type,
                    language="en"  # Default to English
                )

                # Optionally enhance with AI (use_ai defined at stage start)
                if use_ai and self.ai_enhancer:
                    self.logger.debug(f"✨ Enhancing narration with AI for scene {scene.scene_id}")

                    # Build enhanced context with scene position (NEW - Plan B)
                    enhanced_context = {
                        'scene_position': i,
                        'total_scenes': len(video_config.scenes),
                        # Include visual content for AI context
                        'visual_content': scene.visual_content if hasattr(scene, 'visual_content') else {}
                    }

                    narration = await self.ai_enhancer.enhance(
                        narration,
                        scene_type=scene.scene_type,
                        context=enhanced_context
                    )
                elif use_ai and not self.ai_enhancer:
                    self.logger.warning(f"⚠️ AI narration requested but API key not found - using template narration")

                # Update scene with narration
                scene.narration = narration

                self.logger.debug(
                    f"Generated script for {scene.scene_id}: "
                    f"{len(narration)} chars"
                )

            except Exception as e:
                raise StageError(
                    f"Script generation failed for scene {scene.scene_id}: {e}",
                    stage=self.name,
                    details={"scene_id": scene.scene_id, "error": str(e)}
                )

        self.logger.info(f"Script generation complete: {len(video_config.scenes)} scripts created")

        # Get AI usage metrics if AI was used (NEW - Plan B)
        ai_metrics = None
        if use_ai and self.ai_enhancer and hasattr(self.ai_enhancer, 'metrics'):
            try:
                summary = self.ai_enhancer.metrics.get_summary()
                # Handle both real summary dicts and mock objects
                if isinstance(summary, dict):
                    ai_metrics = summary
                    self.logger.info(f"💰 AI Usage: {ai_metrics['api_calls']} calls, "
                                   f"${ai_metrics['estimated_cost_usd']:.4f} estimated cost, "
                                   f"{ai_metrics['success_rate']:.1f}% success rate")
            except (AttributeError, TypeError):
                # Metrics not available (e.g., in tests with mocks)
                pass

        return StageResult(
            success=True,
            stage_name=self.name,
            artifacts={
                "video_config": video_config,
            },
            metadata={
                "scripts_generated": len(video_config.scenes),
                "ai_enhanced": self.ai_enhancer is not None and use_ai,
                "ai_usage_metrics": ai_metrics if ai_metrics else None,
            }
        )
