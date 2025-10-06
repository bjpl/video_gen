"""
Validation Stage - Validates input configuration and video structure.
"""

from typing import Dict, Any
from ..pipeline.stage import Stage, StageResult
from ..shared.models import VideoConfig, SceneConfig
from ..shared.exceptions import ValidationError


class ValidationStage(Stage):
    """
    Validates video configuration before generation.

    Checks:
    - Scene structure and content
    - Narration length and quality
    - Duration constraints
    - Required fields
    """

    def __init__(self, event_emitter=None):
        super().__init__("validation", event_emitter)

    async def execute(self, context: Dict[str, Any]) -> StageResult:
        """Execute validation."""

        # Get video config from context
        self.validate_context(context, ["video_config"])
        video_config: VideoConfig = context["video_config"]

        warnings = []
        errors = []

        # Validate video metadata
        if not video_config.video_id:
            errors.append("Video ID is required")

        if not video_config.title:
            errors.append("Video title is required")

        if not video_config.scenes:
            errors.append("Video must have at least one scene")

        # Validate scenes
        total_estimated_duration = 0.0
        for i, scene in enumerate(video_config.scenes):
            scene_warnings = self._validate_scene(scene, i)
            warnings.extend(scene_warnings)

            # Estimate duration
            if scene.narration:
                word_count = len(scene.narration.split())
                estimated_duration = word_count / 2.25  # ~135 WPM
                total_estimated_duration += estimated_duration

        # Check total duration
        if total_estimated_duration > 600:  # 10 minutes
            warnings.append(
                f"Video is very long ({total_estimated_duration/60:.1f} minutes). "
                "Consider splitting into multiple videos."
            )

        # Emit progress
        await self.emit_progress(
            context["task_id"],
            0.5,
            f"Validated {len(video_config.scenes)} scenes"
        )

        # If we have errors, fail
        if errors:
            raise ValidationError(
                f"Validation failed with {len(errors)} errors",
                stage=self.name,
                details={"errors": errors, "warnings": warnings}
            )

        # Return success with warnings
        return StageResult(
            success=True,
            stage_name=self.name,
            artifacts={},
            metadata={
                "scene_count": len(video_config.scenes),
                "estimated_duration": total_estimated_duration,
            },
            warnings=warnings
        )

    def _validate_scene(self, scene: SceneConfig, index: int) -> list:
        """Validate a single scene and return warnings."""
        warnings = []

        # Check required fields
        if not scene.scene_id:
            warnings.append(f"Scene {index}: Missing scene_id")

        if not scene.narration:
            warnings.append(f"Scene {index} ({scene.scene_id}): Missing narration")

        # Check narration length
        if scene.narration:
            word_count = len(scene.narration.split())
            estimated_duration = word_count / 2.25

            if estimated_duration > scene.max_duration:
                warnings.append(
                    f"Scene {scene.scene_id}: Narration may be too long "
                    f"({word_count} words ≈ {estimated_duration:.1f}s, max {scene.max_duration}s)"
                )

            if estimated_duration < scene.min_duration:
                warnings.append(
                    f"Scene {scene.scene_id}: Narration may be too short "
                    f"({word_count} words ≈ {estimated_duration:.1f}s, min {scene.min_duration}s)"
                )

        # Check scene-type specific requirements
        if scene.scene_type == 'command' and 'commands' not in scene.visual_content:
            warnings.append(
                f"Scene {scene.scene_id}: Command scene missing 'commands' in visual_content"
            )

        if scene.scene_type == 'list' and 'items' not in scene.visual_content:
            warnings.append(
                f"Scene {scene.scene_id}: List scene missing 'items' in visual_content"
            )

        return warnings
