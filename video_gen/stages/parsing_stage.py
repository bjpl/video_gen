"""
Content Parsing Stage - Parses and structures content from various sources.
"""

from typing import Dict, Any

from ..pipeline.stage import Stage, StageResult
from ..shared.models import VideoConfig
from ..content_parser import ContentParser


class ParsingStage(Stage):
    """
    Parses and structures content for video generation.

    - Extracts key concepts
    - Identifies learning objectives
    - Structures content hierarchically
    - Prepares for script generation
    """

    def __init__(self, event_emitter=None):
        super().__init__("content_parsing", event_emitter)
        self.parser = ContentParser()

    async def execute(self, context: Dict[str, Any]) -> StageResult:
        """Execute content parsing."""

        # Validate context
        self.validate_context(context, ["video_config"])
        video_config: VideoConfig = context["video_config"]

        self.logger.info(f"Parsing content for {len(video_config.scenes)} scenes")

        # Parse each scene's content
        parsed_scenes = []
        for i, scene in enumerate(video_config.scenes):
            progress = i / len(video_config.scenes)
            await self.emit_progress(
                context["task_id"],
                progress,
                f"Parsing scene {i+1}/{len(video_config.scenes)}"
            )

            try:
                # Parse scene content (use narration as the content to parse)
                parsed_content = await self.parser.parse(
                    scene.narration,
                    scene_type=scene.scene_type
                )

                # Store parsed content as dict (not ParseResult object) to enable JSON serialization
                if parsed_content and hasattr(parsed_content, '__dict__'):
                    scene.visual_content["parsed_content"] = {
                        "success": getattr(parsed_content, 'success', False),
                        "metadata": getattr(parsed_content, 'metadata', {})
                    }
                parsed_scenes.append(scene)

                self.logger.debug(f"Parsed scene {scene.scene_id}: {scene.scene_type}")

            except Exception as e:
                self.logger.warning(f"Failed to parse scene {scene.scene_id}: {e}")
                # Keep original scene if parsing fails
                parsed_scenes.append(scene)

        # Update video config with parsed scenes
        video_config.scenes = parsed_scenes

        self.logger.info(f"Content parsing complete: {len(parsed_scenes)} scenes processed")

        return StageResult(
            success=True,
            stage_name=self.name,
            artifacts={
                "video_config": video_config,
            },
            metadata={
                "scenes_parsed": len(parsed_scenes),
                "total_scenes": len(video_config.scenes),
            }
        )
