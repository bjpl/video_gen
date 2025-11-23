"""
Input Adaptation Stage - Converts various input formats to VideoConfig.
"""

from typing import Dict, Any

from ..pipeline.stage import Stage, StageResult
from ..shared.models import InputConfig
from ..input_adapters import (
    DocumentAdapter,
    YouTubeAdapter,
    YAMLFileAdapter,
    ProgrammaticAdapter,
)
from ..shared.exceptions import StageError


class InputStage(Stage):
    """
    Adapts various input formats to VideoConfig.

    Supported input types:
    - document: Text files, markdown, PDFs
    - youtube: YouTube URLs
    - yaml: YAML configuration files
    - programmatic: Direct VideoConfig objects
    """

    def __init__(self, event_emitter=None, test_mode: bool = False):
        super().__init__("input_adaptation", event_emitter)

        # Register adapters
        self.adapters = {
            "document": DocumentAdapter(test_mode=test_mode),
            "youtube": YouTubeAdapter(),
            "yaml": YAMLFileAdapter(test_mode=test_mode),
            "programmatic": ProgrammaticAdapter(),
        }

    async def execute(self, context: Dict[str, Any]) -> StageResult:
        """Execute input adaptation."""

        # Get input config
        self.validate_context(context, ["input_config"])
        input_config: InputConfig = context["input_config"]

        # Select appropriate adapter
        adapter_type = input_config.input_type.lower()
        if adapter_type not in self.adapters:
            raise StageError(
                f"Unknown input type: {adapter_type}",
                stage=self.name,
                details={
                    "input_type": adapter_type,
                    "supported_types": list(self.adapters.keys())
                }
            )

        adapter = self.adapters[adapter_type]
        self.logger.info(f"Using adapter: {adapter.name}")

        # Emit progress
        await self.emit_progress(context["task_id"], 0.3, "Adapting input source")

        # Adapt input
        try:
            result = await adapter.adapt(
                input_config.source,
                accent_color=input_config.accent_color,
                voice=input_config.voice,
                video_count=getattr(input_config, 'video_count', 1),
                split_by_h2=getattr(input_config, 'split_by_h2', False)
            )

            if not result.success:
                raise StageError(
                    f"Input adaptation failed: {result.error}",
                    stage=self.name,
                    details={"adapter": adapter.name}
                )

            # Get video config (adapters return VideoSet, extract first video)
            video_set = result.video_set
            if video_set and video_set.videos:
                video_config = video_set.videos[0]
            else:
                raise StageError(
                    "No video config generated from adapter",
                    stage=self.name
                )

            self.logger.info(
                f"Input adapted successfully: {video_config.title}, "
                f"{len(video_config.scenes)} scenes"
            )

            await self.emit_progress(context["task_id"], 1.0, "Input adaptation complete")

            return StageResult(
                success=True,
                stage_name=self.name,
                artifacts={
                    "video_config": video_config,
                    "input_metadata": result.metadata,
                },
                metadata={
                    "adapter_used": adapter.name,
                    "scene_count": len(video_config.scenes),
                    "input_type": adapter_type,
                }
            )

        except Exception as e:
            raise StageError(
                f"Input adaptation error: {e}",
                stage=self.name,
                details={"error": str(e), "adapter": adapter.name}
            )
