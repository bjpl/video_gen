"""
Pipeline execution service.

Provides background task execution for the unified pipeline.
"""
from typing import Any
import logging
from video_gen.shared.models import InputConfig

logger = logging.getLogger(__name__)


async def execute_pipeline_task(pipeline: Any, input_config: InputConfig, task_id: str = None):
    """
    Execute pipeline in background.

    This is the unified execution path for all video generation tasks.
    The pipeline handles all stages automatically with state persistence.

    Args:
        pipeline: PipelineOrchestrator instance
        input_config: Input configuration for the pipeline
        task_id: Optional task ID to use (if not provided, pipeline generates one)
    """
    try:
        # Execute the complete pipeline
        # IMPORTANT: Pass task_id to ensure consistent tracking
        result = await pipeline.execute(input_config, task_id=task_id)

        logger.info(f"Pipeline completed successfully: {result.task_id}")

    except Exception as e:
        logger.error(f"Pipeline execution failed for task {task_id}: {e}", exc_info=True)
        # Pipeline automatically persists failure state
        # No need for manual error handling
