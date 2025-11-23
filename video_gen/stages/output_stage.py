"""
Output Stage - Combines scenes and exports final video.
"""

from pathlib import Path
from typing import Dict, Any, List
import json
import shutil
from datetime import datetime

from ..pipeline.stage import Stage, StageResult
from ..shared.models import VideoConfig
from ..shared.config import config
from ..shared.exceptions import StageError


class OutputStage(Stage):
    """
    Combines scene videos and exports final output.

    - Concatenates all scene videos
    - Adds transitions (if configured)
    - Generates metadata files
    - Creates thumbnails
    - Organizes final outputs
    """

    def __init__(self, event_emitter=None):
        super().__init__("output_handling", event_emitter)

    async def execute(self, context: Dict[str, Any]) -> StageResult:
        """Execute output handling."""

        # Check if we have a complete final video (new workflow) or scene videos (legacy)
        has_final_video = "final_video_path" in context
        has_scene_videos = "scene_videos" in context

        if has_final_video:
            # New workflow: Video is already complete from UnifiedVideoGenerator
            return await self._handle_complete_video(context)
        elif has_scene_videos:
            # Legacy workflow: Need to combine scene videos
            return await self._handle_scene_videos(context)
        else:
            raise StageError(
                "No video artifacts found in context",
                stage=self.name,
                details={"context_keys": list(context.keys())}
            )

    async def _handle_complete_video(self, context: Dict[str, Any]) -> StageResult:
        """Handle output when video is already complete (new workflow)."""

        # Validate context
        self.validate_context(context, ["video_config", "final_video_path", "video_dir"])

        video_config: VideoConfig = context["video_config"]
        final_video_path: Path = context["final_video_path"]
        video_dir: Path = context["video_dir"]

        self.logger.info(f"Organizing final video output: {final_video_path}")

        # Create final output directory
        output_dir = config.output_dir / video_config.video_id
        output_dir.mkdir(parents=True, exist_ok=True)

        # Emit progress
        await self.emit_progress(context["task_id"], 0.3, "Organizing output files")

        # Copy final video to output directory if needed
        output_video_path = output_dir / f"{video_config.video_id}_final.mp4"
        if final_video_path != output_video_path:
            shutil.copy(final_video_path, output_video_path)

        # Emit progress
        await self.emit_progress(context["task_id"], 0.5, "Generating metadata")

        # Generate metadata
        metadata_path = output_dir / f"{video_config.video_id}_metadata.json"
        await self._generate_metadata(video_config, metadata_path, context)

        # Emit progress
        await self.emit_progress(context["task_id"], 0.7, "Creating thumbnail")

        # Generate thumbnail
        thumbnail_path = output_dir / f"{video_config.video_id}_thumbnail.jpg"
        await self._generate_thumbnail(output_video_path, thumbnail_path)

        # Copy additional files
        if "timing_report" in context:
            shutil.copy(
                context["timing_report"],
                output_dir / f"{video_config.video_id}_timing.json"
            )

        self.logger.info(f"Output complete: {output_video_path}")

        # Emit progress
        await self.emit_progress(context["task_id"], 1.0, "Output complete")

        return StageResult(
            success=True,
            stage_name=self.name,
            artifacts={
                "final_video_path": output_video_path,
                "output_dir": output_dir,
                "metadata_path": metadata_path,
                "thumbnail_path": thumbnail_path,
            },
            metadata={
                "video_size": output_video_path.stat().st_size,
                "scene_count": len(video_config.scenes),
                "duration": video_config.total_duration,
                "workflow": "template-based",
            }
        )

    async def _handle_scene_videos(self, context: Dict[str, Any]) -> StageResult:
        """Handle output when scene videos need to be combined (legacy workflow)."""

        # Validate context
        self.validate_context(context, ["video_config", "scene_videos", "video_dir"])

        video_config: VideoConfig = context["video_config"]
        scene_videos: List[Path] = context["scene_videos"]
        video_dir: Path = context["video_dir"]

        self.logger.info(f"Combining {len(scene_videos)} scene videos")

        # Create final output directory
        output_dir = config.output_dir / video_config.video_id
        output_dir.mkdir(parents=True, exist_ok=True)

        # Emit progress
        await self.emit_progress(context["task_id"], 0.2, "Combining scene videos")

        # Combine videos
        final_video_path = output_dir / f"{video_config.video_id}_final.mp4"
        await self._combine_videos(scene_videos, final_video_path)

        # Emit progress
        await self.emit_progress(context["task_id"], 0.6, "Generating metadata")

        # Generate metadata
        metadata_path = output_dir / f"{video_config.video_id}_metadata.json"
        await self._generate_metadata(video_config, metadata_path, context)

        # Emit progress
        await self.emit_progress(context["task_id"], 0.8, "Creating thumbnail")

        # Generate thumbnail
        thumbnail_path = output_dir / f"{video_config.video_id}_thumbnail.jpg"
        await self._generate_thumbnail(final_video_path, thumbnail_path)

        # Copy additional files
        if "timing_report" in context:
            shutil.copy(
                context["timing_report"],
                output_dir / f"{video_config.video_id}_timing.json"
            )

        self.logger.info(f"Output complete: {final_video_path}")

        # Emit progress
        await self.emit_progress(context["task_id"], 1.0, "Output complete")

        return StageResult(
            success=True,
            stage_name=self.name,
            artifacts={
                "final_video_path": final_video_path,
                "output_dir": output_dir,
                "metadata_path": metadata_path,
                "thumbnail_path": thumbnail_path,
            },
            metadata={
                "video_size": final_video_path.stat().st_size,
                "scene_count": len(scene_videos),
                "duration": video_config.total_duration,
                "workflow": "legacy-combined",
            }
        )

    async def _combine_videos(self, scene_videos: List[Path], output_path: Path):
        """Combine scene videos into final video."""
        from moviepy import VideoFileClip, concatenate_videoclips
        import warnings

        try:
            # Filter warnings about corrupted frames (we'll handle them gracefully)
            warnings.filterwarnings('ignore', category=UserWarning, module='moviepy')

            # Validate all input videos exist
            for video in scene_videos:
                if not video.exists():
                    raise StageError(
                        f"Scene video not found: {video}",
                        stage=self.name,
                        details={"missing_file": str(video)}
                    )
                if video.stat().st_size == 0:
                    raise StageError(
                        f"Scene video is empty: {video}",
                        stage=self.name,
                        details={"empty_file": str(video)}
                    )

            # Load all scene clips with error handling
            clips = []
            for video in scene_videos:
                try:
                    clip = VideoFileClip(str(video), audio=True, fps_source='fps')
                    clips.append(clip)
                except Exception as e:
                    self.logger.error(f"Failed to load video {video}: {e}")
                    # Clean up any loaded clips
                    for c in clips:
                        c.close()
                    raise

            # Concatenate with method="compose" to handle varying dimensions
            final_clip = concatenate_videoclips(clips, method="compose")

            # Write final video with robust settings
            final_clip.write_videofile(
                str(output_path),
                fps=30,
                codec='libx264',
                audio_codec='aac',
                preset='medium',
                bitrate='8000k',
                write_logfile=False,
                logger=None,
                ffmpeg_params=[
                    '-pix_fmt', 'yuv420p',
                    '-movflags', '+faststart',
                    '-max_muxing_queue_size', '1024',
                    '-vsync', 'vfr'  # Handle variable frame rate issues
                ]
            )

            # Clean up
            final_clip.close()
            for clip in clips:
                clip.close()

            # Restore warnings
            warnings.filterwarnings('default')

        except Exception as e:
            raise StageError(
                f"Failed to combine videos: {e}",
                stage=self.name,
                details={"error": str(e), "scene_count": len(scene_videos)}
            )

    async def _generate_metadata(
        self,
        video_config: VideoConfig,
        output_path: Path,
        context: Dict[str, Any]
    ):
        """Generate metadata file."""
        # Get language from input_config if available
        language = "en"  # default
        if "input_config" in context and hasattr(context["input_config"], "languages"):
            languages = context["input_config"].languages
            if languages and len(languages) > 0:
                language = languages[0]

        metadata = {
            "video_id": video_config.video_id,
            "title": video_config.title,
            "description": video_config.description,
            "language": language,
            "total_duration": video_config.total_duration,
            "scene_count": len(video_config.scenes),
            "generated_at": datetime.now().isoformat(),
            "pipeline": {
                "task_id": context.get("task_id"),
                "input_type": context.get("input_config").input_type if "input_config" in context else None,
            },
            "scenes": [
                {
                    "scene_id": scene.scene_id,
                    "type": scene.scene_type,
                    "title": scene.visual_content.get("title", scene.scene_id),
                    "duration": scene.final_duration,
                }
                for scene in video_config.scenes
            ]
        }

        with open(output_path, 'w') as f:
            json.dump(metadata, f, indent=2)

    async def _generate_thumbnail(self, video_path: Path, output_path: Path):
        """Generate video thumbnail."""
        from moviepy import VideoFileClip

        try:
            clip = VideoFileClip(str(video_path))
            # Extract frame from middle of video
            frame_time = clip.duration / 2
            frame = clip.get_frame(frame_time)

            # Save as image
            import matplotlib.pyplot as plt
            plt.imsave(str(output_path), frame)

            clip.close()

        except Exception as e:
            self.logger.warning(f"Failed to generate thumbnail: {e}")
            # Thumbnail generation is optional, don't fail the stage
