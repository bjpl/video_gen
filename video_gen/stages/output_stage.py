"""
Output Stage - Combines scenes and exports final video.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
import json
import shutil
import asyncio
from datetime import datetime
import os

from ..pipeline.stage import Stage, StageResult
from ..shared.models import VideoConfig
from ..shared.config import config
from ..shared.exceptions import StageError
from ..shared.storage import create_storage

# Set matplotlib backend BEFORE importing pyplot to avoid GUI issues on headless servers
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend - MUST be before pyplot import


class OutputStage(Stage):
    """
    Combines scene videos and exports final output.

    - Concatenates all scene videos
    - Adds transitions (if configured)
    - Generates metadata files
    - Creates thumbnails
    - Organizes final outputs
    """

    def __init__(self, event_emitter=None, storage_backend=None):
        super().__init__("output_handling", event_emitter)
        # Initialize storage backend (defaults to env var or 'local')
        self.storage = storage_backend or create_storage()

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

        # Emit progress immediately to show stage started
        self.logger.info(f"[output_handling] Starting output handling for task {context.get('task_id')}")
        await self.emit_progress(context["task_id"], 0.05, "Starting output handling")

        # Validate context
        self.validate_context(context, ["video_config", "final_video_path", "video_dir"])

        video_config: VideoConfig = context["video_config"]
        final_video_path: Path = context["final_video_path"]
        video_dir: Path = context["video_dir"]

        self.logger.info(f"Organizing final video output: {final_video_path}")

        # Emit progress after validation
        await self.emit_progress(context["task_id"], 0.1, "Preparing output")

        # Use the existing video_dir as the output directory to avoid redundant file copying
        # The video is already organized in video_dir by video_generation_stage
        output_dir = video_dir  # Use existing video_dir instead of creating a separate output_dir

        # The video is already at the final path - no need to copy
        output_video_path = final_video_path

        self.logger.info(f"Using video from: {output_video_path}")

        # Emit progress
        await self.emit_progress(context["task_id"], 0.2, "Generating metadata")

        # Generate metadata
        metadata_path = output_dir / f"{video_config.video_id}_metadata.json"
        await self._generate_metadata(video_config, metadata_path, context)

        # Emit progress
        await self.emit_progress(context["task_id"], 0.5, "Creating thumbnail")

        # Generate thumbnail with timeout
        thumbnail_path = output_dir / f"{video_config.video_id}_thumbnail.jpg"
        # Thumbnail generation - catch ALL exceptions (optional operation)
        thumbnail_created = False
        try:
            await asyncio.wait_for(
                self._generate_thumbnail(output_video_path, thumbnail_path),
                timeout=30.0  # 30 second timeout for thumbnail
            )
            # Verify thumbnail was actually created
            if thumbnail_path.exists() and thumbnail_path.stat().st_size > 0:
                thumbnail_created = True
        except asyncio.TimeoutError:
            self.logger.warning("Thumbnail generation timed out, skipping")
        except Exception as e:
            self.logger.warning(f"Thumbnail generation failed: {e}")

        # Emit progress
        await self.emit_progress(context["task_id"], 0.7, "Finalizing output")

        # Copy timing report if available (validate source exists first)
        if "timing_report" in context:
            timing_source = Path(context["timing_report"]) if isinstance(context["timing_report"], str) else context["timing_report"]
            if timing_source.exists():
                try:
                    await asyncio.wait_for(
                        asyncio.to_thread(
                            shutil.copy,
                            str(timing_source),
                            output_dir / f"{video_config.video_id}_timing.json"
                        ),
                        timeout=30.0
                    )
                except asyncio.TimeoutError:
                    self.logger.warning("Timing report copy timed out, skipping")
                except Exception as e:
                    self.logger.warning(f"Timing report copy failed: {e}")
            else:
                self.logger.debug(f"Timing report not found: {timing_source}")

        # CRITICAL: Validate video BEFORE claiming completion
        await self.emit_progress(context["task_id"], 0.85, "Validating output")

        # Get video size with NFS retry logic for Railway
        video_size = 0
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if not output_video_path.exists():
                    if attempt < max_retries - 1:
                        self.logger.warning(f"Video file not found (attempt {attempt+1}), waiting for NFS sync...")
                        await asyncio.sleep(1.0)
                        continue
                    else:
                        raise StageError(
                            "Video file does not exist after generation",
                            stage=self.name,
                            details={"expected_path": str(output_video_path)}
                        )

                video_size = output_video_path.stat().st_size

                if video_size == 0:
                    if attempt < max_retries - 1:
                        self.logger.warning(f"Video file empty (attempt {attempt+1}), waiting for NFS sync...")
                        await asyncio.sleep(1.0)
                        continue
                    else:
                        raise StageError(
                            "Generated video file is empty",
                            stage=self.name,
                            details={"video_path": str(output_video_path)}
                        )
                # Successfully got valid video size
                break

            except StageError:
                raise  # Re-raise our own errors
            except (OSError, IOError) as e:
                if attempt < max_retries - 1:
                    self.logger.warning(f"File stat failed (attempt {attempt+1}): {e}, retrying...")
                    await asyncio.sleep(1.0)
                else:
                    raise StageError(
                        f"Cannot access video file: {e}",
                        stage=self.name,
                        details={"video_path": str(output_video_path), "error": str(e)}
                    )

        self.logger.info(f"Output complete: {output_video_path} ({video_size} bytes)")

        # Upload to cloud storage if not using local backend
        await self.emit_progress(context["task_id"], 0.9, "Uploading to storage")

        storage_urls = await self._upload_to_storage(
            video_path=output_video_path,
            metadata_path=metadata_path,
            thumbnail_path=thumbnail_path if thumbnail_created else None,
            video_id=video_config.video_id
        )

        # Only emit 100% after successful validation and upload
        await self.emit_progress(context["task_id"], 1.0, "Output complete")

        # Build artifacts - only include thumbnail if it was created
        artifacts = {
            "final_video_path": output_video_path,
            "output_dir": output_dir,
            "metadata_path": metadata_path,
            "storage_urls": storage_urls,  # Add storage URLs
        }
        if thumbnail_created:
            artifacts["thumbnail_path"] = thumbnail_path

        return StageResult(
            success=True,
            stage_name=self.name,
            artifacts=artifacts,
            metadata={
                "video_size": video_size,
                "scene_count": len(video_config.scenes),
                "duration": video_config.total_duration,
                "workflow": "template-based",
                "has_thumbnail": thumbnail_created,
                "storage_backend": os.getenv("STORAGE_BACKEND", "local"),
                "video_url": storage_urls.get("video_url"),
            }
        )

    async def _handle_scene_videos(self, context: Dict[str, Any]) -> StageResult:
        """Handle output when scene videos need to be combined (legacy workflow)."""

        # Emit progress immediately to show stage started
        await self.emit_progress(context["task_id"], 0.05, "Starting output handling")

        # Validate context
        self.validate_context(context, ["video_config", "scene_videos", "video_dir"])

        video_config: VideoConfig = context["video_config"]
        scene_videos: List[Path] = context["scene_videos"]
        video_dir: Path = context["video_dir"]

        self.logger.info(f"Combining {len(scene_videos)} scene videos")

        # Emit progress after validation
        await self.emit_progress(context["task_id"], 0.1, "Creating output directory")

        # Create final output directory
        output_dir = config.output_dir / video_config.video_id
        output_dir.mkdir(parents=True, exist_ok=True)

        # Emit progress
        await self.emit_progress(context["task_id"], 0.2, "Combining scene videos")

        # Combine videos (run in thread pool to avoid blocking)
        final_video_path = output_dir / f"{video_config.video_id}_final.mp4"
        await asyncio.to_thread(self._combine_videos_sync, scene_videos, final_video_path)

        # Emit progress
        await self.emit_progress(context["task_id"], 0.6, "Generating metadata")

        # Generate metadata
        metadata_path = output_dir / f"{video_config.video_id}_metadata.json"
        await self._generate_metadata(video_config, metadata_path, context)

        # Emit progress
        await self.emit_progress(context["task_id"], 0.8, "Creating thumbnail")

        # Generate thumbnail with timeout
        thumbnail_path = output_dir / f"{video_config.video_id}_thumbnail.jpg"
        try:
            await asyncio.wait_for(
                self._generate_thumbnail(final_video_path, thumbnail_path),
                timeout=30.0  # 30 second timeout for thumbnail
            )
        except asyncio.TimeoutError:
            self.logger.warning("Thumbnail generation timed out, skipping")

        # Copy additional files (non-blocking) with timeout
        if "timing_report" in context:
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(
                        shutil.copy,
                        context["timing_report"],
                        output_dir / f"{video_config.video_id}_timing.json"
                    ),
                    timeout=30.0
                )
            except asyncio.TimeoutError:
                self.logger.warning("Timing report copy timed out, skipping")

        self.logger.info(f"Output complete: {final_video_path}")

        # Upload to cloud storage if not using local backend
        await self.emit_progress(context["task_id"], 0.9, "Uploading to storage")

        storage_urls = await self._upload_to_storage(
            video_path=final_video_path,
            metadata_path=metadata_path,
            thumbnail_path=thumbnail_path,
            video_id=video_config.video_id
        )

        # Emit progress
        await self.emit_progress(context["task_id"], 1.0, "Output complete")

        # Get video size safely
        try:
            video_size = final_video_path.stat().st_size
        except Exception as e:
            self.logger.warning(f"Could not get video size: {e}")
            video_size = 0

        return StageResult(
            success=True,
            stage_name=self.name,
            artifacts={
                "final_video_path": final_video_path,
                "output_dir": output_dir,
                "metadata_path": metadata_path,
                "thumbnail_path": thumbnail_path,
                "storage_urls": storage_urls,  # Add storage URLs
            },
            metadata={
                "video_size": video_size,
                "scene_count": len(scene_videos),
                "duration": video_config.total_duration,
                "workflow": "legacy-combined",
                "storage_backend": os.getenv("STORAGE_BACKEND", "local"),
                "video_url": storage_urls.get("video_url"),
            }
        )

    def _combine_videos_sync(self, scene_videos: List[Path], output_path: Path):
        """Combine scene videos into final video (synchronous version for thread pool)."""
        from moviepy import VideoFileClip, concatenate_videoclips
        import warnings

        clips = []
        final_clip = None

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
            for video in scene_videos:
                try:
                    clip = VideoFileClip(str(video), audio=True, fps_source='fps')
                    clips.append(clip)
                except Exception as e:
                    self.logger.error(f"Failed to load video {video}: {e}")
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

        except Exception as e:
            raise StageError(
                f"Failed to combine videos: {e}",
                stage=self.name,
                details={"error": str(e), "scene_count": len(scene_videos)}
            )

        finally:
            # Always clean up resources
            if final_clip is not None:
                try:
                    final_clip.close()
                except Exception:
                    pass
            for clip in clips:
                try:
                    clip.close()
                except Exception:
                    pass
            # Restore warnings
            warnings.filterwarnings('default')

    async def _combine_videos(self, scene_videos: List[Path], output_path: Path):
        """Combine scene videos into final video (async wrapper)."""
        await asyncio.to_thread(self._combine_videos_sync, scene_videos, output_path)

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

        # Write metadata (use to_thread for non-blocking)
        def write_json():
            with open(output_path, 'w') as f:
                json.dump(metadata, f, indent=2)

        await asyncio.to_thread(write_json)

    async def _generate_thumbnail(self, video_path: Path, output_path: Path):
        """Generate video thumbnail."""
        # Run thumbnail generation in thread pool to avoid blocking
        await asyncio.to_thread(self._generate_thumbnail_sync, video_path, output_path)

    def _generate_thumbnail_sync(self, video_path: Path, output_path: Path):
        """Generate video thumbnail (synchronous version for thread pool)."""
        from moviepy import VideoFileClip
        import matplotlib.pyplot as plt

        # Validate input first
        if not video_path.exists():
            self.logger.warning(f"Video file not found for thumbnail: {video_path}")
            return

        if video_path.stat().st_size == 0:
            self.logger.warning(f"Video file empty for thumbnail: {video_path}")
            return

        clip = None
        try:
            # Load video without audio for faster loading
            clip = VideoFileClip(str(video_path), audio=False)

            # Validate duration
            if not clip.duration or clip.duration <= 0:
                self.logger.warning(f"Invalid video duration: {clip.duration}")
                return

            # Extract frame from middle of video (ensure valid time)
            frame_time = min(clip.duration / 2, clip.duration - 0.1)
            frame = clip.get_frame(frame_time)

            if frame is None:
                self.logger.warning("Failed to extract frame from video")
                return

            # Ensure output directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Save as image (matplotlib already configured with Agg backend at module level)
            plt.imsave(str(output_path), frame, format='jpg')
            plt.close('all')  # Clean up any matplotlib resources

        except ImportError as e:
            self.logger.warning(f"Missing dependency for thumbnail generation: {e}")
        except (OSError, IOError) as e:
            self.logger.warning(f"File system error generating thumbnail: {e}")
        except Exception as e:
            self.logger.warning(f"Failed to generate thumbnail: {e}")
            # Thumbnail generation is optional, don't fail the stage

        finally:
            # Always clean up clip resources
            if clip is not None:
                try:
                    clip.close()
                except Exception as e:
                    self.logger.debug(f"Clip cleanup error (non-fatal): {e}")

            # Always clean up matplotlib
            try:
                plt.close('all')
            except Exception as e:
                self.logger.debug(f"Matplotlib cleanup error (non-fatal): {e}")

    async def _upload_to_storage(
        self,
        video_path: Path,
        metadata_path: Path,
        thumbnail_path: Optional[Path],
        video_id: str
    ) -> Dict[str, str]:
        """
        Upload generated files to configured storage backend.

        Args:
            video_path: Path to final video file
            metadata_path: Path to metadata JSON
            thumbnail_path: Path to thumbnail image (optional)
            video_id: Video ID for remote key generation

        Returns:
            Dictionary with storage URLs:
            - video_url: Public URL to video
            - metadata_url: Public URL to metadata
            - thumbnail_url: Public URL to thumbnail (if provided)
        """
        urls = {}

        try:
            # Upload video
            video_key = f"{video_id}/{video_id}_final.mp4"
            urls["video_url"] = await self.storage.upload_file(
                local_path=video_path,
                remote_key=video_key,
                content_type="video/mp4",
                metadata={
                    "video_id": video_id,
                    "generated_at": datetime.now().isoformat(),
                }
            )

            # Upload metadata
            metadata_key = f"{video_id}/{video_id}_metadata.json"
            urls["metadata_url"] = await self.storage.upload_file(
                local_path=metadata_path,
                remote_key=metadata_key,
                content_type="application/json"
            )

            # Upload thumbnail if available
            if thumbnail_path and thumbnail_path.exists():
                thumbnail_key = f"{video_id}/{video_id}_thumbnail.jpg"
                urls["thumbnail_url"] = await self.storage.upload_file(
                    local_path=thumbnail_path,
                    remote_key=thumbnail_key,
                    content_type="image/jpeg"
                )

            self.logger.info(f"Uploaded files to storage: {urls}")
            return urls

        except Exception as e:
            # Log error but don't fail the stage - files are still local
            self.logger.warning(f"Failed to upload to storage: {e}")
            return {
                "video_url": str(video_path),
                "metadata_url": str(metadata_path),
                "thumbnail_url": str(thumbnail_path) if thumbnail_path else None,
                "upload_error": str(e)
            }
