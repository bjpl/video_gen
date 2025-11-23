"""
Video Generation Stage - Generates videos from audio timing using template-based rendering.
"""

from pathlib import Path
from typing import Dict, Any
import json

from ..pipeline.stage import Stage, StageResult
from ..shared.models import VideoConfig
from ..video_generator.unified import UnifiedVideoGenerator
from ..shared.config import config
from ..shared.exceptions import VideoGenerationError


class VideoGenerationStage(Stage):
    """
    Generates videos from audio timing using the UnifiedVideoGenerator.

    - Uses PIL-based template rendering for professional visuals
    - Supports all 12 scene types (title, command, list, outro, etc.)
    - Syncs with audio timing from timing report
    - Applies smooth animations and transitions
    - Renders complete video with proper keyframe-based rendering
    """

    def __init__(self, event_emitter=None):
        super().__init__("video_generation", event_emitter)

        # Initialize UnifiedVideoGenerator with proper configuration
        self.generator = UnifiedVideoGenerator(
            mode="fast",  # Use NumPy-accelerated rendering
            output_dir=config.video_dir,
            ffmpeg_path=config.ffmpeg_path if hasattr(config, 'ffmpeg_path') else None
        )

    async def execute(self, context: Dict[str, Any]) -> StageResult:
        """Execute video generation using UnifiedVideoGenerator."""

        # Validate context
        self.validate_context(context, ["video_config", "timing_report", "audio_dir"])

        video_config: VideoConfig = context["video_config"]
        timing_report_path: Path = context["timing_report"]
        audio_dir: Path = context["audio_dir"]

        self.logger.info(f"Generating video with {len(video_config.scenes)} scenes using template-based rendering")

        # Load timing report
        with open(timing_report_path, 'r') as f:
            timing_report = json.load(f)

        # Emit progress
        await self.emit_progress(
            context["task_id"],
            0.1,
            "Starting template-based video rendering"
        )

        try:
            # Use UnifiedVideoGenerator to create the complete video with proper templates
            # This will:
            # 1. Render all scenes using PIL-based templates (title, command, list, etc.)
            # 2. Add smooth animations with cubic easing
            # 3. Add transitions between scenes
            # 4. Encode with GPU acceleration
            # 5. Mux with audio

            final_video_path = self.generator._generate_single_video(timing_report_path)

            if not final_video_path or not final_video_path.exists():
                raise VideoGenerationError(
                    "UnifiedVideoGenerator failed to create video",
                    stage=self.name
                )

            self.logger.info(f"Video generation complete: {final_video_path}")

            # Emit completion progress
            await self.emit_progress(
                context["task_id"],
                1.0,
                "Video rendering complete"
            )

            # Create video directory for organization
            video_dir = config.video_dir / video_config.video_id
            video_dir.mkdir(parents=True, exist_ok=True)

            # Move the generated video to the proper location
            organized_video_path = video_dir / f"{video_config.video_id}_final.mp4"
            if final_video_path != organized_video_path:
                import shutil
                shutil.move(str(final_video_path), str(organized_video_path))
                final_video_path = organized_video_path

            return StageResult(
                success=True,
                stage_name=self.name,
                artifacts={
                    "final_video_path": final_video_path,
                    "video_dir": video_dir,
                    "video_config": video_config,
                },
                metadata={
                    "scenes_rendered": len(video_config.scenes),
                    "total_duration": video_config.total_duration,
                    "rendering_mode": "template-based",
                    "file_size": final_video_path.stat().st_size,
                }
            )

        except Exception as e:
            raise VideoGenerationError(
                f"Video generation failed: {e}",
                stage=self.name,
                details={"error": str(e), "timing_report": str(timing_report_path)}
            )

    async def _render_simple_scene(
        self,
        scene,
        scene_timing: dict,
        output_path: Path,
        audio_file: Path
    ):
        """
        Render a simple scene with audio and text overlay.

        This is a placeholder implementation until full Manim/MoviePy integration.
        """
        # MoviePy 2.x imports
        try:
            from moviepy import ColorClip, TextClip, CompositeVideoClip, AudioFileClip
        except ImportError:
            # Fallback for older versions
            from moviepy.editor import ColorClip, TextClip, CompositeVideoClip, AudioFileClip

        duration = scene_timing["duration"]

        # Create background
        background = ColorClip(
            size=(1920, 1080),
            color=scene.visual_content.get("bg_color", [30, 30, 30]),
            duration=duration
        )

        # Create text overlay
        # Get title from visual_content or use narration as fallback
        display_text = scene.visual_content.get("title", scene.narration)

        # MoviePy 2.x TextClip API
        text = TextClip(
            text=display_text,
            font_size=60,
            color='white',
            font=config.fonts.get("title", "Arial"),
            size=(1600, None),
            method='caption'
        ).with_position('center').with_duration(duration)

        # Combine
        video = CompositeVideoClip([background, text])

        # Add audio
        if audio_file and audio_file.exists():
            audio = AudioFileClip(str(audio_file))
            video = video.with_audio(audio)

        # Write video file with proper encoding settings
        video.write_videofile(
            str(output_path),
            fps=30,
            codec='libx264',
            audio_codec='aac',
            preset='medium',
            bitrate='8000k',
            write_logfile=False,
            logger=None,  # Suppress MoviePy output
            # Ensure proper frame finalization
            ffmpeg_params=[
                '-pix_fmt', 'yuv420p',
                '-movflags', '+faststart',
                '-max_muxing_queue_size', '1024'
            ]
        )

        # Clean up resources
        if audio_file and audio_file.exists():
            audio.close()
        video.close()

        # Verify the output file was created successfully
        if not output_path.exists() or output_path.stat().st_size == 0:
            raise VideoGenerationError(
                f"Video file creation failed or resulted in empty file: {output_path}",
                stage=self.name
            )
