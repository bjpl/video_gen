"""
Audio Generation Stage - Generates TTS audio for all scenes with voice rotation support.
"""

import edge_tts
from pathlib import Path
from typing import Dict, Any
import subprocess
import asyncio

from ..pipeline.stage import Stage, StageResult
from ..shared.models import VideoConfig
from ..shared.config import config
from ..shared.exceptions import AudioGenerationError
from ..shared.retry import retry, edge_tts_breaker, RetryStrategy


class AudioGenerationStage(Stage):
    """
    Generates audio for all scenes using Edge TTS.

    - Creates audio files for each scene
    - Supports voice rotation across scenes
    - Measures actual audio duration
    - Calculates final video timing
    - Generates timing report
    """

    def __init__(self, event_emitter=None):
        super().__init__("audio_generation", event_emitter)

    async def execute(self, context: Dict[str, Any]) -> StageResult:
        """Execute audio generation with voice rotation and per-language voice support."""

        # Validate context
        self.validate_context(context, ["video_config"])
        video_config: VideoConfig = context["video_config"]
        target_language = context.get("target_language")  # Optional: for multilingual support

        # Create output directory
        output_dir = config.audio_dir / "unified_system"
        audio_folder_name = f"{video_config.video_id}_audio"
        audio_dir = output_dir / audio_folder_name
        audio_dir.mkdir(parents=True, exist_ok=True)

        self.logger.info(f"Generating audio for {len(video_config.scenes)} scenes")

        # Determine voice configuration based on language
        if target_language and video_config.language_voices:
            # Use per-language voice if configured
            language_voice = video_config.language_voices.get(target_language)
            if language_voice:
                available_voices = [language_voice]
                self.logger.info(
                    f"Using language-specific voice for {target_language}: {language_voice}"
                )
            else:
                available_voices = video_config.voices if video_config.voices else ["male"]
                self.logger.info(
                    f"No specific voice for {target_language}, using default rotation: {available_voices}"
                )
        else:
            # Use standard voice rotation
            available_voices = video_config.voices if video_config.voices else ["male"]
            self.logger.info(f"Voice rotation enabled with voices: {available_voices}")

        # Generate audio for each scene with voice rotation
        total_duration = 0.0
        for i, scene in enumerate(video_config.scenes):
            progress = i / len(video_config.scenes)
            await self.emit_progress(
                context["task_id"],
                progress,
                f"Generating audio for scene {i+1}/{len(video_config.scenes)}"
            )

            # Voice rotation: if scene doesn't have explicit voice, rotate through video's voice array
            if not scene.voice or scene.voice == "male":  # Default voice, apply rotation
                rotated_voice = available_voices[i % len(available_voices)]
                scene.voice = rotated_voice
                self.logger.info(f"Scene {scene.scene_id}: Assigned voice '{rotated_voice}' (rotation index {i % len(available_voices)})")

            # Get voice configuration
            voice = config.get_voice(scene.voice)

            # Generate audio file
            audio_file = audio_dir / f"{scene.scene_id}.mp3"

            try:
                # Generate TTS with retry logic and circuit breaker
                await self._generate_tts_with_retry(
                    scene.narration, voice, audio_file
                )

                # Measure duration
                duration = await self._get_audio_duration(audio_file)

                # Update scene
                scene.actual_audio_duration = duration
                scene.audio_file = audio_file
                scene.final_duration = max(scene.min_duration, duration + 1.0)

                total_duration += scene.final_duration

                self.logger.debug(
                    f"Generated audio for {scene.scene_id}: "
                    f"{duration:.2f}s -> {scene.final_duration:.2f}s (voice: {scene.voice})"
                )

            except Exception as e:
                raise AudioGenerationError(
                    f"Failed to generate audio for scene {scene.scene_id}: {e}",
                    stage=self.name,
                    details={"scene_id": scene.scene_id, "error": str(e)}
                )

        # Update video config
        video_config.total_duration = total_duration
        video_config.audio_dir = audio_dir

        # Generate timing report
        timing_report = await self._generate_timing_report(video_config, audio_dir)

        self.logger.info(
            f"Audio generation complete: {len(video_config.scenes)} scenes, "
            f"total duration: {total_duration:.2f}s"
        )

        return StageResult(
            success=True,
            stage_name=self.name,
            artifacts={
                "audio_dir": audio_dir,
                "timing_report": timing_report,
                "video_config": video_config,  # Updated with audio durations
            },
            metadata={
                "total_duration": total_duration,
                "scene_count": len(video_config.scenes),
                "audio_files_generated": len(video_config.scenes),
                "voices_used": list(set(scene.voice for scene in video_config.scenes)),
            }
        )

    @edge_tts_breaker
    @retry(
        max_attempts=3,
        initial_delay=1.0,
        strategy=RetryStrategy.EXPONENTIAL_JITTER,
        retryable_exceptions=(ConnectionError, TimeoutError, OSError)
    )
    async def _generate_tts_with_retry(
        self, text: str, voice: str, output_file: Path
    ) -> None:
        """Generate TTS audio with retry logic and circuit breaker protection."""
        communicate = edge_tts.Communicate(
            text,
            voice,
            rate="+0%",
            volume="+0%"
        )
        await communicate.save(str(output_file))

    async def _get_audio_duration(self, audio_file: Path) -> float:
        """Get audio file duration using ffmpeg."""
        try:
            result = subprocess.run(
                [config.ffmpeg_path, "-i", str(audio_file)],
                capture_output=True,
                text=True
            )

            # Parse duration from ffmpeg output
            for line in result.stderr.split('\n'):
                if 'Duration:' in line:
                    try:
                        time_str = line.split('Duration:')[1].split(',')[0].strip()
                        parts = time_str.split(':')
                        if len(parts) != 3:
                            continue
                        h, m, s = parts
                        duration = int(h) * 3600 + int(m) * 60 + float(s)
                        return duration
                    except (ValueError, IndexError):
                        self.logger.warning(f"Failed to parse duration from line: {line}")

            # Fallback
            self.logger.warning(f"Could not determine duration for {audio_file}, using default")
            return 5.0

        except Exception as e:
            self.logger.error(f"Error getting audio duration: {e}")
            return 5.0

    async def _generate_timing_report(self, video_config: VideoConfig, output_dir: Path) -> Path:
        """Generate timing report JSON for UnifiedVideoGenerator."""
        import json

        # Convert accent color string to RGB tuple
        color_map = {
            "blue": [59, 130, 246],
            "orange": [255, 107, 53],
            "purple": [139, 92, 246],
            "green": [16, 185, 129],
            "pink": [236, 72, 153],
            "cyan": [34, 211, 238]
        }

        accent_color_str = video_config.accent_color if hasattr(video_config, 'accent_color') else "blue"
        accent_color_rgb = color_map.get(accent_color_str.lower(), [59, 130, 246])

        report = {
            "video_id": video_config.video_id,
            "title": video_config.title,
            "total_duration": video_config.total_duration,
            "total_scenes": len(video_config.scenes),
            "voices_config": video_config.voices,  # Include voice rotation config
            "audio_dir": str(output_dir),  # Include audio directory path
            "accent_color": accent_color_rgb,  # Convert to RGB tuple for templates
            "scenes": []
        }

        cumulative_time = 0
        for scene in video_config.scenes:
            scene_data = {
                "scene_id": scene.scene_id,
                "type": scene.scene_type,
                "voice": scene.voice,
                "start_time": cumulative_time,
                "end_time": cumulative_time + scene.final_duration,
                "duration": scene.final_duration,
                "audio_duration": scene.actual_audio_duration,
                "padding": scene.final_duration - scene.actual_audio_duration,
                "narration_preview": scene.narration[:100],
                "visual_content": scene.visual_content  # Include visual content for template rendering
            }
            report["scenes"].append(scene_data)
            cumulative_time += scene.final_duration

        # Save report
        report_file = output_dir / f"{video_config.video_id}_timing_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        self.logger.info(f"Timing report saved: {report_file}")
        return report_file
