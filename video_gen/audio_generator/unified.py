"""
Unified Audio Generator
======================
Consolidates generate_all_videos_unified_v2.py and generate_video_set.py
Supports both single videos and video sets
"""

import edge_tts
import subprocess
import json
from pathlib import Path
from typing import List, Optional, Callable, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime

from ..shared.models import VideoConfig, SceneConfig
from ..shared.config import config
from ..shared.exceptions import AudioGenerationError


@dataclass
class AudioGenerationConfig:
    """Configuration for audio generation."""

    output_dir: Path
    voices: Optional[Dict[str, str]] = None
    rate: str = "+0%"
    volume: str = "+0%"
    generate_timing_report: bool = True
    cache_enabled: bool = False

    def __post_init__(self):
        """Initialize with defaults."""
        if self.voices is None:
            self.voices = config.voice_config

        self.output_dir = Path(self.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)


@dataclass
class SceneAudioResult:
    """Result from generating audio for a single scene."""

    scene_id: str
    audio_file: Path
    duration: float
    narration: str
    voice: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scene_id": self.scene_id,
            "audio_file": str(self.audio_file),
            "duration": self.duration,
            "narration": self.narration,
            "voice": self.voice
        }


@dataclass
class AudioGenerationResult:
    """Result from audio generation."""

    video_id: str
    audio_dir: Path
    timing_report: Optional[Path] = None
    total_duration: float = 0.0
    scene_results: List[SceneAudioResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """Check if generation was successful."""
        return len(self.errors) == 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "video_id": self.video_id,
            "audio_dir": str(self.audio_dir),
            "timing_report": str(self.timing_report) if self.timing_report else None,
            "total_duration": self.total_duration,
            "scene_count": len(self.scene_results),
            "scene_results": [sr.to_dict() for sr in self.scene_results],
            "success": self.success,
            "errors": self.errors,
            "warnings": self.warnings
        }


class UnifiedAudioGenerator:
    """
    Unified audio generation for all video types.

    Features:
    - Neural TTS (Edge-TTS) with multiple voices
    - Precise duration measurement
    - Timing report generation
    - Support for single and batch processing
    - Progress tracking
    """

    def __init__(
        self,
        config: AudioGenerationConfig,
        progress_callback: Optional[Callable] = None
    ):
        """
        Initialize audio generator.

        Args:
            config: Audio generation configuration
            progress_callback: Optional callback for progress updates
                             Signature: (stage: str, progress: float, message: str) -> None
        """
        self.config = config
        self.progress_callback = progress_callback

    async def generate_for_video_set(
        self,
        videos: List[VideoConfig]
    ) -> Dict[str, AudioGenerationResult]:
        """
        Generate audio for entire video set.

        Args:
            videos: List of VideoConfig objects

        Returns:
            Dict mapping video_id to AudioGenerationResult
        """
        results = {}

        for i, video in enumerate(videos):
            if self.progress_callback:
                self.progress_callback(
                    stage="audio_set",
                    progress=i / len(videos),
                    message=f"Generating audio for {video.video_id} ({i+1}/{len(videos)})"
                )

            result = await self.generate_for_video(video)
            results[video.video_id] = result

        return results

    async def generate_for_video(
        self,
        video: VideoConfig
    ) -> AudioGenerationResult:
        """
        Generate audio for single video.

        Args:
            video: Video configuration

        Returns:
            AudioGenerationResult with all generated files
        """
        # Create output directory
        audio_dir = self.config.output_dir / f"{video.video_id}_audio"
        audio_dir.mkdir(parents=True, exist_ok=True)

        result = AudioGenerationResult(
            video_id=video.video_id,
            audio_dir=audio_dir
        )

        # Generate audio for each scene
        for i, scene in enumerate(video.scenes):
            if self.progress_callback:
                self.progress_callback(
                    stage="audio",
                    progress=i / len(video.scenes),
                    message=f"Generating scene {i+1}/{len(video.scenes)}: {scene.scene_id}"
                )

            try:
                # Generate TTS audio
                scene_result = await self._generate_scene_audio(
                    scene=scene,
                    output_dir=audio_dir,
                    scene_num=i+1
                )

                # Update scene with audio information
                scene.actual_audio_duration = scene_result.duration
                scene.audio_file = scene_result.audio_file
                scene.final_duration = max(scene.min_duration, scene_result.duration + 1.0)

                result.scene_results.append(scene_result)
                result.total_duration += scene.final_duration

            except Exception as e:
                error_msg = f"Failed to generate audio for scene {scene.scene_id}: {str(e)}"
                result.errors.append(error_msg)

                # Update scene with error
                scene.warnings.append(error_msg)

        # Update video config
        video.total_duration = result.total_duration
        video.audio_dir = audio_dir

        # Generate timing report
        if self.config.generate_timing_report and result.success:
            result.timing_report = await self._create_timing_report(
                video=video,
                scene_results=result.scene_results,
                output_dir=audio_dir
            )

        return result

    async def _generate_scene_audio(
        self,
        scene: SceneConfig,
        output_dir: Path,
        scene_num: int
    ) -> SceneAudioResult:
        """
        Generate TTS audio for single scene.

        Args:
            scene: Scene configuration
            output_dir: Output directory for audio files
            scene_num: Scene number for filename

        Returns:
            SceneAudioResult with audio file and metadata
        """
        # Get voice configuration
        voice = self.config.voices.get(scene.voice, self.config.voices["male"])

        # Create output filename
        output_file = output_dir / f"scene_{scene_num:02d}.mp3"

        # Generate audio using Edge-TTS
        communicate = edge_tts.Communicate(
            scene.narration,
            voice,
            rate=self.config.rate,
            volume=self.config.volume
        )
        await communicate.save(str(output_file))

        # Measure duration
        duration = self._measure_audio_duration(output_file)

        return SceneAudioResult(
            scene_id=scene.scene_id,
            audio_file=output_file,
            duration=duration,
            narration=scene.narration,
            voice=scene.voice
        )

    def _measure_audio_duration(self, audio_file: Path) -> float:
        """
        Measure audio file duration with FFmpeg.

        Args:
            audio_file: Path to audio file

        Returns:
            Duration in seconds
        """
        try:
            cmd = [
                config.ffmpeg_path,
                "-i", str(audio_file),
                "-f", "null",
                "-"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )

            # Parse duration from FFmpeg output
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
                    except (ValueError, IndexError) as e:
                        self.logger.warning(f"Failed to parse duration from line: {line}")

            # Fallback: estimate from file size
            return self._estimate_duration_from_filesize(audio_file)

        except Exception as e:
            raise AudioGenerationError(
                f"Failed to measure audio duration: {e}",
                details={"audio_file": str(audio_file)}
            )

    def _estimate_duration_from_filesize(self, audio_file: Path) -> float:
        """
        Estimate duration from file size (fallback method).

        Args:
            audio_file: Path to audio file

        Returns:
            Estimated duration in seconds
        """
        # MP3 at 24kHz mono is approximately 3KB per second
        file_size = audio_file.stat().st_size
        return file_size / 3000.0

    async def _create_timing_report(
        self,
        video: VideoConfig,
        scene_results: List[SceneAudioResult],
        output_dir: Path
    ) -> Path:
        """
        Create JSON timing report.

        Args:
            video: Video configuration
            scene_results: List of scene audio results
            output_dir: Output directory

        Returns:
            Path to timing report
        """
        report = {
            "video_id": video.video_id,
            "title": video.title,
            "description": video.description,
            "total_duration": video.total_duration,
            "total_scenes": len(video.scenes),
            "generated_at": datetime.now().isoformat(),
            "scenes": []
        }

        cumulative_time = 0.0
        for scene, scene_result in zip(video.scenes, scene_results):
            # Use fallback values if fields are None
            final_duration = scene.final_duration or 0.0
            audio_duration = scene_result.duration or 0.0

            scene_data = {
                "scene_id": scene.scene_id,
                "scene_type": scene.scene_type,
                "voice": scene.voice,
                "start_time": cumulative_time,
                "end_time": cumulative_time + final_duration,
                "duration": final_duration,
                "audio_duration": audio_duration,
                "padding": final_duration - audio_duration,
                "audio_file": str(scene_result.audio_file.name),
                "narration_preview": scene.narration[:100] + "..." if len(scene.narration) > 100 else scene.narration
            }
            report["scenes"].append(scene_data)
            cumulative_time += final_duration

        # Save report
        report_file = output_dir / f"{video.video_id}_timing_report.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return report_file


# Convenience functions for backward compatibility
async def generate_audio_for_video(
    video: VideoConfig,
    output_dir: Path,
    voices: Optional[Dict[str, str]] = None,
    progress_callback: Optional[Callable] = None
) -> AudioGenerationResult:
    """
    Legacy function for generating audio for a single video.

    Args:
        video: Video configuration
        output_dir: Output directory
        voices: Optional voice configuration
        progress_callback: Optional progress callback

    Returns:
        AudioGenerationResult
    """
    audio_config = AudioGenerationConfig(
        output_dir=output_dir,
        voices=voices
    )
    generator = UnifiedAudioGenerator(audio_config, progress_callback)
    return await generator.generate_for_video(video)


async def generate_audio_for_video_set(
    videos: List[VideoConfig],
    output_dir: Path,
    voices: Optional[Dict[str, str]] = None,
    progress_callback: Optional[Callable] = None
) -> Dict[str, AudioGenerationResult]:
    """
    Legacy function for generating audio for a video set.

    Args:
        videos: List of video configurations
        output_dir: Output directory
        voices: Optional voice configuration
        progress_callback: Optional progress callback

    Returns:
        Dict mapping video_id to AudioGenerationResult
    """
    audio_config = AudioGenerationConfig(
        output_dir=output_dir,
        voices=voices
    )
    generator = UnifiedAudioGenerator(audio_config, progress_callback)
    return await generator.generate_for_video_set(videos)
