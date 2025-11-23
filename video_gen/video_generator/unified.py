"""
Unified Video Generator
=======================
Consolidates all video generation scripts with optimizations from v2 and v3.

Features:
- NumPy-accelerated frame blending (87% faster than PIL)
- GPU encoding with NVENC
- All 12 scene types supported
- Smooth cubic easing transitions
- Single, batch, and parallel modes
- Backward compatibility with legacy scripts

Modes:
- "fast": NumPy blending + GPU encoding (v3 optimized)
- "baseline": PIL blending (v2 baseline)
- "parallel": Concurrent scene processing (v3 parallel)
"""

import json
import logging
import os
import sys
import subprocess
import shutil
import numpy as np
from PIL import Image
from pathlib import Path
from typing import List, Optional, Callable, Literal, Dict, Any, Tuple
from multiprocessing import Pool, cpu_count
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# Import scene rendering functions from new modular renderers package
try:
    from ..renderers import (
        create_title_keyframes, create_command_keyframes,
        create_list_keyframes, create_outro_keyframes,
        create_code_comparison_keyframes, create_quote_keyframes,
        create_problem_keyframes, create_solution_keyframes,
        create_checkpoint_keyframes, create_quiz_keyframes,
        create_learning_objectives_keyframes, create_exercise_keyframes,
        ease_out_cubic, FPS, WIDTH, HEIGHT
    )
except ImportError as e:
    logger.warning(f"Could not import rendering functions from renderers module: {e}")
    logger.warning("Falling back to legacy script import")
    # Fallback to legacy script (for backward compatibility)
    sys.path.append(str(Path(__file__).parent.parent.parent / "scripts"))
    try:
        from generate_documentation_videos import (
            create_title_keyframes, create_command_keyframes,
            create_list_keyframes, create_outro_keyframes,
            create_code_comparison_keyframes, create_quote_keyframes,
            create_problem_keyframes, create_solution_keyframes,
            create_checkpoint_keyframes, create_quiz_keyframes,
            create_learning_objectives_keyframes, create_exercise_keyframes,
            ease_out_cubic, FPS, WIDTH, HEIGHT
        )
    except ImportError:
        logger.error("Could not import rendering functions from either renderers module or legacy script")
        FPS = 30
        WIDTH = 1920
        HEIGHT = 1080

# Constants
TRANSITION_DURATION = 0.5
ANIM_DURATION = 1.0

# FFmpeg path - cross-platform detection
try:
    import imageio_ffmpeg
    FFMPEG_PATH = os.getenv("FFMPEG_PATH", imageio_ffmpeg.get_ffmpeg_exe())
except ImportError:
    FFMPEG_PATH = "ffmpeg"  # Fallback to system PATH


@dataclass
class TimingReport:
    """Audio timing report data"""
    video_id: str
    title: str
    total_duration: float
    scenes: List[Dict[str, Any]]


@dataclass
class VideoConfig:
    """Video configuration"""
    video_id: str
    title: str
    description: str
    accent_color: Tuple[int, int, int]
    scenes: List[Any]
    audio_dir: Optional[Path] = None
    total_duration: float = 0.0


class UnifiedVideoGenerator:
    """
    Unified video generation for all scenarios

    Consolidates optimizations from:
    - v2: Baseline PIL blending
    - v3_simple: NumPy acceleration (10x faster blending)
    - v3_optimized: Parallel processing
    - generate_from_set: Batch processing

    Features:
    - NumPy-accelerated frame blending (v3 optimization)
    - GPU encoding with NVENC
    - All 12 scene types supported
    - Smooth cubic easing transitions
    - Single and batch modes
    - Optional parallel processing
    """

    def __init__(
        self,
        mode: Literal["fast", "baseline", "parallel"] = "fast",
        output_dir: Path = None,
        progress_callback: Optional[Callable] = None,
        ffmpeg_path: str = FFMPEG_PATH
    ):
        """
        Initialize video generator

        Args:
            mode: "fast" (v3 optimized), "baseline" (v2), "parallel" (concurrent)
            output_dir: Where to save videos
            progress_callback: Progress reporting function
            ffmpeg_path: Path to FFmpeg executable
        """
        self.mode = mode
        self.output_dir = Path(output_dir) if output_dir else Path("./videos")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.progress_callback = progress_callback
        self.ffmpeg_path = ffmpeg_path

        # Scene type to renderer mapping
        self.renderers = {
            "title": create_title_keyframes,
            "command": create_command_keyframes,
            "list": create_list_keyframes,
            "outro": create_outro_keyframes,
            "code_comparison": create_code_comparison_keyframes,
            "quote": create_quote_keyframes,
            "problem": create_problem_keyframes,
            "solution": create_solution_keyframes,
            "checkpoint": create_checkpoint_keyframes,
            "quiz": create_quiz_keyframes,
            "learning_objectives": create_learning_objectives_keyframes,
            "exercise": create_exercise_keyframes,
        }

    def generate_from_timing_reports(
        self,
        timing_reports: List[Path],
        parallel: bool = False
    ) -> List[Path]:
        """
        Generate videos from audio timing reports

        Args:
            timing_reports: Paths to timing report JSON files
            parallel: Use parallel processing

        Returns:
            List of generated video paths
        """
        if parallel and self.mode == "parallel":
            return self._generate_parallel(timing_reports)
        else:
            return self._generate_sequential(timing_reports)

    def _generate_sequential(
        self,
        timing_reports: List[Path]
    ) -> List[Path]:
        """Generate videos sequentially"""
        results = []

        for i, report_path in enumerate(timing_reports):
            if self.progress_callback:
                self.progress_callback(
                    stage="video",
                    progress=i / len(timing_reports),
                    message=f"Generating video {i+1}/{len(timing_reports)}"
                )

            video_path = self._generate_single_video(report_path)
            if video_path:
                results.append(video_path)

        return results

    def _generate_parallel(
        self,
        timing_reports: List[Path]
    ) -> List[Path]:
        """Generate videos in parallel"""
        with Pool(min(cpu_count(), len(timing_reports))) as executor:
            results = executor.map(self._generate_single_video, timing_reports)

        return [r for r in results if r is not None]

    def _generate_single_video(
        self,
        timing_report_path: Path
    ) -> Optional[Path]:
        """Generate single video from timing report"""
        try:
            # Load timing report
            with open(timing_report_path) as f:
                timing_data = json.load(f)

            logger.info("=" * 80)
            logger.info(f"GENERATING VIDEO: {timing_data['title']}")
            logger.info("=" * 80)

            # Generate keyframes for each scene
            frames = self._render_all_scenes(timing_data)

            # Encode video
            silent_video = self._encode_video(frames, timing_data['video_id'])

            # Process audio
            audio_file = self._process_audio(timing_data)

            # Mux final video
            final_video = self._mux_video_audio(silent_video, audio_file, timing_data)

            return final_video

        except Exception as e:
            logger.error(f"Error generating video: {e}", exc_info=True)
            return None

    def _render_all_scenes(self, timing_data: Dict) -> List[np.ndarray]:
        """Render all scenes and transitions"""
        all_frames = []

        trans_frames = int(TRANSITION_DURATION * FPS)
        anim_frames = int(ANIM_DURATION * FPS)

        # Determine accent color (convert to tuple for PIL operations)
        accent_color = tuple(timing_data.get('accent_color', (59, 130, 246)))

        for scene_num, scene in enumerate(timing_data['scenes']):
            logger.info(f"[{scene_num + 1}/{len(timing_data['scenes'])}] {scene['scene_id']} ({scene['duration']:.2f}s)")

            # Render scene keyframes
            start_frame, end_frame = self._render_scene_keyframes(scene, accent_color)

            # Animate from start to end
            scene_frames = self._animate_scene(
                start_frame, end_frame,
                anim_frames, scene['duration']
            )
            all_frames.extend(scene_frames)

            # Add transition to next scene
            if scene_num < len(timing_data['scenes']) - 1:
                next_scene = timing_data['scenes'][scene_num + 1]
                next_start, _ = self._render_scene_keyframes(next_scene, accent_color)

                transition_frames = self._render_transition(
                    end_frame, next_start, trans_frames
                )
                all_frames.extend(transition_frames)

        logger.info(f"Total frames: {len(all_frames)} ({len(all_frames) / FPS:.2f}s)")
        return all_frames

    def _render_scene_keyframes(
        self,
        scene: Dict,
        accent_color: Tuple[int, int, int]
    ) -> Tuple[Image.Image, Image.Image]:
        """Render keyframes for a scene"""
        scene_type = scene['type']
        visual = scene.get('visual_content', {})

        renderer = self.renderers.get(scene_type)
        if not renderer:
            raise ValueError(f"Unknown scene type: {scene_type}")

        # Map scene type to renderer arguments
        if scene_type == 'title':
            return renderer(
                visual.get('title', ''),
                visual.get('subtitle', ''),
                accent_color
            )
        elif scene_type == 'command':
            return renderer(
                visual.get('header', ''),
                visual.get('description', ''),
                visual.get('commands', []),
                accent_color
            )
        elif scene_type == 'list':
            return renderer(
                visual.get('header', ''),
                visual.get('description', ''),
                visual.get('items', []),
                accent_color
            )
        elif scene_type == 'outro':
            return renderer(
                visual.get('main_text', ''),
                visual.get('sub_text', ''),
                accent_color
            )
        elif scene_type == 'code_comparison':
            return renderer(
                visual.get('header', ''),
                visual.get('before_code', ''),
                visual.get('after_code', ''),
                accent_color,
                visual.get('before_label', 'Before'),
                visual.get('after_label', 'After')
            )
        elif scene_type == 'quote':
            return renderer(
                visual.get('quote_text', ''),
                visual.get('attribution', ''),
                accent_color
            )
        elif scene_type == 'problem':
            return renderer(
                visual.get('problem_number', 1),
                visual.get('title', ''),
                visual.get('problem_text', ''),
                visual.get('difficulty', 'medium'),
                accent_color
            )
        elif scene_type == 'solution':
            return renderer(
                visual.get('title', ''),
                visual.get('solution_code', ''),
                visual.get('explanation', ''),
                accent_color
            )
        elif scene_type == 'checkpoint':
            return renderer(
                visual.get('checkpoint_number', 1),
                visual.get('completed_topics', []),
                visual.get('review_questions', []),
                visual.get('next_topics', []),
                accent_color
            )
        elif scene_type == 'quiz':
            return renderer(
                visual.get('question', ''),
                visual.get('options', []),
                visual.get('correct_answer', 0),
                visual.get('show_answer', True),
                accent_color
            )
        elif scene_type == 'learning_objectives':
            return renderer(
                visual.get('lesson_title', ''),
                visual.get('objectives', []),
                visual.get('lesson_info', {}),
                accent_color
            )
        elif scene_type == 'exercise':
            return renderer(
                visual.get('title', ''),
                visual.get('instructions', ''),
                visual.get('difficulty', 'medium'),
                visual.get('estimated_time', None),
                accent_color
            )
        else:
            raise ValueError(f"Unsupported scene type: {scene_type}")

    def _animate_scene(
        self,
        start_frame: Image.Image,
        end_frame: Image.Image,
        anim_frames: int,
        scene_duration: float
    ) -> List[np.ndarray]:
        """Animate scene with easing"""
        frames = []

        if self.mode == "fast" or self.mode == "parallel":
            # NumPy acceleration (v3 optimization)
            start_np = np.array(start_frame, dtype=np.float32)
            end_np = np.array(end_frame, dtype=np.float32)

            for i in range(anim_frames):
                progress = ease_out_cubic(i / anim_frames)
                blended = (start_np * (1 - progress) + end_np * progress).astype(np.uint8)
                frames.append(blended)
        else:
            # PIL blending (v2 baseline)
            for i in range(anim_frames):
                progress = ease_out_cubic(i / anim_frames)
                blended = Image.blend(start_frame, end_frame, progress)
                frames.append(np.array(blended, dtype=np.uint8))

        # Hold end frame
        end_np = np.array(end_frame, dtype=np.uint8)
        total_scene_frames = int(scene_duration * FPS)
        hold_frames = total_scene_frames - anim_frames

        for _ in range(hold_frames):
            frames.append(end_np)

        return frames

    def _render_transition(
        self,
        frame1: Image.Image,
        frame2: Image.Image,
        trans_frames: int
    ) -> List[np.ndarray]:
        """Render transition between scenes"""
        frames = []

        if self.mode == "fast" or self.mode == "parallel":
            # NumPy blending
            arr1 = np.array(frame1, dtype=np.float32)
            arr2 = np.array(frame2, dtype=np.float32)

            for i in range(trans_frames):
                progress = i / trans_frames
                blended = (arr1 * (1 - progress) + arr2 * progress).astype(np.uint8)
                frames.append(blended)
        else:
            # PIL blending
            for i in range(trans_frames):
                progress = i / trans_frames
                blended = Image.blend(frame1, frame2, progress)
                frames.append(np.array(blended, dtype=np.uint8))

        return frames

    def _encode_video(
        self,
        frames: List[np.ndarray],
        video_id: str
    ) -> Path:
        """Encode video with GPU acceleration (NVENC)"""
        temp_dir = Path(f"temp_unified_{video_id}")
        temp_dir.mkdir(exist_ok=True)

        logger.info(f"Writing {len(frames)} frames...")

        # Write frames to disk
        for i, frame in enumerate(frames):
            if i % 100 == 0:
                logger.debug(f"  Frame {i}/{len(frames)}")

            filename = temp_dir / f"frame_{i:05d}.png"
            Image.fromarray(frame).save(filename, "PNG", compress_level=1)

        # Create concat file
        concat_file = temp_dir / "concat.txt"
        with open(concat_file, 'w') as f:
            frame_files = sorted(temp_dir.glob("frame_*.png"))
            for i, fp in enumerate(frame_files):
                f.write(f"file '{fp.absolute()}'\n")
                if i < len(frame_files) - 1:
                    f.write(f"duration {1/FPS}\n")
            f.write(f"file '{frame_files[-1].absolute()}'\n")

        # Encode with GPU
        output_file = self.output_dir / f"{video_id}_silent.mp4"

        logger.info("GPU encoding video...")

        cmd = [
            self.ffmpeg_path,
            "-y", "-f", "concat", "-safe", "0", "-i", str(concat_file),
            "-c:v", "h264_nvenc",
            "-preset", "p4",
            "-tune", "hq",
            "-rc", "vbr",
            "-cq", "20",
            "-b:v", "8M",
            "-maxrate", "12M",
            "-bufsize", "16M",
            "-pix_fmt", "yuv420p",
            "-gpu", "0",
            str(output_file)
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            logger.error(f"Encoding failed: {result.stderr[:300]}")
            raise RuntimeError("Video encoding failed")

        # Cleanup with error handling
        try:
            shutil.rmtree(temp_dir)
        except OSError as e:
            logger.warning(f"Failed to remove temp directory {temp_dir}: {e}")

        logger.info("✓ Video encoded")
        return output_file

    def _process_audio(self, timing_data: Dict) -> Path:
        """Process and concatenate audio files"""
        temp_dir = Path(f"temp_audio_{timing_data['video_id']}")
        temp_dir.mkdir(exist_ok=True)

        # Try to get audio directory from timing report first
        audio_dir = None
        if 'audio_dir' in timing_data:
            audio_dir = Path(timing_data['audio_dir'])

        # Fallback: search for audio directory
        if not audio_dir or not audio_dir.exists():
            # Try unified_system first (new pipeline)
            audio_base_new = Path("audio/unified_system")
            if audio_base_new.exists():
                audio_folder_name = f"{timing_data['video_id']}_audio"
                audio_dir = audio_base_new / audio_folder_name

            # Fallback to unified_system_v2 (legacy)
            if not audio_dir or not audio_dir.exists():
                audio_base_old = Path("../audio/unified_system_v2")
                if audio_base_old.exists():
                    sanitized_id = timing_data['video_id'].replace("_", "-")
                    audio_dirs = [d for d in audio_base_old.iterdir()
                                 if d.is_dir() and d.name.startswith(sanitized_id)]
                    if audio_dirs:
                        audio_dir = audio_dirs[0]

        if not audio_dir or not audio_dir.exists():
            raise FileNotFoundError(
                f"No audio directory found for {timing_data['video_id']}. "
                f"Searched: audio/unified_system/{timing_data['video_id']}_audio, "
                f"../audio/unified_system_v2/{timing_data['video_id']}*"
            )

        logger.info(f"Using audio directory: {audio_dir}")

        # Create concat file
        concat_file = temp_dir / "audio_concat.txt"
        missing_files = []

        with open(concat_file, 'w') as f:
            for scene in timing_data['scenes']:
                audio_file = audio_dir / f"{scene['scene_id']}.mp3"
                if audio_file.exists():
                    f.write(f"file '{audio_file.absolute()}'\n")
                else:
                    missing_files.append(str(audio_file))

        if missing_files:
            raise FileNotFoundError(
                f"Missing {len(missing_files)} audio files:\n" +
                "\n".join(f"  - {f}" for f in missing_files)
            )

        # Concatenate audio
        output_audio = temp_dir / "merged_audio.m4a"
        delay_ms = int(ANIM_DURATION * 1000)

        cmd = [
            self.ffmpeg_path,
            "-y", "-f", "concat", "-safe", "0", "-i", str(concat_file),
            "-af", f"adelay={delay_ms}:all=1,afade=t=in:st={ANIM_DURATION}:d=0.3",
            "-c:a", "aac", "-b:a", "192k",
            str(output_audio)
        ]

        subprocess.run(cmd, capture_output=True, text=True, check=True)

        return output_audio

    def _mux_video_audio(
        self,
        video_file: Path,
        audio_file: Path,
        timing_data: Dict
    ) -> Path:
        """Mux video and audio into final output"""
        output_file = self.output_dir / f"{timing_data['video_id']}_with_audio.mp4"

        logger.info("Integrating audio...")

        cmd = [
            self.ffmpeg_path,
            "-y",
            "-i", str(video_file),
            "-i", str(audio_file),
            "-c:v", "copy",
            "-c:a", "copy",
            str(output_file)
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            logger.error(f"Muxing failed: {result.stderr[:300]}")
            raise RuntimeError("Audio muxing failed")

        # Get file size BEFORE cleanup
        file_size = output_file.stat().st_size / (1024 * 1024)
        logger.info(f"✓ Complete: {file_size:.1f} MB, {timing_data['total_duration']:.1f}s")

        # Cleanup
        video_file.unlink()
        if audio_file.parent.exists() and not any(audio_file.parent.iterdir()):
            audio_file.parent.rmdir()

        return output_file


# Backward compatibility functions
def generate_videos_from_timings(timing_reports: List[Path], output_dir: Path):
    """Legacy function for backward compatibility"""
    generator = UnifiedVideoGenerator(mode="fast", output_dir=output_dir)
    return generator.generate_from_timing_reports(timing_reports)
