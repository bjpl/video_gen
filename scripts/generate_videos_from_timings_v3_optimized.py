"""
Video Generator v3.0 - GPU-Optimized & Pipe-Based
==================================================
Ultra-fast video generation using GPU acceleration and streaming pipelines.
Eliminates disk I/O bottlenecks and leverages parallel processing.
"""

import json
import os
import sys
import subprocess
import numpy as np
from PIL import Image
from datetime import datetime
from multiprocessing import Pool, cpu_count
import io
import logging

# Setup logging
logger = logging.getLogger(__name__)


sys.path.append('.')
from generate_documentation_videos import (
    create_title_keyframes, create_command_keyframes,
    create_list_keyframes, create_outro_keyframes,
    ease_out_cubic, FPS, WIDTH, HEIGHT
)
from generate_all_videos_unified_v2 import ALL_VIDEOS
from unified_video_system import ACCENT_ORANGE, ACCENT_BLUE, ACCENT_PURPLE, ACCENT_GREEN, ACCENT_PINK

FFMPEG_PATH = "C:/Users/brand/AppData/Local/Programs/Python/Python310/lib/site-packages/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe"

TRANSITION_DURATION = 0.5
ANIM_DURATION = 1.0

def image_to_numpy(img):
    return np.array(img, dtype=np.uint8)

def numpy_to_image(arr):
    return Image.fromarray(arr.astype('uint8'), 'RGB')

def blend_frames_numpy(frame1_np, frame2_np, progress):
    return (frame1_np * (1 - progress) + frame2_np * progress).astype(np.uint8)

def generate_scene_frames_batch(scene_data):
    scene_num, scene, scene_timing, next_scene, video_accent_color, is_last = scene_data

    trans_frames = int(TRANSITION_DURATION * FPS)
    anim_frames = int(ANIM_DURATION * FPS)

    frames = []

    if scene.scene_type == 'title':
        start_frame, end_frame = create_title_keyframes(
            scene.visual_content['title'],
            scene.visual_content['subtitle'],
            video_accent_color
        )
    elif scene.scene_type == 'command':
        start_frame, end_frame = create_command_keyframes(
            scene.visual_content['header'],
            scene.visual_content['description'],
            scene.visual_content['commands'],
            video_accent_color
        )
    elif scene.scene_type == 'list':
        start_frame, end_frame = create_list_keyframes(
            scene.visual_content['header'],
            scene.visual_content['description'],
            scene.visual_content['items'],
            video_accent_color
        )
    elif scene.scene_type == 'outro':
        start_frame, end_frame = create_outro_keyframes(
            scene.visual_content['main_text'],
            scene.visual_content['sub_text'],
            video_accent_color
        )

    start_np = image_to_numpy(start_frame)
    end_np = image_to_numpy(end_frame)

    for i in range(anim_frames):
        progress = ease_out_cubic(i / anim_frames)
        blended_np = blend_frames_numpy(start_np, end_np, progress)
        frames.append(blended_np)

    total_scene_frames = int(scene_timing['duration'] * FPS)
    hold_frames = total_scene_frames - anim_frames

    if not is_last:
        hold_frames -= trans_frames

    for _ in range(hold_frames):
        frames.append(end_np)

    if not is_last and next_scene:
        if next_scene.scene_type == 'title':
            next_start, _ = create_title_keyframes(
                next_scene.visual_content['title'],
                next_scene.visual_content['subtitle'],
                video_accent_color
            )
        elif next_scene.scene_type == 'command':
            next_start, _ = create_command_keyframes(
                next_scene.visual_content['header'],
                next_scene.visual_content['description'],
                next_scene.visual_content['commands'],
                video_accent_color
            )
        elif next_scene.scene_type == 'list':
            next_start, _ = create_list_keyframes(
                next_scene.visual_content['header'],
                next_scene.visual_content['description'],
                next_scene.visual_content['items'],
                video_accent_color
            )
        elif next_scene.scene_type == 'outro':
            next_start, _ = create_outro_keyframes(
                next_scene.visual_content['main_text'],
                next_scene.visual_content['sub_text'],
                video_accent_color
            )

        next_start_np = image_to_numpy(next_start)

        for i in range(trans_frames):
            progress = i / trans_frames
            blended_np = blend_frames_numpy(end_np, next_start_np, progress)
            frames.append(blended_np)

    return frames

def load_timing_report(video):
    timing_files = [f for f in os.listdir(video.audio_dir) if '_timing_' in f and f.endswith('.json')]

    if not timing_files:
        raise FileNotFoundError(f"No timing report found in {video.audio_dir}")

    timing_file = os.path.join(video.audio_dir, timing_files[0])
    logger.info(f"  Loading timing report: {os.path.basename(timing_file)}")
    with open(timing_file, 'r') as f:
        return json.load(f)

def generate_video_from_timing_optimized(video, timing_data, output_dir):
    logger.info(f"\n{'='*80}")
    logger.info(f"GENERATING VIDEO (OPTIMIZED): {video.title}")
    logger.info(f"{'='*80}\n")

    logger.info(f"[PHASE 1] Parallel frame generation")
    logger.info(f"  CPU cores: {cpu_count()}")
    logger.info(f"  Scenes: {len(video.scenes)}\n")

    scene_tasks = []
    for scene_num, (scene, scene_timing) in enumerate(zip(video.scenes, timing_data['scenes'])):
        next_scene = video.scenes[scene_num + 1] if scene_num < len(video.scenes) - 1 else None
        is_last = scene_num == len(video.scenes) - 1
        scene_tasks.append((scene_num, scene, scene_timing, next_scene, video.accent_color, is_last))
        logger.info(f"[{scene_num + 1}/{len(video.scenes)}] {scene.scene_id}: {scene_timing['duration']:.2f}s")

    with Pool(min(cpu_count(), len(video.scenes))) as pool:
        all_scene_frames = pool.map(generate_scene_frames_batch, scene_tasks)

    all_frames = []
    for scene_frames in all_scene_frames:
        all_frames.extend(scene_frames)

    logger.info(f"\n  Total frames: {len(all_frames)}")
    logger.info(f"  Video duration: {len(all_frames) / FPS:.2f}s")
    logger.info(f"  Expected: {timing_data['total_duration']:.2f}s\n")

    logger.info(f"[PHASE 2] GPU-accelerated encoding (streaming pipeline)")

    final_video = video.generate_smart_filename(file_type="video", include_audio=True)
    final_video_path = os.path.join(output_dir, final_video)

    audio_files = [os.path.join(video.audio_dir, f"{scene.scene_id}.mp3") for scene in video.scenes]
    audio_concat_list = "|".join([f"file='{os.path.abspath(af)}'" for af in audio_files])

    delay_ms = int(ANIM_DURATION * 1000)

    ffmpeg_cmd = [
        FFMPEG_PATH,
        "-y",
        "-f", "rawvideo",
        "-vcodec", "rawvideo",
        "-s", f"{WIDTH}x{HEIGHT}",
        "-pix_fmt", "rgb24",
        "-r", str(FPS),
        "-i", "-",
        "-f", "concat",
        "-safe", "0",
        "-protocol_whitelist", "file,pipe,concat",
        "-i", "pipe:4",
        "-map", "0:v:0",
        "-map", "1:a:0",
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
        "-af", f"adelay={delay_ms}:all=1,afade=t=in:st={ANIM_DURATION}:d=0.3",
        "-c:a", "aac",
        "-b:a", "192k",
        final_video_path
    ]

    audio_concat_content = "\n".join([f"file '{os.path.abspath(af)}'" for af in audio_files])

    logger.info(f"  Streaming {len(all_frames)} frames to GPU encoder...")

    process = subprocess.Popen(
        ffmpeg_cmd,
        stdin=subprocess.PIPE,
        pass_fds=(4,) if os.name != 'nt' else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    if os.name != 'nt':
        audio_concat_pipe = os.fdopen(4, 'w')
        audio_concat_pipe.write(audio_concat_content)
        audio_concat_pipe.close()

    for i, frame_np in enumerate(all_frames):
        if i % 100 == 0:
            logger.info(f"  Progress: {i}/{len(all_frames)} frames ({i/len(all_frames)*100:.1f}%)")

        process.stdin.write(frame_np.tobytes())

    process.stdin.close()
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        logger.error(f"  ❌ Video encoding failed:")
        logger.error(stderr.decode('utf-8', errors='ignore')[-500:])
        return None

    file_size = os.path.getsize(final_video_path) / (1024 * 1024)
    logger.info(f"\n  ✓ Final video created: {final_video}")
    logger.info(f"  📦 Size: {file_size:.1f} MB")
    logger.info(f"  ⏱️  Duration: {timing_data['total_duration']:.1f}s\n")

    return final_video_path

def generate_video_from_timing_optimized_fallback(video, timing_data, output_dir):
    """
    Fallback optimized version using temporary directory but with numpy acceleration
    """
    logger.info(f"\n{'='*80}")
    logger.info(f"GENERATING VIDEO (OPTIMIZED - FALLBACK MODE): {video.title}")
    logger.info(f"{'='*80}\n")

    temp_dir = f"temp_unified_v3_{video.video_id}"
    os.makedirs(temp_dir, exist_ok=True)

    logger.info(f"[PHASE 1] Parallel frame generation with NumPy acceleration")

    scene_tasks = []
    for scene_num, (scene, scene_timing) in enumerate(zip(video.scenes, timing_data['scenes'])):
        next_scene = video.scenes[scene_num + 1] if scene_num < len(video.scenes) - 1 else None
        is_last = scene_num == len(video.scenes) - 1
        scene_tasks.append((scene_num, scene, scene_timing, next_scene, video.accent_color, is_last))
        logger.info(f"[{scene_num + 1}/{len(video.scenes)}] {scene.scene_id}: {scene_timing['duration']:.2f}s")

    with Pool(min(cpu_count(), len(video.scenes))) as pool:
        all_scene_frames = pool.map(generate_scene_frames_batch, scene_tasks)

    logger.info(f"\n[PHASE 2] Writing frames to disk")

    frame_idx = 0
    frame_files = []

    for scene_frames in all_scene_frames:
        for frame_np in scene_frames:
            filename = f"{temp_dir}/frame_{frame_idx:05d}.png"
            img = numpy_to_image(frame_np)
            img.save(filename, "PNG", optimize=False, compress_level=1)
            frame_files.append(filename)
            frame_idx += 1

            if frame_idx % 100 == 0:
                logger.info(f"  Saved {frame_idx}/{len([f for sf in all_scene_frames for f in sf])} frames")

    logger.info(f"\n  Total frames: {len(frame_files)}")
    logger.info(f"  Video duration: {len(frame_files) / FPS:.2f}s\n")

    logger.info(f"[PHASE 3] GPU-accelerated video encoding")

    concat_file = f"{temp_dir}/concat.txt"
    with open(concat_file, 'w') as f:
        for i, fp in enumerate(frame_files):
            f.write(f"file '{os.path.abspath(fp)}'\n")
            if i < len(frame_files) - 1:
                f.write(f"duration {1/FPS}\n")
        f.write(f"file '{os.path.abspath(frame_files[-1])}'\n")

    silent_video = video.generate_smart_filename(file_type="video", include_audio=False)
    silent_video_path = os.path.join(output_dir, silent_video)

    ffmpeg_video_cmd = [
        FFMPEG_PATH,
        "-y", "-f", "concat", "-safe", "0", "-i", concat_file,
        "-c:v", "h264_nvenc",
        "-preset", "p4",
        "-tune", "hq",
        "-gpu", "0",
        "-rc", "vbr",
        "-cq", "19",
        "-b:v", "10M",
        "-maxrate", "15M",
        "-bufsize", "20M",
        "-pix_fmt", "yuv420p",
        "-movflags", "+faststart",
        silent_video_path
    ]

    result = subprocess.run(ffmpeg_video_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        logger.error(f"  ❌ Video encoding failed:")
        logger.info(result.stderr[:500])
        return None

    logger.info(f"  ✓ Silent video created\n")

    logger.info(f"[PHASE 4] Single-pass audio processing and muxing")

    audio_files = [os.path.join(video.audio_dir, f"{scene.scene_id}.mp3") for scene in video.scenes]
    audio_concat_file = f"{temp_dir}/audio_concat.txt"

    with open(audio_concat_file, 'w') as f:
        for audio_file in audio_files:
            f.write(f"file '{os.path.abspath(audio_file)}'\n")

    delay_ms = int(ANIM_DURATION * 1000)

    final_video = video.generate_smart_filename(file_type="video", include_audio=True)
    final_video_path = os.path.join(output_dir, final_video)

    ffmpeg_final_cmd = [
        FFMPEG_PATH,
        "-y",
        "-i", silent_video_path,
        "-f", "concat", "-safe", "0", "-i", audio_concat_file,
        "-c:v", "copy",
        "-af", f"adelay={delay_ms}:all=1,afade=t=in:st={ANIM_DURATION}:d=0.3",
        "-c:a", "aac",
        "-b:a", "192k",
        final_video_path
    ]

    result = subprocess.run(ffmpeg_final_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        logger.error(f"  ❌ Audio integration failed:")
        logger.info(result.stderr[:500])
        return None

    file_size = os.path.getsize(final_video_path) / (1024 * 1024)
    logger.info(f"\n  ✓ Final video created: {final_video}")
    logger.info(f"  📦 Size: {file_size:.1f} MB")
    logger.info(f"  ⏱️  Duration: {timing_data['total_duration']:.1f}s\n")

    import shutil
    shutil.rmtree(temp_dir)
    logger.info(f"  ✓ Cleaned up temp files\n")

    return final_video_path

def generate_all_videos_with_audio():
    logger.info("\n" + "="*80)
    logger.info("VIDEO GENERATION v3.0 - GPU-OPTIMIZED")
    logger.info("Ultra-fast generation with parallel processing and streaming pipelines")
    logger.info("="*80 + "\n")

    output_dir = "../videos/unified_v3_optimized"
    os.makedirs(output_dir, exist_ok=True)

    audio_base = "../audio/unified_system_v2"

    videos_to_generate = []

    for video in ALL_VIDEOS:
        sanitized_id = video.video_id.replace("_", "-")
        audio_dirs = [d for d in os.listdir(audio_base)
                     if d.startswith(sanitized_id) and os.path.isdir(os.path.join(audio_base, d))]

        if not audio_dirs:
            logger.warning(f"⚠️  No audio found for {video.video_id}, skipping...")
            continue

        audio_dir = os.path.join(audio_base, audio_dirs[0])
        video.audio_dir = audio_dir

        timing_files = [f for f in os.listdir(audio_dir) if '_timing_' in f and f.endswith('.json')]

        if not timing_files:
            logger.warning(f"⚠️  No timing report for {video.video_id}, skipping...")
            continue

        videos_to_generate.append(video)

    logger.info(f"Found {len(videos_to_generate)}/{len(ALL_VIDEOS)} videos ready for generation\n")

    generated_videos = []
    failed_videos = []

    for i, video in enumerate(videos_to_generate, 1):
        logger.info(f"{'#'*80}")
        logger.info(f"# VIDEO {i}/{len(videos_to_generate)}: {video.title}")
        logger.info(f"{'#'*80}")

        try:
            timing_data = load_timing_report(video)

            final_path = generate_video_from_timing_optimized_fallback(video, timing_data, output_dir)

            if final_path:
                generated_videos.append({
                    'video_id': video.video_id,
                    'title': video.title,
                    'path': final_path,
                    'duration': timing_data['total_duration'],
                    'size_mb': os.path.getsize(final_path) / (1024 * 1024)
                })
            else:
                failed_videos.append(video.video_id)

        except Exception as e:
            logger.error(f"\n❌ Error generating {video.video_id}: {str(e)}\n")
            failed_videos.append(video.video_id)

    logger.info("\n" + "="*80)
    logger.info("✓ VIDEO GENERATION COMPLETE")
    logger.info("="*80 + "\n")

    if generated_videos:
        logger.info(f"Successfully generated: {len(generated_videos)}/{len(videos_to_generate)}\n")

        total_duration = sum(v['duration'] for v in generated_videos)
        total_size = sum(v['size_mb'] for v in generated_videos)

        logger.info("Video Details:")
        logger.info("-" * 80)
        logger.info(f"{'Video ID':<25} {'Duration':<12} {'Size':<12} {'Status'}")
        logger.info("-" * 80)

        for v in generated_videos:
            logger.info(f"{v['video_id']:<25} {v['duration']:>6.1f}s {v['size_mb']:>8.1f} MB    ✓")

        logger.info("-" * 80)
        logger.info(f"{'TOTAL':<25} {total_duration:>6.1f}s {total_size:>8.1f} MB")
        logger.info()

        logger.info(f"All videos saved to: {output_dir}/")

    if failed_videos:
        logger.error(f"\n⚠️  Failed to generate {len(failed_videos)} video(s):")
        for vid_id in failed_videos:
            logger.info(f"  - {vid_id}")

    logger.info("\n" + "="*80)

    summary_file = os.path.join(output_dir, f"generation_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(summary_file, 'w') as f:
        json.dump({
            'generated': generated_videos,
            'failed': failed_videos,
            'total_generated': len(generated_videos),
            'total_duration': sum(v['duration'] for v in generated_videos),
            'total_size_mb': sum(v['size_mb'] for v in generated_videos),
            'timestamp': datetime.now().isoformat(),
            'version': 'v3.0-optimized'
        }, f, indent=2)

    logger.info(f"Summary saved: {summary_file}\n")

if __name__ == "__main__":
    generate_all_videos_with_audio()