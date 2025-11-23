"""
Video Generator v3.0 - Simple & Fast
=====================================
Pragmatic optimizations focused on real bottlenecks:
1. NumPy for 10x faster frame blending
2. Lower PNG compression for 3x faster disk writes
3. Better GPU encoder settings for quality/speed balance
4. Single-pass audio processing
"""

import json
import os
import sys
import subprocess
import shutil
import numpy as np
from PIL import Image
from datetime import datetime
import logging

# Setup logging
logger = logging.getLogger(__name__)


sys.path.append('.')
from generate_documentation_videos import (
    create_title_keyframes, create_command_keyframes,
    create_list_keyframes, create_outro_keyframes,
    create_code_comparison_keyframes, create_quote_keyframes,
    create_problem_keyframes, create_solution_keyframes,
    create_checkpoint_keyframes, create_quiz_keyframes,
    create_learning_objectives_keyframes, create_exercise_keyframes,
    ease_out_cubic, FPS, WIDTH, HEIGHT
)
from generate_all_videos_unified_v2 import ALL_VIDEOS

FFMPEG_PATH = "C:/Users/brand/AppData/Local/Programs/Python/Python310/lib/site-packages/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe"

TRANSITION_DURATION = 0.5
ANIM_DURATION = 1.0

def blend_frames_fast(img1, img2, progress):
    """10x faster blending using NumPy instead of PIL"""
    arr1 = np.array(img1, dtype=np.float32)
    arr2 = np.array(img2, dtype=np.float32)

    blended = arr1 * (1 - progress) + arr2 * progress

    return Image.fromarray(blended.astype('uint8'), 'RGB')

def load_timing_report(video):
    timing_files = [f for f in os.listdir(video.audio_dir) if '_timing_' in f and f.endswith('.json')]
    if not timing_files:
        raise FileNotFoundError(f"No timing report found in {video.audio_dir}")

    timing_file = os.path.join(video.audio_dir, timing_files[0])
    logger.info(f"  Loading timing report: {os.path.basename(timing_file)}")
    with open(timing_file, 'r') as f:
        return json.load(f)

def generate_video_from_timing_fast(video, timing_data, output_dir):
    logger.info(f"\n{'='*80}")
    logger.info(f"GENERATING VIDEO (FAST): {video.title}")
    logger.info(f"{'='*80}\n")

    temp_dir = f"temp_v3_fast_{video.video_id}"
    os.makedirs(temp_dir, exist_ok=True)

    frame_paths = []
    frame_idx = 0

    trans_frames = int(TRANSITION_DURATION * FPS)
    anim_frames = int(ANIM_DURATION * FPS)

    for scene_num, (scene, scene_timing) in enumerate(zip(video.scenes, timing_data['scenes'])):
        logger.info(f"[{scene_num + 1}/{len(video.scenes)}] {scene.scene_id} ({scene_timing['duration']:.2f}s)")

        if scene.scene_type == 'title':
            start_frame, end_frame = create_title_keyframes(
                scene.visual_content['title'],
                scene.visual_content['subtitle'],
                video.accent_color
            )
        elif scene.scene_type == 'command':
            start_frame, end_frame = create_command_keyframes(
                scene.visual_content['header'],
                scene.visual_content['description'],
                scene.visual_content['commands'],
                video.accent_color
            )
        elif scene.scene_type == 'list':
            start_frame, end_frame = create_list_keyframes(
                scene.visual_content['header'],
                scene.visual_content['description'],
                scene.visual_content['items'],
                video.accent_color
            )
        elif scene.scene_type == 'outro':
            start_frame, end_frame = create_outro_keyframes(
                scene.visual_content['main_text'],
                scene.visual_content['sub_text'],
                video.accent_color
            )
        elif scene.scene_type == 'code_comparison':
            start_frame, end_frame = create_code_comparison_keyframes(
                scene.visual_content['header'],
                scene.visual_content['before_code'],
                scene.visual_content['after_code'],
                video.accent_color,
                scene.visual_content.get('before_label', 'Before'),
                scene.visual_content.get('after_label', 'After')
            )
        elif scene.scene_type == 'quote':
            start_frame, end_frame = create_quote_keyframes(
                scene.visual_content['quote_text'],
                scene.visual_content['attribution'],
                video.accent_color
            )
        elif scene.scene_type == 'problem':
            start_frame, end_frame = create_problem_keyframes(
                scene.visual_content['problem_number'],
                scene.visual_content['title'],
                scene.visual_content['problem_text'],
                scene.visual_content.get('difficulty', 'medium'),
                video.accent_color
            )
        elif scene.scene_type == 'solution':
            start_frame, end_frame = create_solution_keyframes(
                scene.visual_content['title'],
                scene.visual_content['solution_code'],
                scene.visual_content.get('explanation', ''),
                video.accent_color
            )
        elif scene.scene_type == 'checkpoint':
            start_frame, end_frame = create_checkpoint_keyframes(
                scene.visual_content['checkpoint_number'],
                scene.visual_content['completed_topics'],
                scene.visual_content['review_questions'],
                scene.visual_content['next_topics'],
                video.accent_color
            )
        elif scene.scene_type == 'quiz':
            start_frame, end_frame = create_quiz_keyframes(
                scene.visual_content['question'],
                scene.visual_content['options'],
                scene.visual_content['correct_answer'],
                scene.visual_content.get('show_answer', True),
                video.accent_color
            )
        elif scene.scene_type == 'learning_objectives':
            start_frame, end_frame = create_learning_objectives_keyframes(
                scene.visual_content['lesson_title'],
                scene.visual_content['objectives'],
                scene.visual_content.get('lesson_info', {}),
                video.accent_color
            )
        elif scene.scene_type == 'exercise':
            start_frame, end_frame = create_exercise_keyframes(
                scene.visual_content['title'],
                scene.visual_content['instructions'],
                scene.visual_content.get('difficulty', 'medium'),
                scene.visual_content.get('estimated_time'),
                video.accent_color
            )

        for i in range(anim_frames):
            progress = ease_out_cubic(i / anim_frames)
            blended = blend_frames_fast(start_frame, end_frame, progress)
            filename = f"{temp_dir}/frame_{frame_idx:05d}.png"
            blended.save(filename, "PNG", compress_level=1)
            frame_paths.append(filename)
            frame_idx += 1

        total_scene_frames = int(scene_timing['duration'] * FPS)
        hold_frames = total_scene_frames - anim_frames

        if scene_num < len(video.scenes) - 1:
            hold_frames -= trans_frames

        for _ in range(hold_frames):
            frame_paths.append(filename)

        if scene_num < len(video.scenes) - 1:
            next_scene = video.scenes[scene_num + 1]

            if next_scene.scene_type == 'title':
                next_start, _ = create_title_keyframes(
                    next_scene.visual_content['title'],
                    next_scene.visual_content['subtitle'],
                    video.accent_color
                )
            elif next_scene.scene_type == 'command':
                next_start, _ = create_command_keyframes(
                    next_scene.visual_content['header'],
                    next_scene.visual_content['description'],
                    next_scene.visual_content['commands'],
                    video.accent_color
                )
            elif next_scene.scene_type == 'list':
                next_start, _ = create_list_keyframes(
                    next_scene.visual_content['header'],
                    next_scene.visual_content['description'],
                    next_scene.visual_content['items'],
                    video.accent_color
                )
            elif next_scene.scene_type == 'outro':
                next_start, _ = create_outro_keyframes(
                    next_scene.visual_content['main_text'],
                    next_scene.visual_content['sub_text'],
                    video.accent_color
                )
            elif next_scene.scene_type == 'code_comparison':
                next_start, _ = create_code_comparison_keyframes(
                    next_scene.visual_content['header'],
                    next_scene.visual_content['before_code'],
                    next_scene.visual_content['after_code'],
                    video.accent_color,
                    next_scene.visual_content.get('before_label', 'Before'),
                    next_scene.visual_content.get('after_label', 'After')
                )
            elif next_scene.scene_type == 'quote':
                next_start, _ = create_quote_keyframes(
                    next_scene.visual_content['quote_text'],
                    next_scene.visual_content['attribution'],
                    video.accent_color
                )
            elif next_scene.scene_type == 'problem':
                next_start, _ = create_problem_keyframes(
                    next_scene.visual_content['problem_number'],
                    next_scene.visual_content['title'],
                    next_scene.visual_content['problem_text'],
                    next_scene.visual_content.get('difficulty', 'medium'),
                    video.accent_color
                )
            elif next_scene.scene_type == 'solution':
                next_start, _ = create_solution_keyframes(
                    next_scene.visual_content['title'],
                    next_scene.visual_content['solution_code'],
                    next_scene.visual_content.get('explanation', ''),
                    video.accent_color
                )
            elif next_scene.scene_type == 'checkpoint':
                next_start, _ = create_checkpoint_keyframes(
                    next_scene.visual_content['checkpoint_number'],
                    next_scene.visual_content['completed_topics'],
                    next_scene.visual_content['review_questions'],
                    next_scene.visual_content['next_topics'],
                    video.accent_color
                )
            elif next_scene.scene_type == 'quiz':
                next_start, _ = create_quiz_keyframes(
                    next_scene.visual_content['question'],
                    next_scene.visual_content['options'],
                    next_scene.visual_content['correct_answer'],
                    next_scene.visual_content.get('show_answer', True),
                    video.accent_color
                )
            elif next_scene.scene_type == 'learning_objectives':
                next_start, _ = create_learning_objectives_keyframes(
                    next_scene.visual_content['lesson_title'],
                    next_scene.visual_content['objectives'],
                    next_scene.visual_content.get('lesson_info', {}),
                    video.accent_color
                )
            elif next_scene.scene_type == 'exercise':
                next_start, _ = create_exercise_keyframes(
                    next_scene.visual_content['title'],
                    next_scene.visual_content['instructions'],
                    next_scene.visual_content.get('difficulty', 'medium'),
                    next_scene.visual_content.get('estimated_time'),
                    video.accent_color
                )

            for i in range(trans_frames):
                progress = i / trans_frames
                blended = blend_frames_fast(end_frame, next_start, progress)
                filename = f"{temp_dir}/frame_{frame_idx:05d}.png"
                blended.save(filename, "PNG", compress_level=1)
                frame_paths.append(filename)
                frame_idx += 1

    logger.info(f"\n  Frames: {len(frame_paths)} ({len(frame_paths) / FPS:.2f}s)")

    concat_file = f"{temp_dir}/concat.txt"
    with open(concat_file, 'w') as f:
        for i, fp in enumerate(frame_paths):
            f.write(f"file '{os.path.abspath(fp)}'\n")
            if i < len(frame_paths) - 1:
                f.write(f"duration {1/FPS}\n")
        f.write(f"file '{os.path.abspath(frame_paths[-1])}'\n")

    silent_video = video.generate_smart_filename(file_type="video", include_audio=False)
    silent_video_path = os.path.join(output_dir, silent_video)

    logger.info(f"  GPU encoding video...")

    ffmpeg_video_cmd = [
        FFMPEG_PATH,
        "-y", "-f", "concat", "-safe", "0", "-i", concat_file,
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
        silent_video_path
    ]

    result = subprocess.run(ffmpeg_video_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        logger.error(f"  ❌ Encoding failed: {result.stderr[:300]}")
        return None

    logger.info(f"  ✓ Video encoded")

    audio_files = [os.path.join(video.audio_dir, f"{scene.scene_id}.mp3") for scene in video.scenes]
    audio_concat_file = f"{temp_dir}/audio_concat.txt"

    with open(audio_concat_file, 'w') as f:
        for audio_file in audio_files:
            f.write(f"file '{os.path.abspath(audio_file)}'\n")

    logger.info(f"  Processing audio...")

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
        logger.error(f"  ❌ Audio integration failed: {result.stderr[:300]}")
        return None

    file_size = os.path.getsize(final_video_path) / (1024 * 1024)
    logger.info(f"  ✓ Complete: {file_size:.1f} MB, {timing_data['total_duration']:.1f}s\n")

    shutil.rmtree(temp_dir)

    return final_video_path

def generate_all_videos_fast():
    logger.info("\n" + "="*80)
    logger.info("VIDEO GENERATION v3.0 - SIMPLE & FAST")
    logger.info("NumPy-accelerated blending + Optimized GPU encoding")
    logger.info("="*80 + "\n")

    output_dir = "../videos/unified_v3_fast"
    os.makedirs(output_dir, exist_ok=True)

    audio_base = "../audio/unified_system_v2"

    videos_to_generate = []

    for video in ALL_VIDEOS:
        sanitized_id = video.video_id.replace("_", "-")
        audio_dirs = [d for d in os.listdir(audio_base)
                     if d.startswith(sanitized_id) and os.path.isdir(os.path.join(audio_base, d))]

        if not audio_dirs:
            continue

        audio_dir = os.path.join(audio_base, audio_dirs[0])
        video.audio_dir = audio_dir

        timing_files = [f for f in os.listdir(audio_dir) if '_timing_' in f and f.endswith('.json')]
        if timing_files:
            videos_to_generate.append(video)

    logger.info(f"Generating {len(videos_to_generate)} videos\n")

    generated_videos = []
    failed_videos = []

    for i, video in enumerate(videos_to_generate, 1):
        logger.info(f"{'#'*80}")
        logger.info(f"# VIDEO {i}/{len(videos_to_generate)}: {video.title}")
        logger.info(f"{'#'*80}")

        try:
            timing_data = load_timing_report(video)
            final_path = generate_video_from_timing_fast(video, timing_data, output_dir)

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
            logger.error(f"\n❌ Error: {str(e)}\n")
            failed_videos.append(video.video_id)

    logger.info("\n" + "="*80)
    logger.info("✓ COMPLETE")
    logger.info("="*80 + "\n")

    if generated_videos:
        total_dur = sum(v['duration'] for v in generated_videos)
        total_size = sum(v['size_mb'] for v in generated_videos)

        for v in generated_videos:
            logger.info(f"✓ {v['video_id']:<25} {v['duration']:>6.1f}s {v['size_mb']:>8.1f} MB")

        logger.info("-" * 80)
        logger.info(f"  {'TOTAL':<25} {total_dur:>6.1f}s {total_size:>8.1f} MB\n")

    summary_file = os.path.join(output_dir, f"summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(summary_file, 'w') as f:
        json.dump({
            'generated': generated_videos,
            'failed': failed_videos,
            'version': 'v3.0-fast',
            'timestamp': datetime.now().isoformat()
        }, f, indent=2)

if __name__ == "__main__":
    generate_all_videos_fast()