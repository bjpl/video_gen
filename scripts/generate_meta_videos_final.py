"""
Generate Final Videos for Meta-Documentation
=============================================
Uses the timing reports from meta_docs_videos_manual.py to generate final videos
"""

import json
import os
import subprocess
import shutil
import numpy as np
from PIL import Image
from datetime import datetime
import logging

# Setup logging
logger = logging.getLogger(__name__)


from generate_documentation_videos import (
    create_title_keyframes, create_command_keyframes,
    create_list_keyframes, create_outro_keyframes,
    create_code_comparison_keyframes, create_quote_keyframes,
    ease_out_cubic, FPS, WIDTH, HEIGHT
)

from meta_docs_videos_manual import ALL_VIDEOS

FFMPEG_PATH = "C:/Users/brand/AppData/Local/Programs/Python/Python310/lib/site-packages/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe"
TRANSITION_DURATION = 0.5
ANIM_DURATION = 1.0

def blend_frames_fast(img1, img2, progress):
    """NumPy-accelerated blending"""
    arr1 = np.array(img1, dtype=np.float32)
    arr2 = np.array(img2, dtype=np.float32)
    blended = arr1 * (1 - progress) + arr2 * progress
    return Image.fromarray(blended.astype('uint8'), 'RGB')

def load_timing_report(video):
    """Load timing report for video"""
    timing_files = [f for f in os.listdir(video.audio_dir) if '_timing_' in f and f.endswith('.json')]
    if not timing_files:
        raise FileNotFoundError(f"No timing report in {video.audio_dir}")

    with open(os.path.join(video.audio_dir, timing_files[0]), 'r') as f:
        return json.load(f)

def generate_video(video, timing_data, output_dir):
    """Generate single video"""
    logger.info(f"\n{'='*80}")
    logger.info(f"GENERATING: {video.title}")
    logger.info(f"{'='*80}\n")

    temp_dir = f"temp_meta_{video.video_id}"
    os.makedirs(temp_dir, exist_ok=True)

    frame_paths = []
    frame_idx = 0
    trans_frames = int(TRANSITION_DURATION * FPS)
    anim_frames = int(ANIM_DURATION * FPS)

    for scene_num, (scene, scene_timing) in enumerate(zip(video.scenes, timing_data['scenes'])):
        logger.info(f"[{scene_num + 1}/{len(video.scenes)}] {scene.scene_id} ({scene_timing['duration']:.2f}s)")

        # Generate keyframes based on scene type
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

        # Animation frames
        for i in range(anim_frames):
            progress = ease_out_cubic(i / anim_frames)
            blended = blend_frames_fast(start_frame, end_frame, progress)
            filename = f"{temp_dir}/frame_{frame_idx:05d}.png"
            blended.save(filename, "PNG", compress_level=1)
            frame_paths.append(filename)
            frame_idx += 1

        # Hold frames
        total_scene_frames = int(scene_timing['duration'] * FPS)
        hold_frames = total_scene_frames - anim_frames
        if scene_num < len(video.scenes) - 1:
            hold_frames -= trans_frames

        for _ in range(hold_frames):
            frame_paths.append(filename)

        # Transition to next scene
        if scene_num < len(video.scenes) - 1:
            next_scene = video.scenes[scene_num + 1]

            # Generate next scene's start frame
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
                    video.accent_color
                )
            elif next_scene.scene_type == 'quote':
                next_start, _ = create_quote_keyframes(
                    next_scene.visual_content['quote_text'],
                    next_scene.visual_content['attribution'],
                    video.accent_color
                )

            # Blend transition
            for i in range(trans_frames):
                progress = i / trans_frames
                blended = blend_frames_fast(end_frame, next_start, progress)
                filename = f"{temp_dir}/frame_{frame_idx:05d}.png"
                blended.save(filename, "PNG", compress_level=1)
                frame_paths.append(filename)
                frame_idx += 1

    logger.info(f"\n  Total frames: {len(frame_paths)} ({len(frame_paths)/FPS:.1f}s)")

    # Create concat file
    concat_file = f"{temp_dir}/concat.txt"
    with open(concat_file, 'w') as f:
        for i, fp in enumerate(frame_paths):
            f.write(f"file '{os.path.abspath(fp)}'\n")
            if i < len(frame_paths) - 1:
                f.write(f"duration {1/FPS}\n")
        f.write(f"file '{os.path.abspath(frame_paths[-1])}'\n")

    # Encode video
    silent_video = f"../videos/unified_v3_fast/{video.video_id}_silent.mp4"
    os.makedirs("../videos/unified_v3_fast", exist_ok=True)

    logger.info(f"  Encoding with GPU...")

    subprocess.run([
        FFMPEG_PATH,
        "-y", "-f", "concat", "-safe", "0", "-i", concat_file,
        "-c:v", "h264_nvenc",
        "-preset", "p4",
        "-tune", "hq",
        "-rc", "vbr",
        "-cq", "20",
        "-b:v", "8M",
        "-pix_fmt", "yuv420p",
        silent_video
    ], capture_output=True)

    # Process audio
    audio_files = [os.path.join(video.audio_dir, f"{scene.scene_id}.mp3") for scene in video.scenes]
    audio_concat = f"{temp_dir}/audio_concat.txt"

    with open(audio_concat, 'w') as f:
        for af in audio_files:
            f.write(f"file '{os.path.abspath(af)}'\n")

    # Final video
    final_video = f"../videos/unified_v3_fast/{video.video_id}_with_audio.mp4"

    logger.info(f"  Processing audio...")

    subprocess.run([
        FFMPEG_PATH,
        "-y",
        "-i", silent_video,
        "-f", "concat", "-safe", "0", "-i", audio_concat,
        "-c:v", "copy",
        "-af", f"adelay={int(ANIM_DURATION * 1000)}:all=1,afade=t=in:st={ANIM_DURATION}:d=0.3",
        "-c:a", "aac",
        "-b:a", "192k",
        final_video
    ], capture_output=True)

    file_size = os.path.getsize(final_video) / (1024 * 1024)
    logger.info(f"  ✓ Complete: {file_size:.1f} MB\n")

    # Cleanup
    shutil.rmtree(temp_dir)

    return final_video

def main():
    logger.info("\n" + "="*80)
    logger.info("GENERATING META-DOCUMENTATION VIDEOS")
    logger.info("="*80 + "\n")

    output_dir = "../videos/unified_v3_fast"
    audio_base = "../audio/unified_system_v2"

    for video in ALL_VIDEOS:
        try:
            # Find audio directory for this video
            sanitized_id = video.video_id.replace("_", "-")
            audio_dirs = [d for d in os.listdir(audio_base)
                         if d.startswith(sanitized_id) and os.path.isdir(os.path.join(audio_base, d))]

            if not audio_dirs:
                logger.error(f"❌ No audio directory found for {video.video_id}")
                continue

            video.audio_dir = os.path.join(audio_base, audio_dirs[0])
            logger.info(f"Found audio: {os.path.basename(video.audio_dir)}")

            timing_data = load_timing_report(video)
            final_path = generate_video(video, timing_data, output_dir)
            logger.info(f"✅ Video created: {os.path.basename(final_path)}")
        except Exception as e:
            logger.error(f"❌ Error: {e}")

    logger.info("\n" + "="*80)
    logger.info("✓ ALL VIDEOS COMPLETE")
    logger.info("="*80 + "\n")

if __name__ == "__main__":
    main()
