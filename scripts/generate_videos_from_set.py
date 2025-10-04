"""
Generate Videos from Set
=========================
Render videos for a prepared video set (after audio generation).

This script:
1. Loads set manifest
2. Finds all audio/timing data
3. Generates videos with GPU encoding
4. Updates set manifest with video paths

Usage:
    # Generate videos for one set
    python generate_videos_from_set.py ../output/tutorial_series_2024

    # Generate videos for multiple sets
    python generate_videos_from_set.py ../output/tutorial_series_2024 ../output/marketing_campaign

    # Generate videos for ALL sets in output directory
    python generate_videos_from_set.py --all
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime

sys.path.append('.')

from generate_videos_from_timings_v3_simple import (
    load_timing_report,
    generate_video_from_timing_fast,
    blend_frames_fast
)
from generate_all_videos_unified_v2 import ALL_VIDEOS


class SetVideoRenderer:
    """Render videos for a video set"""

    def __init__(self, set_output_dir: str):
        self.set_output_dir = Path(set_output_dir)
        self.manifest_file = self.set_output_dir / 'set_manifest.json'
        self.manifest = None

        self.load_manifest()

    def load_manifest(self):
        """Load set manifest"""
        if not self.manifest_file.exists():
            raise FileNotFoundError(f"Set manifest not found: {self.manifest_file}")

        with open(self.manifest_file, 'r') as f:
            self.manifest = json.load(f)

        print(f"✓ Loaded set: {self.manifest['set']['name']}")

    def find_videos_to_render(self):
        """Find all videos with audio/timing data ready to render"""
        audio_dir = Path(self.manifest['output_structure']['audio'])
        videos_to_render = []

        # Scan audio directory for timing reports
        if not audio_dir.exists():
            print(f"⚠️  Audio directory not found: {audio_dir}")
            return []

        for audio_subdir in audio_dir.iterdir():
            if audio_subdir.is_dir():
                # Look for timing report
                timing_files = list(audio_subdir.glob("*_timing_*.json"))

                if timing_files:
                    # Load timing report
                    timing_file = timing_files[0]

                    with open(timing_file, 'r') as f:
                        timing_data = json.load(f)

                    videos_to_render.append({
                        'video_id': timing_data['video_id'],
                        'title': timing_data['title'],
                        'audio_dir': str(audio_subdir),
                        'timing_file': str(timing_file),
                        'timing_data': timing_data
                    })

        return videos_to_render

    def render_videos(self):
        """Render all videos in the set"""
        print(f"\n{'='*80}")
        print(f"RENDERING VIDEOS: {self.manifest['set']['name']}")
        print(f"{'='*80}\n")

        videos_to_render = self.find_videos_to_render()

        if not videos_to_render:
            print("⚠️  No videos ready to render (missing audio/timing data)\n")
            return []

        print(f"Found {len(videos_to_render)} video(s) ready to render\n")

        video_output_dir = Path(self.manifest['output_structure']['video'])
        video_output_dir.mkdir(parents=True, exist_ok=True)

        rendered_videos = []

        for i, video_info in enumerate(videos_to_render, 1):
            print(f"{'#'*80}")
            print(f"# VIDEO {i}/{len(videos_to_render)}: {video_info['title']}")
            print(f"{'#'*80}\n")

            try:
                # Create a minimal UnifiedVideo object for rendering
                # (We need this for the render function)
                from unified_video_system import UnifiedVideo, UnifiedScene

                # Reconstruct scenes from timing data
                scenes = []
                for scene_data in video_info['timing_data']['scenes']:
                    # Create minimal scene
                    scene = UnifiedScene(
                        scene_id=scene_data['scene_id'],
                        scene_type=scene_data['type'],
                        visual_content={},  # Will be filled by render function
                        narration='',  # Not needed for rendering
                        voice=scene_data['voice']
                    )

                    scene.final_duration = scene_data['duration']
                    scene.actual_audio_duration = scene_data['audio_duration']
                    scene.scene_id = scene_data['scene_id']

                    scenes.append(scene)

                # Create minimal UnifiedVideo
                video = UnifiedVideo(
                    video_id=video_info['video_id'],
                    title=video_info['title'],
                    description='',
                    accent_color=(59, 130, 246),  # Default blue
                    scenes=scenes
                )

                video.audio_dir = video_info['audio_dir']
                video.total_duration = video_info['timing_data']['total_duration']

                # Render video
                final_path = generate_video_from_timing_fast(
                    video,
                    video_info['timing_data'],
                    str(video_output_dir)
                )

                if final_path:
                    file_size = os.path.getsize(final_path) / (1024 * 1024)
                    rendered_videos.append({
                        'video_id': video_info['video_id'],
                        'title': video_info['title'],
                        'path': final_path,
                        'duration': video.total_duration,
                        'size_mb': file_size
                    })

                    print(f"✓ Rendered: {Path(final_path).name}\n")

            except Exception as e:
                print(f"❌ Error rendering {video_info['video_id']}: {e}\n")

        # Update manifest with video paths
        self.update_manifest_with_videos(rendered_videos)

        return rendered_videos

    def update_manifest_with_videos(self, rendered_videos):
        """Update set manifest with rendered video information"""
        # Add video paths to manifest
        for rendered in rendered_videos:
            # Find matching video in manifest
            for video in self.manifest['videos']:
                if video['video_id'] == rendered['video_id']:
                    video['video_path'] = rendered['path']
                    video['video_size_mb'] = rendered['size_mb']
                    break

        # Add rendering timestamp
        self.manifest['videos_rendered'] = datetime.now().isoformat()

        # Save updated manifest
        with open(self.manifest_file, 'w') as f:
            json.dump(self.manifest, f, indent=2)

        print(f"✓ Updated set manifest: {self.manifest_file}")


def render_sets(set_output_dirs: list):
    """Render videos for multiple sets"""
    print(f"\n{'#'*80}")
    print(f"# MULTI-SET VIDEO RENDERING")
    print(f"# Processing {len(set_output_dirs)} sets")
    print(f"{'#'*80}\n")

    all_results = []

    for i, set_dir in enumerate(set_output_dirs, 1):
        print(f"\n{'='*80}")
        print(f"SET {i}/{len(set_output_dirs)}")
        print(f"{'='*80}\n")

        try:
            renderer = SetVideoRenderer(set_dir)
            rendered = renderer.render_videos()

            all_results.extend(rendered)

        except Exception as e:
            print(f"❌ Error processing set {set_dir}: {e}\n")

    # Summary
    print(f"\n{'#'*80}")
    print(f"# RENDERING COMPLETE")
    print(f"{'#'*80}\n")

    if all_results:
        total_duration = sum(v['duration'] for v in all_results)
        total_size = sum(v['size_mb'] for v in all_results)

        print(f"Rendered {len(all_results)} video(s):\n")

        for video in all_results:
            print(f"  ✓ {video['video_id']:<30} {video['duration']:>6.1f}s  {video['size_mb']:>8.1f} MB")

        print(f"\n  {'TOTAL':<30} {total_duration:>6.1f}s  {total_size:>8.1f} MB\n")

    else:
        print("⚠️  No videos were rendered\n")


def discover_all_sets(output_dir: str = "../output"):
    """Discover all sets in output directory"""
    output_path = Path(output_dir)

    if not output_path.exists():
        return []

    sets = []

    for item in output_path.iterdir():
        if item.is_dir():
            manifest = item / 'set_manifest.json'
            if manifest.exists():
                sets.append(str(item))

    return sets


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Render videos from prepared set(s)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Render one set
  python generate_videos_from_set.py ../output/tutorial_series_2024

  # Render multiple sets
  python generate_videos_from_set.py ../output/tutorial_series_2024 ../output/marketing

  # Render ALL sets
  python generate_videos_from_set.py --all
        """
    )

    parser.add_argument(
        'sets',
        nargs='*',
        help='Set output directories to render'
    )

    parser.add_argument(
        '--all',
        action='store_true',
        help='Render all sets in output directory'
    )

    parser.add_argument(
        '--output-dir',
        default='../output',
        help='Output directory to scan for sets (with --all)'
    )

    args = parser.parse_args()

    # Determine which sets to render
    if args.all:
        print("Discovering sets...")
        sets_to_render = discover_all_sets(args.output_dir)

        if not sets_to_render:
            print(f"⚠️  No sets found in {args.output_dir}\n")
            return

        print(f"Found {len(sets_to_render)} set(s) to render\n")

    elif args.sets:
        sets_to_render = args.sets

    else:
        parser.print_help()
        return

    # Validate sets
    for set_dir in sets_to_render:
        if not Path(set_dir).exists():
            print(f"❌ Set directory not found: {set_dir}")
            sys.exit(1)

    # Render videos
    render_sets(sets_to_render)


if __name__ == "__main__":
    main()
