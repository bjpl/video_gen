"""
Video Set Generator - Batch Process Related Videos
===================================================
Process multiple related videos as a cohesive set with:
- Set-level configuration and defaults
- Organized output structure
- Batch audio generation
- Batch video rendering
- Set-level reports and manifests

Usage:
    # Generate single set
    python generate_video_set.py ../sets/tutorial_series_2024

    # Generate multiple sets
    python generate_video_set.py ../sets/tutorial_series_2024 ../sets/marketing_campaign_q1

    # Generate with custom output
    python generate_video_set.py ../sets/tutorial_series_2024 --output custom/location
"""

import os
import sys
import yaml
import json
import asyncio
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

# Add scripts directory to path
sys.path.append('.')

from unified_video_system import UnifiedVideo, UnifiedScene, VOICE_CONFIG
from unified_video_system import (
    ACCENT_ORANGE, ACCENT_BLUE, ACCENT_PURPLE,
    ACCENT_GREEN, ACCENT_PINK
)
from generate_script_from_yaml import ScriptGenerator

# Color mapping
COLOR_MAP = {
    'orange': ACCENT_ORANGE,
    'blue': ACCENT_BLUE,
    'purple': ACCENT_PURPLE,
    'green': ACCENT_GREEN,
    'pink': ACCENT_PINK
}


class VideoSet:
    """Represents a collection of related videos"""

    def __init__(self, set_dir: str):
        self.set_dir = Path(set_dir)
        self.config = None
        self.videos = []
        self.script_generator = ScriptGenerator()

        # Load set configuration
        self.load_config()

    def load_config(self):
        """Load set configuration"""
        config_file = self.set_dir / "set_config.yaml"

        if not config_file.exists():
            raise FileNotFoundError(f"Set configuration not found: {config_file}")

        with open(config_file, 'r') as f:
            self.config = yaml.safe_load(f)

        # Validate required fields
        if 'set' not in self.config:
            raise ValueError("Configuration must have 'set' section")

        set_config = self.config['set']

        if 'id' not in set_config:
            raise ValueError("Set configuration must have 'id'")

        print(f"✓ Loaded set: {set_config.get('name', set_config['id'])}")

    def get_set_id(self) -> str:
        """Get set identifier"""
        return self.config['set']['id']

    def get_set_name(self) -> str:
        """Get human-readable set name"""
        return self.config['set'].get('name', self.get_set_id())

    def get_defaults(self) -> Dict[str, Any]:
        """Get set-level defaults"""
        return self.config['set'].get('defaults', {})

    def get_output_config(self) -> Dict[str, str]:
        """Get output directory configuration"""
        set_id = self.get_set_id()
        default_output = {
            'base_dir': f"../output/{set_id}",
            'audio_dir': 'audio',
            'video_dir': 'videos',
            'script_dir': 'scripts',
            'report_dir': 'reports'
        }

        return self.config['set'].get('output', default_output)

    def get_naming_config(self) -> Dict[str, Any]:
        """Get naming convention configuration"""
        default_naming = {
            'prefix': '',
            'use_numbers': False,
            'separator': '_'
        }

        return self.config['set'].get('naming', default_naming)

    def create_output_structure(self, base_output: str = None):
        """Create output directory structure"""
        output_config = self.get_output_config()

        if base_output:
            output_config['base_dir'] = base_output

        base_dir = Path(output_config['base_dir'])

        # Create all subdirectories
        dirs = {
            'base': base_dir,
            'audio': base_dir / output_config['audio_dir'],
            'video': base_dir / output_config['video_dir'],
            'script': base_dir / output_config['script_dir'],
            'report': base_dir / output_config['report_dir']
        }

        for dir_path in dirs.values():
            dir_path.mkdir(parents=True, exist_ok=True)

        return dirs

    def load_video_files(self) -> List[Dict[str, Any]]:
        """Load all video YAML files in the set"""
        video_specs = self.config['set'].get('videos', [])
        defaults = self.get_defaults()

        videos = []

        for i, video_spec in enumerate(video_specs):
            # Get video file path
            if isinstance(video_spec, str):
                video_file = video_spec
                overrides = {}
                priority = i
            else:
                video_file = video_spec['file']
                overrides = video_spec.get('overrides', {})
                priority = video_spec.get('priority', i)

            video_path = self.set_dir / video_file

            if not video_path.exists():
                print(f"⚠️  Warning: Video file not found: {video_path}")
                continue

            # Load video YAML
            with open(video_path, 'r') as f:
                video_data = yaml.safe_load(f)

            # Apply defaults and overrides
            video_config = video_data.get('video', {})

            # Apply set defaults first
            for key, value in defaults.items():
                if key not in video_config:
                    video_config[key] = value

            # Apply video-specific overrides
            for key, value in overrides.items():
                video_config[key] = value

            # Update video data
            video_data['video'] = video_config

            # Add metadata
            video_info = {
                'file': video_file,
                'path': video_path,
                'data': video_data,
                'priority': priority,
                'index': i
            }

            videos.append(video_info)

        # Sort by priority
        videos.sort(key=lambda x: x['priority'])

        return videos

    def generate_unified_videos(self) -> List[UnifiedVideo]:
        """Generate UnifiedVideo objects from YAML files"""
        video_files = self.load_video_files()
        naming_config = self.get_naming_config()

        unified_videos = []

        for i, video_info in enumerate(video_files, 1):
            video_data = video_info['data']

            # Apply naming convention
            if naming_config.get('use_numbers'):
                prefix = naming_config.get('prefix', '')
                separator = naming_config.get('separator', '_')
                number = f"{i:02d}"

                # Update video_id with numbering
                original_id = video_data['video']['id']
                if prefix:
                    new_id = f"{prefix}{separator}{number}{separator}{original_id}"
                else:
                    new_id = f"{number}{separator}{original_id}"

                video_data['video']['id'] = new_id

            # Generate UnifiedVideo using script generator
            unified_video_dict = self.script_generator.generate_unified_video(video_data)

            # Convert to UnifiedVideo object
            unified_video = self._dict_to_unified_video(unified_video_dict)

            unified_videos.append(unified_video)

        return unified_videos

    def _dict_to_unified_video(self, video_dict: Dict[str, Any]) -> UnifiedVideo:
        """Convert dictionary to UnifiedVideo object"""
        # Convert scenes
        scenes = []
        for scene_dict in video_dict['scenes']:
            scene = UnifiedScene(
                scene_id=scene_dict['scene_id'],
                scene_type=scene_dict['scene_type'],
                visual_content=scene_dict['visual_content'],
                narration=scene_dict['narration'],
                voice=scene_dict['voice'],
                min_duration=scene_dict['min_duration'],
                max_duration=scene_dict['max_duration']
            )
            scenes.append(scene)

        # Create UnifiedVideo
        accent_color = video_dict['accent_color']
        if isinstance(accent_color, str):
            accent_color = COLOR_MAP.get(accent_color.lower(), ACCENT_BLUE)

        unified_video = UnifiedVideo(
            video_id=video_dict['video_id'],
            title=video_dict['title'],
            description=video_dict['description'],
            accent_color=accent_color,
            scenes=scenes,
            version=video_dict.get('version', 'v2.0')
        )

        return unified_video

    async def generate_set(self, output_base: str = None):
        """Generate all videos in the set"""
        print(f"\n{'='*80}")
        print(f"VIDEO SET GENERATION: {self.get_set_name()}")
        print(f"{'='*80}\n")

        # Create output structure
        output_dirs = self.create_output_structure(output_base)

        print(f"Set ID: {self.get_set_id()}")
        print(f"Output: {output_dirs['base']}\n")

        # Load and generate videos
        print("Loading video definitions...")
        unified_videos = self.generate_unified_videos()

        print(f"✓ Loaded {len(unified_videos)} videos\n")

        # Generate scripts
        print("Generating scripts...")
        for video in unified_videos:
            # Save preview
            preview_file = output_dirs['script'] / f"{video.video_id}_preview.txt"

            # Generate preview content
            video.validate()
            video.generate_preview()

            # Save validation report
            validation_file = output_dirs['report'] / f"{video.video_id}_validation.json"
            with open(validation_file, 'w') as f:
                json.dump(video.validation_report, f, indent=2)

            print(f"  ✓ {video.video_id}")

        print(f"\n✓ Scripts generated\n")

        # Generate audio with timing
        print("Generating audio with precise timing...")

        for i, video in enumerate(unified_videos, 1):
            print(f"\n[{i}/{len(unified_videos)}] {video.title}")

            await video.generate_audio_with_timing(str(output_dirs['audio']))

            # Generate timing report
            video.generate_timing_report()

            # Save metadata manifest
            manifest_file = output_dirs['report'] / f"{video.video_id}_manifest.json"
            video.save_metadata_manifest(str(output_dirs['report']))

            print(f"  ✓ Duration: {video.total_duration:.2f}s")

        print(f"\n✓ All audio generated\n")

        # Generate set manifest
        self.generate_set_manifest(unified_videos, output_dirs)

        print(f"\n{'='*80}")
        print(f"✓ SET PREPARATION COMPLETE: {self.get_set_name()}")
        print(f"{'='*80}\n")

        total_duration = sum(v.total_duration for v in unified_videos)

        print(f"Summary:")
        print(f"  Videos: {len(unified_videos)}")
        print(f"  Total Duration: {total_duration:.1f}s ({total_duration/60:.1f} min)")
        print(f"  Output: {output_dirs['base']}\n")

        print("Next steps:")
        print(f"  1. Review scripts in: {output_dirs['script']}/")
        print(f"  2. Generate videos:")
        print(f"     python generate_videos_from_set.py {output_dirs['base']}\n")

        return unified_videos, output_dirs

    def generate_set_manifest(self, videos: List[UnifiedVideo], output_dirs: Dict):
        """Generate set-level manifest"""
        manifest = {
            'set': {
                'id': self.get_set_id(),
                'name': self.get_set_name(),
                'description': self.config['set'].get('description', ''),
                'version': self.config['set'].get('version', 'v2.0')
            },
            'generated': datetime.now().isoformat(),
            'videos': [],
            'statistics': {
                'total_videos': len(videos),
                'total_duration': sum(v.total_duration for v in videos),
                'total_scenes': sum(len(v.scenes) for v in videos)
            },
            'output_structure': {
                'base': str(output_dirs['base']),
                'audio': str(output_dirs['audio']),
                'video': str(output_dirs['video']),
                'script': str(output_dirs['script']),
                'report': str(output_dirs['report'])
            }
        }

        # Add video info
        for video in videos:
            video_info = {
                'video_id': video.video_id,
                'title': video.title,
                'duration': video.total_duration,
                'scenes': len(video.scenes),
                'audio_dir': str(Path(video.audio_dir).name) if video.audio_dir else None
            }
            manifest['videos'].append(video_info)

        # Save manifest
        manifest_file = output_dirs['base'] / 'set_manifest.json'
        with open(manifest_file, 'w') as f:
            json.dump(manifest, f, indent=2)

        print(f"✓ Set manifest saved: {manifest_file}")


async def generate_sets(set_dirs: List[str], output_base: str = None):
    """Generate multiple video sets"""
    print(f"\n{'#'*80}")
    print(f"# MULTI-SET VIDEO GENERATION")
    print(f"# Processing {len(set_dirs)} video sets")
    print(f"{'#'*80}\n")

    results = []

    for i, set_dir in enumerate(set_dirs, 1):
        print(f"\n{'='*80}")
        print(f"SET {i}/{len(set_dirs)}")
        print(f"{'='*80}\n")

        try:
            video_set = VideoSet(set_dir)
            videos, output_dirs = await video_set.generate_set(output_base)

            results.append({
                'set_id': video_set.get_set_id(),
                'set_name': video_set.get_set_name(),
                'videos': len(videos),
                'status': 'success',
                'output': str(output_dirs['base'])
            })

        except Exception as e:
            print(f"\n❌ Error processing set {set_dir}: {e}\n")
            results.append({
                'set_id': Path(set_dir).name,
                'status': 'failed',
                'error': str(e)
            })

    # Summary
    print(f"\n{'#'*80}")
    print(f"# MULTI-SET GENERATION COMPLETE")
    print(f"{'#'*80}\n")

    successful = [r for r in results if r['status'] == 'success']
    failed = [r for r in results if r['status'] == 'failed']

    print(f"Results:")
    print(f"  ✓ Successful: {len(successful)}")
    print(f"  ✗ Failed: {len(failed)}\n")

    if successful:
        print("Successful sets:")
        for result in successful:
            print(f"  ✓ {result['set_name']}: {result['videos']} videos")
            print(f"    → {result['output']}")

    if failed:
        print("\nFailed sets:")
        for result in failed:
            print(f"  ✗ {result['set_id']}: {result['error']}")

    print()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Generate video sets from organized directories',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate single set
  python generate_video_set.py ../sets/tutorial_series_2024

  # Generate multiple sets
  python generate_video_set.py ../sets/tutorial_series_2024 ../sets/marketing_campaign

  # Custom output location
  python generate_video_set.py ../sets/tutorial_series_2024 --output ../custom/output
        """
    )

    parser.add_argument('sets', nargs='+', help='Set directories to process')
    parser.add_argument('--output', help='Base output directory (overrides set config)')

    args = parser.parse_args()

    # Validate set directories
    for set_dir in args.sets:
        if not Path(set_dir).exists():
            print(f"❌ Set directory not found: {set_dir}")
            sys.exit(1)

        config_file = Path(set_dir) / 'set_config.yaml'
        if not config_file.exists():
            print(f"❌ Set configuration not found: {config_file}")
            print(f"   Each set directory must contain 'set_config.yaml'")
            sys.exit(1)

    # Generate sets
    asyncio.run(generate_sets(args.sets, args.output))


if __name__ == "__main__":
    main()
