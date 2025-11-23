"""
Generate All Video Sets
========================
Automatically discover and generate all video sets in the sets/ directory.

This script:
1. Scans sets/ directory for all set configurations
2. Processes each set in sequence
3. Generates comprehensive multi-set report

Usage:
    python generate_all_sets.py
    python generate_all_sets.py --sets-dir ../custom/sets
    python generate_all_sets.py --output ../custom/output
"""

import os
import sys
import asyncio
from pathlib import Path
from datetime import datetime
import json
import logging

# Setup logging
logger = logging.getLogger(__name__)


sys.path.append('.')

from generate_video_set import generate_sets


def discover_sets(sets_dir: str = "../sets") -> list:
    """
    Discover all video sets in the sets directory.
    A valid set must have a set_config.yaml file.
    """
    sets_path = Path(sets_dir)

    if not sets_path.exists():
        logger.error(f"❌ Sets directory not found: {sets_path}")
        logger.info(f"   Creating directory: {sets_path}")
        sets_path.mkdir(parents=True, exist_ok=True)
        return []

    discovered_sets = []

    # Look for directories containing set_config.yaml
    for item in sets_path.iterdir():
        if item.is_dir():
            config_file = item / "set_config.yaml"
            if config_file.exists():
                discovered_sets.append(str(item))

    return discovered_sets


async def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Discover and generate all video sets',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '--sets-dir',
        default='../sets',
        help='Directory containing video sets (default: ../sets)'
    )

    parser.add_argument(
        '--output',
        help='Base output directory (overrides set configs)'
    )

    parser.add_argument(
        '--list',
        action='store_true',
        help='List discovered sets and exit'
    )

    args = parser.parse_args()

    # Discover sets
    logger.info(f"\n{'='*80}")
    logger.info(f"DISCOVERING VIDEO SETS")
    logger.info(f"{'='*80}\n")

    logger.info(f"Scanning: {args.sets_dir}")

    discovered = discover_sets(args.sets_dir)

    if not discovered:
        logger.warning(f"\n⚠️  No video sets found in {args.sets_dir}")
        logger.info(f"   Create a set with: mkdir -p {args.sets_dir}/my_set")
        logger.info(f"   Then add: {args.sets_dir}/my_set/set_config.yaml\n")
        return

    logger.info(f"\n✓ Found {len(discovered)} video set(s):\n")

    for i, set_path in enumerate(discovered, 1):
        set_name = Path(set_path).name
        logger.info(f"  {i}. {set_name}")

        # Count video files
        yaml_files = list(Path(set_path).glob("*.yaml"))
        # Exclude set_config.yaml
        video_files = [f for f in yaml_files if f.name != "set_config.yaml"]
        logger.info(f"     → {len(video_files)} video file(s)")

    logger.info()

    # If --list flag, exit here
    if args.list:
        logger.info("Use: python generate_all_sets.py (to generate all sets)\n")
        return

    # Confirm generation
    response = input(f"Generate all {len(discovered)} sets? (y/N): ").strip().lower()

    if response != 'y':
        logger.warning("\n⚠️  Generation cancelled\n")
        return

    # Generate all sets
    await generate_sets(discovered, args.output)

    # Save master index
    save_master_index(args.sets_dir, args.output or "../output")


def save_master_index(sets_dir: str, output_dir: str):
    """Save master index of all sets"""
    sets_path = Path(sets_dir)
    output_path = Path(output_dir)

    master_index = {
        'generated': datetime.now().isoformat(),
        'sets_directory': str(sets_path),
        'output_directory': str(output_path),
        'sets': []
    }

    # Scan output directory for set manifests
    for set_output in output_path.iterdir():
        if set_output.is_dir():
            manifest_file = set_output / 'set_manifest.json'

            if manifest_file.exists():
                with open(manifest_file, 'r') as f:
                    manifest = json.load(f)

                master_index['sets'].append({
                    'set_id': manifest['set']['id'],
                    'set_name': manifest['set']['name'],
                    'videos': manifest['statistics']['total_videos'],
                    'duration': manifest['statistics']['total_duration'],
                    'output': str(set_output)
                })

    # Save master index
    index_file = output_path / 'master_index.json'
    with open(index_file, 'w') as f:
        json.dump(master_index, f, indent=2)

    logger.info(f"\n✓ Master index saved: {index_file}\n")


if __name__ == "__main__":
    asyncio.run(main())
