#!/usr/bin/env python3
"""
Font diagnostic utility.

Check which fonts are available and where they are located.
"""

import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from video_gen.shared.fonts import get_font_resolver


def main():
    """Run font diagnostics."""
    print("=" * 70)
    print("Font Resolution Diagnostic Tool")
    print("=" * 70)

    resolver = get_font_resolver()
    info = resolver.get_font_info()

    # Platform info
    print(f"\nPlatform: {info['platform']}")

    # Search paths
    print(f"\nFont Search Paths:")
    for path in info['search_paths']:
        path_obj = Path(path)
        exists = "✓" if path_obj.exists() else "✗"
        print(f"  {exists} {path}")

    # Bundled fonts directory
    print(f"\nBundled Fonts Directory:")
    bundled_dir = Path(info['bundled_fonts_dir'])
    exists = "✓" if bundled_dir.exists() else "✗"
    print(f"  {exists} {info['bundled_fonts_dir']}")

    if bundled_dir.exists():
        bundled_fonts = list(bundled_dir.glob("*.ttf"))
        if bundled_fonts:
            print(f"  Found {len(bundled_fonts)} bundled font(s):")
            for font in bundled_fonts:
                print(f"    • {font.name}")
        else:
            print("  ⚠ No bundled fonts found. Run: python scripts/download_fonts.py")

    # Resolved fonts
    print(f"\nResolved Fonts:")
    all_ok = True
    for category, font_info in info['resolved_fonts'].items():
        if font_info.get('path'):
            exists = "✓" if font_info.get('exists') else "✗"
            print(f"  {exists} {category:12s} → {font_info['path']}")
            if not font_info.get('exists'):
                all_ok = False
        else:
            print(f"  ✗ {category:12s} → ERROR: {font_info.get('error', 'Unknown error')}")
            all_ok = False

    # Summary
    print("\n" + "=" * 70)
    if all_ok:
        print("✓ All fonts resolved successfully!")
        print("\nYour system is ready for video generation.")
    else:
        print("✗ Some fonts could not be resolved.")
        print("\nTo fix:")
        print("  1. Run: python scripts/download_fonts.py")
        print("  2. Or install system fonts (DejaVu recommended)")
        sys.exit(1)

    print("=" * 70)


if __name__ == "__main__":
    main()
