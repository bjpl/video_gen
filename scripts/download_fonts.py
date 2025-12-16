#!/usr/bin/env python3
"""
Download bundled fallback fonts (DejaVu family).

DejaVu fonts are licensed under a free license and can be redistributed.
This script downloads them from the official SourceForge repository.
"""

import logging
import sys
import zipfile
from pathlib import Path
from urllib.request import urlretrieve

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# DejaVu fonts download URL
DEJAVU_VERSION = "2.37"
DEJAVU_URL = f"https://sourceforge.net/projects/dejavu/files/dejavu/{DEJAVU_VERSION}/dejavu-fonts-ttf-{DEJAVU_VERSION}.zip/download"

# Destination directory
FONTS_DIR = Path(__file__).parent.parent / "video_gen" / "assets" / "fonts"

# Fonts we need
REQUIRED_FONTS = [
    "DejaVuSans.ttf",
    "DejaVuSans-Bold.ttf",
    "DejaVuSansMono.ttf",
]


def download_dejavu_fonts():
    """Download and extract DejaVu fonts."""
    # Create fonts directory
    FONTS_DIR.mkdir(parents=True, exist_ok=True)

    # Check if fonts already exist
    existing = [f for f in REQUIRED_FONTS if (FONTS_DIR / f).exists()]
    if len(existing) == len(REQUIRED_FONTS):
        logger.info("All required fonts already exist. Skipping download.")
        for font in REQUIRED_FONTS:
            logger.info(f"  ✓ {font}")
        return

    logger.info(f"Downloading DejaVu fonts version {DEJAVU_VERSION}...")

    # Download zip file to temp location
    temp_zip = FONTS_DIR / "dejavu_temp.zip"
    try:
        urlretrieve(DEJAVU_URL, temp_zip)
        logger.info(f"Downloaded to {temp_zip}")
    except Exception as e:
        logger.error(f"Failed to download fonts: {e}")
        logger.error("You may need to download them manually from:")
        logger.error(f"  {DEJAVU_URL}")
        sys.exit(1)

    # Extract required fonts
    logger.info("Extracting fonts...")
    try:
        with zipfile.ZipFile(temp_zip, "r") as zip_ref:
            # List all files in the zip
            all_files = zip_ref.namelist()

            for font in REQUIRED_FONTS:
                # Find the font in the zip (it's in a subdirectory)
                font_path = next(
                    (f for f in all_files if f.endswith(f"ttf/{font}")),
                    None
                )

                if font_path:
                    # Extract to our fonts directory
                    source = zip_ref.open(font_path)
                    dest = FONTS_DIR / font

                    with open(dest, "wb") as f:
                        f.write(source.read())

                    logger.info(f"  ✓ Extracted {font}")
                else:
                    logger.warning(f"  ✗ Could not find {font} in archive")

    except Exception as e:
        logger.error(f"Failed to extract fonts: {e}")
        sys.exit(1)
    finally:
        # Clean up temp file
        if temp_zip.exists():
            temp_zip.unlink()
            logger.info("Cleaned up temporary files")

    logger.info("Font installation complete!")


if __name__ == "__main__":
    download_dejavu_fonts()
