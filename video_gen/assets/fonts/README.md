# Bundled Fonts Directory

This directory contains fallback fonts used when system fonts are not available.

## DejaVu Fonts

The bundled fonts are from the DejaVu font family, which are freely licensed and can be redistributed.

**License**: DejaVu fonts are licensed under a free license (see LICENSE file in DejaVu distribution)

**Website**: https://dejavu-fonts.github.io/

## Installation

To download the bundled fonts, run:

```bash
python scripts/download_fonts.py
```

This will download and extract:
- `DejaVuSans.ttf` - Regular sans-serif font (used for subtitles)
- `DejaVuSans-Bold.ttf` - Bold sans-serif font (used for titles)
- `DejaVuSansMono.ttf` - Monospace font (used for code)

## Font Resolution Order

The font resolver attempts to find fonts in this order:

1. **System fonts** - Platform-specific locations
   - Windows: `C:/Windows/Fonts/`
   - macOS: `/Library/Fonts/`, `/System/Library/Fonts/`
   - Linux: `/usr/share/fonts/`, `~/.fonts/`

2. **Bundled fonts** - This directory
   - Used when system fonts are not found

If no fonts can be found, the application will raise a `FileNotFoundError` with instructions.

## Manual Installation

If the download script fails, you can manually download DejaVu fonts from:

https://sourceforge.net/projects/dejavu/files/dejavu/2.37/dejavu-fonts-ttf-2.37.zip

Extract these files to this directory:
- `DejaVuSans.ttf`
- `DejaVuSans-Bold.ttf`
- `DejaVuSansMono.ttf`
