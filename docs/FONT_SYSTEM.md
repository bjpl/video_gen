# Cross-Platform Font System

## Overview

The video generation system includes a robust cross-platform font resolution system that automatically locates appropriate fonts on Windows, macOS, and Linux systems, with intelligent fallback to bundled fonts when system fonts are unavailable.

## Architecture

### Font Resolver (`video_gen/shared/fonts.py`)

The `FontResolver` class handles all font resolution logic:

1. **Platform Detection**: Automatically detects the operating system
2. **System Font Search**: Searches platform-specific font directories
3. **Bundled Fallbacks**: Falls back to bundled DejaVu fonts
4. **Caching**: Caches resolved paths for performance
5. **Error Handling**: Provides clear error messages with troubleshooting steps

### Font Categories

Three font categories are used throughout the system:

- **Title**: Bold sans-serif font for headings and titles
- **Subtitle**: Regular sans-serif font for body text and subtitles
- **Code**: Monospace font for code blocks and technical content

### Search Order

For each font category, the resolver searches in this order:

1. **System fonts** in platform-specific locations:
   - Windows: `C:/Windows/Fonts/`
   - macOS: `/Library/Fonts/`, `/System/Library/Fonts/`, `~/Library/Fonts/`
   - Linux: `/usr/share/fonts/`, `/usr/local/share/fonts/`, `~/.fonts/`, `~/.local/share/fonts/`

2. **Bundled fonts** in `video_gen/assets/fonts/`:
   - `DejaVuSans-Bold.ttf` (title)
   - `DejaVuSans.ttf` (subtitle)
   - `DejaVuSansMono.ttf` (code)

3. **Error** if no suitable font found (with installation instructions)

## Platform-Specific Fonts

### Windows

**Title**: Arial Bold (`arialbd.ttf`)
**Subtitle**: Arial (`arial.ttf`)
**Code**: Consolas (`consola.ttf`)

### macOS

**Title**: Arial Bold, Helvetica Bold, or SF Pro Display Bold
**Subtitle**: Arial, Helvetica, or SF Pro Text Regular
**Code**: Menlo, Monaco, or Courier New

### Linux

**Title**: DejaVu Sans Bold, Liberation Sans Bold, or FreeSans Bold
**Subtitle**: DejaVu Sans, Liberation Sans Regular, or FreeSans
**Code**: DejaVu Sans Mono, Liberation Mono Regular, or FreeMono

## Bundled Fonts

The system includes DejaVu fonts as bundled fallbacks. These are high-quality, freely-licensed fonts that work on all platforms.

### License

DejaVu fonts are licensed under a free license and can be redistributed. See the DejaVu fonts project for license details: https://dejavu-fonts.github.io/

### Installation

Bundled fonts can be downloaded automatically:

```bash
python scripts/download_fonts.py
```

This downloads and extracts the necessary DejaVu font files to `video_gen/assets/fonts/`.

### Manual Installation

If automatic download fails, manually download from:
https://sourceforge.net/projects/dejavu/files/dejavu/2.37/dejavu-fonts-ttf-2.37.zip

Extract these files to `video_gen/assets/fonts/`:
- `DejaVuSans.ttf`
- `DejaVuSans-Bold.ttf`
- `DejaVuSansMono.ttf`

## Configuration Integration

The font resolver is integrated into the global configuration system:

```python
from video_gen.shared.config import config

# Fonts are automatically resolved at config initialization
title_font = config.fonts["title"]      # e.g., "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
subtitle_font = config.fonts["subtitle"] # e.g., "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
code_font = config.fonts["code"]         # e.g., "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
```

If font resolution fails during config initialization, a warning is logged and fallback paths are used.

## Usage Examples

### Basic Usage

```python
from video_gen.shared.fonts import resolve_font, resolve_all_fonts

# Resolve a single font
title_font = resolve_font("title")
# Returns: "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

# Resolve all fonts
fonts = resolve_all_fonts()
# Returns: {
#   "title": "/usr/share/fonts/...",
#   "subtitle": "/usr/share/fonts/...",
#   "code": "/usr/share/fonts/..."
# }
```

### Diagnostic Information

```python
from video_gen.shared.fonts import get_font_resolver

resolver = get_font_resolver()
info = resolver.get_font_info()

print(f"Platform: {info['platform']}")
print(f"Search paths: {info['search_paths']}")
print(f"Resolved fonts: {info['resolved_fonts']}")
```

### CLI Diagnostic Tool

Check font resolution status:

```bash
python scripts/check_fonts.py
```

Output:
```
======================================================================
Font Resolution Diagnostic Tool
======================================================================

Platform: Linux

Font Search Paths:
  ✓ /usr/share/fonts
  ✓ /usr/local/share/fonts
  ✗ /home/user/.fonts
  ✗ /home/user/.local/share/fonts

Bundled Fonts Directory:
  ✓ /path/to/video_gen/assets/fonts
  Found 3 bundled font(s):
    • DejaVuSans-Bold.ttf
    • DejaVuSans.ttf
    • DejaVuSansMono.ttf

Resolved Fonts:
  ✓ title        → /usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf
  ✓ subtitle     → /usr/share/fonts/truetype/dejavu/DejaVuSans.ttf
  ✓ code         → /usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf

======================================================================
✓ All fonts resolved successfully!

Your system is ready for video generation.
======================================================================
```

## Troubleshooting

### "FileNotFoundError: Could not find font for category"

This error occurs when no suitable font can be found for a category.

**Solution 1**: Download bundled fonts
```bash
python scripts/download_fonts.py
```

**Solution 2**: Install system fonts

**On Linux**:
```bash
sudo apt-get install fonts-dejavu
# or
sudo dnf install dejavu-sans-fonts
```

**On macOS**:
System fonts should already be available. If not, install DejaVu fonts via Homebrew:
```bash
brew install --cask font-dejavu
```

**On Windows**:
Arial and Consolas should be pre-installed. If missing, install them through Windows Settings.

### Font verification

Check which fonts are available:
```bash
python scripts/check_fonts.py
```

### Custom fonts

To use custom fonts, you can:

1. Install them in system font directories
2. Place them in `video_gen/assets/fonts/` and update `FontResolver.BUNDLED_FONTS`
3. Override fonts after config initialization:

```python
from video_gen.shared.config import config

config.fonts["title"] = "/path/to/custom/font.ttf"
```

## Testing

The font system includes comprehensive tests:

```bash
# Run font resolution tests
pytest tests/shared/test_fonts.py -v

# Test specific functionality
pytest tests/shared/test_fonts.py::TestFontResolver::test_resolve_all_fonts -v
```

Test coverage includes:
- Platform detection
- Font resolution for all categories
- Caching behavior
- Bundled font fallbacks
- Config integration
- Error handling

## Implementation Details

### Font Search Algorithm

```python
def resolve_font(category: str) -> str:
    # 1. Check cache
    if category in cache:
        return cache[category]

    # 2. Get platform-specific font names
    font_names = FONT_FAMILIES[category][platform]

    # 3. Search in platform-specific paths
    for search_path in FONT_PATHS[platform]:
        for font_name in font_names:
            if (search_path / font_name).exists():
                cache[category] = str(search_path / font_name)
                return cache[category]

    # 4. Fall back to bundled fonts
    bundled_font = BUNDLED_FONTS_DIR / BUNDLED_FONTS[category]
    if bundled_font.exists():
        cache[category] = str(bundled_font)
        return cache[category]

    # 5. Raise error with instructions
    raise FileNotFoundError(f"Could not find font for '{category}'...")
```

### Singleton Pattern

The font resolver uses a singleton pattern to ensure consistent resolution across the application:

```python
_font_resolver: Optional[FontResolver] = None

def get_font_resolver() -> FontResolver:
    global _font_resolver
    if _font_resolver is None:
        _font_resolver = FontResolver()
    return _font_resolver
```

## Performance

- **Caching**: Resolved font paths are cached for performance
- **Lazy Loading**: Fonts are only resolved when requested
- **Single Initialization**: Config initializes fonts once at startup
- **No Runtime Overhead**: Font resolution happens once per application lifetime

## Migration Guide

### Migrating from Hardcoded Paths

**Before** (config.py):
```python
self.fonts = {
    "title": "C:/Windows/Fonts/arialbd.ttf",
    "subtitle": "C:/Windows/Fonts/arial.ttf",
    "code": "C:/Windows/Fonts/consola.ttf",
}
```

**After** (config.py):
```python
from video_gen.shared.fonts import resolve_all_fonts

try:
    self.fonts = resolve_all_fonts()
except Exception as e:
    logger.warning(f"Font resolution failed: {e}")
    # Fallback behavior
```

No other code changes required - all existing code that uses `config.fonts` continues to work.

## Future Enhancements

Potential future improvements:

- Support for custom font directories via environment variables
- Font metrics validation (ensure fonts have required glyphs)
- Font subsetting to reduce bundle size
- Additional font categories (e.g., handwriting, serif)
- Font rendering quality settings
- Font preloading for faster startup

## References

- DejaVu Fonts: https://dejavu-fonts.github.io/
- Platform font locations: https://en.wikipedia.org/wiki/Font_management
- TTF format specification: https://developer.apple.com/fonts/TrueType-Reference-Manual/
