"""
Cross-platform font resolution system.

Automatically locates fonts across Windows, macOS, and Linux systems
with intelligent fallbacks to bundled fonts.
"""

import logging
import platform
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class FontResolver:
    """Cross-platform font resolution with intelligent fallbacks.

    Searches common font directories for each operating system and provides
    bundled fallback fonts when system fonts are not available.
    """

    # Font search paths by platform
    FONT_PATHS = {
        "Windows": [
            Path("C:/Windows/Fonts"),
        ],
        "Darwin": [  # macOS
            Path("/Library/Fonts"),
            Path("/System/Library/Fonts"),
            Path.home() / "Library/Fonts",
        ],
        "Linux": [
            Path("/usr/share/fonts"),
            Path("/usr/local/share/fonts"),
            Path.home() / ".fonts",
            Path.home() / ".local/share/fonts",
        ],
    }

    # Font family mappings for different categories
    FONT_FAMILIES = {
        "title": {
            "Windows": ["arialbd.ttf", "Arial Bold.ttf"],
            "Darwin": ["Arial Bold.ttf", "Helvetica Bold.ttf", "SF-Pro-Display-Bold.otf"],
            "Linux": ["DejaVuSans-Bold.ttf", "LiberationSans-Bold.ttf", "FreeSansBold.ttf"],
        },
        "subtitle": {
            "Windows": ["arial.ttf", "Arial.ttf"],
            "Darwin": ["Arial.ttf", "Helvetica.ttf", "SF-Pro-Text-Regular.otf"],
            "Linux": ["DejaVuSans.ttf", "LiberationSans-Regular.ttf", "FreeSans.ttf"],
        },
        "code": {
            "Windows": ["consola.ttf", "Consolas.ttf"],
            "Darwin": ["Menlo.ttc", "Monaco.ttf", "Courier New.ttf"],
            "Linux": ["DejaVuSansMono.ttf", "LiberationMono-Regular.ttf", "FreeMono.ttf"],
        },
    }

    # Bundled fallback fonts (relative to this file)
    BUNDLED_FONTS_DIR = Path(__file__).parent.parent / "assets" / "fonts"

    BUNDLED_FONTS = {
        "title": "DejaVuSans-Bold.ttf",
        "subtitle": "DejaVuSans.ttf",
        "code": "DejaVuSansMono.ttf",
    }

    def __init__(self):
        """Initialize font resolver with platform detection."""
        self.platform = platform.system()
        self._font_cache: Dict[str, Optional[Path]] = {}

    def _search_font_in_paths(
        self,
        font_names: List[str],
        search_paths: List[Path]
    ) -> Optional[Path]:
        """Search for font files in the given paths.

        Args:
            font_names: List of font filenames to search for
            search_paths: List of directories to search in

        Returns:
            Path to the first found font file, or None
        """
        for search_path in search_paths:
            if not search_path.exists():
                continue

            for font_name in font_names:
                # Direct path check
                font_file = search_path / font_name
                if font_file.exists():
                    logger.debug(f"Found font: {font_file}")
                    return font_file

                # Recursive search in subdirectories (limited depth)
                try:
                    for candidate in search_path.rglob(font_name):
                        if candidate.is_file():
                            logger.debug(f"Found font in subdirectory: {candidate}")
                            return candidate
                except (PermissionError, OSError) as e:
                    logger.debug(f"Error searching {search_path}: {e}")
                    continue

        return None

    def _get_bundled_font(self, font_category: str) -> Optional[Path]:
        """Get bundled fallback font.

        Args:
            font_category: Font category (title, subtitle, code)

        Returns:
            Path to bundled font file, or None if not available
        """
        if font_category not in self.BUNDLED_FONTS:
            return None

        bundled_font = self.BUNDLED_FONTS_DIR / self.BUNDLED_FONTS[font_category]
        if bundled_font.exists():
            logger.info(f"Using bundled font for {font_category}: {bundled_font}")
            return bundled_font

        return None

    def resolve_font(self, font_category: str) -> str:
        """Resolve font path for a given category.

        Args:
            font_category: Font category (title, subtitle, code)

        Returns:
            Absolute path to font file as string

        Raises:
            FileNotFoundError: If no suitable font can be found
        """
        # Check cache first
        if font_category in self._font_cache:
            cached = self._font_cache[font_category]
            if cached:
                return str(cached)

        # Get platform-specific font names
        font_names = self.FONT_FAMILIES.get(font_category, {}).get(
            self.platform, []
        )

        if not font_names:
            logger.warning(
                f"No font names defined for {font_category} on {self.platform}"
            )

        # Get platform-specific search paths
        search_paths = self.FONT_PATHS.get(self.platform, [])

        # Search for system fonts
        font_path = self._search_font_in_paths(font_names, search_paths)

        # Fall back to bundled fonts
        if not font_path:
            logger.info(
                f"System font not found for {font_category}, trying bundled fonts"
            )
            font_path = self._get_bundled_font(font_category)

        # Cache the result
        if font_path:
            self._font_cache[font_category] = font_path
            logger.info(f"Resolved {font_category} font: {font_path}")
            return str(font_path)

        # If all else fails, raise an error
        error_msg = (
            f"Could not find font for category '{font_category}' on {self.platform}. "
            f"Searched: {', '.join(str(p) for p in search_paths)}. "
            f"Consider installing DejaVu fonts or placing fonts in {self.BUNDLED_FONTS_DIR}"
        )
        raise FileNotFoundError(error_msg)

    def resolve_all_fonts(self) -> Dict[str, str]:
        """Resolve all font categories.

        Returns:
            Dictionary mapping font categories to resolved paths

        Raises:
            FileNotFoundError: If any font cannot be resolved
        """
        fonts = {}
        for category in ["title", "subtitle", "code"]:
            fonts[category] = self.resolve_font(category)
        return fonts

    def get_font_info(self) -> Dict[str, any]:
        """Get diagnostic information about font resolution.

        Returns:
            Dictionary containing platform info and available fonts
        """
        info = {
            "platform": self.platform,
            "search_paths": [str(p) for p in self.FONT_PATHS.get(self.platform, [])],
            "bundled_fonts_dir": str(self.BUNDLED_FONTS_DIR),
            "resolved_fonts": {},
        }

        for category in ["title", "subtitle", "code"]:
            try:
                font_path = self.resolve_font(category)
                info["resolved_fonts"][category] = {
                    "path": font_path,
                    "exists": Path(font_path).exists(),
                }
            except FileNotFoundError as e:
                info["resolved_fonts"][category] = {
                    "path": None,
                    "error": str(e),
                }

        return info


# Global font resolver instance
_font_resolver: Optional[FontResolver] = None


def get_font_resolver() -> FontResolver:
    """Get global font resolver instance (singleton pattern).

    Returns:
        FontResolver instance
    """
    global _font_resolver
    if _font_resolver is None:
        _font_resolver = FontResolver()
    return _font_resolver


def resolve_font(font_category: str) -> str:
    """Convenience function to resolve a font.

    Args:
        font_category: Font category (title, subtitle, code)

    Returns:
        Absolute path to font file as string
    """
    return get_font_resolver().resolve_font(font_category)


def resolve_all_fonts() -> Dict[str, str]:
    """Convenience function to resolve all fonts.

    Returns:
        Dictionary mapping font categories to resolved paths
    """
    return get_font_resolver().resolve_all_fonts()
