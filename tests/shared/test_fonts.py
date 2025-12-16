"""
Tests for cross-platform font resolution.
"""

import platform
from pathlib import Path
import pytest

from video_gen.shared.fonts import (
    FontResolver,
    get_font_resolver,
    resolve_font,
    resolve_all_fonts,
)


class TestFontResolver:
    """Test font resolution functionality."""

    def test_font_resolver_singleton(self):
        """Font resolver should use singleton pattern."""
        resolver1 = get_font_resolver()
        resolver2 = get_font_resolver()
        assert resolver1 is resolver2

    def test_platform_detection(self):
        """Font resolver should detect current platform."""
        resolver = FontResolver()
        assert resolver.platform in ["Windows", "Darwin", "Linux"]
        assert resolver.platform == platform.system()

    def test_resolve_title_font(self):
        """Should resolve title font to valid path."""
        font_path = resolve_font("title")
        assert font_path is not None
        assert Path(font_path).exists()
        assert font_path.endswith(".ttf") or font_path.endswith(".ttc")

    def test_resolve_subtitle_font(self):
        """Should resolve subtitle font to valid path."""
        font_path = resolve_font("subtitle")
        assert font_path is not None
        assert Path(font_path).exists()
        assert font_path.endswith(".ttf") or font_path.endswith(".ttc")

    def test_resolve_code_font(self):
        """Should resolve code font to valid path."""
        font_path = resolve_font("code")
        assert font_path is not None
        assert Path(font_path).exists()
        assert font_path.endswith(".ttf") or font_path.endswith(".ttc")

    def test_resolve_all_fonts(self):
        """Should resolve all font categories."""
        fonts = resolve_all_fonts()
        assert isinstance(fonts, dict)
        assert "title" in fonts
        assert "subtitle" in fonts
        assert "code" in fonts

        # All paths should exist
        for category, path in fonts.items():
            assert Path(path).exists(), f"Font path for {category} does not exist: {path}"

    def test_font_caching(self):
        """Font paths should be cached after first resolution."""
        resolver = FontResolver()

        # First resolution
        path1 = resolver.resolve_font("title")

        # Second resolution should use cache
        path2 = resolver.resolve_font("title")

        assert path1 == path2
        assert "title" in resolver._font_cache

    def test_bundled_fonts_exist(self):
        """Bundled fallback fonts should exist."""
        bundled_dir = Path(__file__).parent.parent.parent / "video_gen" / "assets" / "fonts"

        # Check for bundled fonts
        expected_fonts = [
            "DejaVuSans.ttf",
            "DejaVuSans-Bold.ttf",
            "DejaVuSansMono.ttf",
        ]

        for font in expected_fonts:
            font_path = bundled_dir / font
            assert font_path.exists(), f"Bundled font missing: {font_path}"

    def test_get_font_info(self):
        """Should provide diagnostic font information."""
        resolver = FontResolver()
        info = resolver.get_font_info()

        assert "platform" in info
        assert "search_paths" in info
        assert "bundled_fonts_dir" in info
        assert "resolved_fonts" in info

        # Should have info for all categories
        assert "title" in info["resolved_fonts"]
        assert "subtitle" in info["resolved_fonts"]
        assert "code" in info["resolved_fonts"]

    def test_invalid_font_category(self):
        """Should handle invalid font category gracefully."""
        resolver = FontResolver()

        # Should raise FileNotFoundError for invalid category
        with pytest.raises(FileNotFoundError):
            resolver.resolve_font("invalid_category")

    @pytest.mark.parametrize("category", ["title", "subtitle", "code"])
    def test_font_categories_absolute_paths(self, category):
        """All resolved font paths should be absolute."""
        font_path = resolve_font(category)
        path = Path(font_path)
        assert path.is_absolute(), f"Font path should be absolute: {font_path}"

    def test_font_families_defined(self):
        """Font families should be defined for all platforms."""
        resolver = FontResolver()

        for category in ["title", "subtitle", "code"]:
            assert category in resolver.FONT_FAMILIES
            families = resolver.FONT_FAMILIES[category]

            # Should have mappings for major platforms
            assert "Windows" in families
            assert "Darwin" in families
            assert "Linux" in families

            # Each platform should have at least one font option
            for platform_name in ["Windows", "Darwin", "Linux"]:
                assert len(families[platform_name]) > 0


class TestConfigIntegration:
    """Test font resolution integration with config."""

    def test_config_loads_fonts(self):
        """Config should successfully load fonts."""
        from video_gen.shared.config import Config

        config = Config()
        assert hasattr(config, "fonts")
        assert isinstance(config.fonts, dict)

        # Should have all required font categories
        assert "title" in config.fonts
        assert "subtitle" in config.fonts
        assert "code" in config.fonts

        # All fonts should exist
        for category, path in config.fonts.items():
            assert Path(path).exists(), f"Config font for {category} does not exist: {path}"

    def test_config_fonts_are_absolute(self):
        """Config fonts should be absolute paths."""
        from video_gen.shared.config import Config

        config = Config()

        for category, path in config.fonts.items():
            path_obj = Path(path)
            assert path_obj.is_absolute(), f"Font path should be absolute: {path}"
