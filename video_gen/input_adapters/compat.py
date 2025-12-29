"""
Compatibility Layer for Input Adapter Migration
================================================

This module provides backward compatibility for code using the deprecated
app.input_adapters API, allowing seamless migration to the canonical
video_gen.input_adapters system.

IMPORTANT: This is NOT a duplication of functionality - it's a thin compatibility
wrapper that delegates all actual work to the canonical async adapters in:
- video_gen.input_adapters.document (DocumentAdapter)
- video_gen.input_adapters.yaml_file (YAMLFileAdapter/YAMLAdapter)
- video_gen.input_adapters.youtube (YouTubeAdapter)
- video_gen.input_adapters.wizard (InteractiveWizard)
- video_gen.input_adapters.programmatic (ProgrammaticAdapter)

Architecture:
    ┌─────────────────────────────────────────────────────────┐
    │  compat.py (THIS FILE)                                  │
    │  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
    │  • CompatAdapter: Sync wrapper base class               │
    │  • DocumentAdapter: Thin wrapper → document.py          │
    │  • YouTubeAdapter: Thin wrapper → youtube.py            │
    │  • YAMLAdapter: Thin wrapper → yaml_file.py             │
    │  • WizardAdapter: Thin wrapper → wizard.py              │
    │  • ProgrammaticAdapter: Thin wrapper → programmatic.py  │
    │                                                          │
    │  NO DUPLICATION: All logic delegated to main adapters!  │
    └─────────────────────────────────────────────────────────┘

API Translation:
    Deprecated: parse(source: str, **options) -> VideoSet (sync)
    Canonical:  async adapt(source: Any, **kwargs) -> InputAdapterResult (async)

Usage (Drop-in replacement):
    # Old code (deprecated)
    from app.input_adapters import DocumentAdapter
    adapter = DocumentAdapter()
    video_set = adapter.parse('document.md')

    # New code (with compat layer)
    from video_gen.input_adapters.compat import DocumentAdapter
    adapter = DocumentAdapter()
    video_set = adapter.parse('document.md')  # Still works!

    # Future (full async migration)
    from video_gen.input_adapters import DocumentAdapter
    adapter = DocumentAdapter()
    result = await adapter.adapt('document.md')
    video_set = result.video_set

Deprecation Warning:
    This compatibility layer is temporary and will be removed in v3.0.
    Migrate to async adapt() API for best performance and features.
"""

from __future__ import annotations  # Enable forward references for type hints

import asyncio
import warnings
from typing import Any, Optional, List

from .base import InputAdapter, InputAdapterResult
from ..shared.models import VideoSet as _VideoSet, VideoConfig as _VideoConfig, SceneConfig


class BackwardCompatibleVideoConfig:
    """Wrapper for VideoConfig providing backward-compatible scene access.

    Old API: video.scenes returns list of dicts with scene['type'], scene['title'], etc.
    New API: video.scenes returns list of SceneConfig objects with scene.scene_type, scene.title, etc.

    This wrapper makes new VideoConfig objects look like old ones by providing
    scenes as dicts while preserving all other VideoConfig attributes.
    """

    def __init__(self, video_config: _VideoConfig):
        """Wrap a VideoConfig to provide backward-compatible scene access.

        Args:
            video_config: The canonical VideoConfig object to wrap
        """
        self._video_config = video_config

    @property
    def scenes(self):
        """Return scenes as list of SceneConfig objects (preserving new API).

        This maintains scene objects as SceneConfig instances so that
        scene.voice and other attributes work correctly.
        Handles both VideoConfig objects and dicts.
        """
        # If wrapped object is a dict, return scenes from dict
        if isinstance(self._video_config, dict):
            return self._video_config.get('scenes', [])
        # Otherwise return from VideoConfig object
        return self._video_config.scenes

    def __getattr__(self, name):
        """Proxy all other attributes to the wrapped VideoConfig."""
        # If wrapped object is a dict, try dict access first
        if isinstance(self._video_config, dict):
            if name in self._video_config:
                return self._video_config[name]
            raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")
        return getattr(self._video_config, name)

    def __getitem__(self, key):
        """Make VideoConfig subscriptable for backward compatibility.

        Allows accessing video['accent_color'] etc.
        Handles both VideoConfig objects and dicts.
        """
        # If wrapped object is a dict (from programmatic adapter), use dict access
        if isinstance(self._video_config, dict):
            return self._video_config[key]
        # Otherwise use attribute access
        return getattr(self._video_config, key)

    def __repr__(self):
        # Handle both dict and object cases
        if isinstance(self._video_config, dict):
            video_id = self._video_config.get('video_id', 'unknown')
        else:
            video_id = self._video_config.video_id
        return f"BackwardCompatibleVideoConfig({video_id})"


class BackwardCompatibleVideoSet(_VideoSet):
    """Wrapper for VideoSet providing backward-compatible video access.

    Inherits from canonical VideoSet to pass isinstance checks while
    providing backward-compatible scene access throughout the video set.

    Uses __new__ to bypass dataclass initialization and manually set attributes.
    """

    def __new__(cls, video_set: _VideoSet):
        """Create new instance bypassing dataclass __init__.

        Args:
            video_set: The canonical VideoSet object to wrap

        Returns:
            New BackwardCompatibleVideoSet instance
        """
        # Create instance without calling __init__
        obj = object.__new__(cls)

        # Manually copy all attributes from wrapped VideoSet
        object.__setattr__(obj, 'set_id', video_set.set_id)
        object.__setattr__(obj, 'name', video_set.name)
        object.__setattr__(obj, 'description', video_set.description)
        object.__setattr__(obj, 'metadata', video_set.metadata)
        object.__setattr__(obj, '_video_set', video_set)
        # Don't set 'videos' directly - we override it as a property below

        return obj

    def __init__(self, video_set: _VideoSet):
        """Initialize is called after __new__, but we do nothing here."""
        pass

    @property
    def videos(self) -> List[BackwardCompatibleVideoConfig]:
        """Return videos with backward-compatible scene access."""
        return [BackwardCompatibleVideoConfig(v) for v in self._video_set.videos]

    def __repr__(self):
        return f"BackwardCompatibleVideoSet({self.set_id})"


class VideoSetConfig:
    """Backward compatibility wrapper for deprecated VideoSetConfig class.

    In the old API, VideoSet took a config parameter which was a VideoSetConfig object.
    In the new API, VideoSet is a dataclass with direct fields.

    This wrapper allows old test code to continue working by storing the config data
    and allowing VideoSet to extract it when needed.

    Example (old API that still works):
        >>> config = VideoSetConfig(set_id='test', set_name='Test Set')
        >>> video_set = VideoSet(config=config, videos=[...])

    New API (recommended):
        >>> video_set = VideoSet(set_id='test', name='Test Set', videos=[...])
    """

    def __init__(
        self,
        set_id: str,
        set_name: str,
        description: str = "",
        **kwargs
    ):
        """Initialize VideoSetConfig with old API parameters.

        Args:
            set_id: Unique identifier for the video set
            set_name: Human-readable name for the set
            description: Optional description of the set
            **kwargs: Additional metadata (stored but not used)
        """
        self.set_id = set_id
        self.set_name = set_name
        self.description = description
        self.metadata = kwargs

        # Emit deprecation warning
        warnings.warn(
            "VideoSetConfig is deprecated. Use VideoSet dataclass directly with "
            "VideoSet(set_id='...', name='...', videos=[...]). "
            "This compatibility wrapper will be removed in v3.0.",
            DeprecationWarning,
            stacklevel=2
        )


class CompatAdapter:
    """Synchronous wrapper providing deprecated .parse() API.

    Wraps canonical async InputAdapter to provide backward-compatible
    synchronous .parse() method. Internally runs async adapt() in
    sync context using asyncio.run().

    Args:
        async_adapter: The canonical async InputAdapter to wrap

    Example:
        >>> from video_gen.input_adapters import DocumentAdapter as AsyncDoc
        >>> compat = CompatAdapter(AsyncDoc())
        >>> video_set = compat.parse('document.md')  # Synchronous!
    """

    def __init__(self, async_adapter: InputAdapter):
        self._adapter = async_adapter
        self._warned = False

    def parse(self, source: str, **options) -> VideoSet:
        """Synchronous parse method (deprecated pattern).

        This method provides backward compatibility with the deprecated
        app.input_adapters.parse() API by:
        1. Running async adapt() in sync context
        2. Extracting VideoSet from InputAdapterResult
        3. Raising exceptions on failure (legacy behavior)

        Args:
            source: Input source path or content
            **options: Adapter-specific options

        Returns:
            VideoSet structure

        Raises:
            ValueError: If adapter fails (legacy exception pattern)
            RuntimeError: If async event loop issues occur

        Warning:
            This method is deprecated and will be removed in v3.0.
            Use async adapt() API for better error handling and performance.
        """
        # Emit deprecation warning (once per adapter instance)
        if not self._warned:
            warnings.warn(
                f"{self._adapter.__class__.__name__}.parse() is deprecated. "
                "Use async adapt() for better error handling and performance. "
                "This compatibility layer will be removed in v3.0.",
                DeprecationWarning,
                stacklevel=2
            )
            self._warned = True

        try:
            # Run async adapt() in sync context
            result = asyncio.run(self._adapter.adapt(source, **options))
        except RuntimeError as e:
            # Handle case where event loop already running
            if 'asyncio.run() cannot be called from a running event loop' in str(e):
                # Create new loop in thread
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(
                        asyncio.run,
                        self._adapter.adapt(source, **options)
                    )
                    result = future.result()
            else:
                raise

        # Extract VideoSet or raise exception (legacy behavior)
        if not result.success:
            error_msg = result.error or "Adapter failed without error message"
            raise ValueError(f"Adapter failed: {error_msg}")

        if result.video_set is None:
            raise ValueError("Adapter succeeded but returned no VideoSet")

        # Wrap in backward-compatible wrapper
        return BackwardCompatibleVideoSet(result.video_set)

    def __repr__(self) -> str:
        return f"CompatAdapter({self._adapter})"


# ═══════════════════════════════════════════════════════════════════════════
#  Drop-in Replacement Adapters (Thin Wrappers)
# ═══════════════════════════════════════════════════════════════════════════
# These classes are THIN WRAPPERS that delegate to canonical async adapters.
# They provide ONLY:
#   1. Backward-compatible sync .parse() API via CompatAdapter base class
#   2. Constructor parameter forwarding to canonical adapters
#   3. NO business logic - ALL work done by canonical adapters
# ═══════════════════════════════════════════════════════════════════════════

class DocumentAdapter(CompatAdapter):
    """Backward-compatible DocumentAdapter.

    THIN WRAPPER: Delegates to video_gen.input_adapters.document.DocumentAdapter
    Provides ONLY sync .parse() API - all business logic in canonical adapter.

    Args:
        test_mode: If True, bypass security checks for testing purposes
        use_ai: If True, use AI enhancement for narration (default: True)

    Example:
        >>> adapter = DocumentAdapter()
        >>> video_set = adapter.parse('README.md')
        >>> print(video_set.videos[0].title)
    """

    def __init__(self, test_mode: bool = False, use_ai: bool = True):
        from .document import DocumentAdapter as AsyncDocumentAdapter
        # Import and wrap canonical async adapter
        super().__init__(AsyncDocumentAdapter(test_mode=test_mode, use_ai=use_ai))


class YouTubeAdapter(CompatAdapter):
    """Backward-compatible YouTubeAdapter.

    THIN WRAPPER: Delegates to video_gen.input_adapters.youtube.YouTubeAdapter
    Provides ONLY sync .parse() API - all business logic in canonical adapter.

    Args:
        test_mode: If True, bypass external API calls for testing purposes

    Example:
        >>> adapter = YouTubeAdapter()
        >>> video_set = adapter.parse('https://youtube.com/watch?v=abc123')
    """

    def __init__(self, test_mode: bool = False):
        from .youtube import YouTubeAdapter as AsyncYouTubeAdapter
        # Import and wrap canonical async adapter
        super().__init__(AsyncYouTubeAdapter(test_mode=test_mode))

    def _extract_video_id(self, url: str) -> str | None:
        """Extract single video ID from YouTube URL.

        Convenience method for extracting a single video ID.
        Delegates to the canonical YouTubeAdapter._extract_video_ids method.

        Args:
            url: YouTube URL

        Returns:
            Video ID string or None if extraction fails
        """
        # Delegate to canonical adapter (no duplication)
        video_ids = self._adapter._extract_video_ids(url)
        return video_ids[0] if video_ids else None


class YAMLAdapter(CompatAdapter):
    """Backward-compatible YAMLAdapter.

    THIN WRAPPER: Delegates to video_gen.input_adapters.yaml_file.YAMLFileAdapter
    Provides ONLY sync .parse() API - all business logic in canonical adapter.

    Args:
        test_mode: If True, bypass security checks for testing purposes
        use_ai: Ignored (YAML adapter doesn't use AI - included for API compatibility)

    Example:
        >>> adapter = YAMLAdapter()
        >>> video_set = adapter.parse('inputs/my_video.yaml')
    """

    def __init__(self, test_mode: bool = False, use_ai: bool = True):
        from .yaml_file import YAMLFileAdapter as AsyncYAMLAdapter
        # YAML adapter doesn't support use_ai (it's for structured data)
        # Import and wrap canonical async adapter
        super().__init__(AsyncYAMLAdapter(test_mode=test_mode))


class WizardAdapter(CompatAdapter):
    """Backward-compatible WizardAdapter.

    THIN WRAPPER: Delegates to video_gen.input_adapters.wizard.InteractiveWizard
    Provides ONLY sync .parse() API - all business logic in canonical adapter.

    Args:
        test_mode: If True, bypass interactive prompts for testing purposes

    Example:
        >>> adapter = WizardAdapter()
        >>> video_set = adapter.parse()  # Interactive prompts
    """

    def __init__(self, test_mode: bool = False):
        from .wizard import InteractiveWizard as AsyncWizard
        # Import and wrap canonical async adapter
        super().__init__(AsyncWizard(test_mode=test_mode))


class ProgrammaticAdapter(CompatAdapter):
    """Backward-compatible ProgrammaticAdapter.

    THIN WRAPPER: Delegates to video_gen.input_adapters.programmatic.ProgrammaticAdapter
    Provides ONLY sync .parse() API - all business logic in canonical adapter.

    Example:
        >>> adapter = ProgrammaticAdapter()
        >>> video_set = adapter.parse(builder_data)
    """

    def __init__(self, test_mode: bool = False):
        from .programmatic import ProgrammaticAdapter as AsyncProgrammatic
        # Import and wrap canonical async adapter
        super().__init__(AsyncProgrammatic(test_mode=test_mode))


# Re-export wrapped models with backward-compatible names
VideoSet = BackwardCompatibleVideoSet
VideoConfig = BackwardCompatibleVideoConfig

# Export all for easy migration (including model classes for backward compatibility)
__all__ = [
    # Core compatibility layer
    "CompatAdapter",
    "BackwardCompatibleVideoConfig",
    "BackwardCompatibleVideoSet",

    # Drop-in replacement adapters
    "DocumentAdapter",
    "YouTubeAdapter",
    "YAMLAdapter",
    "WizardAdapter",
    "ProgrammaticAdapter",

    # Re-export model classes for convenience
    "VideoSet",  # Actually BackwardCompatibleVideoSet
    "VideoConfig",  # Actually BackwardCompatibleVideoConfig
    "VideoSetConfig",  # Backward compatibility wrapper
    "SceneConfig",
    "InputAdapterResult",
]


# Adapter factory function (for backward compatibility)
def get_adapter(adapter_type: str):
    """Get adapter by type name (deprecated pattern).

    Args:
        adapter_type: Adapter type ('document', 'youtube', 'yaml', 'wizard', 'programmatic')

    Returns:
        Adapter instance

    Raises:
        ValueError: If adapter type unknown
    """
    adapters = {
        'document': DocumentAdapter,
        'youtube': YouTubeAdapter,
        'yaml': YAMLAdapter,
        'wizard': WizardAdapter,
        'programmatic': ProgrammaticAdapter,
    }

    adapter_class = adapters.get(adapter_type.lower())
    if not adapter_class:
        raise ValueError(f"Unknown adapter type: {adapter_type}")

    return adapter_class()


__all__.append("get_adapter")


# Module-level deprecation warning
warnings.warn(
    "video_gen.input_adapters.compat is a temporary compatibility layer. "
    "Migrate to async adapt() API for best performance. "
    "This module will be removed in v3.0.",
    DeprecationWarning,
    stacklevel=2
)
