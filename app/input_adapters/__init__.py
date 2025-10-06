"""
Input Adapters
==============
Unified input parsing for video generation system.

All adapters implement BaseInputAdapter and return VideoSet objects.

Available Adapters:
- DocumentAdapter: Parse markdown/text documents
- YouTubeAdapter: Parse YouTube video transcripts
- YAMLAdapter: Parse YAML configuration files
- WizardAdapter: Interactive wizard interface
- ProgrammaticAdapter: Python VideoSetBuilder integration

Usage:
    from app.input_adapters import DocumentAdapter, VideoSet

    # Parse document
    adapter = DocumentAdapter()
    video_set = adapter.parse('README.md')
    video_set.export_to_yaml('output/my_set')

    # Parse YouTube
    from app.input_adapters import YouTubeAdapter

    adapter = YouTubeAdapter()
    video_set = adapter.parse('https://youtube.com/watch?v=VIDEO_ID')

    # Parse YAML
    from app.input_adapters import YAMLAdapter

    adapter = YAMLAdapter()
    video_set = adapter.parse('inputs/my_video.yaml')
"""

from .base import (
    BaseInputAdapter,
    VideoSet,
    VideoSetConfig,
    VideoConfig
)
from .document import DocumentAdapter
from .youtube import YouTubeAdapter
from .yaml_file import YAMLAdapter
from .wizard import WizardAdapter
from .programmatic import (
    ProgrammaticAdapter,
    create_title_scene,
    create_command_scene,
    create_list_scene,
    create_outro_scene
)

__all__ = [
    # Base classes
    'BaseInputAdapter',
    'VideoSet',
    'VideoSetConfig',
    'VideoConfig',

    # Adapters
    'DocumentAdapter',
    'YouTubeAdapter',
    'YAMLAdapter',
    'WizardAdapter',
    'ProgrammaticAdapter',

    # Helper functions
    'create_title_scene',
    'create_command_scene',
    'create_list_scene',
    'create_outro_scene',
]


# Convenience factory function
def get_adapter(input_type: str, **kwargs):
    """
    Get adapter instance by type.

    Args:
        input_type: Type of adapter ('document', 'youtube', 'yaml', 'wizard', 'programmatic')
        **kwargs: Adapter-specific configuration

    Returns:
        Adapter instance

    Example:
        adapter = get_adapter('document', max_scenes=8)
        video_set = adapter.parse('README.md')
    """
    adapters = {
        'document': DocumentAdapter,
        'youtube': YouTubeAdapter,
        'yaml': YAMLAdapter,
        'wizard': WizardAdapter,
        'programmatic': ProgrammaticAdapter,
    }

    adapter_class = adapters.get(input_type.lower())

    if not adapter_class:
        raise ValueError(
            f"Unknown adapter type: {input_type}. "
            f"Available: {', '.join(adapters.keys())}"
        )

    return adapter_class(**kwargs)
