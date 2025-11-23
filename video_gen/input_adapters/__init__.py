"""Input adapters for various content sources.

This module provides adapters for different input types, allowing the system
to accept content from documents, YouTube, interactive wizards, YAML files,
and programmatic APIs.
"""

from .base import InputAdapter, InputAdapterResult
from .document import DocumentAdapter
from .youtube import YouTubeAdapter
from .wizard import InteractiveWizard
from .yaml_file import YAMLFileAdapter
from .programmatic import ProgrammaticAdapter

__all__ = [
    "InputAdapter",
    "InputAdapterResult",
    "DocumentAdapter",
    "YouTubeAdapter",
    "InteractiveWizard",
    "YAMLFileAdapter",
    "ProgrammaticAdapter",
]
