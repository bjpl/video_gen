"""
Pydantic models for the video generation system.

This package contains all request/response models used by the FastAPI application.
Models are organized by domain:
- video: Core video and scene models (new modular structure)
- document: Document input processing (new modular structure)
- youtube: YouTube video processing (new modular structure)
- multilingual: Multi-language video generation (new modular structure)
- requests: Legacy combined models (for backward compatibility)
"""
# Import from new modular structure
from .video import SceneBase, Video, VideoSet
from .document import DocumentInput
from .youtube import YouTubeInput, YouTubeURLValidation, YouTubePreviewRequest
from .multilingual import MultilingualRequest

# Import legacy models for backward compatibility
from .requests import TemplateModel

__all__ = [
    # Video models
    "SceneBase",
    "Video",
    "VideoSet",
    # Document models
    "DocumentInput",
    # YouTube models
    "YouTubeInput",
    "YouTubeURLValidation",
    "YouTubePreviewRequest",
    # Multilingual models
    "MultilingualRequest",
    # Template models
    "TemplateModel",
]
