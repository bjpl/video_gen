"""Script generation for video narration.

This module generates narration scripts for video scenes using AI and
template-based approaches.
"""

from .narration import NarrationGenerator
from .ai_enhancer import AIScriptEnhancer

__all__ = [
    "NarrationGenerator",
    "AIScriptEnhancer",
]
