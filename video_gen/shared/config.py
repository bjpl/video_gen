"""
System-wide configuration management.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional
from dotenv import load_dotenv


class Config:
    """Global configuration singleton."""

    _instance: Optional['Config'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        # Load environment variables
        load_dotenv()

        # Base paths
        self.base_dir = Path(__file__).parent.parent.parent
        self.scripts_dir = self.base_dir / "scripts"
        self.output_dir = self.base_dir / "output"
        self.audio_dir = self.base_dir / "audio"
        self.video_dir = self.base_dir / "videos"

        # FFmpeg configuration (cross-platform)
        try:
            import imageio_ffmpeg
            default_ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
        except ImportError:
            default_ffmpeg = "ffmpeg"  # Fallback to system PATH

        self.ffmpeg_path = os.getenv("FFMPEG_PATH", default_ffmpeg)

        # Video settings
        self.video_width = 1920
        self.video_height = 1080
        self.video_fps = 30

        # Voice configuration
        self.voice_config = {
            "male": "en-US-AndrewMultilingualNeural",
            "male_warm": "en-US-BrandonMultilingualNeural",
            "female": "en-US-AriaNeural",
            "female_friendly": "en-US-AvaMultilingualNeural"
        }

        # Colors
        self.colors = {
            "blue": (59, 130, 246),
            "purple": (139, 92, 246),
            "orange": (255, 107, 53),
            "green": (16, 185, 129),
            "pink": (236, 72, 153),
            "cyan": (34, 211, 238),
        }

        # Font paths (Windows)
        self.fonts = {
            "title": "C:/Windows/Fonts/arialbd.ttf",
            "subtitle": "C:/Windows/Fonts/arial.ttf",
            "code": "C:/Windows/Fonts/consola.ttf",
        }

        # AI API keys
        self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")

        # State storage
        self.state_dir = self.output_dir / "state"
        self.state_dir.mkdir(parents=True, exist_ok=True)

        # Logging
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        self.log_dir = self.output_dir / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self._initialized = True

    def get_voice(self, voice_id: str) -> str:
        """Get Edge TTS voice identifier."""
        return self.voice_config.get(voice_id, self.voice_config["male"])

    def get_color(self, color_name: str) -> tuple:
        """Get RGB color tuple."""
        return self.colors.get(color_name, self.colors["blue"])

    def to_dict(self) -> Dict[str, Any]:
        """Export configuration as dictionary."""
        return {
            "base_dir": str(self.base_dir),
            "output_dir": str(self.output_dir),
            "video_width": self.video_width,
            "video_height": self.video_height,
            "video_fps": self.video_fps,
            "log_level": self.log_level,
        }


# Global config instance
config = Config()
