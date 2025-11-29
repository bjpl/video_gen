"""
System-wide configuration management.

Consolidated configuration system for the entire video_gen package.
This is the single source of truth for all configuration.
"""

import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dotenv import load_dotenv

logger = logging.getLogger(__name__)


class Config:
    """Global configuration singleton.

    Provides centralized configuration management for:
    - File paths and directories
    - FFmpeg and external tools
    - Video/audio settings
    - API keys and services
    - Voice and color presets
    - Performance settings
    """

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

        # Production logging configuration
        self.json_logging = os.getenv("JSON_LOGGING", "false").lower() == "true"
        self.environment = os.getenv("ENVIRONMENT", "development")

        # Retry configuration
        self.retry_max_attempts = int(os.getenv("RETRY_MAX_ATTEMPTS", "3"))
        self.retry_initial_delay = float(os.getenv("RETRY_INITIAL_DELAY", "1.0"))
        self.retry_max_delay = float(os.getenv("RETRY_MAX_DELAY", "60.0"))

        # Circuit breaker configuration
        self.circuit_breaker_failure_threshold = int(
            os.getenv("CIRCUIT_BREAKER_FAILURE_THRESHOLD", "5")
        )
        self.circuit_breaker_timeout = float(
            os.getenv("CIRCUIT_BREAKER_TIMEOUT", "30.0")
        )

        # Timeout configuration
        self.thumbnail_generation_timeout = float(
            os.getenv("THUMBNAIL_GENERATION_TIMEOUT", "30.0")
        )
        self.video_processing_timeout = float(
            os.getenv("VIDEO_PROCESSING_TIMEOUT", "300.0")
        )

        # Performance settings (from old config.py)
        self.max_workers = int(os.getenv("VIDEO_GEN_MAX_WORKERS", "4"))

        # Temporary directory for processing
        self.temp_dir = self.base_dir / "temp"
        self.temp_dir.mkdir(parents=True, exist_ok=True)

        # API keys dictionary (consolidated)
        self.api_keys = {}
        if self.anthropic_api_key:
            self.api_keys["anthropic"] = self.anthropic_api_key
        if openai_key := os.getenv("OPENAI_API_KEY"):
            self.api_keys["openai"] = openai_key
            self.openai_api_key = openai_key
        if youtube_key := os.getenv("YOUTUBE_API_KEY"):
            self.api_keys["youtube"] = youtube_key

        self._initialized = True

    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a specific service.

        Args:
            service: Service name (e.g., "anthropic", "openai", "youtube")

        Returns:
            API key if available, None otherwise
        """
        return self.api_keys.get(service)

    def validate(self) -> None:
        """Validate the configuration.

        Raises:
            ValueError: If configuration is invalid
        """
        # Validate directories exist
        for dir_name, dir_path in [
            ("output", self.output_dir),
            ("audio", self.audio_dir),
            ("video", self.video_dir),
            ("state", self.state_dir),
            ("logs", self.log_dir),
            ("temp", self.temp_dir),
        ]:
            if not dir_path.exists():
                logger.warning(f"{dir_name} directory does not exist: {dir_path}")

        # Validate workers
        if self.max_workers < 1:
            raise ValueError(f"max_workers must be >= 1, got {self.max_workers}")

        # Validate FFmpeg
        if not self.ffmpeg_path:
            logger.warning("FFmpeg path not configured, video generation may fail")

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
