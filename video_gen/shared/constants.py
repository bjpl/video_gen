"""Shared constants for the video_gen package.

This module defines all constants used throughout the video generation system,
including supported languages, scene types, and visual styles.
"""

# Supported languages with full names
SUPPORTED_LANGUAGES = {
    "en": "English",
    "es": "Spanish",
    "fr": "French",
    "de": "German",
    "it": "Italian",
    "pt": "Portuguese",
    "ru": "Russian",
    "zh": "Chinese",
    "ja": "Japanese",
    "ko": "Korean",
    "ar": "Arabic",
    "hi": "Hindi",
    "nl": "Dutch",
    "pl": "Polish",
    "tr": "Turkish",
    "vi": "Vietnamese",
    "th": "Thai",
    "id": "Indonesian",
    "ms": "Malay",
    "uk": "Ukrainian",
    "ro": "Romanian",
    "cs": "Czech",
    "sv": "Swedish",
    "da": "Danish",
    "fi": "Finnish",
    "no": "Norwegian",
    "el": "Greek",
    "he": "Hebrew",
}

# Scene types for educational content
SCENE_TYPES = {
    "intro": "Introduction scene",
    "lesson": "Main lesson content",
    "slide": "Slide-based presentation",
    "code_walkthrough": "Code explanation scene",
    "demo": "Live demonstration",
    "quiz": "Quiz or assessment",
    "summary": "Summary or recap",
    "outro": "Closing scene",
    "transition": "Transition between topics",
}

# Visual styles for rendering
VISUAL_STYLES = {
    "minimal": "Clean, minimal design",
    "professional": "Professional presentation style",
    "playful": "Colorful and engaging",
    "technical": "Technical documentation style",
    "academic": "Academic presentation style",
}

# Default video settings
DEFAULT_VIDEO_SETTINGS = {
    "resolution": (1920, 1080),
    "fps": 30,
    "codec": "libx264",
    "format": "mp4",
    "bitrate": "5000k",
}

# Default audio settings
DEFAULT_AUDIO_SETTINGS = {
    "sample_rate": 44100,
    "channels": 2,
    "bitrate": "192k",
    "format": "mp3",
}

# Pipeline stage names
PIPELINE_STAGES = [
    "input_adaptation",
    "content_parsing",
    "script_generation",
    "audio_generation",
    "video_generation",
    "output_handling",
]

# File extensions
SUPPORTED_INPUT_FORMATS = {
    "document": [".pdf", ".docx", ".txt", ".md"],
    "yaml": [".yaml", ".yml"],
    "video": [".mp4", ".avi", ".mov", ".mkv"],
    "image": [".jpg", ".jpeg", ".png", ".gif", ".svg"],
}

# API rate limits (requests per minute)
API_RATE_LIMITS = {
    "anthropic": 60,
    "openai": 60,
    "elevenlabs": 30,
}

# Maximum values
MAX_SCENE_DURATION = 600  # 10 minutes
MAX_VIDEO_DURATION = 3600  # 1 hour
MAX_CONCURRENT_TASKS = 10

# Timeouts (seconds)
TIMEOUTS = {
    "api_request": 30,
    "audio_generation": 120,
    "video_rendering": 600,
}
