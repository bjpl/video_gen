"""YouTube URL validation and video information utilities.

This module provides comprehensive YouTube URL validation, normalization,
and video metadata fetching capabilities for the video generation system.

Features:
- URL validation for all YouTube URL formats
- URL normalization to standard format
- Video ID extraction from various URL types
- Video metadata preview (title, duration, thumbnail)
- Transcript availability checking
- Duration estimation for video generation
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


# =============================================================================
# Exceptions
# =============================================================================

class YouTubeValidationError(Exception):
    """Exception raised for YouTube validation errors."""

    def __init__(self, message: str, error_code: str = "VALIDATION_ERROR"):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class YouTubeValidationResult:
    """Result of YouTube URL validation.

    Attributes:
        is_valid: Whether the URL is valid
        video_id: Extracted video ID if valid
        normalized_url: Normalized URL if valid
        error: Error message if invalid
        error_code: Error code for programmatic handling
    """

    is_valid: bool
    video_id: Optional[str] = None
    normalized_url: Optional[str] = None
    error: Optional[str] = None
    error_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response."""
        return {
            "is_valid": self.is_valid,
            "video_id": self.video_id,
            "normalized_url": self.normalized_url,
            "error": self.error,
            "error_code": self.error_code,
        }


@dataclass
class YouTubeVideoInfo:
    """YouTube video information for preview.

    Attributes:
        video_id: YouTube video ID
        title: Video title
        channel: Channel name
        duration_seconds: Video duration in seconds
        thumbnail_url: URL to video thumbnail
        has_transcript: Whether transcript is available
        transcript_languages: List of available transcript languages
        view_count: Number of views (optional)
        published_at: Publication date (optional)
    """

    video_id: str
    title: str = ""
    channel: str = ""
    duration_seconds: int = 0
    thumbnail_url: str = ""
    has_transcript: bool = False
    transcript_languages: List[str] = field(default_factory=list)
    view_count: Optional[int] = None
    published_at: Optional[str] = None
    description: str = ""

    @property
    def duration_formatted(self) -> str:
        """Get duration as formatted string (MM:SS or HH:MM:SS)."""
        hours = self.duration_seconds // 3600
        minutes = (self.duration_seconds % 3600) // 60
        seconds = self.duration_seconds % 60

        if hours > 0:
            return f"{hours}:{minutes:02d}:{seconds:02d}"
        return f"{minutes}:{seconds:02d}"

    @property
    def estimated_scenes(self) -> int:
        """Estimate number of scenes for video generation.

        Uses approximately 12 seconds per scene plus title and outro.
        """
        if self.duration_seconds <= 0:
            return 3  # Minimum: title, content, outro

        content_scenes = max(1, self.duration_seconds // 12)
        return content_scenes + 2  # +2 for title and outro

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response."""
        return {
            "video_id": self.video_id,
            "title": self.title,
            "channel": self.channel,
            "duration_seconds": self.duration_seconds,
            "duration_formatted": self.duration_formatted,
            "thumbnail_url": self.thumbnail_url,
            "has_transcript": self.has_transcript,
            "transcript_languages": self.transcript_languages,
            "view_count": self.view_count,
            "published_at": self.published_at,
            "estimated_scenes": self.estimated_scenes,
            "description": self.description,
        }

    def get_preview_data(self) -> Dict[str, Any]:
        """Get data optimized for UI preview display."""
        return {
            "video_id": self.video_id,
            "title": self.title,
            "channel": self.channel,
            "thumbnail_url": self.thumbnail_url,
            "duration_formatted": self.duration_formatted,
            "estimated_scenes": self.estimated_scenes,
            "has_transcript": self.has_transcript,
            "transcript_languages": self.transcript_languages,
            "can_generate": self.has_transcript,
            "generation_estimate": estimate_generation_duration(self.duration_seconds),
        }


# =============================================================================
# URL Patterns
# =============================================================================

# Valid YouTube domains
VALID_YOUTUBE_DOMAINS = {
    'youtube.com',
    'www.youtube.com',
    'm.youtube.com',
    'music.youtube.com',
    'youtu.be',
}

# YouTube video ID pattern (11 characters: alphanumeric, underscore, hyphen)
VIDEO_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{11}$')

# URL patterns for different YouTube URL formats
URL_PATTERNS = {
    'watch': re.compile(r'(?:youtube\.com|m\.youtube\.com)/watch\?.*v=([a-zA-Z0-9_-]{11})'),
    'short_url': re.compile(r'youtu\.be/([a-zA-Z0-9_-]{11})'),
    'embed': re.compile(r'youtube\.com/embed/([a-zA-Z0-9_-]{11})'),
    'v': re.compile(r'youtube\.com/v/([a-zA-Z0-9_-]{11})'),
    'shorts': re.compile(r'youtube\.com/shorts/([a-zA-Z0-9_-]{11})'),
    'live': re.compile(r'youtube\.com/live/([a-zA-Z0-9_-]{11})'),
}


# =============================================================================
# Core Functions
# =============================================================================

def extract_video_id(url: Any) -> Optional[str]:
    """Extract YouTube video ID from URL or direct ID.

    Supports all common YouTube URL formats:
    - Standard watch URLs: https://www.youtube.com/watch?v=VIDEO_ID
    - Short URLs: https://youtu.be/VIDEO_ID
    - Embed URLs: https://www.youtube.com/embed/VIDEO_ID
    - V URLs: https://www.youtube.com/v/VIDEO_ID
    - Shorts URLs: https://www.youtube.com/shorts/VIDEO_ID
    - Live URLs: https://www.youtube.com/live/VIDEO_ID
    - Mobile URLs: https://m.youtube.com/watch?v=VIDEO_ID
    - Direct video ID: VIDEO_ID

    Args:
        url: YouTube URL or video ID (string)

    Returns:
        Video ID if valid, None otherwise
    """
    # Handle non-string input
    if url is None or not isinstance(url, str):
        return None

    # Clean input: strip whitespace and quotes
    url = url.strip().strip('"').strip("'").strip()

    if not url:
        return None

    # Check if it's already a valid video ID
    if VIDEO_ID_PATTERN.match(url):
        return url

    # Try to extract from URL patterns
    for pattern_name, pattern in URL_PATTERNS.items():
        match = pattern.search(url)
        if match:
            video_id = match.group(1)
            if VIDEO_ID_PATTERN.match(video_id):
                return video_id

    # Fallback: try parsing as URL and extracting 'v' parameter
    try:
        parsed = urlparse(url)

        # Check if it's a valid YouTube domain
        hostname = parsed.hostname or ''
        if hostname.replace('www.', '').replace('m.', '') not in ['youtube.com', 'youtu.be']:
            return None

        # Try to get 'v' parameter from query string
        query_params = parse_qs(parsed.query)
        if 'v' in query_params:
            video_id = query_params['v'][0]
            if VIDEO_ID_PATTERN.match(video_id):
                return video_id

        # Try to get from path for youtu.be URLs
        if parsed.hostname == 'youtu.be' and parsed.path:
            video_id = parsed.path.lstrip('/')
            if VIDEO_ID_PATTERN.match(video_id):
                return video_id

    except Exception:
        pass

    return None


def validate_youtube_url(url: Any) -> YouTubeValidationResult:
    """Validate a YouTube URL and return detailed result.

    Args:
        url: URL to validate

    Returns:
        YouTubeValidationResult with validation details
    """
    # Handle None or empty
    if url is None:
        return YouTubeValidationResult(
            is_valid=False,
            error="URL is required",
            error_code="URL_REQUIRED",
        )

    if not isinstance(url, str):
        return YouTubeValidationResult(
            is_valid=False,
            error="URL must be a string",
            error_code="INVALID_TYPE",
        )

    url = url.strip().strip('"').strip("'").strip()

    if not url:
        return YouTubeValidationResult(
            is_valid=False,
            error="URL cannot be empty",
            error_code="URL_EMPTY",
        )

    # Extract video ID
    video_id = extract_video_id(url)

    if video_id is None:
        return YouTubeValidationResult(
            is_valid=False,
            error="Not a valid YouTube URL. Please provide a valid YouTube video link.",
            error_code="INVALID_URL",
        )

    # Build normalized URL
    normalized_url = f"https://www.youtube.com/watch?v={video_id}"

    return YouTubeValidationResult(
        is_valid=True,
        video_id=video_id,
        normalized_url=normalized_url,
    )


def normalize_youtube_url(url: str) -> str:
    """Normalize a YouTube URL to standard format.

    Converts all valid YouTube URL formats to:
    https://www.youtube.com/watch?v=VIDEO_ID

    Args:
        url: YouTube URL to normalize

    Returns:
        Normalized URL

    Raises:
        YouTubeValidationError: If URL is not valid
    """
    result = validate_youtube_url(url)

    if not result.is_valid:
        raise YouTubeValidationError(
            message=result.error,
            error_code=result.error_code,
        )

    return result.normalized_url


# =============================================================================
# Duration Estimation Functions
# =============================================================================

def estimate_generation_duration(video_duration_seconds: int) -> Dict[str, Any]:
    """Estimate how long video generation will take.

    Based on empirical measurements:
    - Audio generation: ~2-3 seconds per scene
    - Scene rendering: ~1-2 seconds per scene
    - Video assembly: ~5-10 seconds total
    - Buffer for processing: 20%

    Args:
        video_duration_seconds: Source video duration in seconds

    Returns:
        Dictionary with estimation details
    """
    if video_duration_seconds <= 0:
        return {
            "estimated_minutes": 1,
            "estimated_seconds": 60,
            "confidence": "low",
            "breakdown": {
                "audio_generation": 30,
                "scene_rendering": 20,
                "video_assembly": 10,
            }
        }

    # Estimate scene count
    scene_count = estimate_scene_count(video_duration_seconds)

    # Estimate time per component (in seconds)
    audio_time = scene_count * 2.5  # ~2.5 seconds per scene for audio
    render_time = scene_count * 1.5  # ~1.5 seconds per scene for rendering
    assembly_time = 10  # Fixed overhead for video assembly
    buffer = (audio_time + render_time + assembly_time) * 0.2  # 20% buffer

    total_seconds = audio_time + render_time + assembly_time + buffer
    total_minutes = max(1, int(total_seconds / 60))

    return {
        "estimated_minutes": total_minutes,
        "estimated_seconds": int(total_seconds),
        "scene_count": scene_count,
        "confidence": "medium" if video_duration_seconds < 600 else "low",
        "breakdown": {
            "audio_generation": int(audio_time),
            "scene_rendering": int(render_time),
            "video_assembly": int(assembly_time),
            "buffer": int(buffer),
        }
    }


def estimate_scene_count(
    video_duration_seconds: int,
    scene_duration: int = 12
) -> int:
    """Estimate number of scenes for a video.

    Args:
        video_duration_seconds: Source video duration in seconds
        scene_duration: Target duration per content scene (default: 12)

    Returns:
        Estimated total scene count (including title and outro)
    """
    if video_duration_seconds <= 0:
        return 3  # Minimum: title, one content, outro

    # Calculate content scenes
    content_scenes = max(1, video_duration_seconds // scene_duration)

    # Add title and outro scenes
    return content_scenes + 2


# =============================================================================
# YouTubeURLValidator Class
# =============================================================================

class YouTubeURLValidator:
    """Validator for YouTube URLs with metadata fetching capabilities.

    This class provides comprehensive YouTube URL validation and
    video information retrieval for preview and processing.

    Example:
        validator = YouTubeURLValidator()
        result = validator.validate("https://youtu.be/dQw4w9WgXcQ")
        if result.is_valid:
            info = await validator.fetch_video_info(result.video_id)
    """

    def __init__(self):
        """Initialize the validator."""
        self._cache: Dict[str, YouTubeVideoInfo] = {}

    def validate(self, url: Any) -> YouTubeValidationResult:
        """Validate a YouTube URL.

        Args:
            url: URL to validate

        Returns:
            YouTubeValidationResult with validation details
        """
        return validate_youtube_url(url)

    async def fetch_video_info(self, video_id: str) -> Optional[YouTubeVideoInfo]:
        """Fetch video information from YouTube.

        Args:
            video_id: YouTube video ID

        Returns:
            YouTubeVideoInfo if successful, None otherwise

        Raises:
            YouTubeValidationError: If fetching fails
        """
        # Check cache first
        if video_id in self._cache:
            return self._cache[video_id]

        try:
            metadata = await self._fetch_video_metadata(video_id)
            if metadata is None:
                return None

            # Check transcript availability
            transcript_info = await self._check_transcript(video_id)

            info = YouTubeVideoInfo(
                video_id=video_id,
                title=metadata.get('title', ''),
                channel=metadata.get('channel', ''),
                duration_seconds=metadata.get('duration_seconds', 0),
                thumbnail_url=metadata.get('thumbnail_url', self._get_thumbnail_url(video_id)),
                has_transcript=transcript_info.get('available', False),
                transcript_languages=transcript_info.get('languages', []),
                view_count=metadata.get('view_count'),
                published_at=metadata.get('published_at'),
                description=metadata.get('description', ''),
            )

            # Cache the result
            self._cache[video_id] = info

            return info

        except Exception as e:
            logger.error(f"Failed to fetch video info for {video_id}: {e}")
            raise YouTubeValidationError(
                message=f"Failed to fetch video information: {str(e)}",
                error_code="FETCH_ERROR",
            )

    async def check_transcript_availability(
        self,
        video_id: str
    ) -> Dict[str, Any]:
        """Check if transcript is available for a video.

        Args:
            video_id: YouTube video ID

        Returns:
            Dictionary with availability info
        """
        return await self._check_transcript(video_id)

    async def _fetch_video_metadata(self, video_id: str) -> Optional[Dict[str, Any]]:
        """Fetch video metadata from YouTube.

        This method can be mocked in tests or extended to use
        different data sources (yt-dlp, YouTube API, etc.)

        Args:
            video_id: YouTube video ID

        Returns:
            Metadata dictionary or None
        """
        try:
            # Try using yt-dlp if available (most reliable)
            try:
                import yt_dlp

                ydl_opts = {
                    'quiet': True,
                    'no_warnings': True,
                    'extract_flat': False,
                }

                with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                    url = f"https://www.youtube.com/watch?v={video_id}"
                    info = ydl.extract_info(url, download=False)

                    return {
                        'title': info.get('title', ''),
                        'channel': info.get('channel', info.get('uploader', '')),
                        'duration_seconds': info.get('duration', 0),
                        'thumbnail_url': info.get('thumbnail', self._get_thumbnail_url(video_id)),
                        'view_count': info.get('view_count'),
                        'published_at': info.get('upload_date'),
                        'description': info.get('description', ''),
                    }

            except ImportError:
                logger.debug("yt-dlp not available, using fallback metadata")

            # Fallback: Return minimal info with thumbnail
            return {
                'title': f'YouTube Video ({video_id})',
                'channel': '',
                'duration_seconds': 0,
                'thumbnail_url': self._get_thumbnail_url(video_id),
            }

        except Exception as e:
            logger.error(f"Error fetching metadata for {video_id}: {e}")
            return None

    async def _check_transcript(self, video_id: str) -> Dict[str, Any]:
        """Check transcript availability using youtube-transcript-api.

        Args:
            video_id: YouTube video ID

        Returns:
            Dictionary with availability and languages
        """
        try:
            from youtube_transcript_api import YouTubeTranscriptApi

            transcript_list = YouTubeTranscriptApi.list_transcripts(video_id)

            languages = []
            for transcript in transcript_list:
                languages.append(transcript.language_code)

            return {
                'available': len(languages) > 0,
                'languages': languages,
            }

        except ImportError:
            logger.warning("youtube-transcript-api not available")
            return {
                'available': False,
                'languages': [],
                'error': 'youtube-transcript-api not installed',
            }

        except Exception as e:
            logger.debug(f"Error checking transcript for {video_id}: {e}")
            return {
                'available': False,
                'languages': [],
                'error': str(e),
            }

    def _get_thumbnail_url(self, video_id: str, quality: str = 'mqdefault') -> str:
        """Get thumbnail URL for a video.

        Args:
            video_id: YouTube video ID
            quality: Thumbnail quality (default, mqdefault, hqdefault, maxresdefault)

        Returns:
            Thumbnail URL
        """
        return f"https://i.ytimg.com/vi/{video_id}/{quality}.jpg"

    def clear_cache(self):
        """Clear the video info cache."""
        self._cache.clear()
