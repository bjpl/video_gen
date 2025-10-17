"""YouTube input adapter for processing video transcripts.

This adapter downloads YouTube video transcripts and converts them into
VideoSet structures for video generation.
"""

import re
from typing import Any, List, Dict
from urllib.parse import urlparse, parse_qs

from .base import InputAdapter, InputAdapterResult
from ..shared.models import VideoSet, VideoConfig, SceneConfig


class YouTubeAdapter(InputAdapter):
    """Adapter for YouTube video transcripts.

    This adapter downloads transcripts from YouTube videos and converts
    them into structured VideoSet objects for video generation.

    Args:
        test_mode: If True, bypass external API calls for testing purposes
    """

    def __init__(self, test_mode: bool = False):
        """Initialize the YouTube adapter.

        Args:
            test_mode: If True, bypass external API calls for testing purposes
        """
        super().__init__(
            name="youtube",
            description="Processes YouTube video transcripts"
        )
        self.test_mode = test_mode

    async def adapt(self, source: Any, **kwargs) -> InputAdapterResult:
        """Adapt a YouTube video to VideoSet structure.

        Args:
            source: YouTube URL or video ID
            **kwargs: Additional parameters:
                - language: Transcript language (default: 'en')
                - scene_duration: Target duration per scene in seconds (default: 12)
                - voice: Voice to use for narration (default: 'male')
                - accent_color: Video accent color (default: 'blue')

        Returns:
            InputAdapterResult with VideoSet
        """
        try:
            # Validate source
            if not await self.validate_source(source):
                return InputAdapterResult(
                    success=False,
                    error=f"Invalid YouTube URL: {source}"
                )

            # Extract video ID(s)
            video_ids = self._extract_video_ids(source)
            if not video_ids:
                return InputAdapterResult(
                    success=False,
                    error=f"Could not extract video ID from: {source}"
                )

            # Check for youtube-transcript-api
            try:
                from youtube_transcript_api import YouTubeTranscriptApi
                from youtube_transcript_api._errors import (
                    TranscriptsDisabled,
                    NoTranscriptFound,
                    VideoUnavailable
                )
            except ImportError:
                return InputAdapterResult(
                    success=False,
                    error="youtube-transcript-api not installed. Install with: pip install youtube-transcript-api"
                )

            # Get parameters
            language = kwargs.get('language', 'en')
            scene_duration = kwargs.get('scene_duration', 12)
            voice = kwargs.get('voice', 'male')
            accent_color = kwargs.get('accent_color', 'blue')

            # Process each video
            videos = []
            for video_id in video_ids:
                try:
                    # Get transcript
                    transcript_list = YouTubeTranscriptApi.list_transcripts(video_id)

                    # Try to get requested language, fall back to auto-generated
                    try:
                        transcript = transcript_list.find_transcript([language])
                    except NoTranscriptFound:
                        # Try auto-generated or any available transcript
                        transcript = transcript_list.find_generated_transcript([language])

                    transcript_data = transcript.fetch()

                    # Create video config
                    video_config = self._create_video_config(
                        video_id=video_id,
                        transcript_data=transcript_data,
                        scene_duration=scene_duration,
                        voice=voice,
                        accent_color=accent_color
                    )
                    videos.append(video_config)

                except TranscriptsDisabled:
                    return InputAdapterResult(
                        success=False,
                        error=f"Transcripts are disabled for video: {video_id}"
                    )
                except NoTranscriptFound:
                    return InputAdapterResult(
                        success=False,
                        error=f"No transcript found for video: {video_id} in language: {language}"
                    )
                except VideoUnavailable:
                    return InputAdapterResult(
                        success=False,
                        error=f"Video unavailable: {video_id}"
                    )

            # Create VideoSet
            video_set = VideoSet(
                set_id=f"youtube_{video_ids[0]}",
                name=videos[0].title if videos else "YouTube Video Set",
                description=f"Generated from YouTube video(s): {', '.join(video_ids)}",
                videos=videos,
                metadata={
                    'source_type': 'youtube',
                    'video_ids': video_ids,
                    'language': language,
                    'source_url': source
                }
            )

            return InputAdapterResult(
                success=True,
                video_set=video_set,
                metadata={
                    'video_count': len(videos),
                    'video_ids': video_ids
                }
            )

        except Exception as e:
            return InputAdapterResult(
                success=False,
                error=f"YouTube adaptation failed: {str(e)}"
            )

    def _extract_video_ids(self, url: str) -> List[str]:
        """Extract video ID(s) from YouTube URL.

        Args:
            url: YouTube URL (video or playlist)

        Returns:
            List of video IDs
        """
        video_ids = []

        # Clean URL - strip quotes and whitespace
        url = str(url).strip().strip('"').strip("'")

        # If it's already a video ID (11 characters, alphanumeric + underscore/hyphen)
        if re.match(r'^[a-zA-Z0-9_-]{11}$', url):
            return [url]

        # Parse URL
        parsed_url = urlparse(url)

        # Check for playlist
        if 'list' in parse_qs(parsed_url.query):
            # For playlists, we need additional library support
            # For now, just return error via empty list
            # This could be enhanced with youtube-dl or similar
            return []

        # Extract video ID from various YouTube URL formats
        if parsed_url.hostname in ('www.youtube.com', 'youtube.com', 'm.youtube.com'):
            if parsed_url.path == '/watch':
                query_params = parse_qs(parsed_url.query)
                if 'v' in query_params:
                    video_ids.append(query_params['v'][0])
            elif parsed_url.path.startswith('/embed/'):
                video_ids.append(parsed_url.path.split('/')[2])
            elif parsed_url.path.startswith('/v/'):
                video_ids.append(parsed_url.path.split('/')[2])
        elif parsed_url.hostname in ('youtu.be',):
            video_ids.append(parsed_url.path[1:])

        return video_ids

    def _create_video_config(
        self,
        video_id: str,
        transcript_data: List[Dict],
        scene_duration: float,
        voice: str,
        accent_color: str
    ) -> VideoConfig:
        """Create VideoConfig from transcript data.

        Args:
            video_id: YouTube video ID
            transcript_data: Transcript data from YouTube API
            scene_duration: Target duration per scene
            voice: Voice for narration
            accent_color: Video accent color

        Returns:
            VideoConfig object
        """
        # Create title from first few words of transcript
        first_text = transcript_data[0]['text'] if transcript_data else "YouTube Video"
        title = self._create_title(first_text)

        # Group transcript into scenes
        scenes = self._create_scenes(
            transcript_data=transcript_data,
            scene_duration=scene_duration,
            voice=voice
        )

        # Add title scene at start
        title_scene = SceneConfig(
            scene_id="scene_000",
            scene_type="title",
            narration=title,
            visual_content={
                "title": title,
                "subtitle": f"From YouTube Video: {video_id}"
            },
            voice=voice,
            min_duration=3.0,
            max_duration=5.0
        )

        # Add outro scene at end
        outro_scene = SceneConfig(
            scene_id=f"scene_{len(scenes) + 1:03d}",
            scene_type="outro",
            narration="Thank you for watching! For more content, visit the original video.",
            visual_content={
                "title": "Thank You!",
                "message": "Visit the original video on YouTube",
                "video_id": video_id
            },
            voice=voice,
            min_duration=3.0,
            max_duration=5.0
        )

        all_scenes = [title_scene] + scenes + [outro_scene]

        return VideoConfig(
            video_id=f"youtube_{video_id}",
            title=title,
            description=f"Video generated from YouTube transcript: {video_id}",
            scenes=all_scenes,
            accent_color=accent_color
        )

    def _create_title(self, text: str, max_length: int = 60) -> str:
        """Create a title from transcript text.

        Args:
            text: Text to create title from
            max_length: Maximum title length

        Returns:
            Title string
        """
        # Clean up text
        text = re.sub(r'\s+', ' ', text).strip()

        # Capitalize first letter
        if text:
            text = text[0].upper() + text[1:]

        # Truncate if too long
        if len(text) > max_length:
            text = text[:max_length].rsplit(' ', 1)[0] + '...'

        return text

    def _create_scenes(
        self,
        transcript_data: List[Dict],
        scene_duration: float,
        voice: str
    ) -> List[SceneConfig]:
        """Create scenes from transcript data.

        Args:
            transcript_data: List of transcript segments
            scene_duration: Target duration per scene
            voice: Voice for narration

        Returns:
            List of SceneConfig objects
        """
        scenes = []
        current_scene_text = []
        current_scene_start = 0
        scene_counter = 1

        for i, segment in enumerate(transcript_data):
            # Add text to current scene
            current_scene_text.append(segment['text'])

            # Calculate duration of current scene
            if i < len(transcript_data) - 1:
                current_duration = transcript_data[i + 1]['start'] - current_scene_start
            else:
                current_duration = segment['start'] + segment.get('duration', 5) - current_scene_start

            # If we've reached target duration or end, create scene
            if current_duration >= scene_duration or i == len(transcript_data) - 1:
                # Combine text
                narration = ' '.join(current_scene_text)

                # Create bullet points from text (split on sentence boundaries)
                bullet_points = self._create_bullet_points(narration)

                # Create scene
                scene = SceneConfig(
                    scene_id=f"scene_{scene_counter:03d}",
                    scene_type="list",
                    narration=narration,
                    visual_content={
                        "title": f"Key Points {scene_counter}",
                        "items": bullet_points
                    },
                    voice=voice,
                    min_duration=max(3.0, current_duration * 0.8),
                    max_duration=max(15.0, current_duration * 1.2)
                )
                scenes.append(scene)

                # Reset for next scene
                current_scene_text = []
                if i < len(transcript_data) - 1:
                    current_scene_start = transcript_data[i + 1]['start']
                scene_counter += 1

        return scenes

    def _create_bullet_points(self, text: str, max_points: int = 4) -> List[str]:
        """Create bullet points from text.

        Args:
            text: Text to convert to bullet points
            max_points: Maximum number of bullet points

        Returns:
            List of bullet point strings
        """
        # Split on sentence boundaries
        sentences = re.split(r'[.!?]+', text)
        sentences = [s.strip() for s in sentences if s.strip()]

        # Limit to max_points
        if len(sentences) > max_points:
            # Take evenly spaced sentences
            step = len(sentences) / max_points
            sentences = [sentences[int(i * step)] for i in range(max_points)]

        # Capitalize and clean
        bullet_points = []
        for sentence in sentences[:max_points]:
            # Remove extra whitespace
            sentence = re.sub(r'\s+', ' ', sentence).strip()
            # Capitalize first letter
            if sentence:
                sentence = sentence[0].upper() + sentence[1:]
            bullet_points.append(sentence)

        return bullet_points

    async def validate_source(self, source: Any) -> bool:
        """Validate YouTube URL or video ID.

        Args:
            source: YouTube URL or video ID

        Returns:
            True if valid, False otherwise
        """
        if not isinstance(source, str):
            return False

        # Check if it's a valid video ID format (11 characters)
        if re.match(r'^[a-zA-Z0-9_-]{11}$', source):
            return True

        # Check if it's a valid YouTube URL
        valid_domains = ['youtube.com', 'youtu.be', 'm.youtube.com', 'www.youtube.com']
        try:
            parsed = urlparse(source)
            return parsed.hostname in valid_domains
        except Exception:
            return False

    def supports_format(self, format_type: str) -> bool:
        """Check if format is supported.

        Args:
            format_type: Format type

        Returns:
            True if "youtube"
        """
        return format_type.lower() == "youtube"
