"""
YouTube Input Adapter
=====================
Parse YouTube video transcripts into video sets.

Supports:
- YouTube video URLs
- Direct video IDs
- Transcript fetching and analysis
- Intelligent segment extraction
- Command/key point detection
"""

import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs

from .base import BaseInputAdapter, VideoSet, VideoConfig

# Try to import YouTube transcript API
try:
    from youtube_transcript_api import YouTubeTranscriptApi
    HAS_YOUTUBE_API = True
except ImportError:
    HAS_YOUTUBE_API = False


class YouTubeAdapter(BaseInputAdapter):
    """Adapter for parsing YouTube video transcripts"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.target_duration = kwargs.get('target_duration', 60)
        self.num_content_scenes = kwargs.get('num_content_scenes', 4)

    def parse(self, source: str, **options) -> VideoSet:
        """
        Parse YouTube video transcript into VideoSet.

        Args:
            source: YouTube URL or video ID
            **options: Parsing options (target_duration, etc.)

        Returns:
            VideoSet with parsed content

        Raises:
            ImportError: If youtube-transcript-api not installed
            ValueError: If transcript cannot be fetched
        """
        if not HAS_YOUTUBE_API:
            raise ImportError(
                "YouTube transcript support requires youtube-transcript-api. "
                "Install: pip install youtube-transcript-api"
            )

        # Extract video ID
        video_id = self._extract_video_id(source)

        if not video_id:
            raise ValueError(f"Could not extract video ID from: {source}")

        # Fetch transcript
        transcript = self._fetch_transcript(video_id)

        if not transcript:
            raise ValueError(f"Could not fetch transcript for video: {video_id}")

        # Analyze transcript
        analysis = self._analyze_transcript(transcript)

        # Extract key segments
        key_segments = self._extract_key_segments(transcript, self.num_content_scenes)

        # Generate scenes
        scenes = self._convert_to_scenes(key_segments)

        # Create video metadata
        set_id = options.get('set_id') or f"youtube_{video_id[:8]}"
        set_name = options.get('set_name') or f"YouTube Summary: {video_id}"
        video_title = options.get('video_title') or "YouTube Content Summary"

        # Create video config
        video = VideoConfig(
            video_id=f"{set_id}_summary",
            title=video_title,
            description=f"Summary of YouTube video {video_id}",
            scenes=scenes
        )

        # Create and return video set
        return self.create_video_set(
            set_id=set_id,
            set_name=set_name,
            videos=[video],
            description=f'Summary from YouTube video {video_id}',
            defaults={
                'accent_color': options.get('accent_color', 'blue'),
                'voice': options.get('voice', 'male'),
                'target_duration': self.target_duration,
                'min_scene_duration': 3.0,
                'max_scene_duration': 15.0
            },
            metadata={
                'source': f'youtube:{video_id}',
                'original_url': f'https://youtube.com/watch?v={video_id}'
            }
        )

    def _extract_video_id(self, url_or_id: str) -> Optional[str]:
        """Extract video ID from URL or return as-is"""
        if not url_or_id.startswith('http'):
            return url_or_id

        # Parse YouTube URL
        parsed = urlparse(url_or_id)

        if 'youtube.com' in parsed.netloc:
            query = parse_qs(parsed.query)
            return query.get('v', [None])[0]
        elif 'youtu.be' in parsed.netloc:
            return parsed.path.strip('/')

        return None

    def _fetch_transcript(self, video_id: str) -> Optional[List[Dict]]:
        """Fetch transcript for YouTube video"""
        try:
            transcript = YouTubeTranscriptApi.get_transcript(video_id)
            print(f"✓ Retrieved {len(transcript)} transcript segments")
            return transcript
        except Exception as e:
            print(f"✗ Could not fetch transcript: {e}")
            return None

    def _analyze_transcript(self, transcript: List[Dict]) -> Dict:
        """Analyze transcript structure"""
        if not transcript:
            return {'total_duration': 0, 'segments': 0, 'paragraphs': []}

        try:
            total_duration = transcript[-1]['start'] + transcript[-1]['duration']
        except (IndexError, KeyError) as e:
            self.logger.warning(f"Failed to calculate total duration: {e}")
            total_duration = 0

        # Combine segments into paragraphs
        paragraphs = []
        current_para = []
        last_time = 0

        for segment in transcript:
            # New paragraph if pause > 2 seconds
            if segment['start'] - last_time > 2.0 and current_para:
                paragraph_index = min(len(paragraphs) * 10, len(transcript) - 1)
                start_time = transcript[paragraph_index]['start'] if paragraph_index >= 0 and transcript else 0

                paragraphs.append({
                    'text': ' '.join(current_para),
                    'start': start_time
                })
                current_para = []

            current_para.append(segment['text'])
            last_time = segment['start'] + segment['duration']

        if current_para:
            paragraphs.append({
                'text': ' '.join(current_para),
                'start': last_time
            })

        return {
            'total_duration': total_duration,
            'segments': len(transcript),
            'paragraphs': paragraphs
        }

    def _extract_key_segments(self, transcript: List[Dict], num_scenes: int) -> List[Dict]:
        """Extract key segments for video scenes"""
        analysis = self._analyze_transcript(transcript)
        paragraphs = analysis['paragraphs']

        if not paragraphs:
            return []

        # Divide into roughly equal segments
        segment_size = len(paragraphs) // num_scenes

        key_segments = []
        for i in range(num_scenes):
            start_idx = i * segment_size
            end_idx = start_idx + segment_size if i < num_scenes - 1 else len(paragraphs)

            segment_paras = paragraphs[start_idx:end_idx]
            combined_text = ' '.join(p['text'] for p in segment_paras)

            key_segments.append({
                'index': i,
                'timestamp_start': segment_paras[0]['start'] if segment_paras else 0,
                'text': combined_text,
                'summary': self._summarize_text(combined_text, max_words=20)
            })

        return key_segments

    def _convert_to_scenes(self, key_segments: List[Dict]) -> List[Dict[str, Any]]:
        """Convert transcript segments to video scenes"""
        scenes = []

        # Scene 1: Title
        title_scene = self.create_scene(
            scene_type='title',
            visual_content={
                'title': 'YouTube Summary',
                'subtitle': 'Key Points'
            }
        )
        scenes.append(title_scene)

        # Scenes 2-N: Content from segments
        for segment in key_segments:
            if self._has_commands(segment['text']):
                # Command scene
                commands = self._extract_commands_from_text(segment['text'])
                scene = self.create_scene(
                    scene_type='command',
                    visual_content={
                        'header': f'Key Point {segment["index"] + 1}',
                        'description': segment['summary'][:50],
                        'commands': commands
                    }
                )
            else:
                # List scene
                key_points = self._extract_key_points(segment['text'])
                scene = self.create_scene(
                    scene_type='list',
                    visual_content={
                        'header': f'Key Point {segment["index"] + 1}',
                        'description': segment['summary'][:50],
                        'items': key_points[:5]
                    }
                )

            scenes.append(scene)

        # Outro
        outro_scene = self.create_scene(
            scene_type='outro',
            visual_content={
                'main_text': 'Watch Full Video',
                'sub_text': 'Link in Description'
            }
        )
        scenes.append(outro_scene)

        return scenes

    def _has_commands(self, text: str) -> bool:
        """Check if text mentions commands"""
        command_patterns = [
            r'npm\s+install',
            r'pip\s+install',
            r'docker\s+run',
            r'git\s+\w+',
            r'python\s+',
            r'node\s+',
            r'\$\s*\w+',
        ]

        for pattern in command_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        return False

    def _extract_commands_from_text(self, text: str) -> List[str]:
        """Extract mentioned commands from text"""
        commands = []

        # Look for quoted commands
        quoted = re.findall(r'["`]([^"`]+)["`]', text)
        for cmd in quoted:
            if len(cmd.split()) <= 5:  # Short commands only
                if not cmd.startswith('$'):
                    cmd = '$ ' + cmd
                commands.append(cmd)

        return commands[:6]

    def _extract_key_points(self, text: str) -> List[str]:
        """Extract key points as list items"""
        # Split into sentences
        sentences = re.split(r'[.!?]+', text)

        points = []
        for sentence in sentences:
            sentence = sentence.strip()
            # Skip if too long or too short
            word_count = len(sentence.split())
            if 3 <= word_count <= 15:
                points.append(sentence)

        return points[:5]

    def _summarize_text(self, text: str, max_words: int = 20) -> str:
        """Summarize text to key points"""
        # Clean text
        text = re.sub(r'\s+', ' ', text)
        text = text.strip()

        # Extract first sentence or key words
        words = text.split()[:max_words]
        summary = ' '.join(words)

        return summary
