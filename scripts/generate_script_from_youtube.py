"""
YouTube Transcript to Video Script Generator
=============================================
Fetches YouTube transcripts and converts them into concise video scripts.

Features:
- Search YouTube by topic
- Fetch video transcriptions
- Intelligent segment extraction
- Condense long content to target duration
- Extract commands/code mentioned

Dependencies:
    pip install youtube-transcript-api google-api-python-client

Usage:
    python generate_script_from_youtube.py --search "python async tutorial"
    python generate_script_from_youtube.py --video-id "dQw4w9WgXcQ"
    python generate_script_from_youtube.py --url "https://youtube.com/watch?v=VIDEO_ID"
"""

import re
import os
import sys
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import logging

# Setup logging
logger = logging.getLogger(__name__)


try:
    from youtube_transcript_api import YouTubeTranscriptApi
    HAS_TRANSCRIPT_API = True
except ImportError:
    HAS_TRANSCRIPT_API = False
    logger.warning("⚠️  Install youtube-transcript-api: pip install youtube-transcript-api")

try:
    from googleapiclient.discovery import build
    HAS_YOUTUBE_API = True
except ImportError:
    HAS_YOUTUBE_API = False
    logger.warning("⚠️  Install google-api-python-client for search: pip install google-api-python-client")


class YouTubeSearcher:
    """Search YouTube videos with intelligent filtering"""

    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get('YOUTUBE_API_KEY')

    def search(self, query, max_results=10, category='tech'):
        """
        Search YouTube with filters

        Note: Requires YouTube API key
        For demo purposes, returns mock results
        """
        if not self.api_key:
            logger.warning("⚠️  No YouTube API key found")
            logger.info("   Set YOUTUBE_API_KEY environment variable")
            logger.info("   Get key: https://console.cloud.google.com/apis/credentials")
            logger.info("\n   For now, use --video-id or --url with known video\n")
            return []

        if not HAS_YOUTUBE_API:
            logger.error("❌ google-api-python-client not installed")
            return []

        youtube = build('youtube', 'v3', developerKey=self.api_key)

        request = youtube.search().list(
            q=query,
            part='snippet',
            type='video',
            maxResults=max_results,
            relevanceLanguage='en',
            videoCaption='closedCaption'  # Only videos with captions
        )

        response = request.execute()

        results = []
        for item in response.get('items', []):
            results.append({
                'video_id': item['id']['videoId'],
                'title': item['snippet']['title'],
                'description': item['snippet']['description'][:200],
                'channel': item['snippet']['channelTitle']
            })

        return results


class TranscriptProcessor:
    """Process YouTube transcripts into video structure"""

    def __init__(self, target_duration=60):
        self.target_duration = target_duration

    def fetch_transcript(self, video_id):
        """Fetch transcript for video"""
        if not HAS_TRANSCRIPT_API:
            raise ImportError("youtube-transcript-api required")

        logger.info(f"Fetching transcript for video: {video_id}")

        try:
            transcript = YouTubeTranscriptApi.get_transcript(video_id)
            logger.info(f"✓ Retrieved {len(transcript)} transcript segments\n")
            return transcript
        except Exception as e:
            logger.error(f"❌ Could not fetch transcript: {e}")
            logger.info("\n   Possible reasons:")
            logger.info("   - Video has no captions")
            logger.info("   - Captions are disabled")
            logger.info("   - Invalid video ID")
            return None

    def analyze_transcript(self, transcript):
        """Analyze transcript structure"""
        total_duration = transcript[-1]['start'] + transcript[-1]['duration'] if transcript else 0

        # Combine segments into paragraphs
        paragraphs = []
        current_para = []
        last_time = 0

        for segment in transcript:
            # New paragraph if pause > 2 seconds
            if segment['start'] - last_time > 2.0 and current_para:
                paragraphs.append({
                    'text': ' '.join(current_para),
                    'start': transcript[len(paragraphs) * 10]['start'] if paragraphs else 0
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

    def extract_key_segments(self, transcript, num_scenes=4):
        """Extract key segments for video scenes"""
        analysis = self.analyze_transcript(transcript)
        paragraphs = analysis['paragraphs']

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
                'summary': self._summarize_text(combined_text)
            })

        return key_segments

    def _summarize_text(self, text, max_words=20):
        """Summarize text to key points"""
        # Clean text
        text = re.sub(r'\s+', ' ', text)
        text = text.strip()

        # Extract first sentence or key words
        words = text.split()[:max_words]
        summary = ' '.join(words)

        return summary

    def convert_to_scenes(self, video_title, key_segments):
        """Convert transcript segments to video scenes"""
        scenes = []

        # Scene 1: Title
        scenes.append({
            'type': 'title',
            'title': self._clean_title(video_title),
            'subtitle': 'Key Points Summary',
            'key_message': 'Essential insights from the tutorial'
        })

        # Scenes 2-N: Content from segments
        for i, segment in enumerate(key_segments, 2):
            # Determine scene type based on content
            if self._has_commands(segment['text']):
                scene_type = 'command'
                scene = {
                    'type': 'command',
                    'id': f'scene_{i:02d}_segment_{segment["index"]}',
                    'header': f'Key Point {segment["index"] + 1}',
                    'description': segment['summary'][:50],
                    'topic': segment['summary'],
                    'commands': self._extract_commands_from_text(segment['text']),
                    'key_points': self._extract_key_points(segment['text'])
                }
            else:
                scene_type = 'list'
                scene = {
                    'type': 'list',
                    'id': f'scene_{i:02d}_segment_{segment["index"]}',
                    'header': f'Key Point {segment["index"] + 1}',
                    'description': segment['summary'][:50],
                    'topic': segment['summary'],
                    'items': self._extract_key_points(segment['text'])[:5]
                }

            scenes.append(scene)

        # Outro
        scenes.append({
            'type': 'outro',
            'main_text': 'Watch Full Video',
            'sub_text': 'Link in Description',
            'key_message': 'See original video for complete details'
        })

        return scenes

    def _clean_title(self, title):
        """Clean up YouTube title"""
        # Remove common YouTube patterns
        title = re.sub(r'\[.*?\]', '', title)  # Remove [tags]
        title = re.sub(r'\(.*?\)', '', title)  # Remove (parentheticals)
        title = re.sub(r'\|.*$', '', title)    # Remove | suffixes
        title = title.strip()
        # Limit length
        words = title.split()[:6]
        return ' '.join(words)

    def _has_commands(self, text):
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

    def _extract_commands_from_text(self, text):
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

    def _extract_key_points(self, text):
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


def extract_video_id(url_or_id):
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


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Generate video script from YouTube transcript')
    parser.add_argument('--search', help='Search YouTube for videos')
    parser.add_argument('--video-id', help='YouTube video ID')
    parser.add_argument('--url', help='YouTube video URL')
    parser.add_argument('--accent-color', default='blue', choices=['orange', 'blue', 'purple', 'green', 'pink', 'cyan'])
    parser.add_argument('--voice', default='male', choices=['male', 'female'])
    parser.add_argument('--duration', type=int, default=60, help='Target duration')

    args = parser.parse_args()

    if not HAS_TRANSCRIPT_API:
        logger.error("❌ youtube-transcript-api not installed")
        logger.info("   Install: pip install youtube-transcript-api")
        sys.exit(1)

    # Determine video ID
    video_id = None

    if args.video_id:
        video_id = args.video_id
    elif args.url:
        video_id = extract_video_id(args.url)
    elif args.search:
        logger.info(f"\n{'='*80}")
        logger.info("YOUTUBE SEARCH")
        logger.info(f"{'='*80}\n")
        logger.info(f"Searching for: {args.search}\n")

        # For now, ask user for video ID since API key might not be available
        logger.warning("⚠️  YouTube search requires API key")
        logger.info("   Please provide video ID or URL directly using:")
        logger.info(f"     --video-id VIDEO_ID")
        logger.info(f"     --url https://youtube.com/watch?v=VIDEO_ID\n")
        sys.exit(1)
    else:
        logger.error("❌ Must provide --search, --video-id, or --url")
        sys.exit(1)

    if not video_id:
        logger.error("❌ Could not extract video ID")
        sys.exit(1)

    logger.info(f"\n{'='*80}")
    logger.info("YOUTUBE TRANSCRIPT TO VIDEO")
    logger.info(f"{'='*80}\n")

    # Fetch transcript
    processor = TranscriptProcessor(target_duration=args.duration)
    transcript = processor.fetch_transcript(video_id)

    if not transcript:
        sys.exit(1)

    # Analyze
    logger.info("Analyzing transcript...")
    analysis = processor.analyze_transcript(transcript)
    logger.info(f"✓ Total duration: {analysis['total_duration']:.0f}s")
    logger.info(f"✓ Paragraphs: {len(analysis['paragraphs'])}\n")

    # Extract key segments
    logger.info(f"Extracting key segments for {args.duration}s video...")
    num_content_scenes = min(4, args.duration // 15)  # ~15s per scene
    key_segments = processor.extract_key_segments(transcript, num_content_scenes)
    logger.info(f"✓ Identified {len(key_segments)} key segments\n")

    # Get video title (would come from API, but using placeholder)
    video_title = f"YouTube Content Summary"

    # Convert to scenes
    logger.info("Converting to video scenes...")
    scenes = processor.convert_to_scenes(video_title, key_segments)
    logger.info(f"✓ Created {len(scenes)} scenes\n")

    # Create YAML
    video_id_slug = f"youtube_{video_id[:8]}"
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    yaml_data = {
        'video': {
            'id': video_id_slug,
            'title': video_title,
            'description': f'Summary from YouTube video {video_id}',
            'accent_color': args.accent_color,
            'voice': args.voice,
            'version': 'v2.0',
            'source': f'youtube:{video_id}'
        },
        'scenes': scenes
    }

    # Save YAML
    os.makedirs('inputs', exist_ok=True)
    yaml_file = f"inputs/{video_id_slug}_{timestamp}.yaml"

    import yaml
    with open(yaml_file, 'w') as f:
        yaml.dump(yaml_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    logger.info(f"{'='*80}")
    logger.info("YAML GENERATED")
    logger.info(f"{'='*80}\n")
    logger.info(f"Output: {yaml_file}\n")
    logger.info(f"Original video: https://youtube.com/watch?v={video_id}\n")
    logger.info("Next steps:")
    logger.info(f"  1. Review YAML: cat {yaml_file}")
    logger.info(f"  2. Generate script: python generate_script_from_yaml.py {yaml_file}")
    logger.info(f"\n{'='*80}\n")


if __name__ == "__main__":
    main()
