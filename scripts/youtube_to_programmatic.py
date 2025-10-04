"""
YouTube to Programmatic Bridge
===============================
Parse YouTube video transcripts and convert to programmatic video sets.

This bridges the YouTube parser with the programmatic API, allowing:
- YouTube URL → VideoSetBuilder
- Transcript → Structured video
- No manual processing needed
- Combine automatic parsing with programmatic control

Usage:
    # Simple: Parse YouTube → generate
    from youtube_to_programmatic import parse_youtube_to_builder

    builder = parse_youtube_to_builder('https://youtube.com/watch?v=VIDEO_ID')
    builder.export_to_yaml('sets/youtube_summary')

    # Advanced: Parse, then enhance
    builder = parse_youtube_to_builder('https://youtube.com/watch?v=ID')
    builder.add_video(...)  # Add more content
    builder.export_to_yaml('sets/enhanced_youtube')
"""

import sys
sys.path.append('.')

from python_set_builder import VideoSetBuilder
from typing import Optional, List
import re
from urllib.parse import urlparse, parse_qs

# Try importing YouTube transcript API
try:
    from youtube_transcript_api import YouTubeTranscriptApi
    HAS_YOUTUBE = True
except ImportError:
    HAS_YOUTUBE = False
    print("⚠️  YouTube transcript support requires: pip install youtube-transcript-api")


def extract_video_id(url_or_id):
    """Extract video ID from YouTube URL or return as-is if already an ID"""
    if 'youtube.com' in url_or_id or 'youtu.be' in url_or_id:
        parsed = urlparse(url_or_id)
        if 'youtube.com' in url_or_id:
            query = parse_qs(parsed.query)
            return query.get('v', [None])[0]
        elif 'youtu.be' in url_or_id:
            return parsed.path.strip('/')
    return url_or_id


def fetch_transcript(video_id):
    """Fetch transcript for YouTube video"""
    if not HAS_YOUTUBE:
        return None

    try:
        transcript_list = YouTubeTranscriptApi.get_transcript(video_id)
        full_text = ' '.join([entry['text'] for entry in transcript_list])
        return {'transcript': full_text, 'entries': transcript_list}
    except Exception as e:
        print(f"⚠️  Could not fetch transcript: {e}")
        return None


def parse_youtube_to_builder(
    youtube_url: str,
    set_id: Optional[str] = None,
    set_name: Optional[str] = None,
    target_duration: int = 60,
    **builder_kwargs
) -> VideoSetBuilder:
    """
    Parse a YouTube video and create a VideoSetBuilder.

    Args:
        youtube_url: YouTube video URL
        set_id: Optional set ID (auto-generated if not provided)
        set_name: Optional set name (auto-generated if not provided)
        target_duration: Target video duration in seconds
        **builder_kwargs: Additional VideoSetBuilder parameters

    Returns:
        VideoSetBuilder with video from YouTube content

    Example:
        # Parse YouTube tutorial
        builder = parse_youtube_to_builder(
            'https://youtube.com/watch?v=VIDEO_ID',
            target_duration=90,
            defaults={'accent_color': 'purple', 'voice': 'female'}
        )

        # Customize further
        builder.add_video(...)

        # Export
        builder.export_to_yaml('sets/youtube_tutorial')
    """

    print(f"Fetching YouTube transcript: {youtube_url}")

    # Extract video ID
    video_id = extract_video_id(youtube_url)

    # Fetch transcript
    transcript_data = fetch_transcript(video_id)

    if not transcript_data:
        raise ValueError(f"Could not fetch transcript for {youtube_url}")

    # Generate IDs if not provided
    if not set_id:
        set_id = f"youtube_{video_id}"

    if not set_name:
        # Try to get video title (simplified - would need YouTube API for real title)
        set_name = f"YouTube Summary: {video_id}"

    print(f"Creating video set: {set_name}")

    # Create builder
    builder = VideoSetBuilder(
        set_id=set_id,
        set_name=set_name,
        **builder_kwargs
    )

    # Convert transcript to scenes
    scenes = _transcript_to_scenes(builder, transcript_data, target_duration)

    builder.add_video(
        video_id=f"{set_id}_summary",
        title=f"Summary: {set_name}",
        description=f"Summary of YouTube video {video_id}",
        scenes=scenes
    )

    print(f"✓ Parsed transcript → {len(scenes)} scenes")

    return builder


def _transcript_to_scenes(builder: VideoSetBuilder, transcript_data: dict, target_duration: int) -> list:
    """Convert transcript to scenes"""

    transcript_text = transcript_data.get('transcript', '')

    # Split transcript into chunks (simple approach)
    words = transcript_text.split()
    total_words = len(words)

    # Calculate words per scene (target ~135 WPM = ~2.25 words/sec)
    words_per_scene = int(target_duration / 5 * 2.25 * 135 / 60)  # Rough estimate

    scenes = []

    # Title scene
    scenes.append(
        builder.create_title_scene(
            "Video Summary",
            "Key Takeaways"
        )
    )

    # Create content scenes from transcript chunks
    num_sections = max(2, min(5, total_words // words_per_scene))

    for i in range(num_sections):
        start_idx = i * len(words) // num_sections
        end_idx = (i + 1) * len(words) // num_sections

        chunk = ' '.join(words[start_idx:end_idx])

        # Extract key points (simplified - find sentences)
        sentences = re.split(r'[.!?]+', chunk)
        key_points = [s.strip() for s in sentences if s.strip()][:4]

        if key_points:
            scenes.append(
                builder.create_list_scene(
                    f"Key Points {i+1}",
                    f"Section {i+1} Highlights",
                    key_points
                )
            )

    # Outro
    scenes.append(
        builder.create_outro_scene(
            "Full Video",
            "Watch on YouTube"
        )
    )

    return scenes


def parse_youtube_to_set(
    youtube_url: str,
    output_dir: str = '../sets',
    **kwargs
) -> str:
    """
    Parse YouTube and export to set (complete workflow).

    Args:
        youtube_url: YouTube video URL
        output_dir: Where to save the set
        **kwargs: VideoSetBuilder parameters

    Returns:
        Path to exported set directory

    Example:
        # One function call!
        set_path = parse_youtube_to_set(
            'https://youtube.com/watch?v=VIDEO_ID',
            defaults={'accent_color': 'blue'}
        )
    """

    builder = parse_youtube_to_builder(youtube_url, **kwargs)
    set_path = builder.export_to_yaml(output_dir)

    print(f"\n✓ YouTube video parsed and exported!")
    print(f"  → {set_path}")
    print(f"\nNext steps:")
    print(f"  cd scripts")
    print(f"  python generate_video_set.py ../{set_path}")

    return str(set_path)


def example_parse_multiple_youtube():
    """Example: Parse multiple YouTube videos into one set"""

    print("\n" + "="*80)
    print("EXAMPLE: Multiple YouTube Videos → One Set")
    print("="*80 + "\n")

    from python_set_builder import VideoSetBuilder

    # Create builder for the set
    builder = VideoSetBuilder(
        set_id='youtube_collection',
        set_name='YouTube Tutorial Collection',
        defaults={'accent_color': 'blue', 'voice': 'male'}
    )

    youtube_videos = [
        'https://youtube.com/watch?v=VIDEO_ID_1',
        'https://youtube.com/watch?v=VIDEO_ID_2',
        'https://youtube.com/watch?v=VIDEO_ID_3'
    ]

    for i, url in enumerate(youtube_videos, 1):
        try:
            # Parse each YouTube video
            temp_builder = parse_youtube_to_builder(url)

            # Get the video
            if temp_builder.videos:
                video = temp_builder.videos[0]
                video.video_id = f"youtube_{i:02d}"
                video.title = f"Tutorial {i}"

                # Add to main set
                builder.videos.append(video)

                print(f"  ✓ Video {i} parsed")

        except Exception as e:
            print(f"  ⚠️  Skipped video {i}: {e}")

    builder.export_to_yaml('../sets/youtube_collection')

    print(f"\n✓ Created set with {len(builder.videos)} YouTube summaries!")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description='Parse YouTube videos into programmatic sets',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Simple parse
  python youtube_to_programmatic.py https://youtube.com/watch?v=VIDEO_ID

  # With options
  python youtube_to_programmatic.py https://youtube.com/watch?v=ID \\
      --accent-color purple \\
      --voice female \\
      --duration 90

  # Run examples
  python youtube_to_programmatic.py --run-examples
        """
    )

    parser.add_argument('url', nargs='?', help='YouTube video URL')
    parser.add_argument('--set-id', help='Set ID')
    parser.add_argument('--set-name', help='Set name')
    parser.add_argument('--accent-color', default='blue', help='Accent color')
    parser.add_argument('--voice', default='male', help='Voice')
    parser.add_argument('--duration', type=int, default=60, help='Target duration')
    parser.add_argument('--output', default='../sets', help='Output directory')
    parser.add_argument('--run-examples', action='store_true', help='Run examples')

    args = parser.parse_args()

    if args.run_examples:
        print("Note: Examples use placeholder URLs - replace with real YouTube URLs")
        example_3_parse_and_customize()
    elif args.url:
        kwargs = {
            'target_duration': args.duration,
            'defaults': {
                'accent_color': args.accent_color,
                'voice': args.voice
            }
        }

        if args.set_id:
            kwargs['set_id'] = args.set_id
        if args.set_name:
            kwargs['set_name'] = args.set_name

        set_path = parse_youtube_to_set(
            args.url,
            output_dir=args.output,
            **kwargs
        )

        print(f"\n✅ Ready to generate!")
    else:
        parser.print_help()
