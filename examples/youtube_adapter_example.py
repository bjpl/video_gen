"""Example usage of the YouTube adapter.

This script demonstrates how to use the YouTube adapter to convert
YouTube video transcripts into VideoSet structures for video generation.
"""

import asyncio
import json
from pathlib import Path
from video_gen.input_adapters.youtube import YouTubeAdapter


async def example_basic_usage():
    """Basic usage example with a YouTube URL."""
    print("=" * 70)
    print("Example 1: Basic YouTube Video Adaptation")
    print("=" * 70)

    adapter = YouTubeAdapter()

    # Example YouTube URL (replace with actual video URL)
    youtube_url = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

    print(f"\nProcessing: {youtube_url}")

    # Adapt the video
    result = await adapter.adapt(youtube_url)

    if result.success:
        print("\n✓ Adaptation successful!")
        print(f"  Video Set ID: {result.video_set.set_id}")
        print(f"  Video Count: {len(result.video_set.videos)}")

        for i, video in enumerate(result.video_set.videos, 1):
            print(f"\n  Video {i}:")
            print(f"    ID: {video.video_id}")
            print(f"    Title: {video.title}")
            print(f"    Scenes: {len(video.scenes)}")

            # Show scene breakdown
            print("\n    Scene Breakdown:")
            for scene in video.scenes[:5]:  # Show first 5 scenes
                print(f"      - {scene.scene_id}: {scene.scene_type}")
                print(f"        Narration: {scene.narration[:60]}...")
    else:
        print(f"\n✗ Adaptation failed: {result.error}")


async def example_with_options():
    """Example with custom options."""
    print("\n" + "=" * 70)
    print("Example 2: YouTube Adaptation with Custom Options")
    print("=" * 70)

    adapter = YouTubeAdapter()

    youtube_url = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

    print(f"\nProcessing: {youtube_url}")
    print("Options:")
    print("  - Language: Spanish (es)")
    print("  - Scene Duration: 15 seconds")
    print("  - Voice: Female")
    print("  - Accent Color: Red")

    # Adapt with custom options
    result = await adapter.adapt(
        youtube_url,
        language='es',
        scene_duration=15,
        voice='female',
        accent_color='red'
    )

    if result.success:
        print("\n✓ Adaptation successful!")
        video = result.video_set.videos[0]
        print(f"  Title: {video.title}")
        print(f"  Accent Color: {video.accent_color}")
        print(f"  Scenes: {len(video.scenes)}")
    else:
        print(f"\n✗ Adaptation failed: {result.error}")
        if "language" in result.error.lower():
            print("  Note: This video may not have Spanish transcripts available")


async def example_export_to_json():
    """Example exporting VideoSet to JSON."""
    print("\n" + "=" * 70)
    print("Example 3: Export VideoSet to JSON")
    print("=" * 70)

    adapter = YouTubeAdapter()
    youtube_url = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

    result = await adapter.adapt(youtube_url)

    if result.success:
        # Export to JSON
        video_set_dict = result.video_set.to_dict()

        # Save to file
        output_path = Path("examples/output/youtube_video_set.json")
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(video_set_dict, f, indent=2, ensure_ascii=False)

        print(f"\n✓ VideoSet exported to: {output_path}")
        print(f"  File size: {output_path.stat().st_size} bytes")

        # Display sample of JSON structure
        print("\nJSON Structure Preview:")
        print(f"  set_id: {video_set_dict['set_id']}")
        print(f"  name: {video_set_dict['name']}")
        print(f"  videos: {len(video_set_dict['videos'])} video(s)")
        print(f"  metadata: {list(video_set_dict['metadata'].keys())}")
    else:
        print(f"\n✗ Export failed: {result.error}")


async def example_url_formats():
    """Example showing different URL format support."""
    print("\n" + "=" * 70)
    print("Example 4: Different YouTube URL Formats")
    print("=" * 70)

    adapter = YouTubeAdapter()

    # Different URL formats
    url_formats = [
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://youtu.be/dQw4w9WgXcQ",
        "https://m.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://www.youtube.com/embed/dQw4w9WgXcQ",
        "dQw4w9WgXcQ",  # Direct video ID
    ]

    print("\nTesting URL format validation:")
    for url in url_formats:
        is_valid = await adapter.validate_source(url)
        video_ids = adapter._extract_video_ids(url)
        print(f"\n  URL: {url}")
        print(f"    Valid: {is_valid}")
        print(f"    Extracted ID: {video_ids[0] if video_ids else 'None'}")


async def example_error_handling():
    """Example demonstrating error handling."""
    print("\n" + "=" * 70)
    print("Example 5: Error Handling")
    print("=" * 70)

    adapter = YouTubeAdapter()

    # Test various error cases
    test_cases = [
        ("Invalid URL", "https://not-youtube.com/video"),
        ("Non-existent video", "https://www.youtube.com/watch?v=invalid123"),
        ("Malformed URL", "not-a-url"),
        ("Non-string input", 12345),
    ]

    for case_name, test_input in test_cases:
        print(f"\n  Testing: {case_name}")
        print(f"    Input: {test_input}")

        result = await adapter.adapt(test_input)

        if result.success:
            print(f"    Result: Success (unexpected)")
        else:
            print(f"    Result: Failed (expected)")
            print(f"    Error: {result.error[:80]}...")


async def example_scene_structure():
    """Example showing detailed scene structure."""
    print("\n" + "=" * 70)
    print("Example 6: Detailed Scene Structure Analysis")
    print("=" * 70)

    adapter = YouTubeAdapter()
    youtube_url = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

    result = await adapter.adapt(youtube_url, scene_duration=10)

    if result.success:
        video = result.video_set.videos[0]

        print(f"\nVideo: {video.title}")
        print(f"Total Scenes: {len(video.scenes)}")
        print("\nScene Details:")

        for i, scene in enumerate(video.scenes, 1):
            print(f"\n  Scene {i} ({scene.scene_id}):")
            print(f"    Type: {scene.scene_type}")
            print(f"    Voice: {scene.voice}")
            print(f"    Duration: {scene.min_duration}-{scene.max_duration}s")
            print(f"    Narration: {scene.narration[:80]}...")

            # Show visual content structure
            print(f"    Visual Content:")
            for key, value in scene.visual_content.items():
                if isinstance(value, list):
                    print(f"      {key}: [{len(value)} items]")
                    if value:
                        print(f"        First item: {str(value[0])[:60]}...")
                else:
                    print(f"      {key}: {str(value)[:60]}...")

            if i >= 3:  # Show first 3 scenes only
                print(f"\n  ... and {len(video.scenes) - 3} more scenes")
                break
    else:
        print(f"\n✗ Failed: {result.error}")


async def main():
    """Run all examples."""
    print("\n" + "=" * 70)
    print("YouTube Adapter Examples")
    print("=" * 70)
    print("\nNote: These examples use a sample YouTube URL.")
    print("For actual usage, replace with a real video URL that has transcripts.")
    print("=" * 70)

    # Run examples
    await example_basic_usage()
    await example_with_options()
    await example_url_formats()
    await example_error_handling()

    # Examples that require actual API calls (may fail without valid video)
    try:
        await example_export_to_json()
        await example_scene_structure()
    except Exception as e:
        print(f"\n\nNote: Advanced examples skipped (requires valid YouTube video)")
        print(f"Error: {str(e)[:100]}")

    print("\n" + "=" * 70)
    print("Examples completed!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
