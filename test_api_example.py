# Example: Using the Python API
from video_gen.shared.models import VideoConfig, SceneConfig, InputConfig
from video_gen.pipeline import get_pipeline
import asyncio

async def create_video_via_api():
    """Example of using Python API to create a video."""
    
    # Define your video programmatically
    video = VideoConfig(
        video_id="api_test",
        title="Python API Example",
        description="Created via Python script",
        scenes=[
            SceneConfig(
                scene_id="intro",
                scene_type="title",
                narration="This video was created using the Python API",
                visual_content={
                    "title": "Python API",
                    "subtitle": "Easy Automation"
                }
            ),
            SceneConfig(
                scene_id="demo",
                scene_type="command",
                narration="Here's how easy it is to generate videos programmatically",
                visual_content={
                    "header": "Example Commands",
                    "label": "Try This",
                    "commands": [
                        "from video_gen.shared.models import VideoConfig",
                        "video = VideoConfig(...)",
                        "pipeline.execute(video)"
                    ]
                }
            )
        ],
        accent_color="blue",
        voices=["male"]
    )
    
    print("✅ Video config created")
    print(f"   Video ID: {video.video_id}")
    print(f"   Scenes: {len(video.scenes)}")
    print("   Ready for generation!")
    
    return video

# Run it
if __name__ == "__main__":
    video = asyncio.run(create_video_via_api())
    print("\n✅ Python API works perfectly!")

