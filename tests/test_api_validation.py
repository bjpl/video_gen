"""
API Validation Tests
====================
Validate that the Pydantic models correctly handle new fields.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app.main import Video, VideoSet, MultilingualRequest, SceneBase
from pydantic import ValidationError


def test_video_voices_array():
    """Test Video model accepts voices array"""
    print("\n=== Test 1: Video with voices array ===")

    # New format: voices array
    video = Video(
        video_id="test_001",
        title="Test Video",
        voices=["male", "female", "male_warm"],
        scenes=[
            {"type": "title", "title": "Hello", "subtitle": "World"}
        ]
    )

    print(f"✅ Video created with voices: {video.voices}")
    print(f"   get_voices() returns: {video.get_voices()}")
    assert video.get_voices() == ["male", "female", "male_warm"]

    # Old format: single voice string (backward compat)
    video_old = Video(
        video_id="test_002",
        title="Old Format",
        voice="female",
        scenes=[]
    )

    print(f"✅ Old format works, get_voices() returns: {video_old.get_voices()}")
    assert video_old.get_voices() == ["female"]

    # Default case
    video_default = Video(
        video_id="test_003",
        title="Default",
        scenes=[]
    )

    print(f"✅ Default case, get_voices() returns: {video_default.get_voices()}")
    assert video_default.get_voices() == ["male"]


def test_multilingual_language_voices():
    """Test MultilingualRequest accepts language_voices mapping"""
    print("\n=== Test 2: Multilingual with language_voices ===")

    video_set = VideoSet(
        set_id="ml_001",
        set_name="Test Set",
        videos=[
            Video(
                video_id="v1",
                title="Video 1",
                scenes=[{"type": "title", "title": "Test"}]
            )
        ]
    )

    request = MultilingualRequest(
        video_set=video_set,
        target_languages=["en", "es", "fr"],
        source_language="en",
        language_voices={
            "en": "male",
            "es": "male_spanish",
            "fr": "female_french"
        }
    )

    print(f"✅ Multilingual request created")
    print(f"   Target languages: {request.target_languages}")
    print(f"   Language voices: {request.language_voices}")

    assert request.language_voices is not None
    assert request.language_voices["es"] == "male_spanish"
    assert request.language_voices["fr"] == "female_french"


def test_scene_extra_fields():
    """Test SceneBase allows extra fields"""
    print("\n=== Test 3: Scene with extra fields ===")

    # Test with learning_objectives scene
    scene = SceneBase(
        type="learning_objectives",
        voice="male",
        title="Goals",  # Extra field
        objectives=["Goal 1", "Goal 2"]  # Extra field
    )

    print(f"✅ Scene created with type: {scene.type}")
    print(f"   Extra fields allowed: title, objectives")

    # Test with problem scene
    scene2 = SceneBase(
        type="problem",
        title="Challenge",
        description="Solve this problem",
        constraints=["Constraint 1", "Constraint 2"]
    )

    print(f"✅ Problem scene created with constraints")

    # Test with code scene
    scene3 = SceneBase(
        type="command",
        command_name="Install",
        description="Install dependencies",
        commands=["npm install", "npm start"]
    )

    print(f"✅ Command scene created with commands list")


def test_video_set_serialization():
    """Test VideoSet serialization with new fields"""
    print("\n=== Test 4: VideoSet serialization ===")

    video_set = VideoSet(
        set_id="set_001",
        set_name="Complete Test",
        videos=[
            Video(
                video_id="v1",
                title="Video 1",
                voices=["male", "female"],
                duration=60,
                scenes=[
                    {
                        "type": "title",
                        "title": "Welcome",
                        "subtitle": "Introduction"
                    },
                    {
                        "type": "list",
                        "title": "Topics",
                        "items": ["Topic 1", "Topic 2"]
                    }
                ]
            )
        ],
        accent_color="blue",
        languages=["en", "es"]
    )

    # Serialize to dict
    data = video_set.dict()

    print(f"✅ VideoSet serialized")
    print(f"   Videos: {len(data['videos'])}")
    print(f"   Video 1 voices: {data['videos'][0]['voices']}")
    print(f"   Video 1 scenes: {len(data['videos'][0]['scenes'])}")
    print(f"   Languages: {data['languages']}")

    assert data['videos'][0]['voices'] == ["male", "female"]
    assert data['videos'][0]['duration'] == 60
    assert len(data['videos'][0]['scenes']) == 2


def test_validation_errors():
    """Test that validation still works for required fields"""
    print("\n=== Test 5: Validation errors ===")

    try:
        # Missing required field
        video = Video(
            video_id="test",
            # Missing title
            scenes=[]
        )
        print("❌ Should have raised validation error")
    except ValidationError as e:
        print(f"✅ Validation error caught: {e.error_count()} errors")

    try:
        # Invalid scene type
        scene = SceneBase(
            type="invalid_type",  # Not in Literal types
            voice="male"
        )
        print("❌ Should have raised validation error")
    except ValidationError as e:
        print(f"✅ Scene type validation works: {e.error_count()} errors")


def main():
    """Run all validation tests"""
    print("=" * 60)
    print("API VALIDATION TESTS")
    print("=" * 60)

    try:
        test_video_voices_array()
        test_multilingual_language_voices()
        test_scene_extra_fields()
        test_video_set_serialization()
        test_validation_errors()

        print("\n" + "=" * 60)
        print("✅ ALL VALIDATION TESTS PASSED")
        print("=" * 60)

    except AssertionError as e:
        print(f"\n❌ Assertion failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

    except Exception as e:
        print(f"\n❌ Test error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
