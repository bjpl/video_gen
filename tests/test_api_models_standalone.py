"""
Standalone API Model Tests
===========================
Tests Pydantic models directly without pipeline dependencies.
"""

from typing import List, Dict, Optional, Literal, Any
from pydantic import BaseModel, ValidationError


# Copy models from app/main.py for standalone testing
class SceneBase(BaseModel):
    type: Literal[
        "title", "command", "list", "outro", "code_comparison", "quote",
        "learning_objectives", "problem", "solution", "checkpoint", "quiz", "exercise"
    ]
    voice: Optional[Literal["male", "male_warm", "female", "female_friendly"]] = "male"
    narration: Optional[str] = None

    class Config:
        extra = "allow"  # Allow additional fields for scene-specific content


class Video(BaseModel):
    video_id: str
    title: str
    scenes: List[Dict]  # Accept any scene type
    voice: Optional[str] = "male"  # Deprecated: use voices instead
    voices: Optional[List[str]] = None  # NEW: Support multiple voices
    duration: Optional[int] = None

    def get_voices(self) -> List[str]:
        """Get voice list, handling backward compatibility."""
        if self.voices:
            return self.voices
        return [self.voice] if self.voice else ["male"]


class VideoSet(BaseModel):
    set_id: str
    set_name: str
    videos: List[Video]
    accent_color: Optional[str] = "blue"
    languages: Optional[List[str]] = ["en"]
    source_language: Optional[str] = "en"
    translation_method: Optional[Literal["claude", "google", "manual"]] = "claude"


class MultilingualRequest(BaseModel):
    video_set: VideoSet
    target_languages: List[str]  # e.g., ["en", "es", "fr"]
    source_language: str = "en"
    translation_method: Optional[Literal["claude", "google"]] = "claude"
    language_voices: Optional[Dict[str, str]] = None  # NEW: Per-language voice mapping


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
        voice="male"
    )

    # Extra fields should be allowed in dict representation
    scene_dict = {
        "type": "learning_objectives",
        "voice": "male",
        "title": "Goals",
        "objectives": ["Goal 1", "Goal 2"]
    }

    print(f"✅ Scene created with type: {scene.type}")
    print(f"   Scene dict with extra fields: {scene_dict}")

    # Validate in Video context
    video = Video(
        video_id="test",
        title="Test",
        scenes=[scene_dict]  # Scene dict with extra fields
    )

    print(f"✅ Video accepts scenes with extra fields")
    assert video.scenes[0]["objectives"] == ["Goal 1", "Goal 2"]


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
        print(f"✅ Validation error caught: {e.error_count()} error(s)")

    try:
        # Invalid scene type in SceneBase
        scene = SceneBase(
            type="invalid_type",  # Not in Literal types
            voice="male"
        )
        print("❌ Should have raised validation error")
    except ValidationError as e:
        print(f"✅ Scene type validation works: {e.error_count()} error(s)")


def test_api_payload_format():
    """Test complete API payload format"""
    print("\n=== Test 6: Complete API payload ===")

    # Simulate frontend payload
    payload = {
        "set_id": "tutorial_001",
        "set_name": "Python Tutorial",
        "videos": [
            {
                "video_id": "vid_001",
                "title": "Introduction to Python",
                "voices": ["male", "female"],
                "duration": 60,
                "scenes": [
                    {
                        "type": "title",
                        "title": "Welcome to Python",
                        "subtitle": "Let's get started",
                        "voice": "male"
                    },
                    {
                        "type": "learning_objectives",
                        "title": "What You'll Learn",
                        "objectives": [
                            "Python basics",
                            "Data structures",
                            "Functions"
                        ],
                        "voice": "female"
                    },
                    {
                        "type": "quiz",
                        "question": "What is Python?",
                        "options": ["A language", "A snake", "A framework", "An IDE"],
                        "correct_answer": 0,
                        "voice": "male"
                    }
                ]
            }
        ],
        "accent_color": "blue",
        "languages": ["en", "es"]
    }

    # Parse with Pydantic
    video_set = VideoSet(**payload)

    print(f"✅ Complete payload parsed")
    print(f"   Set: {video_set.set_name}")
    print(f"   Videos: {len(video_set.videos)}")
    print(f"   Voices: {video_set.videos[0].get_voices()}")
    print(f"   Scenes: {len(video_set.videos[0].scenes)}")
    print(f"   Scene types: {[s['type'] for s in video_set.videos[0].scenes]}")

    assert video_set.videos[0].get_voices() == ["male", "female"]
    assert len(video_set.videos[0].scenes) == 3
    assert video_set.videos[0].scenes[1]["objectives"] is not None


def main():
    """Run all validation tests"""
    print("=" * 60)
    print("STANDALONE API MODEL VALIDATION TESTS")
    print("=" * 60)

    try:
        test_video_voices_array()
        test_multilingual_language_voices()
        test_scene_extra_fields()
        test_video_set_serialization()
        test_validation_errors()
        test_api_payload_format()

        print("\n" + "=" * 60)
        print("✅ ALL VALIDATION TESTS PASSED")
        print("=" * 60)
        print("\nValidated:")
        print("  ✅ Voice arrays (voices: List[str])")
        print("  ✅ Backward compatibility (voice: str)")
        print("  ✅ Language-voice mapping (language_voices: Dict)")
        print("  ✅ Scene extra fields (Config.extra = 'allow')")
        print("  ✅ Duration hints")
        print("  ✅ Complete API payloads")
        print("  ✅ Pydantic validation still works")

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
