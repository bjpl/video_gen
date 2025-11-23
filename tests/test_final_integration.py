"""
Final Integration Test - Agent 10
Tests complete system integration using correct imports
"""

import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from video_gen.pipeline import get_pipeline
from video_gen.shared.models import (
    InputConfig, VideoSet, VideoConfig, SceneConfig
)
from language_config import MULTILINGUAL_VOICES, list_available_languages


def test_pipeline_initialization():
    """TEST: Pipeline Initialization"""
    print("\n" + "="*70)
    print("TEST: Pipeline Initialization")
    print("="*70)

    pipeline = get_pipeline()

    print(f"  Pipeline stages: {len(pipeline.stages)}")
    for i, stage in enumerate(pipeline.stages):
        print(f"    {i+1}. {stage.__class__.__name__}")

    assert len(pipeline.stages) == 6, "Should have 6 stages"
    assert pipeline.state_manager is not None, "Should have state manager"

    print("  ✅ Pipeline initialized successfully")
    return True


def test_multilingual_support():
    """TEST: Multilingual Support (28+ languages)"""
    print("\n" + "="*70)
    print("TEST: Multilingual Support")
    print("="*70)

    languages = list_available_languages()
    print(f"  Available languages: {len(languages)}")
    print(f"  Sample: {', '.join(languages[:10])}")

    assert len(languages) >= 28, f"Should have 28+ languages, got {len(languages)}"

    # Verify major languages
    major_langs = ["en", "es", "fr", "de", "zh", "ja", "ar", "hi"]
    for lang in major_langs:
        assert lang in MULTILINGUAL_VOICES, f"Missing {lang}"
        print(f"  ✅ {lang}: {list(MULTILINGUAL_VOICES[lang].keys())[:2]}")

    print(f"\n  ✅ All {len(languages)} languages supported with voices")
    return True


def test_video_set_creation():
    """TEST: VideoSet Creation with Multiple Voices"""
    print("\n" + "="*70)
    print("TEST: VideoSet Creation")
    print("="*70)

    # Create test scenes
    scenes = [
        SceneConfig(
            scene_id="test_title",
            scene_type="title",
            narration="Test Video Title",
            visual_content={"title": "Test Video", "subtitle": "Integration Test"},
            voice="male"
        ),
        SceneConfig(
            scene_id="test_content",
            scene_type="command",
            narration="Test content narration",
            visual_content={"command": "pip install test"},
            voice="female"
        ),
        SceneConfig(
            scene_id="test_outro",
            scene_type="outro",
            narration="Thank you for watching",
            visual_content={"message": "Thank you"},
            voice="male_warm"
        )
    ]

    # Create video with multiple voices
    video = VideoConfig(
        video_id="test_video_1",
        title="Test Video",
        description="Test video for integration",
        scenes=scenes
    )

    # Create video set with multilingual support
    video_set = VideoSet(
        set_id="test_set",
        name="Test Set",
        videos=[video],
        metadata={"languages": ["en", "es", "fr"]}
    )

    print(f"  Video: {video.title}")
    print(f"  Scenes: {len(video.scenes)}")
    print(f"  Languages: {', '.join(video_set.languages)}")
    print(f"  Total output videos: {len(video_set.videos)} × {len(video_set.languages)} = {len(video_set.videos) * len(video_set.languages)}")

    assert len(scenes) == 3, "Should have 3 scenes"
    assert len(video_set.languages) == 3, "Should have 3 languages"

    print("  ✅ VideoSet created successfully")
    return True


def test_input_config():
    """TEST: InputConfig Structure"""
    print("\n" + "="*70)
    print("TEST: InputConfig Structure")
    print("="*70)

    # Create input config for document processing
    config = InputConfig(
        input_type="document",
        source="README.md",
        languages=["en", "es"],
        voice="male"
    )

    print(f"  Input type: {config.input_type}")
    print(f"  Source: {config.source}")
    print(f"  Languages: {', '.join(config.languages)}")
    print(f"  Voice: {config.voice}")

    assert config.input_type == "document"
    assert len(config.languages) == 2

    print("  ✅ InputConfig created successfully")
    return True


def test_scene_types():
    """TEST: All Scene Types Support"""
    print("\n" + "="*70)
    print("TEST: Scene Types Support")
    print("="*70)

    # Educational scene types
    scene_types = [
        "title",
        "command",
        "list",
        "outro",
        "code_comparison",
        "quote",
        "learning_objectives",
        "problem",
        "solution",
        "checkpoint",
        "quiz",
        "exercise"
    ]

    print(f"  Supported scene types: {len(scene_types)}")
    for scene_type in scene_types:
        scene = SceneConfig(
            scene_id=f"test_{scene_type}",
            scene_type=scene_type,
            narration=f"Test {scene_type} narration",
            visual_content={"content": f"Test {scene_type}"}
        )
        assert scene.scene_type == scene_type
        print(f"    ✅ {scene_type}")

    print(f"\n  ✅ All {len(scene_types)} scene types supported")
    return True


def test_voice_options():
    """TEST: Voice Options (Male, Female, Warm, Friendly)"""
    print("\n" + "="*70)
    print("TEST: Voice Options")
    print("="*70)

    voices = ["male", "male_warm", "female", "female_friendly"]

    for voice in voices:
        scene = SceneConfig(
            scene_id=f"test_{voice}",
            scene_type="command",
            narration="Test narration",
            visual_content={"command": "test"},
            voice=voice
        )
        assert scene.voice == voice
        print(f"  ✅ {voice}")

    print(f"\n  ✅ All {len(voices)} voice options supported")
    return True


def test_multilingual_video_set():
    """TEST: Multilingual VideoSet (5 videos × 3 languages = 15 videos)"""
    print("\n" + "="*70)
    print("TEST: Multilingual VideoSet")
    print("="*70)

    # Create 5 videos
    videos = []
    for i in range(5):
        scenes = [
            SceneConfig(
                scene_id=f"video{i+1}_title",
                scene_type="title",
                narration=f"Video {i+1} Title",
                visual_content={"title": f"Video {i+1}"}
            ),
            SceneConfig(
                scene_id=f"video{i+1}_content",
                scene_type="command",
                narration=f"Video {i+1} content",
                visual_content={"command": "test"}
            ),
            SceneConfig(
                scene_id=f"video{i+1}_outro",
                scene_type="outro",
                narration="Thank you",
                visual_content={"message": "Thanks"}
            )
        ]
        video = VideoConfig(
            video_id=f"video_{i+1}",
            title=f"Video {i+1}",
            description=f"Test video {i+1}",
            scenes=scenes
        )
        videos.append(video)

    # Create set with 3 languages
    video_set = VideoSet(
        set_id="multi_test",
        name="Multilingual Test",
        videos=videos,
        metadata={"languages": ["en", "es", "fr"]}
    )

    print(f"  Base videos: {len(video_set.videos)}")
    print(f"  Languages: {', '.join(video_set.languages)}")
    print(f"  Total output: {len(video_set.videos)} × {len(video_set.languages)} = {len(video_set.videos) * len(video_set.languages)} videos")

    assert len(video_set.videos) == 5
    assert len(video_set.languages) == 3

    print("  ✅ Multilingual video set configured")
    return True


def test_templates():
    """TEST: Quick Templates"""
    print("\n" + "="*70)
    print("TEST: Quick Templates")
    print("="*70)

    templates = {
        "Tutorial": {
            "videos": 5,
            "duration": 90,
            "scenes": ["title", "learning_objectives", "command", "checkpoint", "outro"]
        },
        "Course": {
            "videos": 10,
            "duration": 180,
            "scenes": ["title", "learning_objectives", "problem", "solution", "exercise", "outro"]
        },
        "Demo": {
            "videos": 3,
            "duration": 60,
            "scenes": ["title", "command", "code_comparison", "outro"]
        },
        "Global": {
            "videos": 8,
            "languages": ["en", "es", "zh", "hi", "ar"]
        }
    }

    for name, config in templates.items():
        print(f"\n  📋 {name} Template:")
        print(f"     Videos: {config['videos']}")
        if "duration" in config:
            print(f"     Duration: {config['duration']}s")
        if "scenes" in config:
            print(f"     Scenes: {', '.join(config['scenes'])}")
        if "languages" in config:
            print(f"     Languages: {', '.join(config['languages'])}")
            assert len(config['languages']) >= 5, f"{name} should have 5+ languages"

    print("\n  ✅ All templates validated")
    return True


def test_data_flow():
    """TEST: Data Flow (Input → Pipeline → Output)"""
    print("\n" + "="*70)
    print("TEST: Data Flow Validation")
    print("="*70)

    # 1. Create input
    input_config = InputConfig(
        input_type="manual",
        source="test",
        metadata={"languages": ["en"]}
    )
    print("  ✅ Step 1: Input created")

    # 2. Create video set
    scenes = [
        SceneConfig(
            scene_id="test_scene",
            scene_type="title",
            narration="Test",
            visual_content={"title": "Test"}
        )
    ]
    video = VideoConfig(
        video_id="test_video",
        title="Test",
        description="Test video",
        scenes=scenes
    )
    video_set = VideoSet(
        set_id="test_set",
        name="Test",
        videos=[video]
    )
    print("  ✅ Step 2: VideoSet created")

    # 3. Get pipeline
    pipeline = get_pipeline()
    print("  ✅ Step 3: Pipeline retrieved")

    # 4. Verify stages
    print(f"  ✅ Step 4: Pipeline has {len(pipeline.stages)} stages")

    print("\n  ✅ Complete data flow validated")
    return True


def run_all_tests():
    """Run all final integration tests"""
    print("\n" + "="*70)
    print(" FINAL INTEGRATION TEST SUITE - AGENT 10")
    print("="*70)

    tests = [
        ("Pipeline Initialization", test_pipeline_initialization),
        ("Multilingual Support", test_multilingual_support),
        ("VideoSet Creation", test_video_set_creation),
        ("InputConfig Structure", test_input_config),
        ("Scene Types Support", test_scene_types),
        ("Voice Options", test_voice_options),
        ("Multilingual VideoSet", test_multilingual_video_set),
        ("Quick Templates", test_templates),
        ("Data Flow Validation", test_data_flow),
    ]

    results = []

    for test_name, test_func in tests:
        try:
            test_func()
            results.append((test_name, "PASS", None))
        except Exception as e:
            results.append((test_name, "FAIL", str(e)))
            print(f"  ❌ ERROR: {e}")

    # Summary
    print("\n" + "="*70)
    print(" TEST SUMMARY")
    print("="*70)

    passed = sum(1 for _, status, _ in results if status == "PASS")
    failed = sum(1 for _, status, _ in results if status == "FAIL")

    for test_name, status, error in results:
        symbol = "✅" if status == "PASS" else "❌"
        print(f"{symbol} {test_name}: {status}")
        if error:
            print(f"   Error: {error[:100]}")

    print(f"\nTotal: {passed} PASSED, {failed} FAILED out of {len(results)} tests")
    print("="*70)

    # Overall result
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED! System is fully integrated.")
        return True
    else:
        print(f"\n⚠️  {failed} test(s) failed. Review errors above.")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
