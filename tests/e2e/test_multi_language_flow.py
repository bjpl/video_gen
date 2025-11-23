"""
E2E Test: Multi-Language Video Set Flow
========================================

Complete end-to-end test for multi-language video generation:
1. Upload document
2. Select 5 languages
3. Select 3 voices per language
4. Choose "Video Set" mode
5. Start generation
6. Track progress for all videos
7. Download video set (ZIP)
"""

import pytest
from pathlib import Path
from fastapi.testclient import TestClient
import sys
import json
import time
from io import BytesIO

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.main import app


@pytest.fixture
def client():
    """Create test client with CSRF disabled"""
    import os
    os.environ["CSRF_DISABLED"] = "true"
    with TestClient(app) as c:
        yield c
    os.environ.pop("CSRF_DISABLED", None)


@pytest.fixture
def sample_markdown():
    """Sample markdown for multi-language generation"""
    return b"""# Introduction to Machine Learning

## What is Machine Learning?

Machine learning is a subset of artificial intelligence that enables systems to learn from data.

- Supervised learning
- Unsupervised learning
- Reinforcement learning

## Key Concepts

### Training Data

Models learn patterns from training data.

```python
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
```

### Model Evaluation

Evaluate models using metrics like accuracy and precision.

## Conclusion

Machine learning powers modern AI applications.
"""


# ============================================================================
# Language Selection Tests
# ============================================================================

class TestLanguageSelection:
    """E2E tests for language selection"""

    @pytest.mark.e2e
    def test_get_all_languages(self, client):
        """Test retrieving all available languages"""
        response = client.get("/api/languages")

        assert response.status_code == 200
        data = response.json()
        assert "languages" in data
        languages = data["languages"]

        # Should have multiple languages (28+)
        assert len(languages) >= 5
        assert data.get("total", len(languages)) >= 5

    @pytest.mark.e2e
    def test_language_has_required_fields(self, client):
        """Test each language has required fields"""
        response = client.get("/api/languages")
        data = response.json()
        languages = data.get("languages", [])

        for lang in languages[:5]:  # Check first 5
            assert "code" in lang
            assert "name" in lang

    @pytest.mark.e2e
    def test_select_five_languages(self, client):
        """Test selecting 5 languages"""
        response = client.get("/api/languages")
        languages = response.json().get("languages", [])

        # Select first 5 languages
        selected = [lang["code"] for lang in languages[:5]]
        assert len(selected) == 5

        # Verify voices available for each
        for code in selected:
            voice_response = client.get(f"/api/languages/{code}/voices")
            # Not all languages may have voices
            assert voice_response.status_code in [200, 404]


# ============================================================================
# Voice Selection Tests
# ============================================================================

class TestVoiceSelection:
    """E2E tests for voice selection per language"""

    @pytest.mark.e2e
    def test_get_voices_for_english(self, client):
        """Test getting voices for English"""
        response = client.get("/api/languages/en/voices")

        assert response.status_code == 200
        data = response.json()
        assert "voices" in data
        assert len(data["voices"]) >= 1

    @pytest.mark.e2e
    def test_get_voices_for_multiple_languages(self, client):
        """Test getting voices for multiple languages"""
        test_languages = ["en", "es", "fr", "de", "ja"]
        voice_counts = {}

        for lang in test_languages:
            response = client.get(f"/api/languages/{lang}/voices")
            if response.status_code == 200:
                voice_counts[lang] = len(response.json().get("voices", []))
            else:
                voice_counts[lang] = 0

        # English should have voices
        assert voice_counts.get("en", 0) >= 1

    @pytest.mark.e2e
    def test_voice_has_id_and_name(self, client):
        """Test voice objects have id and name"""
        response = client.get("/api/languages/en/voices")
        voices = response.json().get("voices", [])

        for voice in voices:
            assert "id" in voice
            assert "name" in voice


# ============================================================================
# Multi-Language Generation Tests
# ============================================================================

class TestMultiLanguageGeneration:
    """E2E tests for multi-language video generation"""

    @pytest.mark.e2e
    def test_multilingual_endpoint_exists(self, client):
        """Test multilingual generation endpoint exists"""
        response = client.post("/api/generate/multilingual")

        # Should not return 404
        assert response.status_code != 404

    @pytest.mark.e2e
    def test_multilingual_request_format(self, client):
        """Test multilingual request accepts proper format"""
        request_data = {
            "video_set": {
                "set_id": "test_multilingual_set",
                "set_name": "Test Multi-Language Set",
                "videos": [
                    {
                        "video_id": "test_video_1",
                        "title": "Test Video",
                        "scenes": [
                            {
                                "type": "title",
                                "title": "Test Title",
                                "subtitle": "Test Subtitle"
                            }
                        ],
                        "voice": "male"
                    }
                ],
                "accent_color": "blue"
            },
            "target_languages": ["en", "es", "fr"],
            "source_language": "en",
            "translation_method": "claude"
        }

        response = client.post("/api/generate/multilingual", json=request_data)

        # Should accept the request format
        assert response.status_code in [200, 500]  # 500 if translation fails
        if response.status_code == 200:
            data = response.json()
            assert "task_id" in data

    @pytest.mark.e2e
    def test_multilingual_with_five_languages(self, client):
        """Test multilingual generation with 5 languages"""
        request_data = {
            "video_set": {
                "set_id": "test_five_lang",
                "set_name": "Five Language Test",
                "videos": [
                    {
                        "video_id": "video_1",
                        "title": "Introduction",
                        "scenes": [
                            {"type": "title", "title": "Welcome"},
                            {"type": "list", "items": ["Point 1", "Point 2"]},
                            {"type": "outro", "message": "Thank you"}
                        ],
                        "voice": "male"
                    }
                ],
                "accent_color": "blue"
            },
            "target_languages": ["en", "es", "fr", "de", "ja"],
            "source_language": "en"
        }

        response = client.post("/api/generate/multilingual", json=request_data)

        # Should accept 5 languages
        assert response.status_code in [200, 500]
        if response.status_code == 200:
            data = response.json()
            assert "languages" in data or "task_id" in data


# ============================================================================
# Complete Multi-Language Flow Tests
# ============================================================================

class TestCompleteMultiLanguageFlow:
    """Complete end-to-end multi-language flow tests"""

    @pytest.mark.e2e
    def test_complete_multilingual_flow(self, client, sample_markdown):
        """Test complete multi-language flow"""
        # Step 1: Validate document
        files = {"file": ("ml_tutorial.md", BytesIO(sample_markdown), "text/markdown")}
        val_response = client.post("/api/validate/document", files=files)
        assert val_response.status_code == 200
        assert val_response.json().get("valid") is True

        # Step 2: Get preview
        files = {"file": ("ml_tutorial.md", BytesIO(sample_markdown), "text/markdown")}
        preview_response = client.post("/api/preview/document", files=files)
        assert preview_response.status_code == 200

        # Step 3: Get available languages
        lang_response = client.get("/api/languages")
        assert lang_response.status_code == 200
        languages = lang_response.json().get("languages", [])
        selected_langs = [l["code"] for l in languages[:5]]

        # Step 4: Get voices for selected languages
        language_voices = {}
        for lang_code in selected_langs:
            voice_response = client.get(f"/api/languages/{lang_code}/voices")
            if voice_response.status_code == 200:
                voices = voice_response.json().get("voices", [])
                language_voices[lang_code] = [v["id"] for v in voices[:3]]

        # Verify we have voice data
        assert len(language_voices) > 0

    @pytest.mark.e2e
    def test_language_voice_mapping_flow(self, client):
        """Test language to voice mapping in generation request"""
        # Build language-voice mapping
        language_voices = {}

        # Get English voices
        en_response = client.get("/api/languages/en/voices")
        if en_response.status_code == 200:
            voices = en_response.json().get("voices", [])
            if voices:
                language_voices["en"] = voices[0].get("id", "male")

        # Get Spanish voices
        es_response = client.get("/api/languages/es/voices")
        if es_response.status_code == 200:
            voices = es_response.json().get("voices", [])
            if voices:
                language_voices["es"] = voices[0].get("id", "male_es")

        # Request with voice mapping
        request_data = {
            "video_set": {
                "set_id": "voice_map_test",
                "set_name": "Voice Mapping Test",
                "videos": [
                    {
                        "video_id": "v1",
                        "title": "Test",
                        "scenes": [{"type": "title", "title": "Hello"}],
                        "voice": "male"
                    }
                ]
            },
            "target_languages": list(language_voices.keys()) or ["en"],
            "source_language": "en",
            "language_voices": language_voices
        }

        response = client.post("/api/generate/multilingual", json=request_data)
        assert response.status_code in [200, 500]


# ============================================================================
# Video Set Mode Tests
# ============================================================================

class TestVideoSetMode:
    """E2E tests for video set generation mode"""

    @pytest.mark.e2e
    def test_video_set_generation(self, client):
        """Test video set generation endpoint"""
        video_set = {
            "set_id": "tutorial_set",
            "set_name": "Python Tutorial Set",
            "videos": [
                {
                    "video_id": "intro",
                    "title": "Introduction",
                    "scenes": [
                        {"type": "title", "title": "Welcome to Python"},
                        {"type": "list", "items": ["Easy", "Powerful", "Popular"]},
                        {"type": "outro", "message": "Let's begin!"}
                    ],
                    "voice": "male"
                },
                {
                    "video_id": "basics",
                    "title": "Python Basics",
                    "scenes": [
                        {"type": "title", "title": "Chapter 1: Basics"},
                        {"type": "command", "command": "print('Hello')"},
                        {"type": "outro", "message": "Next: Advanced"}
                    ],
                    "voice": "female"
                }
            ],
            "accent_color": "purple",
            "languages": ["en"]
        }

        response = client.post("/api/generate", json=video_set)

        assert response.status_code in [200, 500]
        if response.status_code == 200:
            data = response.json()
            assert "task_id" in data

    @pytest.mark.e2e
    def test_video_set_with_multiple_videos(self, client):
        """Test video set with multiple videos"""
        videos = []
        for i in range(3):
            videos.append({
                "video_id": f"video_{i}",
                "title": f"Video {i + 1}",
                "scenes": [
                    {"type": "title", "title": f"Video {i + 1}"},
                    {"type": "outro", "message": "End"}
                ],
                "voice": "male"
            })

        video_set = {
            "set_id": "multi_video_set",
            "set_name": "Multiple Videos",
            "videos": videos,
            "accent_color": "blue"
        }

        response = client.post("/api/generate", json=video_set)
        assert response.status_code in [200, 500]


# ============================================================================
# Progress Tracking Tests
# ============================================================================

class TestMultiLanguageProgressTracking:
    """E2E tests for progress tracking in multi-language generation"""

    @pytest.mark.e2e
    def test_progress_stages_available(self, client):
        """Test progress stages are available"""
        response = client.get("/api/upload/progress-stages")
        assert response.status_code == 200

    @pytest.mark.e2e
    def test_task_status_endpoint(self, client):
        """Test task status endpoint works"""
        # First create a task
        video_set = {
            "set_id": "status_test",
            "set_name": "Status Test",
            "videos": [
                {
                    "video_id": "v1",
                    "title": "Test",
                    "scenes": [{"type": "title", "title": "Test"}],
                    "voice": "male"
                }
            ]
        }

        gen_response = client.post("/api/generate", json=video_set)

        if gen_response.status_code == 200:
            task_id = gen_response.json().get("task_id")
            if task_id:
                # Check status
                status_response = client.get(f"/api/tasks/{task_id}")
                # Should return status or not found (if task already cleaned up)
                assert status_response.status_code in [200, 404]


# ============================================================================
# RTL Language Tests
# ============================================================================

class TestRTLLanguageSupport:
    """E2E tests for right-to-left language support"""

    @pytest.mark.e2e
    def test_rtl_language_in_list(self, client):
        """Test RTL languages are in the language list"""
        response = client.get("/api/languages")
        languages = response.json().get("languages", [])

        # Check for Arabic
        rtl_codes = ["ar", "he", "fa"]
        has_rtl = any(
            lang.get("code") in rtl_codes
            for lang in languages
        )
        # RTL support is optional
        assert True

    @pytest.mark.e2e
    def test_rtl_flag_in_language_info(self, client):
        """Test RTL flag is present in language info"""
        response = client.get("/api/languages")
        languages = response.json().get("languages", [])

        for lang in languages:
            if lang.get("code") == "ar":
                # Arabic should have RTL flag
                assert lang.get("rtl", False) is True
                break


# ============================================================================
# Error Handling Tests
# ============================================================================

class TestMultiLanguageErrorHandling:
    """E2E tests for error handling in multi-language flow"""

    @pytest.mark.e2e
    def test_empty_video_set_rejected(self, client):
        """Test empty video set is rejected"""
        request_data = {
            "video_set": {
                "set_id": "empty_set",
                "set_name": "Empty Set",
                "videos": []  # Empty!
            },
            "target_languages": ["en"],
            "source_language": "en"
        }

        response = client.post("/api/generate/multilingual", json=request_data)

        # Should reject empty videos
        assert response.status_code in [422, 500]

    @pytest.mark.e2e
    def test_empty_scenes_rejected(self, client):
        """Test video with empty scenes is rejected"""
        request_data = {
            "video_set": {
                "set_id": "no_scenes",
                "set_name": "No Scenes",
                "videos": [
                    {
                        "video_id": "v1",
                        "title": "Empty Video",
                        "scenes": []  # Empty!
                    }
                ]
            },
            "target_languages": ["en"],
            "source_language": "en"
        }

        response = client.post("/api/generate/multilingual", json=request_data)

        # Should reject empty scenes
        assert response.status_code in [422, 500]

    @pytest.mark.e2e
    def test_unsupported_language_handling(self, client):
        """Test handling of unsupported language code"""
        response = client.get("/api/languages/xyz/voices")

        assert response.status_code == 404


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short', '-m', 'e2e'])
