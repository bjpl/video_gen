"""
Test Backend API Voice Array Handling
======================================
Tests for the new voice array and language-voice mapping features.
"""

import pytest
import requests
import json
import time
from typing import Dict, Any


BASE_URL = "http://localhost:8000"


@pytest.mark.skip(reason="Requires running web server")
def test_video_with_voice_array():
    """Test 1: Send video with voices array"""
    print("\n=== TEST 1: Video with Voice Array ===")

    payload = {
        "set_id": "test_voices_001",
        "set_name": "Voice Array Test",
        "videos": [
            {
                "video_id": "vid_001",
                "title": "Multi-Voice Tutorial",
                "voices": ["male", "female", "male_warm"],  # NEW: Array of voices
                "duration": 45,
                "scenes": [
                    {
                        "type": "title",
                        "title": "Welcome",
                        "subtitle": "Multi-Voice Demo",
                        "voice": "male"
                    },
                    {
                        "type": "list",
                        "title": "Key Points",
                        "items": ["Point 1", "Point 2", "Point 3"],
                        "voice": "female"
                    },
                    {
                        "type": "outro",
                        "title": "Thank You",
                        "subtitle": "See you next time",
                        "voice": "male_warm"
                    }
                ]
            }
        ],
        "accent_color": "blue"
    }

    response = requests.post(f"{BASE_URL}/api/generate", json=payload)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    assert "task_id" in data
    assert data["status"] == "started"

    return data["task_id"]


@pytest.mark.skip(reason="Requires running web server")
def test_multilingual_with_language_voices():
    """Test 2: Multilingual request with per-language voice mapping"""
    print("\n=== TEST 2: Multilingual with Language-Voice Mapping ===")

    payload = {
        "video_set": {
            "set_id": "test_ml_002",
            "set_name": "Multilingual Voice Test",
            "videos": [
                {
                    "video_id": "vid_ml_001",
                    "title": "Introduction",
                    "voices": ["male"],
                    "scenes": [
                        {
                            "type": "title",
                            "title": "Hello World",
                            "subtitle": "Welcome"
                        }
                    ]
                }
            ],
            "accent_color": "purple"
        },
        "target_languages": ["en", "es", "fr"],
        "source_language": "en",
        "translation_method": "claude",
        "language_voices": {  # NEW: Per-language voice selection
            "en": "male",
            "es": "male_spanish",
            "fr": "female_french"
        }
    }

    response = requests.post(f"{BASE_URL}/api/generate/multilingual", json=payload)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    assert "task_id" in data
    assert data["status"] == "started"
    assert len(data.get("languages", [])) == 3

    return data["task_id"]


@pytest.mark.skip(reason="Requires running web server")
def test_backward_compatibility():
    """Test 3: Old format still works (voice: str)"""
    print("\n=== TEST 3: Backward Compatibility (voice: str) ===")

    payload = {
        "set_id": "test_compat_003",
        "set_name": "Backward Compatibility Test",
        "videos": [
            {
                "video_id": "vid_compat_001",
                "title": "Old Format Video",
                "voice": "female",  # OLD FORMAT: Single voice string
                "scenes": [
                    {
                        "type": "title",
                        "title": "Testing",
                        "subtitle": "Old API format"
                    }
                ]
            }
        ],
        "accent_color": "green"
    }

    response = requests.post(f"{BASE_URL}/api/generate", json=payload)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    return response.json()["task_id"]


@pytest.mark.skip(reason="Requires running web server")
def test_scene_content_richness():
    """Test 4: Rich scene content with all fields"""
    print("\n=== TEST 4: Rich Scene Content ===")

    payload = {
        "set_id": "test_scenes_004",
        "set_name": "Rich Scene Content Test",
        "videos": [
            {
                "video_id": "vid_rich_001",
                "title": "Educational Content",
                "voices": ["male", "female"],
                "scenes": [
                    {
                        "type": "learning_objectives",
                        "title": "Learning Goals",
                        "objectives": [
                            "Understand API design",
                            "Master REST principles",
                            "Build scalable systems"
                        ],
                        "voice": "male",
                        "narration": "By the end of this lesson, you will master these concepts."
                    },
                    {
                        "type": "problem",
                        "title": "The Challenge",
                        "description": "How do we handle concurrent requests?",
                        "constraints": [
                            "Must be thread-safe",
                            "Low latency required",
                            "Scalable to 1000+ users"
                        ],
                        "voice": "female"
                    },
                    {
                        "type": "solution",
                        "title": "The Solution",
                        "explanation": "Use async/await with connection pooling",
                        "code": [
                            "async def handle_request():",
                            "    async with pool.acquire() as conn:",
                            "        result = await conn.fetch(query)",
                            "        return result"
                        ],
                        "voice": "male"
                    },
                    {
                        "type": "quiz",
                        "question": "Which pattern ensures thread safety?",
                        "options": [
                            "Global variables",
                            "Connection pooling",
                            "Shared state",
                            "Direct access"
                        ],
                        "correct_answer": 1,
                        "voice": "female"
                    }
                ]
            }
        ],
        "accent_color": "orange"
    }

    response = requests.post(f"{BASE_URL}/api/generate", json=payload)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

    assert response.status_code == 200
    return response.json()["task_id"]


@pytest.mark.skip(reason="Requires running web server")
def check_task_status(task_id: str) -> Dict[str, Any]:
    """Check status of a task"""
    print(f"\n=== Checking Task Status: {task_id} ===")

    response = requests.get(f"{BASE_URL}/api/tasks/{task_id}")
    print(f"Status: {response.status_code}")

    if response.status_code == 200:
        data = response.json()
        print(f"Task Status: {data.get('status')}")
        print(f"Progress: {data.get('progress')}%")
        print(f"Message: {data.get('message')}")
        return data
    else:
        print(f"Error: {response.text}")
        return {}


def main():
    """Run all API tests"""
    print("=" * 60)
    print("BACKEND API VOICE ARRAY TESTING")
    print("=" * 60)

    # Check if server is running
    try:
        response = requests.get(f"{BASE_URL}/api/health")
        if response.status_code != 200:
            print("❌ Server not responding. Start with: cd app && uvicorn main:app")
            return
        print("✅ Server is running\n")
    except Exception as e:
        print(f"❌ Cannot connect to server: {e}")
        print("   Start with: cd app && uvicorn main:app")
        return

    # Run tests
    task_ids = []

    try:
        # Test 1: Voice arrays
        task_id = test_video_with_voice_array()
        task_ids.append(("Voice Array", task_id))
        time.sleep(1)

        # Test 2: Language-voice mapping
        task_id = test_multilingual_with_language_voices()
        task_ids.append(("Language Voices", task_id))
        time.sleep(1)

        # Test 3: Backward compatibility
        task_id = test_backward_compatibility()
        task_ids.append(("Backward Compat", task_id))
        time.sleep(1)

        # Test 4: Rich scene content
        task_id = test_scene_content_richness()
        task_ids.append(("Rich Scenes", task_id))
        time.sleep(1)

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return

    # Check all task statuses
    print("\n" + "=" * 60)
    print("TASK STATUS SUMMARY")
    print("=" * 60)

    for name, task_id in task_ids:
        print(f"\n{name}:")
        check_task_status(task_id)
        time.sleep(0.5)

    print("\n" + "=" * 60)
    print("✅ ALL TESTS COMPLETED")
    print("=" * 60)
    print("\nResults:")
    print(f"  - {len(task_ids)} tasks created")
    print(f"  - All API endpoints accepting new formats")
    print(f"  - Backward compatibility maintained")
    print("\nNOTE: Actual video generation may take time.")
    print("      Monitor progress at: http://localhost:8000/progress")


if __name__ == "__main__":
    main()
