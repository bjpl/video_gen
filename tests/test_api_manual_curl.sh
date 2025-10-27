#!/bin/bash
# Manual API Testing with cURL
# =============================
# Run these commands to test the API manually

BASE_URL="http://localhost:8000"

echo "=========================================="
echo "BACKEND API MANUAL TESTING"
echo "=========================================="
echo ""

# Test 1: Health check
echo "=== Test 1: Health Check ==="
curl -s $BASE_URL/api/health | python -m json.tool
echo ""
echo ""

# Test 2: Voice array format
echo "=== Test 2: Video with Voice Array ==="
curl -X POST $BASE_URL/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "set_id": "test_curl_001",
    "set_name": "cURL Voice Test",
    "videos": [{
      "video_id": "vid_001",
      "title": "Multi-Voice Video",
      "voices": ["male", "female", "male_warm"],
      "duration": 45,
      "scenes": [
        {
          "type": "title",
          "title": "Welcome",
          "subtitle": "Testing voice arrays",
          "voice": "male"
        },
        {
          "type": "list",
          "title": "Features",
          "items": ["Voice 1", "Voice 2", "Voice 3"],
          "voice": "female"
        }
      ]
    }],
    "accent_color": "blue"
  }' | python -m json.tool
echo ""
echo ""

# Test 3: Multilingual with language-voice mapping
echo "=== Test 3: Multilingual with Language-Voice Mapping ==="
curl -X POST $BASE_URL/api/generate/multilingual \
  -H "Content-Type: application/json" \
  -d '{
    "video_set": {
      "set_id": "ml_curl_001",
      "set_name": "Multilingual Test",
      "videos": [{
        "video_id": "vid_ml_001",
        "title": "Hello World",
        "voices": ["male"],
        "scenes": [
          {
            "type": "title",
            "title": "Greetings",
            "subtitle": "In multiple languages"
          }
        ]
      }],
      "accent_color": "purple"
    },
    "target_languages": ["en", "es", "fr"],
    "source_language": "en",
    "language_voices": {
      "en": "male",
      "es": "male_spanish",
      "fr": "female_french"
    }
  }' | python -m json.tool
echo ""
echo ""

# Test 4: Backward compatibility (old format)
echo "=== Test 4: Backward Compatibility (voice: string) ==="
curl -X POST $BASE_URL/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "set_id": "test_curl_compat",
    "set_name": "Backward Compat Test",
    "videos": [{
      "video_id": "vid_compat",
      "title": "Old Format",
      "voice": "female",
      "scenes": [
        {
          "type": "title",
          "title": "Old API",
          "subtitle": "Still works"
        }
      ]
    }],
    "accent_color": "green"
  }' | python -m json.tool
echo ""
echo ""

# Test 5: Rich scene content
echo "=== Test 5: Rich Scene Content ==="
curl -X POST $BASE_URL/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "set_id": "test_curl_rich",
    "set_name": "Rich Content Test",
    "videos": [{
      "video_id": "vid_rich",
      "title": "Educational Content",
      "voices": ["male", "female"],
      "scenes": [
        {
          "type": "learning_objectives",
          "title": "Learning Goals",
          "objectives": ["Understand APIs", "Master REST", "Build systems"],
          "voice": "male"
        },
        {
          "type": "problem",
          "title": "The Challenge",
          "description": "How to handle concurrency?",
          "constraints": ["Thread-safe", "Low latency", "Scalable"],
          "voice": "female"
        },
        {
          "type": "quiz",
          "question": "What is REST?",
          "options": ["A protocol", "An architecture", "A framework", "A language"],
          "correct_answer": 1,
          "voice": "male"
        }
      ]
    }],
    "accent_color": "orange"
  }' | python -m json.tool
echo ""
echo ""

echo "=========================================="
echo "✅ Manual API tests completed"
echo "=========================================="
echo ""
echo "To check task status:"
echo "  curl $BASE_URL/api/tasks/{task_id}"
echo ""
echo "To view progress in browser:"
echo "  http://localhost:8000/progress"
