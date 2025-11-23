@echo off
REM Manual API Testing with cURL (Windows)
REM ======================================

set BASE_URL=http://localhost:8000

echo ==========================================
echo BACKEND API MANUAL TESTING
echo ==========================================
echo.

REM Test 1: Health check
echo === Test 1: Health Check ===
curl -s %BASE_URL%/api/health
echo.
echo.

REM Test 2: Voice array format
echo === Test 2: Video with Voice Array ===
curl -X POST %BASE_URL%/api/generate ^
  -H "Content-Type: application/json" ^
  -d "{\"set_id\": \"test_curl_001\", \"set_name\": \"cURL Voice Test\", \"videos\": [{\"video_id\": \"vid_001\", \"title\": \"Multi-Voice Video\", \"voices\": [\"male\", \"female\", \"male_warm\"], \"duration\": 45, \"scenes\": [{\"type\": \"title\", \"title\": \"Welcome\", \"subtitle\": \"Testing voice arrays\", \"voice\": \"male\"}, {\"type\": \"list\", \"title\": \"Features\", \"items\": [\"Voice 1\", \"Voice 2\", \"Voice 3\"], \"voice\": \"female\"}]}], \"accent_color\": \"blue\"}"
echo.
echo.

REM Test 3: Multilingual with language-voice mapping
echo === Test 3: Multilingual with Language-Voice Mapping ===
curl -X POST %BASE_URL%/api/generate/multilingual ^
  -H "Content-Type: application/json" ^
  -d "{\"video_set\": {\"set_id\": \"ml_curl_001\", \"set_name\": \"Multilingual Test\", \"videos\": [{\"video_id\": \"vid_ml_001\", \"title\": \"Hello World\", \"voices\": [\"male\"], \"scenes\": [{\"type\": \"title\", \"title\": \"Greetings\", \"subtitle\": \"In multiple languages\"}]}], \"accent_color\": \"purple\"}, \"target_languages\": [\"en\", \"es\", \"fr\"], \"source_language\": \"en\", \"language_voices\": {\"en\": \"male\", \"es\": \"male_spanish\", \"fr\": \"female_french\"}}"
echo.
echo.

REM Test 4: Backward compatibility
echo === Test 4: Backward Compatibility (voice: string) ===
curl -X POST %BASE_URL%/api/generate ^
  -H "Content-Type: application/json" ^
  -d "{\"set_id\": \"test_curl_compat\", \"set_name\": \"Backward Compat Test\", \"videos\": [{\"video_id\": \"vid_compat\", \"title\": \"Old Format\", \"voice\": \"female\", \"scenes\": [{\"type\": \"title\", \"title\": \"Old API\", \"subtitle\": \"Still works\"}]}], \"accent_color\": \"green\"}"
echo.
echo.

echo ==========================================
echo Done! All manual tests completed
echo ==========================================
echo.
echo To check task status:
echo   curl %BASE_URL%/api/tasks/{task_id}
echo.
echo To view progress in browser:
echo   http://localhost:8000/progress
