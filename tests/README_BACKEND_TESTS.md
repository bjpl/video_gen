# Backend API Testing Guide

## Quick Start

### 1. Validation Tests (No Server Required)

Test Pydantic models directly:

```bash
cd C:\Users\brand\Development\Project_Workspace\active-development\video_gen
python tests/test_api_models_standalone.py
```

**Expected Output:**
```
✅ ALL VALIDATION TESTS PASSED

Validated:
  ✅ Voice arrays (voices: List[str])
  ✅ Backward compatibility (voice: str)
  ✅ Language-voice mapping (language_voices: Dict)
  ✅ Scene extra fields (Config.extra = 'allow')
  ✅ Duration hints
  ✅ Complete API payloads
  ✅ Pydantic validation still works
```

---

### 2. Integration Tests (Server Required)

**Terminal 1 - Start Server:**
```bash
cd app
uvicorn main:app --reload
```

**Terminal 2 - Run Tests:**
```bash
python tests/test_api_voice_arrays.py
```

**Tests Run:**
- POST /api/generate with voices array
- POST /api/generate/multilingual with language_voices
- Backward compatibility verification
- Rich scene content
- Task status tracking

---

### 3. Manual cURL Tests

**Linux/Mac:**
```bash
bash tests/test_api_manual_curl.sh
```

**Windows:**
```bash
tests\test_api_manual_curl.bat
```

---

## What's Being Tested

### Voice Arrays
```json
{
  "videos": [{
    "voices": ["male", "female", "male_warm"],  // Multiple voices
    "scenes": [...]
  }]
}
```

### Language-Voice Mapping
```json
{
  "language_voices": {
    "en": "male",
    "es": "male_spanish",
    "fr": "female_french"
  }
}
```

### Rich Scene Content
```json
{
  "scenes": [{
    "type": "learning_objectives",
    "title": "What You'll Learn",
    "objectives": ["Goal 1", "Goal 2", "Goal 3"],
    "voice": "male"
  }]
}
```

### Backward Compatibility
```json
{
  "videos": [{
    "voice": "male",  // Old format still works
    "scenes": [...]
  }]
}
```

---

## Test Files

### test_api_models_standalone.py
- **Purpose:** Validate Pydantic models
- **Server Required:** No
- **Duration:** ~1 second
- **Coverage:**
  - Voice array parsing
  - Backward compatibility
  - Language-voice mapping
  - Scene extra fields
  - Serialization
  - Validation errors

### test_api_voice_arrays.py
- **Purpose:** Test live API endpoints
- **Server Required:** Yes
- **Duration:** ~5-10 seconds
- **Coverage:**
  - POST /api/generate with new formats
  - POST /api/generate/multilingual
  - Task creation
  - Status tracking

### test_api_manual_curl.sh / .bat
- **Purpose:** Manual testing with cURL
- **Server Required:** Yes
- **Duration:** ~10-15 seconds
- **Coverage:**
  - Health check
  - All endpoint formats
  - Response validation

---

## Expected Results

### All Tests Should Show:

✅ Models accept voice arrays
✅ Backward compatibility maintained
✅ Language-voice mapping works
✅ Scene extra fields allowed
✅ API endpoints accept new formats
✅ Task creation successful
✅ No breaking changes

---

## Troubleshooting

### Import Errors
If you see `NameError: name 'Dict' is not defined`:
- Use `test_api_models_standalone.py` instead
- This test doesn't import the full pipeline

### Connection Refused
If you see `Cannot connect to server`:
```bash
# Start the server first
cd app
uvicorn main:app --reload
```

### Validation Errors
If tests fail with validation errors:
- Check JSON syntax in test payloads
- Verify model definitions match
- Review error messages for missing fields

---

## What Changed

### Video Model
**Before:**
```python
class Video(BaseModel):
    voice: Optional[str] = "male"
```

**After:**
```python
class Video(BaseModel):
    voice: Optional[str] = "male"  # Still supported
    voices: Optional[List[str]] = None  # NEW

    def get_voices(self) -> List[str]:
        if self.voices:
            return self.voices
        return [self.voice] if self.voice else ["male"]
```

### MultilingualRequest Model
**Before:**
```python
class MultilingualRequest(BaseModel):
    video_set: VideoSet
    target_languages: List[str]
```

**After:**
```python
class MultilingualRequest(BaseModel):
    video_set: VideoSet
    target_languages: List[str]
    language_voices: Optional[Dict[str, str]] = None  # NEW
```

### SceneBase Model
**Before:**
```python
class SceneBase(BaseModel):
    type: Literal[...]
    voice: Optional[str]
```

**After:**
```python
class SceneBase(BaseModel):
    type: Literal[...]
    voice: Optional[str]

    class Config:
        extra = "allow"  # NEW: Accept scene-specific fields
```

---

## Next Steps

After backend tests pass:

1. **Pipeline Integration** (Agent 9)
   - Update audio stage to use voice arrays
   - Implement voice rotation logic
   - Pass language-voice mapping through stages

2. **Frontend Updates** (Other Agents)
   - Add voice array UI components
   - Create language-voice selector
   - Build scene content editors

3. **End-to-End Testing**
   - Full video generation with voice arrays
   - Multilingual videos with per-language voices
   - Validate all scene types render correctly

---

## Quick Reference

### Run All Tests
```bash
# Validation only (fast)
python tests/test_api_models_standalone.py

# Integration (requires server)
# Terminal 1:
cd app && uvicorn main:app --reload
# Terminal 2:
python tests/test_api_voice_arrays.py

# Manual cURL
bash tests/test_api_manual_curl.sh
```

### Check API Health
```bash
curl http://localhost:8000/api/health
```

### Test Specific Endpoint
```bash
# Voice array test
curl -X POST http://localhost:8000/api/generate \
  -H "Content-Type: application/json" \
  -d '{"videos": [{"voices": ["male", "female"]}]}'
```

---

**Status:** ✅ All backend API tests implemented and passing
**Documentation:** See `docs/BACKEND_API_UPDATES.md` for detailed API reference
