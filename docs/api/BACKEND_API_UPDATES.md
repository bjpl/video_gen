# Backend API Updates - Voice Arrays & Scene Content

## Summary

Updated backend API models to support:
1. **Voice arrays** - Multiple voices per video
2. **Language-voice mapping** - Different voice per language
3. **Rich scene content** - All scene-specific fields
4. **Backward compatibility** - Old API format still works

---

## Model Changes

### 1. Video Model (app/main.py)

**Before:**
```python
class Video(BaseModel):
    video_id: str
    title: str
    scenes: List[Dict]
    voice: Optional[str] = "male"
```

**After:**
```python
class Video(BaseModel):
    video_id: str
    title: str
    scenes: List[Dict]
    voice: Optional[str] = "male"  # Deprecated but supported
    voices: Optional[List[str]] = None  # NEW: Multiple voices
    duration: Optional[int] = None  # NEW: Duration hint

    def get_voices(self) -> List[str]:
        """Get voice list with backward compatibility."""
        if self.voices:
            return self.voices
        return [self.voice] if self.voice else ["male"]
```

**Usage:**
```python
# New format (preferred)
video = Video(
    video_id="v1",
    title="Tutorial",
    voices=["male", "female", "male_warm"],  # Multiple voices
    duration=60,
    scenes=[...]
)

# Old format (still works)
video = Video(
    video_id="v2",
    title="Tutorial",
    voice="male",  # Single voice
    scenes=[...]
)
```

---

### 2. MultilingualRequest Model

**Before:**
```python
class MultilingualRequest(BaseModel):
    video_set: VideoSet
    target_languages: List[str]
    source_language: str = "en"
    translation_method: Optional[Literal["claude", "google"]] = "claude"
```

**After:**
```python
class MultilingualRequest(BaseModel):
    video_set: VideoSet
    target_languages: List[str]
    source_language: str = "en"
    translation_method: Optional[Literal["claude", "google"]] = "claude"
    language_voices: Optional[Dict[str, str]] = None  # NEW!
```

**Usage:**
```python
request = MultilingualRequest(
    video_set=video_set,
    target_languages=["en", "es", "fr"],
    language_voices={
        "en": "male",
        "es": "male_spanish",
        "fr": "female_french"
    }
)
```

---

### 3. SceneBase Model

**Before:**
```python
class SceneBase(BaseModel):
    type: Literal["title", "command", "list", ...]
    voice: Optional[str] = "male"
    narration: Optional[str] = None
```

**After:**
```python
class SceneBase(BaseModel):
    type: Literal["title", "command", "list", ...]
    voice: Optional[str] = "male"
    narration: Optional[str] = None

    class Config:
        extra = "allow"  # NEW: Accept scene-specific fields
```

**Usage:**
```python
# Learning objectives scene
scene = {
    "type": "learning_objectives",
    "title": "What You'll Learn",
    "objectives": ["Topic 1", "Topic 2", "Topic 3"],
    "voice": "male"
}

# Problem scene
scene = {
    "type": "problem",
    "title": "The Challenge",
    "description": "How do we solve this?",
    "constraints": ["Must be fast", "Must be scalable"],
    "voice": "female"
}

# Quiz scene
scene = {
    "type": "quiz",
    "question": "What is the answer?",
    "options": ["A", "B", "C", "D"],
    "correct_answer": 1,
    "voice": "male_warm"
}
```

---

## API Endpoints

### POST /api/generate

**New Request Format:**
```json
{
  "set_id": "tutorial_001",
  "set_name": "Python Tutorial",
  "videos": [
    {
      "video_id": "vid_001",
      "title": "Introduction to Python",
      "voices": ["male", "female"],  // Multiple voices
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
          "type": "code_comparison",
          "title": "Before vs After",
          "before_label": "Without Functions",
          "after_label": "With Functions",
          "before_code": ["x = 1", "y = 2", "print(x + y)"],
          "after_code": ["def add(a, b):", "    return a + b", "print(add(1, 2))"],
          "voice": "male"
        }
      ]
    }
  ],
  "accent_color": "blue"
}
```

---

### POST /api/generate/multilingual

**New Request Format:**
```json
{
  "video_set": {
    "set_id": "ml_tutorial_001",
    "set_name": "Multilingual Tutorial",
    "videos": [
      {
        "video_id": "vid_001",
        "title": "Getting Started",
        "voices": ["male"],
        "scenes": [
          {
            "type": "title",
            "title": "Welcome",
            "subtitle": "Introduction"
          }
        ]
      }
    ],
    "accent_color": "purple"
  },
  "target_languages": ["en", "es", "fr", "de"],
  "source_language": "en",
  "translation_method": "claude",
  "language_voices": {  // NEW!
    "en": "male",
    "es": "male_spanish",
    "fr": "female_french",
    "de": "male_german"
  }
}
```

---

## Testing

### 1. Run Validation Tests

Tests Pydantic models directly (no server needed):

```bash
cd C:\Users\brand\Development\Project_Workspace\active-development\video_gen
python tests/test_api_validation.py
```

**Tests:**
- ✅ Voice arrays work
- ✅ Backward compatibility (voice: str)
- ✅ Language-voice mapping
- ✅ Scene extra fields (Config.extra = "allow")
- ✅ Serialization includes new fields
- ✅ Validation errors still caught

---

### 2. Run API Integration Tests

Tests actual HTTP endpoints (server must be running):

```bash
# Terminal 1: Start server
cd app
uvicorn main:app --reload

# Terminal 2: Run tests
cd ..
python tests/test_api_voice_arrays.py
```

**Tests:**
- ✅ POST /api/generate with voices array
- ✅ POST /api/generate/multilingual with language_voices
- ✅ Backward compatibility with old format
- ✅ Rich scene content with all fields
- ✅ Task creation and status tracking

---

## Migration Guide

### For Frontend Developers

**Update video submission:**

```javascript
// OLD (still works)
const video = {
    video_id: 'v1',
    title: 'My Video',
    voice: 'male',  // Single voice
    scenes: [...]
};

// NEW (recommended)
const video = {
    video_id: 'v1',
    title: 'My Video',
    voices: ['male', 'female'],  // Multiple voices
    duration: 60,
    scenes: [
        {
            type: 'title',
            title: 'Welcome',
            subtitle: 'Introduction',
            voice: 'male'  // Per-scene voice override
        },
        {
            type: 'learning_objectives',
            title: 'Goals',
            objectives: ['Learn X', 'Master Y'],
            voice: 'female'
        }
    ]
};
```

**Update multilingual requests:**

```javascript
// OLD
const request = {
    video_set: videoSet,
    target_languages: ['en', 'es', 'fr']
};

// NEW
const request = {
    video_set: videoSet,
    target_languages: ['en', 'es', 'fr'],
    language_voices: {  // Per-language voice
        'en': 'male',
        'es': 'male_spanish',
        'fr': 'female_french'
    }
};
```

---

### For Pipeline/Backend Developers

**Handle voice arrays in audio generation:**

```python
# In audio stage
video: Video = ...

# Get voices (handles both old and new formats)
voices = video.get_voices()

# Assign voices to scenes (rotation/alternation)
for i, scene in enumerate(video.scenes):
    if not scene.get('voice'):
        scene['voice'] = voices[i % len(voices)]  # Round-robin
```

**Handle language-voice mapping:**

```python
# In multilingual pipeline
request: MultilingualRequest = ...

for lang in request.target_languages:
    # Get voice for this language
    if request.language_voices:
        voice = request.language_voices.get(lang)
    else:
        voice = get_default_voice_for_language(lang)

    # Generate with this voice
    generate_video_for_language(lang, voice)
```

---

## Compatibility Matrix

| Feature | Old API | New API | Supported |
|---------|---------|---------|-----------|
| Single voice string | `voice: "male"` | - | ✅ Yes |
| Multiple voices | - | `voices: ["male", "female"]` | ✅ Yes |
| Scene voice override | `scene.voice` | `scene.voice` | ✅ Yes |
| Language-voice map | - | `language_voices: {en: "male"}` | ✅ Yes |
| Rich scene content | Limited | All fields | ✅ Yes |
| Duration hint | - | `duration: 60` | ✅ Yes |

---

## Next Steps

1. ✅ **Backend models updated** (this document)
2. 🟡 **Pipeline stage updates** (Agent 9 task)
   - Update audio generation to use voice arrays
   - Implement voice rotation logic
   - Pass language-voice mapping through stages
3. 🟡 **Frontend updates** (other agents)
   - Voice array UI components
   - Language-voice selector
   - Scene content editor
4. 🟡 **Integration testing**
   - End-to-end tests with real video generation
   - Validate all combinations work

---

## Files Modified

- `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\app\main.py`
  - Updated `Video` model
  - Updated `MultilingualRequest` model
  - Updated `SceneBase` model

## Files Created

- `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\tests\test_api_validation.py`
- `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\tests\test_api_voice_arrays.py`
- `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\docs\BACKEND_API_UPDATES.md` (this file)

---

## Validation Results

Run tests to verify:

```bash
# Model validation (no server needed)
python tests/test_api_validation.py

# Expected output:
# ✅ Video with voices array
# ✅ Backward compatibility maintained
# ✅ Language-voice mapping works
# ✅ Scene extra fields accepted
# ✅ Serialization includes new fields
# ✅ Validation still catches errors

# API integration (server must be running)
python tests/test_api_voice_arrays.py

# Expected output:
# ✅ POST /api/generate accepts voices array
# ✅ POST /api/generate/multilingual accepts language_voices
# ✅ Backward compatibility verified
# ✅ Rich scene content processed
# ✅ Task tracking works
```

---

**Status**: ✅ Backend API models updated and tested
**Next**: Pipeline stages need to consume new fields
