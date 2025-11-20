# SPARC Methodology: Strategic Fix Analysis
**Date:** 2025-11-19
**Branch:** claude/evaluate-app-architecture-01BWEEDVgpoKaw7p2NWVNQLV
**Time Budget:** 4-6 hours
**Principle:** Strategic value, not architectural perfection

---

## Executive Summary

Based on comprehensive swarm agent evaluations, this SPARC analysis identifies **5 critical fixes** that maximize value while maintaining pragmatic scope. These fixes resolve runtime failures, eliminate 632 lines of dead code, and restore broken workflows—all completable in one focused session.

**Key Insight:** The application has good architecture (unified pipeline, clean separation) but suffers from **incremental debt** - dead code from refactoring, Pydantic v2 migration incomplete, and abandoned file upload feature.

---

# PHASE 1: SPECIFICATION

## 1.1 Problem Statement

### Critical Issues (MUST FIX)

**Issue #1: Pydantic v2 Serialization Bug** ⚠️ RUNTIME FAILURE
- **Location:** `app/main.py` lines 291, 494
- **Problem:** Using deprecated `.dict()` method with Pydantic v2.12+
- **Impact:** `/api/generate` endpoint FAILS at runtime with AttributeError
- **Evidence:**
  ```python
  # Line 291 (BROKEN)
  source=json.dumps(video_set.dict())  # .dict() doesn't exist in Pydantic v2

  # Line 494 (BROKEN)
  source=request.video_set.dict()
  ```
- **User Impact:** Generate workflow completely broken
- **Fix Complexity:** Trivial (2 character changes)
- **Value:** Critical - unblocks primary workflow

**Issue #2: Dead Code - 632 Lines of Unused Files** 📦 TECHNICAL DEBT
- **Files:**
  - `app/models.py` (282 lines) - NOT imported anywhere
  - `app/services/video_service.py` (350 lines) - NOT imported anywhere
- **Problem:** Legacy files from pre-pipeline architecture
- **Impact:**
  - Confusion for new developers
  - False maintenance burden
  - Duplication with `app/main.py` models
- **Evidence:** `grep -r "from app.models import"` returns 0 results
- **Fix Complexity:** Trivial (delete 2 files)
- **Value:** High - reduces cognitive load, eliminates confusion

**Issue #3: Model Duplication** 🔄 CODE SMELL
- **Location:** Models defined in 3 places:
  1. `app/models.py` (282 lines - DEAD CODE)
  2. `app/main.py` (7 model classes - ACTIVE)
  3. `video_gen/shared/models.py` (pipeline models - ACTIVE)
- **Problem:** app/models.py defines models that are redefined in app/main.py
- **Impact:** Maintenance confusion, source of truth unclear
- **Fix Complexity:** Trivial (delete dead file, add comment)
- **Value:** Medium - improves clarity

### High Priority Issues (SHOULD FIX)

**Issue #4: Missing Input Validation** 🛡️ PRODUCTION RISK
- **Location:** `/api/generate`, `/api/parse/*` endpoints
- **Problem:** No validation for:
  - Empty scenes list
  - Invalid accent_color values
  - Missing required scene fields
  - Malformed video_set structure
- **Impact:** Poor error messages, potential runtime failures
- **Evidence:** Pydantic models in main.py use `extra = "allow"` (permissive)
- **Fix Complexity:** Low (add validators, 30-60 min)
- **Value:** High - prevents cryptic errors

**Issue #5: File Upload Not Implemented** 📁 BROKEN WORKFLOW
- **Location:** UI shows "Upload Document" option, but no backend endpoint
- **Problem:** No `/api/upload` endpoint exists
- **Impact:**
  - Wizard workflow incomplete (50% broken per Workflow Explorer)
  - Users can't upload YAML/Markdown files
  - Must manually place files on server
- **Current State:** UI promises feature that doesn't exist
- **Fix Complexity:** Medium (implement upload endpoint, 1-2 hours)
- **Value:** High - completes core workflow

### Medium Priority (COULD FIX)

**Issue #6: Parse/Generate Separation Not Complete**
- **Status:** Endpoints exist (`/api/parse/*`, `/api/generate`) but...
- **Problem:** Frontend wizard doesn't properly chain parse → edit → generate
- **Impact:** Workflow requires manual intervention
- **Fix Complexity:** Medium-High (requires frontend + backend)
- **Value:** Medium
- **Decision:** OUT OF SCOPE (4-6 hour constraint)

---

## 1.2 Requirements Definition

### MUST WORK (Critical - Session Blockers)
1. ✅ `/api/generate` endpoint executes without AttributeError
2. ✅ Codebase contains only active, used files (no dead code)
3. ✅ Single source of truth for API models (no duplication)

### SHOULD WORK (High Value - User Facing)
4. ✅ Input validation provides clear error messages
5. ✅ File upload endpoint accepts YAML/Markdown documents
6. ✅ Uploaded files processed through parse workflow

### COULD WORK (Nice to Have - Future Sessions)
7. ❌ End-to-end wizard parse → edit → generate (OUT OF SCOPE)
8. ❌ File upload progress indicator (OUT OF SCOPE)
9. ❌ Input preview before generation (OUT OF SCOPE)

---

# PHASE 2: PSEUDOCODE

## Fix #1: Pydantic v2 Serialization (2 min)

```python
# BEFORE (BROKEN)
source=json.dumps(video_set.dict())

# AFTER (FIXED)
source=json.dumps(video_set.model_dump())

# Alternative (if compatibility needed)
source=json.dumps(video_set.model_dump(mode='json'))
```

**Algorithm:**
1. Search for `.dict()` calls on Pydantic models
2. Replace with `.model_dump()`
3. Test `/api/generate` endpoint
4. Verify serialization works

**Edge Cases:**
- None (straightforward API change)

**Testing:**
```bash
# Manual test
curl -X POST http://localhost:8000/api/generate \
  -H "Content-Type: application/json" \
  -d '{"set_id": "test", "set_name": "Test", "videos": []}'
```

---

## Fix #2: Remove Dead Code (5 min)

```bash
# Algorithm
1. Verify files are not imported:
   grep -r "from app.models import" app/
   grep -r "from app.services" app/

2. Verify no runtime references:
   grep -r "VideoGenerationService" app/

3. Delete files:
   git rm app/models.py
   git rm app/services/video_service.py

4. Add documentation:
   # Add comment to app/main.py explaining model location
```

**Rationale:**
- Files from pre-pipeline refactoring (Oct 11, 2025)
- Replaced by unified pipeline architecture
- No imports = no usage = safe to delete

**Risk Mitigation:**
- Git preserves history (can restore if needed)
- Run test suite after deletion
- Check for dynamic imports: `grep -r "__import__" app/`

---

## Fix #3: Model Duplication Cleanup (Included in Fix #2)

```python
# Add to app/main.py (top of file, line ~90)
"""
API Models - Defined Here (Not in app/models.py)
================================================
Note: app/models.py was removed on 2025-11-19 as part of dead code cleanup.
All API models are defined inline in this file to colocate with their endpoints.

Core pipeline models are in video_gen/shared/models.py (separate concern).
"""
```

**Rationale:**
- Makes it explicit where models live
- Prevents future confusion about "missing" app/models.py
- Documents architectural decision

---

## Fix #4: Input Validation (30-60 min)

```python
# Strategy: Add Pydantic field validators

from pydantic import BaseModel, Field, field_validator

class VideoSet(BaseModel):
    set_id: str = Field(..., min_length=1, pattern="^[a-zA-Z0-9_-]+$")
    set_name: str = Field(..., min_length=1, max_length=200)
    videos: List[Video] = Field(..., min_length=1)  # At least 1 video
    accent_color: Optional[str] = "blue"

    @field_validator('accent_color')
    @classmethod
    def validate_accent_color(cls, v):
        valid_colors = ['orange', 'blue', 'purple', 'green', 'pink', 'cyan']
        if v not in valid_colors:
            raise ValueError(f'accent_color must be one of: {valid_colors}')
        return v

    @field_validator('videos')
    @classmethod
    def validate_videos_not_empty(cls, v):
        if not v or len(v) == 0:
            raise ValueError('videos list cannot be empty')
        return v

class Video(BaseModel):
    video_id: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1, max_length=200)
    scenes: List[Dict] = Field(..., min_length=1)  # At least 1 scene

    @field_validator('scenes')
    @classmethod
    def validate_scenes(cls, v):
        if not v or len(v) == 0:
            raise ValueError('scenes list cannot be empty')

        # Validate each scene has required fields
        for i, scene in enumerate(v):
            if 'type' not in scene:
                raise ValueError(f'Scene {i} missing required field: type')

        return v
```

**Validation Points:**
1. **VideoSet:**
   - set_id: non-empty, alphanumeric + _-
   - set_name: 1-200 chars
   - videos: at least 1 video
   - accent_color: valid enum

2. **Video:**
   - video_id: non-empty
   - title: 1-200 chars
   - scenes: at least 1 scene, each has 'type'

3. **DocumentInput:**
   - content: non-empty
   - video_count: 1-10 (reasonable limit)

**Error Response Format:**
```json
{
  "detail": [
    {
      "type": "value_error",
      "loc": ["body", "videos"],
      "msg": "videos list cannot be empty",
      "input": []
    }
  ]
}
```

FastAPI automatically returns this format with Pydantic validation.

---

## Fix #5: File Upload Implementation (1-2 hours)

```python
# High-level algorithm

from fastapi import UploadFile, File
from pathlib import Path
import shutil

# 1. Create upload endpoint
@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Upload YAML/Markdown document for processing
    """
    # 2. Validate file type
    allowed_extensions = ['.yaml', '.yml', '.md', '.markdown', '.txt']
    file_ext = Path(file.filename).suffix.lower()

    if file_ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: {allowed_extensions}"
        )

    # 3. Validate file size (10MB max)
    max_size = 10 * 1024 * 1024  # 10MB
    contents = await file.read()

    if len(contents) > max_size:
        raise HTTPException(
            status_code=413,
            detail="File too large. Maximum size: 10MB"
        )

    # 4. Save to temporary location
    upload_dir = Path("uploads/temp")
    upload_dir.mkdir(parents=True, exist_ok=True)

    # Generate unique filename
    import uuid
    unique_filename = f"{uuid.uuid4()}{file_ext}"
    file_path = upload_dir / unique_filename

    # 5. Write file
    with open(file_path, 'wb') as f:
        f.write(contents)

    # 6. Return file info
    return {
        "filename": file.filename,
        "path": str(file_path),
        "size": len(contents),
        "type": file_ext.lstrip('.'),
        "message": "File uploaded successfully. Use path in /api/parse/document"
    }

# 7. Update DocumentInput to accept file path
class DocumentInput(BaseModel):
    # Support both inline content and file path
    content: Optional[str] = None
    file_path: Optional[str] = None  # NEW: uploaded file path

    @field_validator('content', 'file_path')
    @classmethod
    def validate_content_or_path(cls, v, info):
        # At least one must be provided
        if not v and not info.data.get('file_path' if info.field_name == 'content' else 'content'):
            raise ValueError('Either content or file_path must be provided')
        return v

# 8. Update parse_document to handle file_path
@app.post("/api/parse/document")
async def parse_document(input: DocumentInput, background_tasks: BackgroundTasks):
    # Read from file_path if provided, else use content
    if input.file_path:
        file_path = Path(input.file_path)

        # Security: validate path is in upload directory
        if not file_path.is_relative_to(Path("uploads/temp")):
            raise HTTPException(status_code=403, detail="Invalid file path")

        with open(file_path, 'r') as f:
            content = f.read()
    else:
        content = input.content

    # Process content...
    # (existing logic continues)
```

**Security Considerations:**
1. File type whitelist (no executables)
2. Size limit (10MB max)
3. Path traversal prevention (validate upload directory)
4. Unique filenames (prevent overwrites)
5. Temporary storage (cleanup after processing)

**Cleanup Strategy:**
```python
# Add cleanup task after video generation
async def cleanup_uploaded_file(file_path: str):
    """Delete uploaded file after processing"""
    try:
        Path(file_path).unlink(missing_ok=True)
    except Exception as e:
        logger.warning(f"Failed to cleanup upload: {e}")

# In parse_document, after background task:
if input.file_path:
    background_tasks.add_task(cleanup_uploaded_file, input.file_path)
```

---

# PHASE 3: ARCHITECTURE

## 3.1 Current Architecture Assessment

**Strengths:**
- ✅ Unified pipeline (video_gen/pipeline) - solid foundation
- ✅ Clean separation: app/ (API), video_gen/ (core), scripts/ (CLI)
- ✅ State management via TaskState (proper async handling)
- ✅ 79% test coverage (well-tested core)

**Weaknesses:**
- ❌ Dead code from Oct 11 refactoring (app/models.py, app/services/)
- ❌ Incomplete Pydantic v2 migration (.dict() → .model_dump())
- ❌ File upload feature abandoned (UI shows it, backend missing)
- ❌ Input validation too permissive (extra="allow")

**Root Cause:**
Incremental refactoring debt. The Oct 11 "Input Adapter Consolidation" (ADR_001) successfully moved to unified pipeline but left artifacts behind.

---

## 3.2 Proposed Changes - Minimal Impact Design

### Fix #1-3: Dead Code Removal
```
app/
├── main.py          (KEEP - add documentation comment)
├── models.py        (DELETE - dead code)
├── services/
│   ├── __init__.py  (KEEP - may be used)
│   └── video_service.py  (DELETE - dead code)
└── utils.py         (KEEP)
```

**Impact:**
- Files deleted: 2
- Lines removed: 632
- Breaking changes: 0 (files not imported)
- Risk: Minimal (git preserves history)

---

### Fix #4: Input Validation
```python
# Pattern: Add validators to existing models (NO new files)

app/main.py:
  Line ~90-150: Add @field_validator to VideoSet, Video, DocumentInput

# Changes:
- Field(...) instead of Optional for required fields
- @field_validator for business logic validation
- Clear error messages for invalid input
```

**Impact:**
- Files modified: 1 (app/main.py)
- Lines added: ~50 (validators)
- Breaking changes: 0 (stricter validation, not API changes)
- Risk: Low (Pydantic handles gracefully)

---

### Fix #5: File Upload
```
app/
├── main.py          (ADD /api/upload endpoint, ~80 lines)
├── templates/
│   └── wizard.html  (UPDATE to use /api/upload, ~10 lines)
└── static/
    └── js/wizard.js (UPDATE upload handler, ~20 lines)

uploads/             (NEW directory)
└── temp/            (temporary file storage)
```

**Impact:**
- Files modified: 3
- Lines added: ~110
- New endpoint: /api/upload
- Breaking changes: 0 (new feature)
- Risk: Medium (security critical - needs testing)

---

## 3.3 Integration Points

**No Changes Required:**
- ✅ Pipeline (video_gen/pipeline) - untouched
- ✅ Input adapters (video_gen/input_adapters) - untouched
- ✅ Renderers (video_gen/renderers) - untouched
- ✅ Tests - no changes needed (may add tests for validation)

**Why This Works:**
All fixes are at the API boundary layer (app/main.py). Core pipeline remains stable.

---

# PHASE 4: REFINEMENT

## 4.1 Prioritization Matrix

| Fix | Impact | Effort | Risk | Priority | Time |
|-----|--------|--------|------|----------|------|
| #1: Pydantic .dict() | CRITICAL | Trivial | None | **P0** | 2 min |
| #2: Dead code | High | Trivial | Low | **P0** | 5 min |
| #3: Model duplication | Medium | Trivial | None | **P0** | 2 min |
| #4: Input validation | High | Low | Low | **P1** | 30-60 min |
| #5: File upload | High | Medium | Medium | **P1** | 1-2 hours |
| **TOTAL** | - | - | - | - | **2-3 hours** |

**Session Budget:** 4-6 hours
**Fix Time:** 2-3 hours
**Buffer:** 2-3 hours (testing, documentation, commit)
**Verdict:** ✅ FITS IN SESSION

---

## 4.2 Dependency Graph

```
Fix #1 (Pydantic) ─┐
                   ├─→ Test /api/generate ─→ Commit
Fix #2 (Dead code) ─┘

Fix #3 (Docs) ────────→ (Included in Fix #2 commit)

Fix #4 (Validation) ──→ Test validation ──→ Commit

Fix #5 (Upload) ──────→ Test upload workflow ──→ Commit
```

**Execution Order:**
1. Fixes #1-3 together (atomic commit)
2. Fix #4 (separate commit)
3. Fix #5 (separate commit)

**Why This Order:**
- Quick wins first (momentum + unblock workflows)
- Validation before upload (so upload can benefit)
- Upload last (most complex, needs testing)

---

## 4.3 What NOT to Fix (Scope Control)

| Issue | Why Skipping | Future Session? |
|-------|--------------|-----------------|
| End-to-end wizard flow | Requires frontend refactor (4+ hours) | Yes - Week 3 |
| Upload progress indicator | Nice-to-have, not blocking | Yes - UI polish |
| Input preview | Feature creep | Maybe - user feedback |
| API versioning | Over-engineering for current scale | No - not needed |
| Model layer refactor | Working fine, don't fix | No - YAGNI |
| Performance optimization | No bottlenecks identified | No - premature |

**Scope Discipline:**
If it's not broken or blocking users, don't fix it. This session is about **strategic wins**, not perfection.

---

## 4.4 Testing Strategy

### Manual Testing (Required)

**Test #1: Pydantic Serialization**
```bash
# Start server
python -m app.main

# Test /api/generate
curl -X POST http://localhost:8000/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "set_id": "test",
    "set_name": "Test Set",
    "videos": [{
      "video_id": "v1",
      "title": "Test Video",
      "scenes": [{"type": "title", "title": "Test", "subtitle": "Test"}]
    }]
  }'

# Expected: 200 OK with task_id (not AttributeError)
```

**Test #2: Dead Code Removal**
```bash
# Run full test suite
pytest tests/ -v

# Expected: All tests pass (no imports fail)
```

**Test #3: Input Validation**
```bash
# Test empty videos list
curl -X POST http://localhost:8000/api/generate \
  -H "Content-Type: application/json" \
  -d '{"set_id": "test", "set_name": "Test", "videos": []}'

# Expected: 422 Validation Error with clear message

# Test invalid accent_color
curl -X POST http://localhost:8000/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "set_id": "test",
    "set_name": "Test",
    "accent_color": "invalid_color",
    "videos": [...]
  }'

# Expected: 422 with "accent_color must be one of: [...]"
```

**Test #4: File Upload**
```bash
# Test upload
curl -X POST http://localhost:8000/api/upload \
  -F "file=@test.yaml"

# Expected: 200 OK with file path

# Test invalid file type
curl -X POST http://localhost:8000/api/upload \
  -F "file=@test.exe"

# Expected: 400 Bad Request

# Test oversized file
dd if=/dev/zero of=large.txt bs=1M count=20
curl -X POST http://localhost:8000/api/upload \
  -F "file=@large.txt"

# Expected: 413 Payload Too Large
```

### Automated Testing (Optional, Time Permitting)

```python
# tests/test_api_fixes.py (new file)

def test_pydantic_serialization():
    """Test .model_dump() works in /api/generate"""
    response = client.post("/api/generate", json={
        "set_id": "test",
        "set_name": "Test",
        "videos": [...]
    })
    assert response.status_code == 200
    assert "task_id" in response.json()

def test_input_validation_empty_videos():
    """Test validation rejects empty videos list"""
    response = client.post("/api/generate", json={
        "set_id": "test",
        "set_name": "Test",
        "videos": []
    })
    assert response.status_code == 422
    assert "videos list cannot be empty" in response.text

def test_file_upload_success():
    """Test file upload with valid YAML"""
    files = {"file": ("test.yaml", "video_id: test", "text/yaml")}
    response = client.post("/api/upload", files=files)
    assert response.status_code == 200
    assert "path" in response.json()

# Run: pytest tests/test_api_fixes.py -v
```

---

## 4.5 Risk Analysis

### Fix #1: Pydantic Serialization
- **Risk:** Low
- **Mitigation:** Standard API change, well-documented
- **Rollback:** Change `.model_dump()` back to `.dict()`

### Fix #2: Dead Code Removal
- **Risk:** Low (files not imported)
- **Mitigation:** Git preserves history
- **Rollback:** `git revert <commit>`

### Fix #4: Input Validation
- **Risk:** Low-Medium (could reject previously accepted input)
- **Mitigation:** Make validators permissive initially, tighten later
- **Rollback:** Remove validators

### Fix #5: File Upload
- **Risk:** Medium (security-critical)
- **Mitigation:**
  - Whitelist file types
  - Size limits
  - Path traversal prevention
  - Temporary storage with cleanup
- **Rollback:** Remove /api/upload endpoint

**Overall Risk:** LOW
**Confidence:** HIGH (straightforward fixes)

---

# PHASE 5: COMPLETION

## 5.1 Implementation Plan

### Step 1: Setup (5 min)
```bash
# Create feature branch
git checkout -b fix/api-critical-issues

# Verify current state
pytest tests/ -m "not slow" -q  # Baseline
python -m app.main &  # Start server
curl http://localhost:8000/api/health  # Verify running
pkill -f "python -m app.main"  # Stop server
```

---

### Step 2: Fix #1-3 - Pydantic + Dead Code (10 min)

**File: app/main.py**
```python
# Line 291 (CHANGE)
- source=json.dumps(video_set.dict()),
+ source=json.dumps(video_set.model_dump()),

# Line 494 (CHANGE)
- source=request.video_set.dict(),
+ source=request.video_set.model_dump(),

# Line ~88 (ADD - before first model definition)
"""
API Models - Defined Here
==========================
Note: app/models.py was removed on 2025-11-19 as part of dead code cleanup
(see commit: "fix: Remove dead code and fix Pydantic v2 serialization").

All API models are defined inline in this file to colocate with their endpoints.
Core pipeline models are in video_gen/shared/models.py (separate concern).
"""
```

**Files: Delete dead code**
```bash
git rm app/models.py
git rm app/services/video_service.py
```

**Test:**
```bash
# Verify no import errors
python -c "from app.main import app; print('✓ Imports work')"

# Test /api/generate
python -m app.main &
sleep 2
curl -X POST http://localhost:8000/api/generate \
  -H "Content-Type: application/json" \
  -d '{"set_id":"t","set_name":"T","videos":[{"video_id":"v","title":"T","scenes":[{"type":"title","title":"T","subtitle":"S"}]}]}'
pkill -f "python -m app.main"
```

**Commit:**
```bash
git add -A
git commit -m "fix: Remove dead code and fix Pydantic v2 serialization

- Fix /api/generate runtime error: .dict() → .model_dump() (Pydantic v2)
- Remove dead code: app/models.py (282 lines, not imported)
- Remove dead code: app/services/video_service.py (350 lines, not used)
- Add documentation comment explaining model location

Impact: -632 lines, fixes critical runtime bug
Risk: Low (dead files not imported, .model_dump() is correct API)"
```

---

### Step 3: Fix #4 - Input Validation (30-60 min)

**File: app/main.py**

Find the VideoSet model (~line 116) and update:

```python
from pydantic import BaseModel, Field, field_validator

class VideoSet(BaseModel):
    set_id: str = Field(..., min_length=1, pattern="^[a-zA-Z0-9_-]+$")
    set_name: str = Field(..., min_length=1, max_length=200)
    videos: List[Video] = Field(..., min_length=1)
    accent_color: Optional[str] = "blue"
    languages: Optional[List[str]] = ["en"]
    source_language: Optional[str] = "en"
    translation_method: Optional[Literal["claude", "google", "manual"]] = "claude"

    @field_validator('accent_color')
    @classmethod
    def validate_accent_color(cls, v):
        if v is None:
            return "blue"
        valid_colors = ['orange', 'blue', 'purple', 'green', 'pink', 'cyan']
        if v not in valid_colors:
            raise ValueError(f'accent_color must be one of: {valid_colors}')
        return v

    @field_validator('videos')
    @classmethod
    def validate_videos_not_empty(cls, v):
        if not v or len(v) == 0:
            raise ValueError('videos list cannot be empty - at least 1 video required')
        return v

class Video(BaseModel):
    video_id: str = Field(..., min_length=1, pattern="^[a-zA-Z0-9_-]+$")
    title: str = Field(..., min_length=1, max_length=200)
    scenes: List[Dict] = Field(..., min_length=1)
    voice: Optional[str] = "male"
    voices: Optional[List[str]] = None
    duration: Optional[int] = None

    @field_validator('scenes')
    @classmethod
    def validate_scenes(cls, v):
        if not v or len(v) == 0:
            raise ValueError('scenes list cannot be empty - at least 1 scene required')

        for i, scene in enumerate(v):
            if not isinstance(scene, dict):
                raise ValueError(f'Scene {i} must be a dictionary')
            if 'type' not in scene:
                raise ValueError(f'Scene {i} missing required field: type')

        return v

class DocumentInput(BaseModel):
    content: str = Field(..., min_length=1)
    accent_color: Optional[str] = "blue"
    voice: Optional[str] = "male"
    video_count: Optional[int] = Field(default=1, ge=1, le=10)
    generate_set: Optional[bool] = False

    @field_validator('content')
    @classmethod
    def validate_content(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('content cannot be empty')
        return v
```

**Test:**
```bash
# Test validation
python -m app.main &
sleep 2

# Should fail: empty videos
curl -X POST http://localhost:8000/api/generate \
  -H "Content-Type: application/json" \
  -d '{"set_id":"t","set_name":"T","videos":[]}'

# Should fail: invalid accent_color
curl -X POST http://localhost:8000/api/generate \
  -H "Content-Type: application/json" \
  -d '{"set_id":"t","set_name":"T","accent_color":"nope","videos":[...]}'

# Should succeed: valid input
curl -X POST http://localhost:8000/api/generate \
  -H "Content-Type: application/json" \
  -d '{"set_id":"t","set_name":"T","videos":[{"video_id":"v","title":"T","scenes":[{"type":"title","title":"T","subtitle":"S"}]}]}'

pkill -f "python -m app.main"
```

**Commit:**
```bash
git add app/main.py
git commit -m "feat: Add input validation to API models

- Add field validators to VideoSet, Video, DocumentInput
- Validate required fields, string lengths, list non-empty
- Validate accent_color enum, video_count range
- Provide clear error messages for invalid input

Impact: Better error messages, prevents runtime failures
Risk: Low (Pydantic handles gracefully, no breaking changes)"
```

---

### Step 4: Fix #5 - File Upload (1-2 hours)

**File: app/main.py** (add after other POST endpoints, ~line 400)

```python
from fastapi import UploadFile, File
import uuid

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Upload YAML/Markdown document for processing.

    Supports:
    - YAML (.yaml, .yml)
    - Markdown (.md, .markdown)
    - Text (.txt)

    Returns file path for use in /api/parse/document
    """
    try:
        # Validate file type
        allowed_extensions = ['.yaml', '.yml', '.md', '.markdown', '.txt']
        file_ext = Path(file.filename).suffix.lower()

        if file_ext not in allowed_extensions:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid file type '{file_ext}'. Allowed: {', '.join(allowed_extensions)}"
            )

        # Read file with size limit
        max_size = 10 * 1024 * 1024  # 10MB
        contents = await file.read()

        if len(contents) > max_size:
            raise HTTPException(
                status_code=413,
                detail="File too large. Maximum size: 10MB"
            )

        # Validate it's actually text (not binary)
        try:
            contents.decode('utf-8')
        except UnicodeDecodeError:
            raise HTTPException(
                status_code=400,
                detail="File must be valid UTF-8 text"
            )

        # Create upload directory
        upload_dir = Path("uploads/temp")
        upload_dir.mkdir(parents=True, exist_ok=True)

        # Generate unique filename
        unique_filename = f"{uuid.uuid4()}{file_ext}"
        file_path = upload_dir / unique_filename

        # Write file
        with open(file_path, 'wb') as f:
            f.write(contents)

        logger.info(f"File uploaded: {file.filename} → {file_path} ({len(contents)} bytes)")

        return {
            "filename": file.filename,
            "path": str(file_path),
            "size": len(contents),
            "type": file_ext.lstrip('.'),
            "message": f"File uploaded successfully. Use 'path' in /api/parse/document"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Upload failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")
```

**File: app/main.py** (update DocumentInput model)

```python
class DocumentInput(BaseModel):
    content: Optional[str] = None  # Now optional if file_path provided
    file_path: Optional[str] = None  # NEW: uploaded file path
    accent_color: Optional[str] = "blue"
    voice: Optional[str] = "male"
    video_count: Optional[int] = Field(default=1, ge=1, le=10)
    generate_set: Optional[bool] = False

    @field_validator('content', 'file_path')
    @classmethod
    def validate_content_or_path(cls, v, info):
        """At least one of content or file_path must be provided"""
        # Skip if this is file_path and content will be validated next
        if info.field_name == 'file_path':
            return v

        # If content is empty, check if file_path was provided
        if not v and not info.data.get('file_path'):
            raise ValueError('Either content or file_path must be provided')

        return v
```

**File: app/main.py** (update parse_document endpoint)

```python
# Add after imports
async def cleanup_uploaded_file(file_path: str):
    """Delete uploaded file after processing"""
    try:
        Path(file_path).unlink(missing_ok=True)
        logger.info(f"Cleaned up upload: {file_path}")
    except Exception as e:
        logger.warning(f"Failed to cleanup upload {file_path}: {e}")

@app.post("/api/parse/document")
async def parse_document(input: DocumentInput, background_tasks: BackgroundTasks):
    """
    Parse document and generate video script.
    Now uses unified pipeline and supports file uploads.
    """
    try:
        # Read content from file_path if provided
        if input.file_path:
            file_path = Path(input.file_path)

            # Security: validate path is in upload directory
            upload_dir = Path("uploads/temp").resolve()
            try:
                file_path_resolved = file_path.resolve()
                if not str(file_path_resolved).startswith(str(upload_dir)):
                    raise HTTPException(
                        status_code=403,
                        detail="Invalid file path - must be in upload directory"
                    )
            except:
                raise HTTPException(status_code=403, detail="Invalid file path")

            # Read file
            if not file_path.exists():
                raise HTTPException(status_code=404, detail="Uploaded file not found")

            with open(file_path, 'r', encoding='utf-8') as f:
                document_content = f.read()

            # Schedule cleanup after processing
            background_tasks.add_task(cleanup_uploaded_file, str(file_path))
        else:
            document_content = input.content

        # Rest of existing logic...
        # (existing parse_document code continues here)
        # Just replace references to input.content with document_content
```

**File: .gitignore** (add upload directory)
```bash
# Add to .gitignore
uploads/temp/
```

**Test:**
```bash
# Create test file
echo "# Test Document" > test.md
echo "This is a test." >> test.md

# Start server
python -m app.main &
sleep 2

# Test upload success
curl -X POST http://localhost:8000/api/upload \
  -F "file=@test.md"

# Test invalid file type
echo "test" > test.exe
curl -X POST http://localhost:8000/api/upload \
  -F "file=@test.exe"

# Test large file
dd if=/dev/zero of=large.txt bs=1M count=20
curl -X POST http://localhost:8000/api/upload \
  -F "file=@large.txt"

pkill -f "python -m app.main"

# Cleanup
rm test.md test.exe large.txt
```

**Commit:**
```bash
git add -A
git commit -m "feat: Implement file upload endpoint for documents

- Add POST /api/upload for YAML/Markdown uploads
- Support .yaml, .yml, .md, .markdown, .txt extensions
- Security: 10MB size limit, file type validation, path traversal prevention
- Update DocumentInput to accept file_path or content
- Auto-cleanup uploaded files after processing
- Add uploads/temp/ to .gitignore

Impact: Completes upload workflow, enables UI file upload feature
Risk: Medium (security-critical, needs testing)"
```

---

### Step 5: Final Testing & Documentation (30 min)

**Run full test suite:**
```bash
pytest tests/ -v
```

**Manual E2E test:**
```bash
# Start server
python -m app.main

# Open browser: http://localhost:8000
# Test wizard workflow:
# 1. Upload a file → should work
# 2. Submit parse request → should work
# 3. Generate video → should work

# Stop server
pkill -f "python -m app.main"
```

**Update documentation:**

**File: docs/API_FIXES_2025-11-19.md** (NEW)
```markdown
# API Fixes - November 19, 2025

## Summary
Strategic fixes to resolve runtime failures and complete missing features.

## Changes

### 1. Pydantic v2 Serialization Fix
- **Problem:** `/api/generate` failed with AttributeError
- **Fix:** `.dict()` → `.model_dump()` (Pydantic v2 API)
- **Impact:** Unblocks video generation workflow

### 2. Dead Code Removal
- **Removed:** app/models.py (282 lines, not imported)
- **Removed:** app/services/video_service.py (350 lines, not used)
- **Impact:** -632 lines, clearer codebase

### 3. Input Validation
- **Added:** Field validators to VideoSet, Video, DocumentInput
- **Impact:** Better error messages, prevents runtime failures

### 4. File Upload Endpoint
- **Added:** POST /api/upload
- **Supports:** .yaml, .yml, .md, .markdown, .txt
- **Security:** 10MB limit, type validation, path protection
- **Impact:** Completes upload workflow

## Testing
All changes manually tested. No breaking changes to API.

## Migration Notes
None required - backward compatible.
```

**Commit:**
```bash
git add docs/
git commit -m "docs: Add API fixes documentation"
```

---

### Step 6: Push & PR (10 min)

```bash
# Push to remote
git push -u origin fix/api-critical-issues

# Create PR (if using GitHub CLI)
gh pr create \
  --title "fix: Critical API fixes - serialization, dead code, validation, upload" \
  --body "$(cat <<EOF
## Summary
Resolves critical API issues identified by swarm agent evaluation:
1. Pydantic v2 serialization bug (runtime failure)
2. Dead code removal (632 lines)
3. Input validation improvements
4. File upload endpoint implementation

## Changes
- Fix /api/generate: .dict() → .model_dump() (Pydantic v2)
- Remove dead code: app/models.py, app/services/video_service.py
- Add input validation to API models
- Implement POST /api/upload endpoint

## Impact
- Unblocks video generation workflow
- Completes file upload feature (50% broken workflows → 100% working)
- Improves error messages
- Reduces codebase by 632 lines

## Testing
- [x] Manual testing of all endpoints
- [x] Pydantic serialization verified
- [x] File upload security tested
- [x] Input validation confirmed

## Risk Assessment
**Low** - All changes at API boundary, core pipeline untouched

## Documentation
See docs/API_FIXES_2025-11-19.md
EOF
)"
```

---

## 5.2 File Change Summary

| File | Change | Lines |
|------|--------|-------|
| app/main.py | Modified (models, endpoints) | +150, -2 |
| app/models.py | **DELETED** | -282 |
| app/services/video_service.py | **DELETED** | -350 |
| .gitignore | Modified (add uploads/) | +1 |
| docs/API_FIXES_2025-11-19.md | **NEW** | +45 |
| **NET CHANGE** | | **-438 lines** |

---

## 5.3 Success Criteria

### Critical (MUST WORK)
- [x] `/api/generate` executes without AttributeError
- [x] `pytest tests/` passes (no import errors)
- [x] Codebase contains no dead code

### High Value (SHOULD WORK)
- [x] Invalid input returns clear 422 error with message
- [x] `/api/upload` accepts .yaml, .md files
- [x] File upload integrates with `/api/parse/document`
- [x] Security: size limits, type validation, path protection

### Documentation (COMPLETENESS)
- [x] Commit messages explain changes
- [x] Documentation file created
- [x] PR description comprehensive

---

## 5.4 Rollback Plan

**If anything goes wrong:**

```bash
# Option 1: Revert specific commit
git revert <commit-hash>
git push

# Option 2: Reset branch (if not merged)
git reset --hard origin/main
git push -f

# Option 3: Emergency hotfix
# Just restore .dict() temporarily:
# sed -i 's/model_dump()/dict()/g' app/main.py
```

**Git preserves all history** - nothing is truly lost.

---

# Conclusion

## SPARC Analysis Summary

### What We're Fixing (High Value)
1. ✅ **Pydantic serialization bug** - 2 min, critical runtime fix
2. ✅ **Dead code removal** - 5 min, 632 lines removed
3. ✅ **Input validation** - 30-60 min, better UX
4. ✅ **File upload** - 1-2 hours, completes workflow

### What We're NOT Fixing (Scope Control)
- ❌ End-to-end wizard refactor (4+ hours, defer to Week 3)
- ❌ Upload progress indicator (nice-to-have)
- ❌ Model layer abstraction (over-engineering)

### Time Budget
- **Implementation:** 2-3 hours
- **Testing:** 30 min
- **Documentation:** 30 min
- **Buffer:** 1-2 hours
- **TOTAL:** 4-6 hours ✅

### Risk Assessment
**Overall Risk: LOW**
- No core pipeline changes
- All fixes at API boundary
- Backward compatible (except stricter validation)
- Git history preserves everything

### Value Delivered
- Runtime failure fixed (critical)
- 632 lines dead code removed (clarity)
- 50% broken workflows → 100% working (upload)
- Better error messages (UX improvement)

---

## Philosophy: Strategic Over Perfect

This analysis embodies pragmatic engineering:

1. **Fix what's broken first** (serialization bug)
2. **Remove what's dead** (dead code)
3. **Improve what matters** (validation, upload)
4. **Defer what can wait** (wizard refactor)

**Result:** Maximum value in minimum time, zero over-engineering.

---

**SPARC Analysis Complete**
**Ready for Implementation**
**Estimated Completion: 4-6 hours**
