# GOAL PLAN: Programmatic API Feature Parity with CLI

**Goal:** Make programmatic API as easy to use as CLI for AI narration

**Date:** October 6, 2025
**Priority:** HIGH
**Estimated Effort:** 1-2 hours

---

## 🎯 Problem Statement

**Current Situation:**

CLI has easy AI narration:
```bash
python scripts/create_video.py --document README.md --use-ai  ✅ WORKS
```

Programmatic API doesn't:
```python
InputConfig(
    input_type="programmatic",
    source=video,
    use_ai_narration=True  # ❌ DOESN'T WORK - parameter ignored
)
```

**Gap:** Users can't easily enable AI narration in programmatic scripts.

---

## 🎯 Success Criteria

After completion, this should work:

```python
from video_gen.shared.models import VideoConfig, InputConfig
from video_gen.pipeline import get_pipeline

video = VideoConfig(...)

result = await pipeline.execute(InputConfig(
    input_type="programmatic",
    source=video,
    use_ai_narration=True  # ✨ This should enable AI narration
))
```

**Expected behavior:**
- ✅ AI generates natural narration for all scenes
- ✅ Uses ANTHROPIC_API_KEY from environment
- ✅ Falls back to template if key missing
- ✅ Works exactly like CLI --use-ai flag

---

## 📋 Implementation Steps (8 Tasks)

### **Task 1: Analyze CLI Implementation** (15 min)

**What:** Understand how CLI --use-ai flag works

**Actions:**
1. Read `scripts/create_video.py` - find --use-ai handling
2. Trace how flag gets passed to pipeline
3. Identify which stage uses it
4. Document the flow

**Expected outcome:** Clear understanding of current AI narration flow

---

### **Task 2: Design API Parameter** (10 min)

**What:** Design clean programmatic API for AI narration

**Actions:**
1. Add `use_ai_narration: bool` to InputConfig model
2. Default to False (backward compatible)
3. Document parameter in docstring

**Code change:**
```python
# video_gen/shared/models.py - InputConfig
use_ai_narration: bool = False  # Enable AI-enhanced narration
```

**Expected outcome:** Parameter exists in data model

---

### **Task 3: Implement in InputConfig** (5 min)

**What:** Make InputConfig pass flag through pipeline

**Actions:**
1. Add use_ai_narration to InputConfig.to_dict()
2. Ensure it's serialized in context
3. Available to all pipeline stages

**Expected outcome:** Flag accessible in pipeline context

---

### **Task 4: Update ScriptGenerationStage** (20 min)

**What:** Make script stage respect use_ai_narration flag

**Actions:**
1. Read `video_gen/stages/script_generation_stage.py`
2. Check context for `use_ai_narration` flag
3. Enable AIScriptEnhancer when flag=True
4. Use ANTHROPIC_API_KEY (not openai_api_key)
5. Handle fallback if key missing

**Code changes:**
```python
# script_generation_stage.py
use_ai = context.get("use_ai_narration", False)
has_key = os.getenv("ANTHROPIC_API_KEY")

if use_ai and has_key:
    # Use AI enhancer
    narration = await self.ai_enhancer.enhance(...)
else:
    # Use template
    narration = template_narration
```

**Expected outcome:** Stage uses AI when flag is True

---

### **Task 5: Update Documentation** (15 min)

**What:** Document AI narration in programmatic guides

**Actions:**
1. Update API_PARAMETERS_REFERENCE.md - add use_ai_narration
2. Update PROGRAMMATIC_GUIDE.md - add AI examples
3. Add comparison: Template vs AI narration

**Example to add:**
```python
# Template narration (fast, free)
InputConfig(source=video, use_ai_narration=False)

# AI narration (natural, requires API key)
InputConfig(source=video, use_ai_narration=True)
```

**Expected outcome:** Users know how to enable AI

---

### **Task 6: End-to-End Test** (10 min)

**What:** Verify AI narration works programmatically

**Actions:**
1. Create test script
2. Generate 1 video with use_ai_narration=True
3. Verify AI API calls in logs
4. Verify output sounds natural

**Test code:**
```python
video = VideoConfig(
    video_id="ai_test",
    title="AI Narration Test",
    scenes=[SceneConfig(...)]
)

result = await pipeline.execute(InputConfig(
    input_type="programmatic",
    source=video,
    use_ai_narration=True  # Test this!
))

# Check logs for: "Using AI narration"
```

**Expected outcome:** AI narration confirmed working

---

### **Task 7: Update Internet Guide Script** (5 min)

**What:** Fix user's bilingual script to use AI properly

**Actions:**
1. Update generate_internet_guide_bilingual.py
2. Change metadata to proper InputConfig parameter
3. Test with 1 video first

**Code fix:**
```python
InputConfig(
    input_type="programmatic",
    source=video,
    languages=["en", "es"],
    use_ai_narration=True  # ✨ Proper parameter (not metadata)
)
```

**Expected outcome:** User's script works with AI narration

---

### **Task 8: Commit & Document** (10 min)

**What:** Commit all changes with clear documentation

**Actions:**
1. Commit code changes
2. Commit documentation updates
3. Create completion report
4. Push to GitHub

**Expected outcome:** Feature complete and documented

---

## 📊 Timeline

**Total estimated time: 1-2 hours**

| Task | Time | Cumulative |
|------|------|------------|
| 1. Analyze CLI | 15 min | 15 min |
| 2. Design parameter | 10 min | 25 min |
| 3. Implement InputConfig | 5 min | 30 min |
| 4. Update stage | 20 min | 50 min |
| 5. Update docs | 15 min | 65 min |
| 6. Test | 10 min | 75 min |
| 7. Update script | 5 min | 80 min |
| 8. Commit | 10 min | **90 min** |

**Parallel execution possible:** Tasks 5 (docs) can run parallel with Task 4 (code)

---

## 🎯 Execution Strategy

**Approach:** Sequential with one parallel task

**Phase 1: Analysis & Design (25 min)**
- Tasks 1-2: Understand current, design solution

**Phase 2: Implementation (25 min)**
- Task 3: InputConfig changes
- Task 4: ScriptGenerationStage changes

**Phase 3: Documentation (15 min - parallel with Phase 2)**
- Task 5: Update all docs (can run parallel)

**Phase 4: Validation (15 min)**
- Tasks 6-7: Test and fix user script

**Phase 5: Commit (10 min)**
- Task 8: Push everything

---

## ✅ Acceptance Criteria

Feature is complete when:

1. ✅ `use_ai_narration=True` in InputConfig enables AI narration
2. ✅ Works exactly like CLI --use-ai flag
3. ✅ Falls back to template if no API key
4. ✅ Documented in API_PARAMETERS_REFERENCE.md
5. ✅ Working example in PROGRAMMATIC_GUIDE.md
6. ✅ User's Internet Guide script generates with AI
7. ✅ End-to-end test passes
8. ✅ All changes committed and pushed

---

## 🚀 Ready to Execute

**Next step:** Begin Task 1 - Analyze CLI implementation

**Estimated completion:** 90 minutes from start

**Expected outcome:** Programmatic API has full feature parity with CLI for AI narration

---

**This plan is ready. Shall I execute all 8 tasks now?**
