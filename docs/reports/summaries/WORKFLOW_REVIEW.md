# Systematic Workflow Review - Video Generation Issues

**Date:** October 6, 2025
**Context:** User reports videos still broken after multiple fixes
**Approach:** Step back, review systematically, understand root causes

---

## 🎯 User Requirements (What We Need)

1. **5 videos** from Internet_Guide_Vol1_Core_Infrastructure.md
2. **~90 seconds** each
3. **3 voices** (male, female, male_warm) - rotated across videos
4. **Bilingual** - English + Spanish (10 videos total)
5. **AI-enhanced** - Smart slide breakdown + natural narration
6. **Clean visuals** - No markdown formatting on slides
7. **Aligned narration** - Narration describes what's on screen

---

## 🔬 Current Workflow Analysis

### **Step 1: Document Parsing (DocumentAdapter)**

**What happens:**
```
Internet_Guide_Vol1.md
  → DocumentAdapter.adapt()
  → Splits by H2 sections
  → Creates 5 VideoConfig objects
  → Each with SceneConfig list
```

**What should happen:**
- Read markdown
- Split by ## headers
- Extract content (lists, code, text)
- **Clean markdown formatting** (remove [text](#links))
- Create meaningful scenes

**Current status:** ❓ NEEDS VERIFICATION
- Is H2 splitting working correctly?
- Are markdown links being cleaned?
- Are lists being extracted properly?

---

### **Step 2: Content Parsing (ParsingStage - AI)**

**What happens:**
```
For each scene:
  → AI analyzes scene.narration
  → Extracts topics, keywords
  → Returns metadata
```

**AI Prompt (current):**
```
Analyze this content for educational video...
Extract: topics, keywords, complexity, key_takeaways, suggested_visuals
```

**Current status:** ✅ WORKING (I see API calls)
- But: Does this metadata actually get USED?
- Or: Just stored and ignored?

---

### **Step 3: Script Generation (ScriptGenerationStage - AI)**

**What should happen:**
```
For each scene:
  IF use_ai_narration=True:
    → Take existing scene.narration
    → Enhance with AI
    → Make it natural/conversational
  ELSE:
    → Use template/existing narration
```

**Current status:** ⚠️ PARTIALLY WORKING
- Code tries to call `ai_enhancer.enhance()`
- Old code had no `enhance()` method (I added it)
- New code should work BUT videos still broken

**Question:** Is the enhanced narration actually being USED or discarded?

---

### **Step 4: Audio Generation**

**What happens:**
```
For each scene:
  → Use scene.narration (enhanced or template)
  → Generate TTS audio
  → Measure duration
  → Save to audio file
```

**Current status:** ✅ APPEARS TO WORK
- I see audio files generated
- Durations look reasonable (13-19 seconds)

---

### **Step 5: Video Rendering**

**What happens:**
```
For each scene:
  → Read scene.visual_content
  → Call renderer (title, list, command, etc.)
  → Generate frames
  → Combine with audio
```

**Current status:** ❓ THIS IS WHERE THE PROBLEM LIKELY IS

**Questions:**
1. What's in scene.visual_content when it reaches renderer?
2. Are the markdown-cleaned items actually there?
3. Or are we using original un-cleaned data?

---

## 🚨 Hypothesis: The Core Problem

**I suspect the issue is:**

**Document Adapter creates scenes with visual_content**
```python
visual_content = {
    'items': ["[Text](#link)", ...]  # Raw markdown
}
```

**But my cleanup code runs DURING scene creation**
```python
# Clean item
cleaned_item = re.sub(...)  # This happens
items.append(cleaned_item)   # Adds cleaned version

# BUT THEN:
visual_content = {'items': items}  # Should have cleaned items
```

**However:** If the video is using CACHED data from earlier runs, it would still show old markdown!

---

## 🔍 What I Need to Check

1. **Are scene.visual_content items actually cleaned?**
   - Check the actual scene objects being created
   - Verify cleaned items are in visual_content

2. **Is narration actually being enhanced?**
   - Check if AI-enhanced text is in scene.narration
   - Or is original template text still there?

3. **Is there caching causing old data to be used?**
   - Check if audio/video files are being regenerated
   - Or reusing old cached files

4. **Are there TWO document adapters?**
   - `app/input_adapters/document.py` (I didn't fix this one!)
   - `video_gen/input_adapters/document.py` (I fixed this one)
   - Which one is the script using?

---

## 🎯 Next Steps (Systematic Approach)

### **Immediate:**
1. Check which document adapter the script is actually using
2. Add import re to BOTH if needed
3. Verify markdown cleaning is in the USED adapter

### **Then:**
4. Clear ALL cached outputs
5. Run ONE video (not 10) as test
6. Inspect the generated scene data
7. Verify slides are clean
8. Verify narration matches

### **Only After Test Passes:**
9. Run full 10-video generation

---

**This review identifies the real issues instead of guessing. Let me now execute this systematic check.**
