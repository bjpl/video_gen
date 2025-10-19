# Prompt Comparison: OLD (Working) vs. NEW (Current) System

**Analysis Date:** October 18, 2025
**Analyst:** Based on git history analysis (commit 31e0299c vs current)

---

## Executive Summary

The OLD system (31e0299c) that was creating videos "to spec" had **SIGNIFICANTLY MORE CONSTRAINED AND SPECIFIC** prompts for AI narration generation. The NEW system uses a more generic, flexible approach that likely produces less predictable/desirable results for technical content.

**Key Finding:** The OLD prompts were BETTER because they were MORE RESTRICTIVE, not more creative.

---

## Side-by-Side Comparison

### 1. Model & Temperature

| Aspect | OLD System (Working) | NEW System (Current) |
|--------|---------------------|---------------------|
| **Model** | `claude-sonnet-4-20250514` | `claude-sonnet-4-5-20250929` |
| **Temperature** | **0.5** (explicit - more consistent) | **Not specified** (default 1.0 - more variable) |
| **Max Tokens** | 150 | 500 |
| **Implication** | Lower creativity, higher consistency | Higher creativity, more variance |

### 2. Word Count Constraints

| Scene Type | OLD System | NEW System |
|-----------|-----------|------------|
| **Title** | **~10 words** (very specific) | 50-150 words / 20-200 words |
| **Command** | **15-20 words** (tight range) | 50-150 words / 20-200 words |
| **List** | **15-20 words** (tight range) | 50-150 words / 20-200 words |
| **Outro** | **10-15 words** (tight range) | 50-150 words / 20-200 words |
| **Code Comparison** | **12-18 words** (tight range) | 50-150 words / 20-200 words |

**Analysis:** OLD system gave AI MUCH LESS ROOM to elaborate. NEW system allows 5-20x more words!

### 3. Anti-Marketing Language

#### OLD System (Explicit, Detailed)

```
Avoid these marketing words:
- "powerful", "amazing", "revolutionary", "game-changing"
- "transform", "unleash", "empower", "elevate"
- "journey", "explore", "discover" (unless literally exploring)
- Excessive adjectives and adverbs

Use instead:
- Direct descriptions of functionality
- Technical accuracy
- Factual benefits
- Straightforward explanations
```

#### NEW System (Brief, Generic)

```
- Avoid jargon unless necessary for technical content
```

**Analysis:** OLD had 12+ specific banned words with alternatives. NEW has generic "avoid jargon" only.

### 4. Tone & Persona

| Aspect | OLD System | NEW System |
|--------|-----------|------------|
| **Persona** | "Like explaining to a **developer colleague**" | "Professional **narrator** for technical videos" |
| **Tone** | "Technical documentation tone (NOT marketing)" | "Conversational but professional tone" |
| **Emphasis** | "NOT marketing/promotional" (repeated 3x) | "Clear, engaging, and natural-sounding" |
| **Style** | "Factual, educational - NOT sales language" | "Natural when spoken aloud" |

**Analysis:** OLD emphasized TECHNICAL DOC tone. NEW emphasizes NARRATOR/ENGAGEMENT.

### 5. Prompt Structure

#### OLD System - Title Scene Prompt

```python
context = f"""
Create technical video narration for a title scene.

Title: {scene_data.get('title', '')}
Subtitle: {scene_data.get('subtitle', '')}
Key message: {scene_data.get('key_message', '')}

Create a brief, direct introduction (1-2 sentences, ~10 words).
Style: Technical, factual, educational - NOT marketing/sales language.
Avoid: "powerful", "amazing", "transform", "instantly", "revolutionary"
Use: Direct statements about what it is and does.
"""
```

**Key Features:**
- Scene-specific structure (different prompt per scene type)
- Explicit word count (~10 words)
- Specific banned words listed
- Clear style directive (technical, factual)

#### NEW System - Generic Enhancement Prompt

```python
prompt = f"""You are a professional narrator for technical educational videos.
Enhance this narration to be clear, engaging, and natural-sounding.

Original narration: "{script}"

Scene Context: This is for a {scene_context} in an educational video.
Position Context: {position_context}

Enhancement Guidelines:
- Make it sound natural when spoken aloud
- Keep it concise and clear
- Maintain technical accuracy
- Use conversational but professional tone
- Keep similar length (±30% - target 50-150 words for most scenes)
- Avoid jargon unless necessary

Quality Requirements:
- Must be 20-200 words (strict limit)
- No markdown formatting
- Natural speech patterns

Return ONLY the enhanced narration text."""
```

**Key Features:**
- Generic prompt for all scene types
- Scene position awareness (NEW - good addition!)
- Looser word count (50-150 or 20-200 words)
- "Engaging" and "natural-sounding" emphasized
- No specific banned words
- ±30% length flexibility

**Analysis:** NEW tries to be ONE PROMPT FOR ALL, OLD had CUSTOM PROMPTS per scene type.

---

## 6. Specific OLD Prompt Examples

### OLD - Command Scene Prompt (Most Important)

```
Create technical tutorial narration for a command/code scene.

Topic: {topic}
Header: {header}
Commands shown: {count} commands
Key points: {points}

Create clear, instructional narration (2-3 sentences, 15-20 words).
Style: Technical documentation, straightforward, educational.
Avoid: Marketing language, hype, superlatives.
Focus: What the commands do and why you'd use them.
Tone: Like explaining to a developer colleague, not selling a product.
```

**Why This Worked:**
1. **15-20 words total** - Forces brevity
2. **"Like explaining to developer colleague"** - Clear persona
3. **"Not selling a product"** - Explicit anti-sales
4. **"2-3 sentences"** - Structure constraint
5. **"What commands do and why"** - Clear purpose

### OLD - List Scene Prompt

```
Create technical documentation narration for a list scene.

Topic: {topic}
Items to mention: {items}

Create narration that introduces the list (2 sentences, 15-20 words).
Style: Technical documentation, factual, clear.
Avoid: Promotional language, excitement, hype.
Focus: Factual description of what each item is/does.
Tone: Educational reference material, not sales copy.
```

**Why This Worked:**
1. **"2 sentences, 15-20 words"** - Very specific
2. **"Educational reference material"** - Clear genre
3. **"NOT sales copy"** - Explicit prohibition

### OLD - Outro Scene Prompt

```
Create technical documentation outro narration.

Main message: {message}
Documentation link: {link}

Create a brief, factual closing (1-2 sentences, 10-15 words).
Style: Direct, helpful, informative - NOT motivational/sales language.
Avoid: "journey", "transform", "unleash", "empower"
Focus: Point to documentation/resources factually.
Tone: End of technical documentation, not marketing pitch.
```

**Why This Worked:**
1. **"10-15 words"** - Ultra-brief
2. **Specific banned words** - "journey", "transform", etc.
3. **"NOT marketing pitch"** - Repeated emphasis

---

## 7. What Made OLD Prompts BETTER

### ✅ **Extreme Specificity**
- **10 words** vs. "20-200 words" - 20x tighter constraint
- Forces conciseness
- Prevents AI from elaborating unnecessarily

### ✅ **Scene-Type Specialization**
- Different prompt for each scene type
- Optimized instructions per use case
- No "one size fits all" compromise

### ✅ **Anti-Marketing Obsession**
- 12+ specific banned words
- "NOT marketing" repeated 3x per prompt
- Clear alternatives provided ("Use: Direct descriptions...")

### ✅ **Developer-to-Developer Tone**
- "Like explaining to a developer colleague"
- Technical documentation genre
- Anti-sales, anti-hype, anti-engagement

### ✅ **Lower Temperature (0.5)**
- More deterministic output
- Less creative variance
- More predictable results

### ✅ **Tight Word Counts**
- 10-20 word ranges
- 2-3 sentence limits
- Enforces brevity

---

## 8. What NEW System CHANGED (And Why It May Be Worse)

### ❌ **Generic Enhancement Pattern**
- One prompt for all scenes
- Lost scene-specific optimization
- "Professional narrator" vs. "developer colleague"

### ❌ **Looser Constraints**
- 20-200 word range (vs. 10-20)
- ±30% length flexibility (vs. exact counts)
- More room for AI to elaborate

### ❌ **Engagement Emphasis**
- "Clear, engaging, natural-sounding"
- "Professional narrator"
- May produce more promotional language

### ❌ **Missing Anti-Marketing**
- No banned word list
- Only "avoid jargon" mentioned
- AI free to use marketing language

### ❌ **Higher Temperature (Default)**
- No explicit temperature setting
- Uses default (1.0) - more creative
- More variance between generations

### ✅ **Scene Position Awareness (GOOD ADDITION)**
- "This is the OPENING scene - set the tone"
- "This is the FINAL scene - provide closure"
- Better narrative flow across video

**The NEW system added ONE GOOD THING (position awareness) but lost FIVE CRITICAL CONSTRAINTS.**

---

## 9. Validation Differences

### OLD System
- No explicit validation (relied on prompt constraints)
- Assumed AI would follow strict word counts
- Temperature 0.5 for consistency

### NEW System (Plan B Enhancements)
- **Quality validation AFTER generation**
- Checks word count (20-200)
- Checks length ratio (±50% for long templates)
- Checks for markdown formatting
- **Falls back to original if validation fails**

**Analysis:** NEW added validation AFTER generation to catch issues. OLD prevented issues via TIGHTER PROMPTS.

---

## 10. Example Output Comparison (Hypothetical)

### Title Scene: "Video Generation System"

#### OLD Prompt Output (10 words target):
> "Video Generation System creates professional educational videos from documentation."
>
> **Word count:** 10
> **Tone:** Direct, factual

#### NEW Prompt Output (20-200 words, conversational):
> "Welcome to the Video Generation System! This powerful tool transforms your documentation into engaging, professional-quality educational videos. Whether you're creating tutorials, guides, or training materials, this system makes it easy to bring your content to life with beautiful visuals and natural-sounding narration."
>
> **Word count:** 45
> **Tone:** Engaging, promotional
> **Issues:** "Powerful", "engaging", "bring to life" - marketing language

### Command Scene: "Install Dependencies"

#### OLD Prompt Output (15-20 words):
> "Install required packages with pip install. This gives you video rendering and text-to-speech capabilities."
>
> **Word count:** 17
> **Tone:** Technical instruction

#### NEW Prompt Output (50-150 words target):
> "Let's get started by installing the dependencies you'll need. Simply run the pip install command shown on screen, and you'll have everything set up in moments. This will give you access to powerful video rendering capabilities, high-quality text-to-speech features, and a complete toolkit for creating professional videos. Once installed, you'll be ready to start generating content right away!"
>
> **Word count:** 65
> **Tone:** Conversational, enthusiastic
> **Issues:** "Simply", "powerful", "in moments", "right away" - more words than needed

---

## 11. Root Cause Analysis

### Why Did OLD Work Better?

**The OLD system succeeded because it CONSTRAINED the AI heavily:**

1. **Tight word counts** → Forced brevity → Less room for marketing fluff
2. **Specific banned words** → AI knew exactly what to avoid
3. **Technical doc tone** → Clear genre definition
4. **Developer colleague** → Peer-to-peer voice, not teacher-to-student
5. **Temperature 0.5** → More deterministic, less creative variance
6. **Scene-specific prompts** → Optimized per use case

**The NEW system may struggle because it ALLOWS the AI more freedom:**

1. **Loose word counts** → AI can elaborate → More marketing language creeps in
2. **Generic "avoid jargon"** → Not specific enough
3. **"Engaging narrator"** → Encourages entertainment over education
4. **Default temperature** → More creative variance
5. **One-size-fits-all** → Compromises for all scenes

### The Paradox

**For technical content, LESS AI CREATIVITY = BETTER RESULTS**

- Technical docs need consistency, not creativity
- Educational videos need facts, not engagement tricks
- Developer audience prefers direct info over storytelling

**The OLD system understood this. The NEW system optimized for "natural-sounding narrator" which may produce more promotional content.**

---

## 12. Recommendations

### Immediate Fixes (Restore OLD Behavior)

**1. Restore Scene-Specific Prompts**
- Separate prompt templates for each scene type
- Don't try to make one prompt handle everything

**2. Restore Tight Word Counts**
- Title: 10 words
- Command: 15-20 words
- List: 15-20 words
- Outro: 10-15 words
- Code comparison: 12-18 words

**3. Restore Anti-Marketing Language**
```python
BANNED_WORDS = [
    "powerful", "amazing", "revolutionary", "game-changing",
    "transform", "unleash", "empower", "elevate",
    "journey", "explore", "discover", "instantly"
]

PROMPT_SUFFIX = """
Avoid these marketing words: {', '.join(BANNED_WORDS)}
Use instead: Direct descriptions, technical accuracy, factual benefits
"""
```

**4. Set Temperature to 0.5**
```python
response = client.messages.create(
    model="claude-sonnet-4-5-20250929",
    max_tokens=150,  # Lower from 500
    temperature=0.5,  # Add explicit temperature
    messages=[...]
)
```

**5. Restore "Developer Colleague" Persona**
```
Tone: Like explaining to a developer colleague, not performing for an audience.
```

### Keep NEW Additions That Work

**✅ Scene Position Awareness** - This is good! Keep it.
```python
if scene_number == 1:
    position_context = "This is the OPENING scene..."
```

**✅ Quality Validation** - Good safety net. Keep it.
```python
validation_result = self._validate_enhanced_script(enhanced, script)
```

**✅ Usage Metrics** - Helpful for monitoring. Keep it.
```python
self.metrics.record_call(...)
```

---

## 13. Implementation Strategy

### Phase 1: Restore OLD Prompts (1-2 hours)
1. Create `video_gen/script_generator/prompt_templates.py`
2. Port OLD prompts verbatim from 31e0299c
3. Add temperature=0.5 to all AI calls
4. Test with sample scenes

### Phase 2: Merge with NEW Features (1-2 hours)
1. Add scene position awareness to OLD prompts
2. Keep validation logic
3. Keep usage metrics
4. Test hybrid approach

### Phase 3: A/B Test (Optional)
1. Generate videos with OLD prompts
2. Generate videos with NEW prompts
3. Compare results
4. Gather user feedback

---

## 14. Key Takeaways

### For AI Prompts in Technical Content:

1. **CONSTRAINTS = QUALITY**
   - Tighter word counts produce better results
   - Specific banned words prevent marketing language
   - Lower temperature ensures consistency

2. **SPECIALIZATION > GENERALIZATION**
   - Scene-specific prompts outperform generic ones
   - Don't try to make one prompt do everything
   - Each scene type has unique requirements

3. **TECHNICAL ≠ ENGAGING**
   - For developer audiences, factual beats engaging
   - "Professional narrator" produces promotional content
   - "Developer colleague" produces technical content

4. **LESS CREATIVITY FOR DOCS**
   - Technical documentation needs consistency
   - Educational videos need predictability
   - Temperature 0.5 better than 1.0

5. **EXPLICIT > IMPLICIT**
   - List specific banned words
   - Give exact word counts
   - State tone repeatedly
   - AI needs explicit constraints for technical content

---

## 15. Conclusion

**The OLD system created videos "to spec" because:**

1. It constrained the AI with tight word counts (10-20 words)
2. It explicitly banned marketing language with specific examples
3. It used lower temperature (0.5) for consistency
4. It had scene-specific prompts, not generic ones
5. It emphasized "developer colleague" tone, not "professional narrator"

**The NEW system may produce less desirable results because:**

1. It allows 20-200 words (10-20x more room for fluff)
2. It only says "avoid jargon" (not specific)
3. It uses default temperature (more variance)
4. It tries to handle all scenes with one prompt
5. It emphasizes "engaging" over "factual"

**Recommendation:** Port the OLD prompts to the NEW system, keep the NEW features (position awareness, validation, metrics), and get the best of both worlds.

**Estimated Fix Time:** 2-4 hours
**Expected Improvement:** Videos match user specs more consistently
**Risk:** Low - OLD prompts are proven to work

---

**Next Step:** Would you like me to implement Phase 1 (restore OLD prompts) now?
