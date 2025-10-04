# 🎙️ Voice System - Complete Guide

**Four Professional Neural TTS Voices Available**

---

## 🎯 Voice Options (Updated)

### **You Now Have: 4 Voices** ✅

| Voice Key | Voice ID | Gender | Style | Best For |
|-----------|----------|--------|-------|----------|
| **`male`** | en-US-AndrewMultilingualNeural | Male | Professional, confident | Technical tutorials, formal content |
| **`male_warm`** 🆕 | en-US-BrandonMultilingualNeural | Male | Warm, engaging | Marketing, friendly content, social media |
| **`female`** | en-US-AriaNeural | Female | Clear, crisp | Educational content, documentation, tutorials |
| **`female_friendly`** 🆕 | en-US-AvaMultilingualNeural | Female | Friendly, pleasant | Onboarding, help content, welcoming videos |

---

## 🎬 How to Use Multiple Voices

### **Pattern 1: Single Voice (Consistency)**

```yaml
video:
  voice: male  # Andrew for entire video

scenes:
  - type: title
    # Uses male (Andrew)
  - type: command
    # Uses male (Andrew)
  - type: outro
    # Uses male (Andrew)
```

**Best for:** Short videos, professional consistency

---

### **Pattern 2: Alternating Male/Female (Variety)**

```yaml
video:
  voice: male  # Default

scenes:
  - type: title
    voice: male      # Andrew introduces

  - type: command
    voice: female    # Aria explains

  - type: list
    voice: male      # Andrew lists features

  - type: quote
    voice: female    # Aria emphasizes principle

  - type: outro
    voice: male      # Andrew closes
```

**Best for:** Longer videos (60s+), maintaining engagement

---

### **Pattern 3: Professional/Casual Mix**

```yaml
video:
  voice: male  # Professional default

scenes:
  - type: title
    voice: male          # Andrew - formal intro

  - type: command
    voice: male          # Andrew - technical content

  - type: quote
    voice: male_warm     # Brandon - inspirational quote

  - type: list
    voice: female_friendly  # Ava - friendly tips

  - type: outro
    voice: male          # Andrew - professional close
```

**Best for:** Balancing technical and approachable tones

---

### **Pattern 4: All Four Voices (Maximum Variety)**

```yaml
scenes:
  - type: title
    voice: male              # Andrew - formal intro

  - type: command
    voice: female            # Aria - clear technical

  - type: code_comparison
    voice: male_warm         # Brandon - friendly explanation

  - type: quote
    voice: female_friendly   # Ava - warm inspiration

  - type: list
    voice: female            # Aria - organized info

  - type: outro
    voice: male              # Andrew - professional close
```

**Best for:** Long video series (10-15 videos), maximizing variety

---

## 📋 Voice Selection Decision Tree

```
START: What's your content?
│
├─ Technical Tutorial / API Docs?
│  └─> Use: male (Andrew) or female (Aria)
│      Why: Professional, clear delivery
│
├─ Marketing / Product Demo?
│  └─> Use: male_warm (Brandon) or female_friendly (Ava)
│      Why: Warm, engaging, approachable
│
├─ Mixed (Technical + Marketing)?
│  └─> Use: Alternate
│      Technical sections: male or female
│      Marketing sections: male_warm or female_friendly
│
├─ Long Video (90s+)?
│  └─> Use: Alternating voices
│      Prevents monotony, maintains engagement
│
└─ Video Series (10-15 videos)?
   └─> Use: Consistent voice per video, vary across series
       Video 1-3: male
       Video 4-6: female
       Video 7-9: male_warm
       Video 10-12: female_friendly
```

---

## 🎨 Voice Characteristics

### **Andrew (male) - The Professional**

**Voice ID:** `en-US-AndrewMultilingualNeural`

**Characteristics:**
- Tone: Confident, authoritative
- Pacing: Moderate to fast
- Clarity: Excellent
- Warmth: Medium

**Best For:**
✅ Technical documentation
✅ Software tutorials
✅ API references
✅ Professional demos
✅ Formal presentations

**Example Narration:**
> "File operations in Claude Code provide precise control over your codebase. Execute read, write, and edit commands with intelligent context awareness."

---

### **Brandon (male_warm) - The Engager** 🆕

**Voice ID:** `en-US-BrandonMultilingualNeural`

**Characteristics:**
- Tone: Warm, friendly
- Pacing: Moderate
- Clarity: Excellent
- Warmth: High

**Best For:**
✅ Marketing content
✅ Product introductions
✅ Social media videos
✅ Community content
✅ Inspirational messages

**Example Narration:**
> "Hey there! Let's explore how Claude Code can transform your development workflow. You're going to love these features!"

---

### **Aria (female) - The Educator**

**Voice ID:** `en-US-AriaNeural`

**Characteristics:**
- Tone: Clear, articulate
- Pacing: Moderate
- Clarity: Excellent (best for complex topics)
- Warmth: Medium-high

**Best For:**
✅ Educational content
✅ Step-by-step tutorials
✅ Complex explanations
✅ Technical documentation
✅ Training videos

**Example Narration:**
> "Understanding asynchronous programming requires grasping three key concepts. Event loops, coroutines, and task scheduling work together seamlessly."

---

### **Ava (female_friendly) - The Guide** 🆕

**Voice ID:** `en-US-AvaMultilingualNeural`

**Characteristics:**
- Tone: Friendly, caring
- Pacing: Slightly slower (patient)
- Clarity: Excellent
- Warmth: Very high

**Best For:**
✅ Onboarding videos
✅ Help content
✅ Beginner tutorials
✅ Welcome messages
✅ Empathetic content

**Example Narration:**
> "Don't worry if this seems confusing at first. We'll walk through each step together, and you'll be creating amazing projects in no time!"

---

## 💡 Voice Mixing Strategies

### **Strategy 1: Consistent Single Voice**

```yaml
voice: male  # Andrew throughout
```

**Pros:**
- ✅ Recognizable brand voice
- ✅ Professional consistency
- ✅ Simple to configure

**Cons:**
- ⚠️ Can feel monotonous in long videos

**Best for:** Short videos (30-60s), professional content

---

### **Strategy 2: Gender Alternation**

```yaml
scenes:
  - voice: male     # Andrew
  - voice: female   # Aria
  - voice: male     # Andrew
  - voice: female   # Aria
```

**Pros:**
- ✅ Variety maintains engagement
- ✅ Clear distinction between sections
- ✅ Professional balance

**Cons:**
- ⚠️ Pattern might feel formulaic

**Best for:** Medium videos (60-90s), educational content

---

### **Strategy 3: Role-Based Voices**

```yaml
scenes:
  - type: title
    voice: male              # Andrew - formal opening

  - type: command
    voice: female            # Aria - clear technical

  - type: quote
    voice: male_warm         # Brandon - inspirational

  - type: list
    voice: female_friendly   # Ava - friendly tips

  - type: outro
    voice: male              # Andrew - professional close
```

**Pros:**
- ✅ Voice matches content type
- ✅ Maximum variety
- ✅ Engaging throughout

**Cons:**
- ⚠️ More complex to configure
- ⚠️ Can feel disjointed if overused

**Best for:** Long videos (90-120s), mixed content types

---

### **Strategy 4: Series Consistency**

```yaml
# Video 1-3: Andrew (technical)
# Video 4-6: Aria (educational)
# Video 7-9: Brandon (friendly)
# Video 10-12: Ava (welcoming)
```

**Pros:**
- ✅ Consistency within video
- ✅ Variety across series
- ✅ Viewer can recognize content type by voice

**Cons:**
- ⚠️ Requires planning across series

**Best for:** Video series (10-15 videos)

---

## 🚀 Updated Usage Examples

### **Example 1: Technical Tutorial (Single Voice)**

```yaml
video:
  title: "API Documentation"
  voice: male  # Andrew - professional throughout

scenes:
  - type: title
  - type: command
  - type: list
  - type: outro
  # All use Andrew (male) - consistent, professional
```

---

### **Example 2: Learning Video (Alternating)**

```yaml
video:
  title: "Python Decorators"
  voice: male  # Default

scenes:
  - type: title
    voice: male      # Andrew intro

  - type: command
    voice: female    # Aria explains

  - type: code_comparison
    voice: male      # Andrew shows code

  - type: quote
    voice: female    # Aria emphasizes

  - type: outro
    voice: male      # Andrew closes

  # Alternates for engagement
```

---

### **Example 3: Welcoming Onboarding (All Four Voices)**

```yaml
video:
  title: "Welcome to Our Platform"
  voice: female_friendly  # Ava - friendly default

scenes:
  - type: title
    voice: female_friendly  # Ava - warm welcome

  - type: list
    voice: female          # Aria - clear features

  - type: command
    voice: male_warm       # Brandon - engaging demo

  - type: quote
    voice: male            # Andrew - professional principle

  - type: outro
    voice: female_friendly # Ava - friendly farewell

  # Mix professional and warm tones
```

---

## 📊 Voice Usage Recommendations

### **By Video Length:**

| Duration | Recommendation | Voices |
|----------|----------------|--------|
| **30s** | Single voice | 1 voice |
| **60s** | Single or alternating | 1-2 voices |
| **90s** | Alternating | 2 voices |
| **120s+** | Multiple voices | 2-4 voices |

### **By Content Type:**

| Content Type | Primary Voice | Secondary Voice |
|--------------|---------------|-----------------|
| **Technical Docs** | male (Andrew) | female (Aria) |
| **Tutorials** | female (Aria) | male (Andrew) |
| **Marketing** | male_warm (Brandon) | female_friendly (Ava) |
| **Onboarding** | female_friendly (Ava) | male_warm (Brandon) |
| **Best Practices** | male (Andrew) | female (Aria) |
| **Troubleshooting** | female (Aria) | male (Andrew) |

---

## ✅ Testing All Four Voices

```bash
# Generate example with all 4 voices
cd projects/claude_code_demos/scripts
python generate_script_from_yaml.py ../inputs/example_four_voices.yaml

# Check generated script
cat drafts/voice_variety_demo_SCRIPT_*.md

# Should show different voices per scene:
# Scene 1: male (Andrew)
# Scene 2: male_warm (Brandon)
# Scene 3: female (Aria)
# Scene 4: female_friendly (Ava)
# Scene 5: male (Andrew)
```

---

## 🎯 Final Answer to Your Question

### **"Do we still have multiple voices or just one?"**

# ✅ **You Have FOUR Voices with Per-Scene Control**

**Current state:**
- ✅ 4 professional neural voices (Andrew, Brandon, Aria, Ava)
- ✅ Per-scene selection (set in YAML per scene)
- ✅ Default voice per video (with scene overrides)
- ✅ Full flexibility (mix any pattern)

**How to use:**

```yaml
# Choose per scene:
scenes:
  - voice: male              # Andrew
  - voice: male_warm         # Brandon
  - voice: female            # Aria
  - voice: female_friendly   # Ava
```

**Examples:**
- Single voice: All scenes same voice
- Alternating: Male/female pattern
- Role-based: Match voice to content type
- Maximum variety: Use all 4 voices

**Flexibility Rating:** ⭐⭐⭐⭐⭐ **Excellent**

---

*Voice System - Updated 2025-10-03*
*Voices: 4 (Andrew, Brandon, Aria, Ava)*
*Control: Per-scene YAML configuration*
*Status: ✅ Fully Flexible*
