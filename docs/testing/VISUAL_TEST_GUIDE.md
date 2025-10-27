# 🎯 Visual Test Guide - Where to Find Everything

## Server Status
✅ Running at: **http://localhost:8000**

---

## 🔍 Step-by-Step Test Instructions

### Test 1: Multi-Voice Per Video

**Path**: Home → Create → Choose "Video Set" → Step 2

**What to look for**:

1. **Global Settings Section** (always visible):
   ```
   ⚙️ Video Settings
   ├─ 📊 Number of Videos: ●──── 3 videos
   ├─ Duration: 60s
   ├─ Narrator Voice: ▼ Andrew [🔊]  ← Preview button!
   ├─ AI Enhancement: [toggle]
   └─ Accent Color: ● ● ● ● ● ●
   ```

2. **Click "🎬 Customize Each Video"** (purple panel below global settings)
   - This expands to show ALL videos

3. **Inside expanded panel**:
   ```
   ❶ Video 1 of 3
   ├─ Video Title: [____________]
   ├─ 🎙️ Voice Tracks (1)  [+ Add Voice]  ← Click this!
   │  ├─ Track 1: ▼ Andrew [🔊] [×]
   │  └─ [When you click + Add Voice...]
   │     Track 2: ▼ Aria [🔊] [×]
   ├─ Duration Override: [____] seconds
   ```

4. **Click "+ Add Voice"** multiple times
   - You should be able to add up to 4 voice tracks
   - Each track has a [🔊] preview button
   - Each track has a [×] remove button

---

### Test 2: Per-Language Voice Selection

**Path**: Home → Create → Choose "Single Video" → Step 2

**What to look for**:

1. **Scroll down to "🌍 Multilingual Generation"**
2. **Toggle it ON** (switch should turn green)
3. **Panel expands to show**:
   ```
   Source Language: ▼ English

   Target Languages (1 selected)
   [EN+ES] [European] [Asian]  ← Quick presets

   ☐ EN  ☐ ES  ☐ FR  ☐ DE  ... (28+ checkboxes)

   Translation Method:
   ⭐ Claude API | Google Translate
   ```

4. **Click the "EN+ES" preset** (or check ES manually)
5. **NEW SECTION APPEARS** (scroll down):
   ```
   🎙️ Voice per Language
   ├─ EN  English    ▼ Andrew (Male)      [🔊]
   └─ ES  Español    ▼ Diego (Spanish)    [🔊]
   ```

6. **Click checkboxes** to select more languages (FR, DE, JA, etc.)
   - Each language gets its own row
   - Each language gets its own voice dropdown
   - Each has a 🔊 preview button

---

### Test 3: Voice Preview

**Any voice dropdown in the system**:

1. **Find any voice dropdown** (there are many):
   - Single video voice tracks
   - Set video voice tracks
   - Per-language voices
   - Global narrator voice

2. **Click the 🔊 button** next to the dropdown
   - Button should turn orange
   - You should hear: "Hello, this is a sample of this voice"
   - Button pulses while playing

3. **Try different voices**:
   - Andrew (Male) - Professional tone
   - Brandon (Male Warm) - Warmer tone
   - Aria (Female) - Clear female voice
   - Ava (Female Friendly) - Friendly female voice

---

### Test 4: Full Configuration Example

**Complete workflow to test everything**:

#### Step 1: Choose Type
1. Go to http://localhost:8000
2. Click "🎥 Quick Start"
3. Click "📚 Video Set" card

#### Step 2: Configure
1. **Content Source**: Select "📄 Document"
2. **Document Path**: Enter `inputs/Internet_Guide_README.md`

3. **Global Settings**:
   - Number of Videos: Set to **5**
   - Duration: Set to **90s**
   - Narrator Voice: Select "Brandon" and click 🔊
   - AI Enhancement: Toggle **ON**
   - Accent Color: Click **Purple**

4. **Click "🎬 Customize Each Video"** (expand it)

5. **For Video 1**:
   - Title: "Introduction"
   - Click "+ Add Voice" → Now you have 2 voices
   - Track 1: Andrew [click 🔊 to test]
   - Track 2: Aria [click 🔊 to test]
   - Duration: 60

6. **For Video 2**:
   - Title: "Core Concepts"
   - Click "+ Add Voice" twice → Now 3 voices
   - Track 1: Andrew
   - Track 2: Aria
   - Track 3: Brandon
   - Duration: 120

7. **For Video 3**: (leave defaults)

8. **Scroll to Multilingual** (green panel)
   - Toggle **ON**
   - Click "European" preset (EN, ES, FR, DE, IT)
   - **New section appears**: "🎙️ Voice per Language"
   - Set voices:
     - EN: Andrew
     - ES: Diego (Spanish)
     - FR: Pierre (French)
     - DE: Hans (German)
     - IT: Marco (Italian)
   - Click 🔊 on any to test
   - Translation: Claude AI

9. **Review Summary**:
   ```
   Videos: 5 videos
   Avg Duration: 90s
   Total Voice Tracks: 8 (across all videos)
   Languages: 5 langs

   ✓ AI Enhancement
   ✓ Multilingual
   ✓ Multi-voice in some videos

   Total videos to generate: 5 × 5 = 25 videos
   ```

10. **Click "Generate 5 Videos × 5 Languages"**
    - Should redirect to progress page
    - Shows pipeline stages
    - Shows per-video progress
    - Shows per-language progress

---

## 🐛 Troubleshooting

### "I don't see the Voice per Language section"
**Solution**:
1. Make sure multilingual toggle is **ON** (green)
2. Make sure you've selected at least 1 target language
3. Scroll down - it's below the language grid

### "I can't add multiple voice tracks"
**Solution**:
1. Make sure you're in "🎬 Customize Each Video" panel
2. Click the purple expand button if collapsed
3. Look for "+ Add Voice" button (blue or purple)
4. Max is 4 voices per video

### "🔊 Preview button doesn't work"
**Possible causes**:
1. Browser doesn't support Web Speech API (use Chrome/Edge/Firefox)
2. Voice preview script not loaded - check browser console
3. Try refreshing the page

### "The page looks broken"
**Solution**:
1. Hard refresh: Ctrl+Shift+R (or Cmd+Shift+R on Mac)
2. Clear browser cache
3. Check browser console for JavaScript errors

---

## ✅ What Should Work Now

**Multi-Voice**:
- ✅ Can add 1-4 voice tracks per video
- ✅ Can select different voices per track
- ✅ Can preview each voice with 🔊 button
- ✅ Works in both single and set modes
- ✅ Shows in summary

**Per-Language Voices**:
- ✅ Appears when multilingual is ON
- ✅ One dropdown per selected language
- ✅ Language-specific voice options
- ✅ Preview button for each language
- ✅ Auto-initializes defaults

**Video Count**:
- ✅ Slider visible for ALL input methods
- ✅ Shows "Can override auto-detect" for Document/YouTube/YAML
- ✅ Range: 1-20 videos
- ✅ Real-time video list updates

**Per-Video Settings**:
- ✅ Collapsible panel "🎬 Customize Each Video"
- ✅ Edit each video independently
- ✅ Custom titles
- ✅ Custom voice tracks
- ✅ Custom durations

---

## 📸 Where Everything Is Located

```
/create page (Step 2)

┌─────────────────────────────────────────┐
│ 📚 Video Set Configuration              │
├─────────────────────────────────────────┤
│ Content Source: [📄] [✍️] [📺] [📝]    │
│ Document Path: [_________________]      │
├─────────────────────────────────────────┤
│ ⚙️ Global Settings                      │
│   📊 Number of Videos: ●──── 5          │ ← ALWAYS VISIBLE
│   Duration: ●──── 90s                   │
│   Narrator: ▼ Andrew [🔊]               │ ← Global voice preview
│   AI: [ON]  Color: ● ● ● ●             │
├─────────────────────────────────────────┤
│ 🎬 Customize Each Video [Expand ▼]     │ ← CLICK TO OPEN
│ ┌───────────────────────────────────┐   │
│ │ ❶ Video 1 of 5                    │   │
│ │ Title: [___________]               │   │
│ │ 🎙️ Voice Tracks (2) [+ Add Voice] │   │ ← ADD MULTIPLE VOICES
│ │  Track 1: ▼ Andrew [🔊] [×]        │   │ ← PREVIEW & REMOVE
│ │  Track 2: ▼ Aria   [🔊] [×]        │   │
│ │ Duration: [60]                     │   │
│ ├───────────────────────────────────┤   │
│ │ ❷ Video 2 of 5                    │   │
│ │ (same structure...)               │   │
│ └───────────────────────────────────┘   │
├─────────────────────────────────────────┤
│ 🌍 Multilingual [Toggle ON]             │
│ ┌───────────────────────────────────┐   │
│ │ Source: ▼ English                 │   │
│ │ Targets: [EN] [ES] [FR] ...       │   │ ← SELECT LANGUAGES
│ │ Translation: ⭐ Claude | Google    │   │
│ │                                   │   │
│ │ 🎙️ Voice per Language             │   │ ← APPEARS WHEN LANGS SELECTED
│ │  EN English   ▼ Andrew  [🔊]       │   │
│ │  ES Español   ▼ Diego   [🔊]       │   │ ← ONE PER LANGUAGE
│ │  FR Français  ▼ Pierre  [🔊]       │   │
│ └───────────────────────────────────┘   │
├─────────────────────────────────────────┤
│ 📋 Generation Summary                   │
│   Videos: 5  Duration: 90s              │
│   Voice Tracks: 8  Languages: 3         │
│   Total: 5 × 3 = 15 videos              │
│                                         │
│ [📚 Generate 5 Videos × 3 Languages]    │
└─────────────────────────────────────────┘
```

---

## 🧪 Quick Tests

**Test A**: Voice Preview
1. Open any voice dropdown
2. Click 🔊 button
3. Should hear voice sample
4. Button turns orange while playing

**Test B**: Add Multiple Voices
1. Expand "🎬 Customize Each Video"
2. Click "+ Add Voice" on Video 1
3. Should see Track 2 appear
4. Max 4 tracks total

**Test C**: Per-Language Voices
1. Turn multilingual toggle ON (green)
2. Click "European" preset button
3. Scroll down
4. Should see "🎙️ Voice per Language" section
5. Should see 5 rows (EN, ES, FR, DE, IT)

---

## 🎬 Video Test

**Open browser console** (F12) and run:
```javascript
// Check if voice preview is loaded
console.log(window.voicePreview);  // Should show VoicePreview object

// Test voice manually
window.voicePreview.preview('male');  // Should speak
```

---

## 📊 Expected Results

If everything is working:

1. ✅ Voice per language section **visible** when multilingual ON
2. ✅ Can add up to **4 voice tracks** per video
3. ✅ All voice dropdowns have **🔊 preview buttons**
4. ✅ Clicking 🔊 **plays voice sample**
5. ✅ Video count slider **visible for all input methods**
6. ✅ Per-video panel **expands** to show all videos
7. ✅ Each video **fully customizable** (title, voices, duration)

---

**Refresh your browser** (Ctrl+Shift+R) and follow this guide! 🚀
