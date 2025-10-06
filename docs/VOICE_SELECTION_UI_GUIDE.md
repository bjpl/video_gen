# Per-Language Voice Selection - User Guide

## Visual Layout

```
┌─────────────────────────────────────────────────────────────────┐
│ 🌍 Multilingual Generation                              [ON]    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ Source Language: English (English) ▼                            │
│                                                                 │
│ Target Languages (3 selected)                                  │
│ ┌─────────────────────────────────────────────────────────────┐│
│ │ [EN+ES] [European] [Asian]                                  ││
│ │                                                             ││
│ │ ☑ EN  ☑ ES  ☑ FR  ☐ DE  ☐ IT  ☐ PT                        ││
│ │ ☐ JA  ☐ ZH  ☐ KO  ☐ AR  ☐ HI  ☐ RU                        ││
│ └─────────────────────────────────────────────────────────────┘│
│                                                                 │
│ Translation Method                                              │
│ ┌──────────────────────────┬──────────────────────────┐        │
│ │ [✓] ⭐ Claude API         │ [ ] Google Translate      │        │
│ │     High quality          │     Free & fast           │        │
│ └──────────────────────────┴──────────────────────────┘        │
│                                                                 │
│ 🎙️ Voice per Language                                          │
│ ┌─────────────────────────────────────────────────────────────┐│
│ │ ┌─────────────────────────────────────────────────────────┐││
│ │ │ EN  English    Andrew (Male) - Professional      ▼      │││
│ │ └─────────────────────────────────────────────────────────┘││
│ │ ┌─────────────────────────────────────────────────────────┐││
│ │ │ ES  Spanish    Diego (Spanish Male)              ▼      │││
│ │ └─────────────────────────────────────────────────────────┘││
│ │ ┌─────────────────────────────────────────────────────────┐││
│ │ │ FR  French     Pierre (French Male)              ▼      │││
│ │ └─────────────────────────────────────────────────────────┘││
│ └─────────────────────────────────────────────────────────────┘│
│ 💡 Each language can have a unique voice for natural           │
│    localization                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Interaction Flow

### Step 1: Enable Multilingual
```
User toggles [🌍 Multilingual Generation] switch
↓
Multilingual panel expands
↓
Default: Source=EN, Target=[EN], Method=Claude
↓
Voice per Language section shows EN with default voice
```

### Step 2: Select Target Languages

**Option A: Use Preset**
```
User clicks [EN+ES] button
↓
Target languages update to ['en', 'es']
↓
Auto-initialize voices:
  EN → 'male' (Andrew)
  ES → 'male_spanish' (Diego)
```

**Option B: Manual Selection**
```
User checks FR checkbox
↓
FR added to targetLanguages
↓
Auto-initialize: FR → 'male_french' (Pierre)
↓
Voice per Language section updates:
  Shows EN, ES, FR rows
```

### Step 3: Customize Voices (Optional)

```
User opens ES dropdown
↓
Sees available Spanish voices:
  - Diego (Spanish Male)    ← currently selected
  - Maria (Spanish Female)
↓
User selects Maria
↓
State updates: languageVoices.es = 'female_spanish'
↓
Summary updates: "3 unique voices"
```

## Voice Options by Language

### English (en)
- Andrew (Male) - Professional
- Brandon (Warm) - Engaging
- Aria (Female) - Clear
- Ava (Friendly) - Pleasant

### Spanish (es)
- Diego (Spanish Male)
- Maria (Spanish Female)

### French (fr)
- Pierre (French Male)
- Claire (French Female)

### German (de)
- Hans (German Male)
- Anna (German Female)

### Italian (it)
- Marco (Italian Male)
- Sofia (Italian Female)

### Portuguese (pt)
- João (Portuguese Male)
- Ana (Portuguese Female)

### Japanese (ja)
- Takumi (Japanese Male)
- Sakura (Japanese Female)

### Chinese (zh)
- Wei (Chinese Male)
- Li (Chinese Female)

### Korean (ko)
- Min-jun (Korean Male)
- Seo-yeon (Korean Female)

### Arabic (ar)
- Ahmed (Arabic Male)
- Fatima (Arabic Female)

### Hindi (hi)
- Raj (Hindi Male)
- Priya (Hindi Female)

### Russian (ru)
- Dmitri (Russian Male)
- Natasha (Russian Female)

## Examples

### Example 1: Simple Bilingual
```yaml
Configuration:
  Target Languages: [EN, ES]
  Voices:
    EN: male (Andrew)
    ES: male_spanish (Diego)

Result: 2 videos
  - video_en.mp4 (Andrew narrating)
  - video_es.mp4 (Diego narrating)
```

### Example 2: European Market
```yaml
Configuration:
  Target Languages: [EN, ES, FR, DE, IT]
  Voices:
    EN: male (Andrew)
    ES: female_spanish (Maria)
    FR: female_french (Claire)
    DE: female_german (Anna)
    IT: female_italian (Sofia)

Result: 5 videos
  - All with female voices for consistency
  - Each in native language with native voice
```

### Example 3: Global Campaign
```yaml
Configuration:
  Target Languages: [EN, ES, FR, JA, ZH, KO]
  Voices:
    EN: male_warm (Brandon)
    ES: male_spanish (Diego)
    FR: male_french (Pierre)
    JA: male_japanese (Takumi)
    ZH: male_chinese (Wei)
    KO: male_korean (Min-jun)

Result: 6 videos
  - All with male voices
  - Each culturally appropriate
  - Consistent professional tone
```

## UI States

### Empty State
```
No languages selected
Voice per Language section: Hidden
```

### Default State
```
1 language (EN) selected
Voice per Language section:
  EN | English | Andrew (Male) - Professional ▼
```

### Multi-Language State
```
3+ languages selected
Voice per Language section:
  [Scrollable list of language-voice pairs]
  Shows up to 264px height, then scrolls
```

### Generation Summary
```
Languages: 3 languages
✓ Multilingual
✓ 3 unique voices
```

## Keyboard Navigation

- **Tab**: Move between language dropdowns
- **Enter/Space**: Open dropdown
- **Arrow Up/Down**: Navigate voice options
- **Enter**: Select voice
- **Esc**: Close dropdown

## Responsive Behavior

### Desktop (>768px)
- Full 3-column layout
- All controls visible
- No scrolling needed for <10 languages

### Tablet (768px)
- 2-column layout
- Dropdowns remain full width
- Scroll container appears at 5+ languages

### Mobile (<640px)
- Single column
- Stacked language rows
- Touch-friendly tap targets (44px minimum)

## Accessibility

- ✅ ARIA labels on all controls
- ✅ Keyboard navigation support
- ✅ Focus indicators
- ✅ Screen reader friendly
- ✅ High contrast mode compatible
- ✅ Language names in both English and native

## Tips for Users

1. **Use Presets**: Faster than manual selection
   - EN+ES for bilingual content
   - European for EU market
   - Asian for APAC region

2. **Voice Consistency**:
   - Use all male or all female voices for professional consistency
   - Mix voices for variety in course content

3. **Cultural Matching**:
   - Default voices are culturally appropriate
   - Choose based on target audience preference

4. **Testing**:
   - Generate with 1-2 languages first
   - Verify voice quality before scaling to 10+ languages

5. **Performance**:
   - Each language = 1 additional video
   - EN+ES+FR = 3 videos generated
   - Plan processing time accordingly

## Troubleshooting

**Q: Voice dropdown is empty**
A: Unsupported language detected. System falls back to English voices.

**Q: Can't change voice**
A: Ensure multilingual mode is enabled and language is selected.

**Q: Voices don't match summary**
A: Check that languageVoices object is populated. Refresh page if needed.

**Q: Too many languages, can't scroll**
A: Use search/filter if available. Max height is 264px with auto-scroll.
