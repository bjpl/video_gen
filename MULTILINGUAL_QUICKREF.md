# Multilingual Video Generation - Quick Reference

**Fast lookup for multilingual features**

**KEY FEATURE: Bidirectional translation - ANY language → ANY language!**

---

## ⚡ Quick Start

### **English → Spanish + French:**
```bash
python generate_multilingual_set.py --source README.md --languages en es fr
```

### **Spanish → English (REVERSE!):**
```bash
python generate_multilingual_set.py --source README_ES.md --languages es en --source-lang es
```

### **From GitHub:**
```bash
python generate_multilingual_set.py --github https://github.com/user/repo --languages en es fr de
```

### **Programmatically:**
```python
from scripts.multilingual_builder import MultilingualVideoSet

# English → Spanish
ml = MultilingualVideoSet("demo", "Demo", languages=['en', 'es'], source_language='en')

# Spanish → English (REVERSE!)
ml = MultilingualVideoSet("demo", "Demo", languages=['es', 'en'], source_language='es')

ml.add_video_source(video_id='intro', title='Intro', scenes=[...])
await ml.auto_translate_and_export()
```

---

## 🌐 Supported Languages

| Code | Language | Code | Language | Code | Language |
|------|----------|------|----------|------|----------|
| **en** | English | **es** | Spanish | **fr** | French |
| **de** | German | **pt** | Portuguese | **it** | Italian |
| **ja** | Japanese | **zh** | Chinese | **ko** | Korean |
| **ar** | Arabic | **hi** | Hindi | **ru** | Russian |
| **nl** | Dutch | **pl** | Polish | **sv** | Swedish |
| **tr** | Turkish | **th** | Thai | **vi** | Vietnamese |

**28+ languages total** • `python generate_multilingual_set.py --list-languages`

---

## 📋 Common Commands

```bash
# List languages
python generate_multilingual_set.py --list-languages

# English → Spanish + French
python generate_multilingual_set.py --source FILE.md --languages en es fr

# Spanish → English (REVERSE!)
python generate_multilingual_set.py --source FILE_ES.md --languages es en --source-lang es

# French → English + Spanish
python generate_multilingual_set.py --source FILE_FR.md --languages fr en es --source-lang fr

# From GitHub
python generate_multilingual_set.py --github URL --languages en es fr de

# From YouTube
python generate_multilingual_set.py --youtube URL --languages en es --duration 60

# Specify source language (default: en)
--source-lang es  # Spanish source
--source-lang fr  # French source
--source-lang ja  # Japanese source

# Specify translation method
--method claude  # High quality (requires API key)
--method google  # Free fallback

# Generate all multilingual sets
python generate_all_sets.py

# Render all languages
python generate_videos_from_set.py --all
```

---

## 🐍 Python API

### **Create Multilingual Set**

```python
from scripts.multilingual_builder import MultilingualVideoSet

ml = MultilingualVideoSet(
    base_id="tutorial",
    base_name="Tutorial",
    languages=['en', 'es', 'fr']
)
```

### **Add Source Content**

```python
ml.add_video_source(
    video_id='intro',
    title='Introduction',
    description='Getting started',
    scenes=[{...}, {...}]
)
```

### **Auto-Translate & Export**

```python
paths = await ml.auto_translate_and_export()
# Returns: {'en': 'sets/tutorial_en', 'es': 'sets/tutorial_es', ...}
```

### **Manual Translation**

```python
ml.add_video_manual(
    lang='es',
    video_id='intro',
    title='Introducción',
    description='Comenzando',
    scenes=[...]
)
```

---

## 🎙️ Voice Selection

```python
from scripts.language_config import get_voice_for_language

# Default voice
voice = get_voice_for_language('es', 'male')

# Regional variant
voice_mx = get_voice_for_language('es', 'female', variant='mx')
voice_ar = get_voice_for_language('es', 'male', variant='ar')

# French variants
voice_fr = get_voice_for_language('fr', 'female')
voice_ca = get_voice_for_language('fr', 'male', variant='ca')
```

---

## 🔀 Translation Methods

| Method | Quality | Cost | Speed |
|--------|---------|------|-------|
| **Claude** | ⭐⭐⭐⭐⭐ | ~$0.01/video | ~15s/language |
| **Google** | ⭐⭐⭐ | Free | ~3s/language |
| **Manual** | ⭐⭐⭐⭐⭐ | Time | Varies |

---

## 📁 Output Structure

```
sets/
├── tutorial_en/
├── tutorial_es/
├── tutorial_fr/
└── ...

output/
├── tutorial_en/videos/
├── tutorial_es/videos/
└── ...
```

---

## 💡 Common Patterns

### **Bilingual EN/ES**
```python
languages=['en', 'es']
```

### **European Markets**
```python
languages=['en', 'es', 'fr', 'de', 'it']
```

### **Global Reach**
```python
languages=['en', 'es', 'fr', 'de', 'pt', 'it', 'ja', 'zh', 'ko', 'ar']
```

### **Regional Spanish**
```python
# Spain
variant='es'

# Mexico
variant='mx'

# Argentina
variant='ar'
```

---

## 🎯 Quick Examples

### **Parse & Translate:**
```bash
python generate_multilingual_set.py --source README.md --languages en es fr
```

### **GitHub → 5 Languages:**
```python
await generate_from_github(
    'https://github.com/django/django',
    languages=['en', 'es', 'fr', 'de', 'pt']
)
```

### **Manual Bilingual:**
```python
ml.add_video_manual('en', 'intro', 'Title', 'Desc', [scenes_en])
ml.add_video_manual('es', 'intro', 'Título', 'Desc', [scenes_es])
```

---

## 🔧 Configuration

### **Set API Key:**
```bash
export ANTHROPIC_API_KEY="sk-ant-api03-..."
```

### **Translation Cache:**
```
.translation_cache/
└── {hash}.json  # Auto-cached
```

---

## 📊 Language Codes

**Common codes:**
- `en` - English
- `es` - Spanish
- `fr` - French
- `de` - German
- `pt` - Portuguese
- `it` - Italian
- `ja` - Japanese
- `zh` - Chinese
- `ko` - Korean

**Full list:** `python generate_multilingual_set.py --list-languages`

---

## ✅ Checklist

**To generate multilingual videos:**

- [ ] Choose source (markdown, GitHub, YouTube)
- [ ] Select target languages
- [ ] Set API key (for Claude) or use Google Translate
- [ ] Run multilingual generator
- [ ] Generate audio with `generate_all_sets.py`
- [ ] Render videos with `generate_videos_from_set.py --all`
- [ ] Distribute language-specific videos!

---

**🌍 Generate professional videos in 28+ languages!**

See `MULTILINGUAL_GUIDE.md` for complete documentation.

---

## 🔄 Bidirectional Translation

### **ANY → ANY Language**

```bash
# English → Spanish
--source-lang en --languages en es

# Spanish → English
--source-lang es --languages es en

# French → English + Spanish
--source-lang fr --languages fr en es

# Japanese → English + Chinese + Korean
--source-lang ja --languages ja en zh ko

# German → All European
--source-lang de --languages de en fr es it nl
```

**All 28+ languages work as source OR target!**

---

## 💡 Common Patterns

### **European Markets**
```python
# English content → European languages
languages=['en', 'es', 'fr', 'de', 'it']

# German content → European languages
source_language='de'
languages=['de', 'en', 'fr', 'es', 'it']
```

### **Asian Markets**
```python
# English → Asian languages
languages=['en', 'ja', 'zh', 'ko']

# Japanese → Asian + English
source_language='ja'
languages=['ja', 'en', 'zh', 'ko']
```

### **Latin America**
```python
# Spanish (Mexico) → EN + PT
source_language='es'
languages=['es', 'en', 'pt']
```

---

## ✅ Bidirectional Examples

```python
# Spanish → English
ml = MultilingualVideoSet(..., source_language='es', languages=['es', 'en'])

# French → Multiple
ml = MultilingualVideoSet(..., source_language='fr', languages=['fr', 'en', 'es', 'de'])

# Japanese → Western
ml = MultilingualVideoSet(..., source_language='ja', languages=['ja', 'en', 'es', 'fr'])
```

**See:** `scripts/examples/reverse_translation_examples.py`

