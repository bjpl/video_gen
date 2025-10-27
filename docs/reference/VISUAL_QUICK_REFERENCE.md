# Visual Quick Reference - Video Generation Workflows

**One-page visual guide to all video generation approaches**

---

## 🎯 Decision Matrix: Choose Your Workflow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    WHAT DO YOU HAVE? → CHOOSE WORKFLOW                  │
└─────────────────────────────────────────────────────────────────────────┘

YOUR INPUT              METHOD              TIME        CODE         OUTPUT
═══════════════════════════════════════════════════════════════════════════

📄 README.md           Parse Document      1 sec       1 line       ✅ Video
   ↓                   ↓                   ↓           ↓            ↓
   parse_document_to_set('README.md')      Instant     Zero effort  Ready!

🔗 GitHub URL          Parse GitHub        2 sec       2 lines      ✅ Video
   ↓                   ↓                   ↓           ↓            ↓
   github_readme_to_video(url).export()    Fast        Minimal      Ready!

🎥 YouTube URL         Parse YouTube       5 sec       2 lines      ✅ Summary
   ↓                   ↓                   ↓           ↓            ↓
   parse_youtube_to_set(url)               Quick       Easy         60-sec!

💾 Database            Build Programmatic  5 min       20-50 lines  ✅ Series
   ↓                   ↓                   ↓           ↓            ↓
   VideoSetBuilder + loop                  Medium      Full control 100s!

🌍 Translation         Multilingual        15 sec      3 lines      ✅ N langs
   ↓                   ↓                   ↓           ↓            ↓
   MultilingualVideoSet().auto_translate   Fast        Automatic    28+ langs!
```

---

## 📊 Workflow Comparison

| Workflow | Speed | Effort | Control | Best For |
|----------|-------|--------|---------|----------|
| **Parse Markdown** | ⚡⚡⚡ Instant | ⭐ Minimal | ⭐⭐⭐ Medium | Existing docs |
| **Parse GitHub** | ⚡⚡ Fast | ⭐ Minimal | ⭐⭐⭐ Medium | Public repos |
| **Parse YouTube** | ⚡⚡ Fast | ⭐ Minimal | ⭐⭐ Basic | Video summaries |
| **Build Programmatic** | ⚡ Medium | ⭐⭐⭐ High | ⭐⭐⭐⭐⭐ Full | Data/API |
| **Multilingual** | ⚡⚡ Fast | ⭐ Minimal | ⭐⭐⭐⭐ High | Global content |

---

## 🚀 5-Second Decision Guide

```
┌─────────────────────────────────────────────────────────┐
│  I HAVE...                    → USE THIS WORKFLOW       │
└─────────────────────────────────────────────────────────┘

📝 Markdown file                → parse_document_to_set()
   "Just parse my README!"         ✓ Zero config
                                   ✓ 1 line code
                                   ✓ Done in seconds

🌐 GitHub repository            → github_readme_to_video()
   "Turn repo into video!"         ✓ No download
                                   ✓ Auto-fetch
                                   ✓ Latest version

🎬 YouTube video                → parse_youtube_to_set()
   "Make a summary!"               ✓ Auto transcript
                                   ✓ Key points
                                   ✓ 60-sec output

🗃️ Database records             → VideoSetBuilder()
   "Generate from data!"           ✓ Loop records
                                   ✓ Template-based
                                   ✓ Batch generate

🌍 Need other languages         → MultilingualVideoSet()
   "Global audience!"              ✓ Auto-translate
                                   ✓ 28+ languages
                                   ✓ Native voices
```

---

## 📋 Code Templates

### **Template 1: Markdown → Video (Fastest)**

```python
# ONE LINE TO VIDEO
from scripts.document_to_programmatic import parse_document_to_set

parse_document_to_set('README.md')
# Done! Sets exported to sets/readme/

# Then generate:
# cd scripts
# python generate_video_set.py ../sets/readme
# python generate_videos_from_set.py ../output/readme
```

**Result:** Video in ~5 minutes, zero manual work

---

### **Template 2: GitHub → Video**

```python
# GITHUB TO VIDEO
from scripts.document_to_programmatic import github_readme_to_video

github_readme_to_video('https://github.com/fastapi/fastapi') \
    .export_to_yaml('sets/fastapi')

# Then generate (same as above)
```

**Result:** Any public repo → professional video

---

### **Template 3: YouTube → Summary**

```python
# YOUTUBE TO SUMMARY
from scripts.youtube_to_programmatic import parse_youtube_to_set

parse_youtube_to_set(
    'https://youtube.com/watch?v=VIDEO_ID',
    target_duration=60  # Condense to 60 seconds
)

# Then generate (same commands)
```

**Result:** 30-min video → 60-sec summary

---

### **Template 4: Database → Video Series**

```python
# DATABASE TO VIDEOS
from scripts.python_set_builder import VideoSetBuilder
import sqlite3

conn = sqlite3.connect('data.db')
cursor = conn.execute('SELECT * FROM products')

builder = VideoSetBuilder("products", "Product Catalog")

for row in cursor:
    builder.add_video(
        video_id=f"product_{row[0]}",
        title=row[1],
        scenes=[
            builder.create_title_scene(row[1], row[2]),
            builder.create_list_scene("Features", "What You Get", [
                (f['name'], f['desc']) for f in row[3]
            ]),
            builder.create_outro_scene("Try It", row[4])
        ]
    )

builder.export_to_yaml('sets/products')
```

**Result:** Every database record → video

---

### **Template 5: English → Multiple Languages**

```python
# MULTILINGUAL EXPANSION
from scripts.multilingual_builder import MultilingualVideoSet

ml = MultilingualVideoSet(
    base_id="tutorial",
    base_name="Tutorial",
    languages=['en', 'es', 'fr', 'de', 'pt']  # 5 languages!
)

# Add English content
ml.add_video_source(
    video_id='intro',
    title='Introduction',
    description='Getting Started',
    scenes=[...]  # English scenes
)

# Auto-translate to all languages
await ml.auto_translate_and_export()

# Result: 5 language versions!
```

**Result:** 1 English video → 5 languages automatically

---

## 🎨 Visual Workflow Patterns

### **Pattern 1: Single Video (Quick)**

```
Input File → Parse → Export → Generate → Video
  (1 sec)     (auto)   (auto)   (5 min)   (done!)
```

### **Pattern 2: Video Set (Programmatic)**

```
Data Source → Loop → Build → Export → Generate → Videos
 (query)      (code)  (scenes) (YAML)   (batch)   (series!)
```

### **Pattern 3: Multilingual (Global)**

```
1 English → Translate → N Languages → Generate → N Videos
  (source)   (Claude)    (auto)        (batch)    (global!)
```

### **Pattern 4: Hybrid (Best Practice)**

```
Parse → Customize → Export → Generate → Enhanced Video
(auto)   (manual)    (YAML)   (render)   (perfect!)
```

---

## 🔧 Troubleshooting Quick Checks

### **✅ Pre-Flight Checklist**

```
Before parsing:
□ File exists and readable (ls README.md)
□ Valid markdown (H1, H2, code blocks)
□ UTF-8 encoding (file README.md)

Before building:
□ Data source accessible
□ Import paths correct
□ VideoSetBuilder imported

Before translating:
□ ANTHROPIC_API_KEY set (Claude)
□ Languages supported (28+ available)
□ Source language defined

Before generating:
□ YAML files in sets/
□ TTS configured (Azure)
□ Disk space available (1GB+)
```

### **🐛 Quick Fixes**

```
Problem                     Fix
═════════════════════════════════════════════════
Parse fails                → Check file encoding (UTF-8)
GitHub 404                 → Verify URL format
No narration               → Add narration param OR omit for auto
Export fails               → Check directory exists
Translation slow           → Use Google (free) for testing
Video silent               → Check TTS credentials
```

---

## 📈 Success Metrics

### **Expected Performance:**

| Operation | Time | Lines of Code | Output Quality |
|-----------|------|---------------|----------------|
| Parse markdown | 1-2 sec | 1 | ⭐⭐⭐⭐ Good |
| Parse GitHub | 2-3 sec | 2 | ⭐⭐⭐⭐ Good |
| Parse YouTube | 5-10 sec | 2 | ⭐⭐⭐ Summary |
| Build programmatic | 5-10 min | 20-50 | ⭐⭐⭐⭐⭐ Perfect |
| Translate (Claude) | 2-3 sec/scene | 3 | ⭐⭐⭐⭐⭐ Excellent |
| Translate (Google) | 0.5 sec/scene | 3 | ⭐⭐⭐ Good |
| Generate video | 5 min | N/A | ⭐⭐⭐⭐⭐ Professional |

---

## 🎯 Use Case Selector

```
┌─────────────────────────────────────────────────────────┐
│  MY GOAL...                   → RECOMMENDED WORKFLOW    │
└─────────────────────────────────────────────────────────┘

"Turn docs into video"        → Parse markdown/GitHub
                                 ✓ Fastest
                                 ✓ Zero setup
                                 ✓ Auto-everything

"Create marketing series"      → Build programmatic
                                 ✓ Custom control
                                 ✓ Brand voice
                                 ✓ Template-based

"Global product launch"        → Multilingual
                                 ✓ 28+ languages
                                 ✓ Auto-translate
                                 ✓ Native voices

"Database to videos"           → Build + loop
                                 ✓ Batch generate
                                 ✓ Consistent style
                                 ✓ Scale infinitely

"YouTube summaries"            → Parse YouTube
                                 ✓ Auto-summarize
                                 ✓ Key points
                                 ✓ Short format

"Combine multiple sources"     → Hybrid approach
                                 ✓ Parse + build
                                 ✓ Best of both
                                 ✓ Maximum flexibility
```

---

## 💡 Pro Tips

### **Fastest Path to Video:**

1. **Have markdown?** → `parse_document_to_set('README.md')` → Done!
2. **Have GitHub URL?** → `github_readme_to_video(url).export()` → Done!
3. **Have YouTube?** → `parse_youtube_to_set(url)` → Done!

### **Maximum Control:**

1. **Custom content?** → `VideoSetBuilder()` → Full power!
2. **Database?** → Loop + `builder.add_video()` → Infinite scale!
3. **Exact narration?** → Add `narration="..."` → Word-perfect!

### **Global Reach:**

1. **Need languages?** → `MultilingualVideoSet()` → 28+ supported!
2. **Regional variants?** → `variant='mx'` → es-MX, fr-CA, etc.!
3. **Quality translation?** → Claude API → Context-aware!

---

## 🔄 Integration Patterns

### **Pattern: Parse + Enhance**

```python
# Start automatic
builder = parse_document_to_builder('README.md')

# Add custom intro
builder.videos[0].scenes.insert(0,
    builder.create_title_scene("Welcome", "Enhanced Version")
)

# Export enhanced version
builder.export_to_yaml('sets/enhanced')
```

### **Pattern: Multi-Source Combine**

```python
builder = VideoSetBuilder("combined", "Combined Content")

# From markdown
md_builder = parse_document_to_builder('README.md')
builder.videos.extend(md_builder.videos)

# From YouTube
yt_builder = parse_youtube_to_builder('youtube_url')
builder.videos.extend(yt_builder.videos)

# Custom
builder.add_video(video_id='bonus', title='Bonus', scenes=[...])

builder.export_to_yaml('sets/combined')
```

### **Pattern: Translate + Customize**

```python
ml = MultilingualVideoSet("tutorial", "Tutorial", ['en', 'es'])

# Auto-translate
ml.add_video_source(...)
await ml.auto_translate_and_export()

# Then refine Spanish intro
es_builder = ml.builders['es']
es_builder.videos[0].scenes[0].narration = "Bienvenido! Custom intro..."

# Re-export
ml.export_all_languages()
```

---

## 📚 Quick Links

- **Full Parse Guide:** [PARSE_RAW_CONTENT.md](../PARSE_RAW_CONTENT.md)
- **Full Build Guide:** [PROGRAMMATIC_GUIDE.md](../PROGRAMMATIC_GUIDE.md)
- **Control Levels:** [CONTENT_CONTROL_GUIDE.md](../CONTENT_CONTROL_GUIDE.md)
- **Multilingual:** [MULTILINGUAL_GUIDE.md](../MULTILINGUAL_GUIDE.md)
- **Enhancement Summary:** [GUIDE_ENHANCEMENTS_SUMMARY.md](./GUIDE_ENHANCEMENTS_SUMMARY.md)

---

**🎬 Choose workflow → Copy template → Generate video → Done!**
