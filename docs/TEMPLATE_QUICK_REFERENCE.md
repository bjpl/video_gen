# Template System - Quick Reference

## 🚀 Quick Start

### Save a Template
1. Configure your video settings (Step 2)
2. Click **💾 Save as Template** (top right)
3. Enter template name and description
4. Click **Save Template**

### Load a Template
1. Click **📚 My Templates** to expand
2. Click on any template card
3. Settings auto-populate instantly

### Manage Templates
1. Click **📚 My Templates** → hover for count
2. Or click **Manage Templates** button
3. Export, Import, or Delete templates

## 📋 Template Actions

| Action | How To | Location |
|--------|--------|----------|
| **Save** | Click "Save as Template" button | Step 2 header |
| **Load** | Click template card | Quick Templates |
| **Delete** | Hover → Click × | Template card |
| **Export Single** | Template Manager → Export | Modal |
| **Export All** | Template Manager → Export All | Modal header |
| **Import** | Template Manager → Import | Modal header |
| **Manage** | Click "My Templates" | Quick Templates |

## 🎯 Built-in Templates

### Tutorial (📚)
- 3 videos
- EN + ES
- Tutorial theme
- Multi-voice narration

### Course (🎓)
- 10 videos
- Multi-voice
- Educational format
- Alternating narrators

### Demo (💻)
- 1 video
- Quick 30s
- Single voice
- Product demo

### Global (🌍)
- 5 videos
- 10 languages
- Marketing campaign
- Multi-voice

## 💾 Template Structure

```json
{
  "id": "unique_id",
  "name": "Template Name",
  "description": "What this template does",
  "mode": "single|set",
  "config": {
    "inputMethod": "manual|document|youtube|yaml",
    "duration": 60,
    "color": "blue",
    "multilingual": true,
    "targetLanguages": ["en", "es"],
    "videos": [/* video configs */]
  }
}
```

## 🔧 Configuration Saved

### For Single Video
- ✅ Input method (manual/document/YouTube/YAML)
- ✅ Video title
- ✅ Duration
- ✅ Voice tracks (up to 4)
- ✅ Color theme
- ✅ AI enhancement setting
- ✅ Multilingual settings
- ✅ Translation method

### For Video Set
- ✅ Input method
- ✅ Set name
- ✅ Number of videos
- ✅ Default duration
- ✅ Per-video titles
- ✅ Per-video voices
- ✅ Color theme
- ✅ Multilingual settings
- ✅ All language configurations

## 📤 Export/Import

### Export Template
```
Template Manager → Click "Export" on template
Downloads: template-[name].json
```

### Export All Templates
```
Template Manager → Click "Export All"
Downloads: video-templates-[date].json
```

### Import Template
```
Template Manager → Click "Import"
Select .json file
Template added to list
```

## 🎨 UI Components

### Save Template Modal
- Template name input (required)
- Description textarea (optional)
- Current config summary
- Save/Cancel buttons

### Template Manager Modal
- Template list with details
- Per-template actions (Load, Export, Delete)
- Bulk operations (Import, Export All, Clear)

### My Templates Section
- Expandable section in Quick Templates
- Shows template count
- Grid layout of user templates
- Delete button on hover

## ⚡ Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `ESC` | Close any modal |
| Click outside | Close modal |

## 🔍 Template Manager Features

### Individual Template Card Shows:
- 📝 Template name
- 🏷️ Mode badge (Single/Set)
- 📄 Description
- 📊 Video count
- 🎤 Input method
- 🌍 Multilingual status
- 📅 Created date

### Actions Available:
- **Load** - Apply template to current config
- **Export** - Download as JSON
- **Delete** - Remove template (with confirmation)

### Bulk Operations:
- **Export All** - Download all templates
- **Import** - Upload templates from file
- **Clear All** - Delete all templates (with confirmation)

## 🌟 Best Practices

### Naming Templates
✅ **Good**: "Course: 10 Videos EN/ES/FR"
❌ **Bad**: "Template 1"

✅ **Good**: "Product Demo 30s Blue Theme"
❌ **Bad**: "My Video"

### Organizing Templates
1. Use descriptive names with key details
2. Include video count and languages in name
3. Add purpose/use case in description
4. Export important templates regularly
5. Delete unused templates

### Backup Strategy
1. Export all templates monthly
2. Save JSON files to cloud storage
3. Version control template files
4. Document template purposes

## 🐛 Troubleshooting

### Template Not Saving
- ✅ Check localStorage enabled
- ✅ Disable private browsing
- ✅ Check browser console
- ✅ Try different browser

### Template Not Loading
- ✅ Verify template format
- ✅ Check all fields present
- ✅ Ensure valid JSON
- ✅ Re-import template

### Import Fails
- ✅ Validate JSON syntax
- ✅ Check UTF-8 encoding
- ✅ Verify required fields
- ✅ Try single template first

## 📊 Template Statistics

### Storage Limits
- **Browser**: ~5-10MB localStorage
- **Templates**: Thousands possible
- **Average size**: 2-5KB per template
- **Recommendation**: Export if >100 templates

### Performance
- **Load time**: Instant (milliseconds)
- **Save time**: Instant (milliseconds)
- **Export/Import**: <1 second
- **No server delay**: Client-side only

## 🔗 Related Files

| File | Purpose |
|------|---------|
| `template-manager.js` | Core template logic |
| `create-with-templates.js` | Alpine.js integration |
| `save-template-modal.html` | Save UI |
| `template-manager-modal.html` | Manage UI |
| `main.py` | Backend endpoints (future) |

## 📚 Common Workflows

### Workflow 1: Create & Save
```
1. Configure video settings
2. Test with one video
3. Save as template
4. Use for future projects
```

### Workflow 2: Load & Modify
```
1. Load existing template
2. Modify specific settings
3. Generate videos
4. Save modified version as new template
```

### Workflow 3: Share Templates
```
1. Export template to JSON
2. Share file with team
3. Team imports template
4. Consistent configurations
```

## ⚙️ Advanced Usage

### Template Inheritance (Manual)
```
1. Load base template
2. Modify specific fields
3. Save as new template
4. Maintain related templates
```

### A/B Testing
```
1. Save template A (blue theme)
2. Save template B (purple theme)
3. Generate with both
4. Compare results
```

### Multi-Language Workflows
```
1. Create EN template
2. Save with EN settings
3. Duplicate & modify for other languages
4. Generate region-specific versions
```

## 🎯 Summary

**What You Can Do:**
- ✅ Save unlimited templates
- ✅ Load with one click
- ✅ Export/Import as JSON
- ✅ Full config preservation
- ✅ Client-side (fast & private)
- ✅ Manage all templates easily

**What Gets Saved:**
- ✅ All video settings
- ✅ Voice configurations
- ✅ Multilingual setup
- ✅ Color themes
- ✅ Input methods
- ✅ Everything you configured

**Benefits:**
- ⚡ Instant setup for repeat projects
- 🔄 Consistent configurations
- 💾 No server storage needed
- 🚀 Workflow acceleration
- 👥 Easy sharing via export
- 🎨 Template customization
