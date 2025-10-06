# Template Save/Load System

## Overview

The Template Save/Load System allows users to save their video generation configurations as reusable templates, making it easy to recreate complex setups with a single click.

## Features

### 1. Save Current Configuration
- **Button Location**: Step 2 configuration page, next to mode indicator
- **What Gets Saved**:
  - Mode (single video or video set)
  - Input method (manual, document, YouTube, YAML)
  - All video settings (duration, voices, scenes)
  - Multilingual configuration
  - Translation settings
  - Color theme

### 2. Template Management
- **My Templates Section**: Expandable section in Quick Templates area
- **Built-in Templates**: Tutorial, Course, Demo, Global (pre-configured)
- **User Templates**: Custom templates saved by the user

### 3. Template Operations

#### Save Template
```javascript
// Click "💾 Save as Template" button
// Modal opens with:
// - Template Name (required)
// - Description (optional)
// - Current config summary
```

#### Load Template
```javascript
// Click on any template card
// Configuration auto-populates all fields
// Mode and step automatically set
```

#### Delete Template
```javascript
// Hover over user template
// Click × button to delete
// Confirmation dialog appears
```

#### Export/Import
```javascript
// Export single template: Download as JSON
// Export all: Download all templates
// Import: Upload JSON file(s)
```

## Template Structure

### Template Object
```json
{
  "id": "1234567890",
  "name": "My Course Template",
  "description": "10-video course with multi-voice narration",
  "mode": "set",
  "config": {
    "inputMethod": "manual",
    "name": "Complete Course",
    "videoCount": 10,
    "duration": 180,
    "color": "purple",
    "multilingual": true,
    "sourceLanguage": "en",
    "targetLanguages": ["en", "es", "fr"],
    "translationMethod": "claude",
    "videos": [
      {
        "title": "Lesson 1",
        "voices": ["male"],
        "duration": null
      }
      // ... more videos
    ]
  },
  "createdAt": "2025-01-15T10:30:00Z",
  "updatedAt": "2025-01-15T10:30:00Z"
}
```

### Single Video Template
```json
{
  "id": "1234567891",
  "name": "Quick Demo",
  "description": "30-second product demo",
  "mode": "single",
  "config": {
    "inputMethod": "manual",
    "title": "Product Demo",
    "duration": 30,
    "color": "blue",
    "useAI": true,
    "multilingual": false,
    "videos": [
      {
        "title": "Product Demo",
        "voices": ["male_warm"],
        "duration": 30
      }
    ]
  },
  "createdAt": "2025-01-15T11:00:00Z",
  "updatedAt": "2025-01-15T11:00:00Z"
}
```

## Client-Side Storage

### LocalStorage Implementation
```javascript
// Storage key
const STORAGE_KEY = 'video_gen_templates';

// Save templates
localStorage.setItem(STORAGE_KEY, JSON.stringify(templates));

// Load templates
const templates = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
```

### Template Manager Class
```javascript
class TemplateManager {
  constructor() {
    this.storageKey = 'video_gen_templates';
    this.templates = this.loadTemplates();
  }

  loadTemplates() { /* ... */ }
  saveTemplates() { /* ... */ }
  createTemplate(name, description, mode, config) { /* ... */ }
  getAll() { /* ... */ }
  getById(id) { /* ... */ }
  deleteTemplate(id) { /* ... */ }
  exportTemplate(id) { /* ... */ }
  importTemplate(jsonData) { /* ... */ }
}
```

## Backend API Endpoints

### Save Template (Future Enhancement)
```http
POST /api/templates/save
Content-Type: application/json

{
  "name": "My Template",
  "description": "Description here",
  "mode": "set",
  "config": { /* full config */ }
}

Response:
{
  "success": true,
  "template_id": "tmpl_1234567890",
  "message": "Template saved successfully"
}
```

### List Templates
```http
GET /api/templates/list

Response:
{
  "templates": [],
  "message": "Templates are stored client-side in browser localStorage"
}
```

### Delete Template
```http
DELETE /api/templates/{template_id}

Response:
{
  "success": true,
  "message": "Template deleted successfully"
}
```

## User Interface Components

### 1. Save Template Modal
**File**: `app/templates/components/save-template-modal.html`

Features:
- Template name input (required)
- Description textarea (optional)
- Current config summary
- Save/Cancel buttons

### 2. Template Manager Modal
**File**: `app/templates/components/template-manager-modal.html`

Features:
- List all user templates
- Export/Import buttons
- Individual template actions (Load, Export, Delete)
- Clear all templates option

### 3. My Templates Section
**Location**: Quick Templates area in `create.html`

Features:
- Expandable section showing template count
- Grid layout of user templates
- Delete button on hover

## Alpine.js Integration

### Extended Video Creator
```javascript
function extendVideoCreatorWithTemplates(baseCreator) {
  return {
    ...baseCreator,

    // Template state
    showSaveTemplateModal: false,
    showTemplateManager: false,
    userTemplates: [],

    // Methods
    saveTemplate() { /* ... */ },
    loadUserTemplate(template) { /* ... */ },
    deleteTemplate(id) { /* ... */ },
    exportTemplate(id) { /* ... */ },
    importTemplates(event) { /* ... */ }
  };
}
```

### Usage in create.html
```html
<div x-data="videoCreatorWithTemplates()" x-init="init()">
  <!-- Your existing content -->

  <!-- Include modals -->
  {% include 'components/save-template-modal.html' %}
  {% include 'components/template-manager-modal.html' %}
</div>
```

## File Structure

```
app/
├── static/js/
│   ├── template-manager.js          # Template management class
│   └── create-with-templates.js     # Alpine.js integration
├── templates/
│   ├── create.html                  # Updated with template UI
│   └── components/
│       ├── save-template-modal.html        # Save template modal
│       └── template-manager-modal.html     # Manage templates modal
└── main.py                          # Backend endpoints
```

## Usage Examples

### Example 1: Save Tutorial Template
```javascript
// User configures:
// - Mode: Set
// - 3 videos
// - EN + ES languages
// - Tutorial theme

// Click "Save as Template"
// Enter name: "Tutorial Series"
// Enter description: "3-part tutorial with English and Spanish"
// Click Save

// Template saved to localStorage
// Available in "My Templates"
```

### Example 2: Load Template
```javascript
// Click "My Templates" to expand
// Click on "Tutorial Series" card
// All settings auto-populate:
//   - Mode: Set
//   - 3 videos
//   - EN + ES selected
//   - Tutorial configuration loaded
```

### Example 3: Export/Import
```javascript
// Export single template:
// Click "Manage Templates"
// Find template
// Click "Export"
// Downloads: template-tutorial-series.json

// Import template:
// Click "Import" in Template Manager
// Select JSON file
// Template added to list
```

## Best Practices

### 1. Template Naming
- Use descriptive names: "10-Video Course EN/ES" not "Template 1"
- Include key details: video count, languages, purpose
- Keep names concise (under 30 characters)

### 2. Template Organization
- Create templates for common workflows
- Export important templates as backup
- Use descriptions to document template purpose

### 3. Template Maintenance
- Regularly export templates as backup
- Delete unused templates
- Update templates when workflow changes

## Future Enhancements

### Server-Side Storage
- Store templates in database
- User accounts and authentication
- Share templates across devices
- Team collaboration on templates

### Template Marketplace
- Share templates with community
- Browse and import public templates
- Template categories and ratings
- Template versioning

### Advanced Features
- Template variables/parameters
- Conditional logic in templates
- Template inheritance/composition
- A/B testing with template variants

## Troubleshooting

### Templates Not Saving
- Check browser localStorage is enabled
- Verify no browser privacy mode
- Check console for errors
- Try exporting then importing

### Templates Not Loading
- Verify template format is correct
- Check all required fields present
- Ensure mode is 'single' or 'set'
- Validate JSON structure

### Import Fails
- Verify JSON is valid
- Check file encoding (UTF-8)
- Ensure template has all required fields
- Try single template import first

## API Reference

### TemplateManager Class Methods

#### `createTemplate(name, description, mode, config)`
Creates and saves a new template.

**Parameters:**
- `name` (string): Template name
- `description` (string): Template description
- `mode` (string): 'single' or 'set'
- `config` (object): Full configuration object

**Returns:** Template object with generated ID

#### `getAll()`
Retrieves all saved templates.

**Returns:** Array of template objects

#### `getById(id)`
Get specific template by ID.

**Parameters:**
- `id` (string): Template ID

**Returns:** Template object or undefined

#### `deleteTemplate(id)`
Delete template by ID.

**Parameters:**
- `id` (string): Template ID

**Returns:** Boolean success status

#### `exportTemplate(id)`
Export template as JSON file.

**Parameters:**
- `id` (string): Template ID

**Returns:** Template object or null

#### `importTemplate(jsonData)`
Import template from JSON.

**Parameters:**
- `jsonData` (string|object): JSON string or object

**Returns:** Imported template object or null

## Summary

The Template Save/Load System provides:
- ✅ One-click configuration saving
- ✅ Quick template loading
- ✅ Export/Import functionality
- ✅ Template management UI
- ✅ Client-side storage (localStorage)
- ✅ Server-side API ready for future
- ✅ Built-in and custom templates
- ✅ Full configuration preservation

This system dramatically improves workflow efficiency by allowing users to save and reuse complex video generation setups.
