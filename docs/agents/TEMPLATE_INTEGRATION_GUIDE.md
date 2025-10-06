# Template System Integration Guide

## Quick Integration Checklist

Follow these steps to add template functionality to `create.html`:

### Step 1: Add JavaScript Files to Base Template

**File**: `app/templates/base.html`

Add before closing `</body>` tag:

```html
<!-- Template System Scripts -->
<script src="{{ url_for('static', path='/js/template-manager.js') }}"></script>
<script src="{{ url_for('static', path='/js/create-with-templates.js') }}"></script>
```

### Step 2: Update Alpine.js Component in create.html

**File**: `app/templates/create.html`

**Find** (around line 45):
```html
<div x-data="videoCreator()" x-init="init()">
```

**Replace with**:
```html
<div x-data="videoCreatorWithTemplates()" x-init="init()">
```

### Step 3: Update Quick Templates Section

**File**: `app/templates/create.html`

**Find** (lines 78-110 approximately):
```html
<!-- Quick Templates -->
<div x-show="step === 1" class="bg-gradient-to-r from-yellow-50 to-orange-50 border-2 border-yellow-200 rounded-xl p-4 mb-6">
    <h3 class="font-bold text-gray-900 mb-3 flex items-center gap-2">
        <span class="text-xl">⚡</span>
        Quick Templates
    </h3>
    <div class="grid md:grid-cols-4 gap-3">
        <!-- Built-in templates -->
    </div>
</div>
```

**Replace with**:
```html
<!-- Quick Templates -->
<div x-show="step === 1" class="bg-gradient-to-r from-yellow-50 to-orange-50 border-2 border-yellow-200 rounded-xl p-4 mb-6">
    <div class="flex items-center justify-between mb-3">
        <h3 class="font-bold text-gray-900 flex items-center gap-2">
            <span class="text-xl">⚡</span>
            Quick Templates
        </h3>
        <button @click="showUserTemplates = !showUserTemplates" type="button"
                class="text-sm text-blue-600 hover:text-blue-700 font-medium flex items-center gap-1">
            📚 My Templates (<span x-text="userTemplates.length"></span>)
            <svg class="w-4 h-4 transition-transform" :class="showUserTemplates ? 'rotate-180' : ''" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
            </svg>
        </button>
    </div>

    <!-- Built-in Templates -->
    <div class="grid md:grid-cols-4 gap-3 mb-3">
        <button @click="loadTemplate('tutorial')" type="button"
                class="p-3 bg-white hover:bg-yellow-50 border-2 border-yellow-200 rounded-lg text-left transition-all hover:shadow-md">
            <div class="text-2xl mb-1">📚</div>
            <div class="font-semibold text-sm">Tutorial</div>
            <div class="text-xs text-gray-600">3 videos, EN+ES</div>
        </button>
        <button @click="loadTemplate('course')" type="button"
                class="p-3 bg-white hover:bg-yellow-50 border-2 border-yellow-200 rounded-lg text-left transition-all hover:shadow-md">
            <div class="text-2xl mb-1">🎓</div>
            <div class="font-semibold text-sm">Course</div>
            <div class="text-xs text-gray-600">10 videos, multi-voice</div>
        </button>
        <button @click="loadTemplate('demo')" type="button"
                class="p-3 bg-white hover:bg-yellow-50 border-2 border-yellow-200 rounded-lg text-left transition-all hover:shadow-md">
            <div class="text-2xl mb-1">💻</div>
            <div class="font-semibold text-sm">Demo</div>
            <div class="text-xs text-gray-600">1 video, quick</div>
        </button>
        <button @click="loadTemplate('global')" type="button"
                class="p-3 bg-white hover:bg-yellow-50 border-2 border-yellow-200 rounded-lg text-left transition-all hover:shadow-md">
            <div class="text-2xl mb-1">🌍</div>
            <div class="font-semibold text-sm">Global</div>
            <div class="text-xs text-gray-600">5 videos, 10 langs</div>
        </button>
    </div>

    <!-- User Templates -->
    <div x-show="showUserTemplates" x-collapse class="mt-3 pt-3 border-t border-yellow-300">
        <div x-show="userTemplates.length === 0" class="text-sm text-gray-500 text-center py-2">
            No custom templates yet. Configure your settings and click "Save as Template"
        </div>
        <div x-show="userTemplates.length > 0" class="grid md:grid-cols-4 gap-3">
            <template x-for="template in userTemplates" :key="template.id">
                <div class="p-3 bg-white border-2 border-blue-200 rounded-lg relative group">
                    <button @click="loadUserTemplate(template)" type="button" class="w-full text-left">
                        <div class="text-2xl mb-1">💾</div>
                        <div class="font-semibold text-sm" x-text="template.name"></div>
                        <div class="text-xs text-gray-600" x-text="template.description"></div>
                    </button>
                    <button @click="deleteTemplate(template.id)" type="button"
                            class="absolute top-1 right-1 w-6 h-6 bg-red-500 text-white rounded-full opacity-0 group-hover:opacity-100 transition-opacity text-xs font-bold">
                        ×
                    </button>
                </div>
            </template>
        </div>
    </div>
</div>
```

### Step 4: Add Save Template Button to Step 2 Header

**File**: `app/templates/create.html`

**Find** (line 181 approximately):
```html
<div class="bg-gradient-to-r from-blue-500 to-blue-600 px-6 py-3 flex items-center justify-between">
    <h2 class="text-white font-semibold">Step 2: Configure Video Settings</h2>
    <span class="text-white text-sm px-3 py-1 bg-white/20 rounded-full" x-text="mode === 'single' ? '🎥 Single Video' : '📚 Video Set'"></span>
</div>
```

**Replace with**:
```html
<div class="bg-gradient-to-r from-blue-500 to-blue-600 px-6 py-3 flex items-center justify-between">
    <h2 class="text-white font-semibold">Step 2: Configure Video Settings</h2>
    <div class="flex items-center gap-2">
        <button @click="showSaveTemplateModal = true" type="button"
                class="text-sm bg-white/20 hover:bg-white/30 text-white px-3 py-1 rounded-lg font-medium transition-colors flex items-center gap-1">
            💾 Save as Template
        </button>
        <span class="text-white text-sm px-3 py-1 bg-white/20 rounded-full" x-text="mode === 'single' ? '🎥 Single Video' : '📚 Video Set'"></span>
    </div>
</div>
```

### Step 5: Include Modal Components

**File**: `app/templates/create.html`

**Add before** the closing `</div>` of the main Alpine.js component (around line 1023):

```html
    <!-- Template Modals -->
    {% include 'components/save-template-modal.html' %}
    {% include 'components/template-manager-modal.html' %}

</div> <!-- End of x-data="videoCreatorWithTemplates()" -->
```

### Step 6: Verify File Structure

Ensure these files exist:

```
app/
├── static/js/
│   ├── template-manager.js              ✅ Created
│   └── create-with-templates.js         ✅ Created
└── templates/
    ├── base.html                        ⚠️  Update (add scripts)
    ├── create.html                      ⚠️  Update (5 changes above)
    └── components/
        ├── save-template-modal.html     ✅ Created
        └── template-manager-modal.html  ✅ Created
```

## Testing Steps

After integration, test the following:

### 1. Basic Template Save/Load
```
1. Open /create page
2. Configure video settings (Step 2)
3. Click "💾 Save as Template"
4. Enter name and description
5. Click "Save Template"
6. Verify success message
7. Click "📚 My Templates"
8. Verify template appears
9. Click template to load
10. Verify all settings populated
```

### 2. Template Delete
```
1. Click "📚 My Templates"
2. Hover over template card
3. Click × button
4. Confirm deletion
5. Verify template removed
```

### 3. Export/Import
```
1. Click "📚 My Templates"
2. (Future: Add manage button)
3. Export template
4. Verify JSON downloads
5. Import template
6. Verify template added
```

### 4. Built-in Templates
```
1. Go to Step 1
2. Click "Tutorial" template
3. Verify settings loaded
4. Repeat for Course, Demo, Global
```

## Troubleshooting

### Issue: Templates not saving
**Solution**:
- Check browser console for errors
- Verify localStorage is enabled
- Disable private/incognito mode
- Check browser compatibility

### Issue: Templates not loading
**Solution**:
- Verify `videoCreatorWithTemplates()` is used
- Check template structure in localStorage
- Clear localStorage and try again
- Check console for parse errors

### Issue: Modals not appearing
**Solution**:
- Verify modal components are included
- Check Alpine.js initialization
- Inspect element for `x-show` attributes
- Verify Tailwind CSS classes loaded

### Issue: Save button not visible
**Solution**:
- Verify Step 2 header updated correctly
- Check `showSaveTemplateModal` state exists
- Inspect element styling
- Check responsive breakpoints

## Verification Checklist

After integration, verify:

- [ ] Scripts load without errors (check Network tab)
- [ ] Alpine.js component initializes with templates
- [ ] "My Templates" button shows correct count
- [ ] Save Template button appears in Step 2
- [ ] Save Template modal opens/closes
- [ ] Template Manager modal opens/closes (if added)
- [ ] Built-in templates still work
- [ ] Templates save to localStorage
- [ ] Templates load correctly
- [ ] Templates delete with confirmation
- [ ] Export downloads JSON file
- [ ] Import accepts JSON file
- [ ] Success/error messages display
- [ ] Responsive design works on mobile

## Optional: Add Template Manager Button

For full template management UI, add this button to Step 1 or the header:

```html
<button @click="showTemplateManager = true" type="button"
        class="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg font-medium">
    📚 Manage Templates
</button>
```

## Complete Integration in One File

If you prefer a single comprehensive update to `create.html`, see:
- `docs/TEMPLATE_SYSTEM.md` - Full UI examples
- `app/templates/components/` - Modal components

## Support

For issues or questions:
1. Check `docs/TEMPLATE_SYSTEM.md` for detailed documentation
2. See `docs/TEMPLATE_QUICK_REFERENCE.md` for common solutions
3. Review browser console for specific errors
4. Check localStorage contents: `localStorage.getItem('video_gen_templates')`

## Summary

After following these steps, you will have:

✅ Full template save/load functionality
✅ Template management UI
✅ Export/Import capabilities
✅ Built-in and custom templates
✅ Persistent storage (localStorage)
✅ User-friendly interface

Total changes required: **5 updates** to existing files + **4 new files** already created.
