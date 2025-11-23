# Quick Test Guide - New Components

## ✅ Server is Running

Your server is confirmed running at: **http://127.0.0.1:8000**

All new components have been integrated into `create-unified.html`!

---

## 🧪 Test the New UI

### 1. Refresh Your Browser

**Hard refresh** to clear cache:
- **Windows/Linux**: `Ctrl + Shift + R`
- **Mac**: `Cmd + Shift + R`

Or visit: **http://127.0.0.1:8000/create?v=2**

---

## 2. What You Should See

### **Step 1: Input**

**When you select "File":**
- ✨ **NEW**: Modern drag-drop zone with hover effects
- ✨ **NEW**: Real-time validation feedback
- ✨ **NEW**: File preview after validation

**When you select "URL":**
- ✨ **NEW**: Real-time YouTube URL validation
- ✨ **NEW**: Inline validation indicators (✅ ❌ ⚠️)

### **Step 2: Configure**

- ✨ **NEW**: Multi-Language Selector
  - Search/filter languages
  - Popular languages quick-select
  - Voice count per language
- ✨ **NEW**: Multi-Voice Selector
  - Multiple voices per language
  - Voice preview with audio playback
  - Gender indicators

### **Step 3: Review**

- ✨ **NEW**: Preview Panel
  - Document structure visualization
  - Estimated scenes and duration
  - Collapsible sections

### **Step 4: Generate**

- ✨ **NEW**: Progress Indicator
  - 7-stage progress tracking
  - Real-time updates (if SSE enabled)
  - Time estimation

---

## 3. Browser Console Tests

Open console (F12) and run:

```javascript
// Test 1: Check if components are loaded
console.log('DragDrop:', typeof dragDropZone);
console.log('Validation:', typeof ValidationAPI);
console.log('Preview:', typeof previewPanel);
console.log('Languages:', typeof multiLanguageSelector);
console.log('Voices:', typeof multiVoiceSelector);
console.log('Progress:', typeof progressIndicator);

// Test 2: Check Alpine.js store
console.log('State:', Alpine.store('appState'));

// Test 3: Check utilities
console.log('EventBus:', window.eventBus ? '✅' : '❌');
console.log('Storage:', window.storage ? '✅' : '❌');
console.log('API Client:', window.apiClient ? '✅' : '❌');
console.log('Security:', window.securityUtils ? '✅' : '❌');

// Test 4: Trigger an event
if (window.eventBus) {
    eventBus.on('test', (data) => console.log('✅ Event received:', data));
    eventBus.emit('test', {message: 'Hello from new UI!'});
}
```

---

## 4. Component-Specific Tests

### Test Drag-Drop

1. Go to **Step 1**
2. Select **"File"**
3. **Drag a `.md` or `.txt` file** onto the drop zone
4. You should see:
   - Hover effect during drag
   - Validation spinner
   - Success banner with file info
   - Preview panel with document structure

### Test Validation

1. Go to **Step 1**
2. Select **"URL"**
3. Type a YouTube URL slowly: `https://www.youtube.com/watch?v=dQw4w9WgXcQ`
4. You should see:
   - Real-time validation (debounced 500ms)
   - ✅ Success indicator when valid
   - Video ID extracted

### Test Multi-Language

1. Go to **Step 2**
2. Scroll to **Languages** section
3. You should see:
   - Search box
   - Popular languages chips
   - Full language list with flags
   - Selected count

### Test Multi-Voice

1. After selecting languages in Step 2
2. Scroll to **Voices** section
3. You should see:
   - Voice options per language
   - Preview buttons (🔊)
   - Gender indicators (♂️ ♀️)
   - Selected voices chips

### Test Preview Panel

1. Upload a file in **Step 1**
2. Go to **Step 3: Review**
3. You should see:
   - Document title
   - Sections count
   - Estimated scenes
   - Estimated duration
   - Collapsible sections list

### Test Progress Indicator

1. Complete Steps 1-3
2. Go to **Step 4: Generate**
3. Click **"Start Generation"**
4. You should see:
   - Progress bar animating
   - Current stage indicator
   - Stage list with status icons
   - Time elapsed/remaining

---

## 5. If Components Don't Show

### Check 1: Clear Browser Cache

```bash
# Hard refresh
Ctrl + Shift + R  (Windows/Linux)
Cmd + Shift + R   (Mac)
```

### Check 2: Check Server Logs

Look for these lines confirming components loaded:
```
GET /static/js/components/drag-drop-zone.js HTTP/1.1" 200
GET /static/js/components/validation-feedback.js HTTP/1.1" 200
GET /static/js/components/preview-panel.js HTTP/1.1" 200
GET /static/js/components/multi-language-selector.js HTTP/1.1" 200
GET /static/js/components/multi-voice-selector.js HTTP/1.1" 200
GET /static/js/components/progress-indicator.js HTTP/1.1" 200
```

### Check 3: Console Errors

Open F12 → Console tab. Look for:
- ❌ Red errors (indicates syntax issues)
- ⚠️ Yellow warnings (usually safe to ignore)

### Check 4: Network Tab

F12 → Network tab → Refresh page
- All `.js` files should show **200 OK**
- All `.html` includes should load

---

## 6. Known Issues & Workarounds

### Issue: "TypeError: Cannot read property..."

**Fix**: Hard refresh browser (Ctrl+Shift+R)

### Issue: Components not visible

**Fix**: Check that you're on `/create` or `/create-unified`, not `/create-legacy`

### Issue: Drag-drop not working

**Fix**: Make sure you selected **"File"** input type first

### Issue: Languages not loading

**Fix**: API endpoint `/api/languages` needs to be implemented (see below)

---

## 7. Missing API Endpoints (Optional)

These endpoints will make multi-language features fully functional:

```python
# Add to app/main.py

@app.get("/api/languages")
async def get_languages():
    return {"languages": [
        {"code": "en", "name": "English", "name_local": "English",
         "voices": ["male", "female"], "voice_count": 2},
        {"code": "es", "name": "Spanish", "name_local": "Español",
         "voices": ["male", "female"], "voice_count": 2}
    ]}

@app.get("/api/languages/{lang_code}/voices")
async def get_voices(lang_code: str):
    return {"language": lang_code, "voices": [
        {"id": "male", "name": "Andrew (Male)", "gender": "male"},
        {"id": "female", "name": "Aria (Female)", "gender": "female"}
    ]}
```

---

## 8. Success Indicators

### ✅ Components Loaded Successfully

You should see in logs:
```
200 OK on all /static/js/components/*.js files
200 OK on all /static/js/utils/*.js files
200 OK on /static/css/components.css
```

### ✅ UI Updated Successfully

You should see:
- Modern drag-drop zone (not basic file input)
- Real-time validation indicators
- Multi-language selector with search
- Preview panel with collapsible sections

---

## 9. Reporting Issues

If something doesn't work:

1. **Check browser console** (F12)
2. **Check server logs**
3. **Try hard refresh** (Ctrl+Shift+R)
4. **Test in incognito mode**

---

**Current Status**: All components integrated ✅
**Next Step**: Refresh browser and test!

Visit: **http://127.0.0.1:8000/create**
