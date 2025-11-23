# Accessibility Implementation Checklist
**Week 1 P0 Tasks - Action Items for Implementation Team**

**Source:** Research findings in `accessibility-best-practices.md`
**Total Time:** 7 hours
**Target:** WCAG 2.1 AA compliance (95/100 accessibility score)

---

## Task 1: Add ARIA Labels (2 hours)

### Files to Modify
- `app/templates/create.html`
- `app/templates/multilingual.html`

### Implementation Steps

#### Step 1.1: Icon-Only Buttons
**Pattern to use:**
```html
<button @click="action()"
        aria-label="Descriptive action name">
    <span aria-hidden="true">🔊</span>
    <span class="sr-only">Button description</span>
</button>
```

**Specific fixes:**
1. Voice preview buttons (line ~247 in create.html)
   ```html
   <button @click="previewVoice(voice)"
           aria-label="Preview voice sample for {{voice.name}}">
       <span aria-hidden="true">🔊</span>
   </button>
   ```

2. Back button (top right)
   ```html
   <button @click="previousStep()"
           aria-label="Return to video type selection">
       <span aria-hidden="true">←</span>
   </button>
   ```

3. Color palette buttons
   ```html
   <button @click="single.color = 'blue'"
           aria-label="Select blue theme"
           :aria-pressed="single.color === 'blue' ? 'true' : 'false'">
       <span class="bg-blue-500 w-12 h-12 rounded-lg" aria-hidden="true"></span>
       <span class="sr-only">Blue</span>
   </button>
   ```

#### Step 1.2: Toggle Switches with State
```html
<button @click="single.useAI = !single.useAI"
        :aria-pressed="single.useAI ? 'true' : 'false'"
        :aria-label="single.useAI ? 'Disable AI enhancement' : 'Enable AI enhancement'">
    <span aria-hidden="true">🤖</span>
    <span class="sr-only" x-text="single.useAI ? 'AI On' : 'AI Off'"></span>
</button>
```

#### Step 1.3: Range Sliders
```html
<input type="range"
       min="30" max="300" step="5"
       x-model="single.duration"
       :aria-valuetext="single.duration + ' seconds'"
       aria-label="Video duration">
```

**Test:** Tab through interface with NVDA - verify all buttons announce name + state

---

## Task 2: SR-Only Text for Emojis (1 hour)

### Decision Tree
1. **Standalone emoji** (no text nearby) → `role="img"` + `aria-label`
2. **Emoji + text together** → `aria-hidden="true"` (decorative)
3. **Emoji in button/link** → `aria-hidden="true"` + accessible button label

### Implementation Steps

#### Step 2.1: Add sr-only CSS Class
**File:** `app/static/css/main.css` (or create if needed)

```css
.sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border-width: 0;
}
```

#### Step 2.2: Fix Semantic Emojis
**multilingual.html line 19:**
```html
<!-- BEFORE -->
<h1>🌍 Multilingual Video Generation</h1>

<!-- AFTER -->
<h1>
    <span role="img" aria-label="Globe">🌍</span>
    Multilingual Video Generation
</h1>
```

**create.html - status indicators:**
```html
<!-- Success messages -->
<span role="img" aria-label="Success">✅</span> Video generated successfully

<!-- Error messages -->
<span role="img" aria-label="Error">❌</span> Generation failed

<!-- Loading states -->
<span role="img" aria-label="Loading">⏳</span> Processing...
```

#### Step 2.3: Hide Decorative Emojis
**Quick presets (multilingual.html line 218-238):**
```html
<button @click="targetLanguages = ['en', 'es']">
    <div class="font-medium">
        <span aria-hidden="true">🇺🇸🇪🇸</span>
        EN + ES
    </div>
    <div class="text-sm text-gray-600">Bilingual</div>
</button>
```

**Test:** Use screen reader to verify emoji announcements are appropriate

---

## Task 3: Color Contrast Verification (3 hours)

### Step 3.1: Install Testing Tools (15 min)
```bash
# Browser extension
# Install axe DevTools for Chrome/Firefox

# CLI tool (optional)
npm install --save-dev @axe-core/cli
```

### Step 3.2: Run Automated Audit (30 min)
1. Open `http://localhost:5000/create` in browser
2. Open DevTools → axe DevTools tab
3. Click "Scan ALL of my page"
4. Filter results by "Color contrast"
5. Document all failures with screenshots
6. Export report as JSON

### Step 3.3: Fix Identified Issues (1.5 hours)

**Expected fixes based on research:**

#### Fix 1: Disabled Button States
```html
<!-- BEFORE (fails 4.5:1) -->
<button disabled class="bg-gray-300 text-gray-500">
    Generate Video
</button>

<!-- AFTER (passes 4.6:1) -->
<button disabled class="bg-gray-300 text-gray-700">
    Generate Video
</button>
```

#### Fix 2: Placeholder Text
```html
<!-- BEFORE (fails if placeholder conveys required info) -->
<input type="text" placeholder="Enter YouTube URL" class="placeholder-gray-400">

<!-- AFTER: Use helper text instead -->
<label for="youtube-url" class="text-sm font-medium text-gray-700">
    YouTube URL <span class="text-red-500">*</span>
</label>
<input type="text" id="youtube-url"
       placeholder="https://youtube.com/watch?v=..."
       class="placeholder-gray-500">
<p class="text-sm text-gray-600 mt-1">
    Paste a YouTube video URL to extract content
</p>
```

#### Fix 3: Hover States
```css
/* Ensure hover states maintain 4.5:1 contrast */
.hover-text:hover {
    color: #374151; /* gray-700 */
    background: #F3F4F6; /* gray-100 */
}
```

### Step 3.4: Verify with Manual Tools (45 min)
1. Use [WebAIM Contrast Checker](https://webaim.org/resources/contrastchecker/)
2. Test each color combination flagged by axe
3. Test browser zoom at 125%, 150%, 200%
4. Verify no content gets cut off

### Step 3.5: Re-run axe Audit (15 min)
- Verify 0 color contrast violations
- Document passing ratios in test report

**Test:** Lighthouse accessibility score should be 95+/100

---

## Task 4: Add Role Attributes (1 hour)

### Step 4.1: Loading Indicators

**create.html - generation progress:**
```html
<div x-show="loading"
     role="status"
     aria-live="polite"
     aria-atomic="true">
    <span class="sr-only">Generating video, please wait</span>
    <svg class="animate-spin" aria-hidden="true">...</svg>
</div>
```

### Step 4.2: Error Messages

```html
<div x-show="error"
     role="alert"
     aria-live="assertive"
     class="text-red-600">
    <span role="img" aria-label="Error">❌</span>
    {{ errorMessage }}
</div>
```

### Step 4.3: Progress Updates

```html
<div role="region" aria-labelledby="progress-title">
    <h2 id="progress-title">Generation Progress</h2>

    <div role="progressbar"
         :aria-valuenow="progress"
         aria-valuemin="0"
         aria-valuemax="100"
         :aria-valuetext="`${progress}% complete - ${currentStage}`">
        <div class="progress-bar" :style="`width: ${progress}%`"></div>
    </div>

    <div aria-live="polite" aria-atomic="false">
        {{ currentStage }}
    </div>
</div>
```

### Step 4.4: Modal Dialogs (if present)

```html
<div role="dialog"
     aria-labelledby="modal-title"
     aria-modal="true"
     x-show="showModal">
    <h2 id="modal-title">Confirm Generation</h2>
    <button @click="closeModal()"
            aria-label="Close dialog">
        <span aria-hidden="true">×</span>
    </button>
    <!-- Modal content -->
</div>
```

**Test:** Trigger loading/error states with screen reader active, verify announcements

---

## Testing Checklist

### Automated Testing
- [ ] axe DevTools: 0 violations (run on all pages)
- [ ] Lighthouse Accessibility: 95+/100
- [ ] WAVE extension: 0 errors

### Manual Testing
- [ ] Keyboard navigation: Tab through entire form (no traps, logical order)
- [ ] NVDA screen reader: All elements announce name, role, value, state
- [ ] VoiceOver (macOS): Test on Safari if available
- [ ] Browser zoom: Test at 125%, 150%, 200% (no content cut off)
- [ ] High contrast mode: Test in Windows high contrast mode

### Specific Tests
- [ ] Icon buttons: All announce descriptive labels
- [ ] Emojis: Semantic ones have `role="img"`, decorative ones `aria-hidden`
- [ ] Color palette: Each color announces name + description
- [ ] Sliders: Value changes announced in real-time
- [ ] Toggle switches: State (on/off) announced
- [ ] Loading states: "Generating video" announced
- [ ] Error messages: Announced immediately with `role="alert"`
- [ ] Form validation: Errors associated with inputs via `aria-describedby`

---

## Success Criteria

**Before Implementation:**
- Accessibility Score: 67/100 (per UX analysis)
- ARIA labels: Incomplete
- Color contrast: Unverified
- Screen reader: Not tested

**After Implementation:**
- ✅ Accessibility Score: 95+/100
- ✅ ARIA labels: Complete for all interactive elements
- ✅ Color contrast: 100% WCAG AA compliant (4.5:1 for text)
- ✅ Screen reader: Full keyboard + NVDA/JAWS support
- ✅ WCAG 2.1 AA: Compliant
- ✅ Section 508: Compliant

---

## Quick Reference

### ARIA Label Pattern
```html
<button aria-label="Action description">
    <span aria-hidden="true">[icon]</span>
</button>
```

### Emoji Pattern (Semantic)
```html
<span role="img" aria-label="Description">🔊</span>
```

### Emoji Pattern (Decorative)
```html
<span aria-hidden="true">🔊</span> [Adjacent text]
```

### Live Region Pattern
```html
<div role="status" aria-live="polite">
    [Dynamic content updates]
</div>
```

### Error Message Pattern
```html
<input aria-invalid="true" aria-describedby="error-id">
<div id="error-id" role="alert">Error message</div>
```

---

## Files to Modify Summary

1. **app/templates/create.html** - Main video creation interface
   - Add ARIA labels to buttons (~15 buttons)
   - Fix emoji accessibility (~8 emojis)
   - Add role attributes to loading/error states

2. **app/templates/multilingual.html** - Multilingual generation interface
   - Add ARIA labels to preset buttons (~4 buttons)
   - Fix emoji accessibility (~3 emojis)
   - Add role attributes to loading states

3. **app/static/css/main.css** (or create)
   - Add `.sr-only` utility class
   - Fix color contrast issues in hover states

4. **Test files to create:**
   - `tests/accessibility/aria-labels.test.js`
   - `tests/accessibility/color-contrast.test.js`

---

## Estimated Time Breakdown

| Task | Time | Priority |
|------|------|----------|
| ARIA labels implementation | 2 hours | P0 |
| SR-only text for emojis | 1 hour | P0 |
| Color contrast audit + fixes | 3 hours | P0 |
| Role attributes | 1 hour | P0 |
| **Total** | **7 hours** | **P0** |

---

## Resources

**Documentation:**
- Full research: `docs/research/accessibility-best-practices.md`
- UX analysis: `app/docs/UX_ANALYSIS_REPORT.md`
- Quick wins: `app/docs/UX_QUICK_WINS.md`

**Testing Tools:**
- axe DevTools (browser extension)
- WebAIM Contrast Checker: https://webaim.org/resources/contrastchecker/
- WAVE extension: https://wave.webaim.org/extension/
- NVDA screen reader: https://www.nvaccess.org/download/

**Standards:**
- WCAG 2.1 Quick Reference: https://www.w3.org/WAI/WCAG21/quickref/
- WAI-ARIA Authoring Practices: https://www.w3.org/WAI/ARIA/apg/

---

**Last Updated:** November 17, 2025
**Maintained By:** Hive Mind Research Agent
**Next Review:** After P0 implementation (Week 2)
