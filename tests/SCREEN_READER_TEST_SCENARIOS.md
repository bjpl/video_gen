# Screen Reader Test Scenarios - P0 Testing
**Video Gen Project | WCAG AA Compliance**
*Created: 2025-11-17 | Tester Agent*

---

## Purpose

Comprehensive screen reader testing scenarios for NVDA, JAWS, and VoiceOver.
Ensures video generation web UI is accessible to blind and visually impaired users.

---

## Prerequisites

### Screen Reader Software
- **NVDA** (Windows): https://www.nvaccess.org/download/
- **JAWS** (Windows): https://www.freedomscientific.com/products/software/jaws/
- **VoiceOver** (macOS): Built-in (Cmd+F5 to toggle)

### Testing Environment
- Supported browsers: Chrome, Firefox, Safari
- Keyboard-only navigation (no mouse)
- Audio output enabled
- Screen reader activated before starting tests

---

## Test Scenarios

### Scenario 1: First-Time User - Homepage Landing

**User Goal:** Understand what the site does and how to get started

**Steps:**
1. Navigate to homepage (http://localhost:8000)
2. Let screen reader read page automatically

**Expected Announcements:**
```
[Page Title]: "Video Generator - Create Educational Videos"
[Main Heading]: "Welcome to Video Generator"
[Description]: "Professional video generation system supporting 28+ languages"
[Navigation]: "Main navigation with 4 items: Home, Create Video, Examples, Documentation"
[Main Content]: Begins reading primary content
[Call-to-Action]: "Create Your First Video" button
```

**Pass Criteria:**
- [ ] Page title is descriptive and meaningful
- [ ] H1 heading clearly describes page purpose
- [ ] Navigation landmark announced correctly
- [ ] Main content landmark identified
- [ ] Primary action button is easily findable
- [ ] No "unlabeled" or "button" generic announcements

**Tester Notes:**
_Record actual announcements and any issues encountered_

---

### Scenario 2: Creating a New Video - Form Navigation

**User Goal:** Fill out video creation form successfully

**Steps:**
1. Activate "Create Video" button/link
2. Navigate through form using Tab key
3. Fill in each field
4. Submit form

**Expected Announcements for Each Field:**
```
[Field 1]: "Video title, edit text, required"
[Field 2]: "Video description, multiline edit text"
[Field 3]: "Language selection, combobox, English selected"
[Field 4]: "Voice selection, combobox, Christopher Neural selected"
[Field 5]: "Upload document, button, or drag and drop files here"
[Submit]: "Generate Video, button"
```

**Expected Form Errors (if invalid):**
```
[Error Summary]: "Form has 2 errors. Please correct the following:"
[Error 1]: "Video title is required"
[Error 2]: "Please select a language"
[Focus moves to]: First error field
[Field with Error]: "Video title, edit text, required, invalid entry, Video title is required"
```

**Pass Criteria:**
- [ ] Each form field has descriptive label
- [ ] Required fields announced as "required"
- [ ] Field type announced correctly (edit text, combobox, button)
- [ ] Field hints/instructions announced
- [ ] Current field value announced
- [ ] Validation errors announced clearly
- [ ] Error summary uses ARIA live region
- [ ] Focus moves to first error field
- [ ] Field-level errors associated with fields (aria-describedby)

**Tester Notes:**
_Record form navigation flow and error announcements_

---

### Scenario 3: Video Generation Progress - Dynamic Updates

**User Goal:** Understand video generation progress and status

**Steps:**
1. Submit valid video creation form
2. Wait for progress updates
3. Listen for completion announcement

**Expected Announcements:**
```
[Initial]: "Generating video, please wait"
[Progress Update 1]: "20% complete, analyzing document"
[Progress Update 2]: "40% complete, generating scenes"
[Progress Update 3]: "60% complete, rendering video"
[Progress Update 4]: "80% complete, adding audio"
[Completion]: "Video generated successfully. Click to preview."
```

**Pass Criteria:**
- [ ] Progress updates use ARIA live region (polite or assertive)
- [ ] Each stage clearly announced
- [ ] Percentage completion announced
- [ ] Success/error messages announced automatically
- [ ] User not interrupted excessively (polite updates)
- [ ] Final status clearly communicated
- [ ] Next action suggested (e.g., "Click to preview")

**Tester Notes:**
_Record timing and clarity of progress announcements_

---

### Scenario 4: Video Player Controls - Playback Management

**User Goal:** Play, pause, and control generated video

**Steps:**
1. Tab to video player
2. Navigate through player controls
3. Use controls to play, pause, adjust volume

**Expected Announcements:**
```
[Player Region]: "Video player region"
[Play Button]: "Play, button"
[After activation]: "Playing"
[Pause Button]: "Pause, button"
[Volume Control]: "Volume slider, 75 percent"
[Mute Button]: "Mute, button, not pressed"
[After mute]: "Mute, button, pressed"
[Progress Bar]: "Seek slider, 30 seconds of 2 minutes"
[Playback Rate]: "Playback speed, button, 1x"
[Captions]: "Captions, button, captions off"
[Fullscreen]: "Fullscreen, button, not fullscreen"
```

**Keyboard Controls:**
```
Space/Enter: Play/Pause
Arrow Up/Down: Volume +/-
Arrow Left/Right: Seek backward/forward
M: Mute/Unmute
F: Fullscreen toggle
C: Captions toggle
```

**Pass Criteria:**
- [ ] Video player identified as landmark
- [ ] All controls have descriptive labels
- [ ] Button states announced (pressed/not pressed, playing/paused)
- [ ] Slider controls announce current value and range
- [ ] Keyboard shortcuts work without screen reader interference
- [ ] Focus trap stays within modal controls when fullscreen
- [ ] Time information announced clearly
- [ ] Captions status announced

**Tester Notes:**
_Test keyboard shortcuts and control announcements_

---

### Scenario 5: Navigation - Site Structure Understanding

**User Goal:** Navigate efficiently using heading structure and landmarks

**Steps:**
1. Use screen reader's heading navigation (H key in NVDA/JAWS)
2. Use landmark navigation (D key)
3. Navigate through page structure

**Expected Structure:**
```
[Landmarks]:
- Banner (site header)
- Navigation (main menu)
- Main (primary content)
- Complementary (sidebar, if present)
- Contentinfo (footer)

[Heading Hierarchy]:
H1: "Create Professional Videos" (1 per page)
  H2: "Choose Your Input Method"
    H3: "Upload Document"
    H3: "Paste Text"
    H3: "YouTube URL"
  H2: "Configuration Options"
    H3: "Video Settings"
    H3: "Audio Settings"
  H2: "Generated Videos"
    H3: [Individual video titles]
```

**Pass Criteria:**
- [ ] Heading hierarchy is logical (no skipped levels)
- [ ] Only one H1 per page
- [ ] Headings describe section content accurately
- [ ] All landmarks properly labeled
- [ ] Skip to main content link available
- [ ] Navigation landmark contains site navigation
- [ ] Complementary landmark used appropriately
- [ ] Footer uses contentinfo landmark

**Tester Notes:**
_Map complete heading hierarchy and landmarks_

---

### Scenario 6: Error Recovery - Validation and Help

**User Goal:** Understand and correct form validation errors

**Steps:**
1. Submit form with multiple errors
2. Navigate through errors
3. Correct errors
4. Resubmit successfully

**Expected Error Handling:**
```
[On Submit]:
"Form submission failed. 3 errors found. Please correct the following:"
[Focus moves to error summary]

[Error Summary]:
"Error 1: Video title is required, link"
"Error 2: Invalid language selection, link"
"Error 3: File upload failed, link"

[Clicking error link]:
Focus moves to corresponding field

[Field with Error]:
"Video title, edit text, required, invalid entry"
"Error: Video title must be between 3 and 100 characters"
[aria-invalid="true" and aria-describedby points to error message]

[After Correction]:
Field no longer announced as invalid
Error message cleared

[Successful Submission]:
"Video created successfully. Redirecting to video page."
```

**Pass Criteria:**
- [ ] Error summary announced via ARIA live region
- [ ] Error count announced
- [ ] Each error has link to corresponding field
- [ ] Clicking error link moves focus
- [ ] Field errors associated with fields (aria-describedby)
- [ ] Fields marked as invalid (aria-invalid)
- [ ] Error messages are specific and actionable
- [ ] Success confirmation announced
- [ ] Inline validation provides immediate feedback

**Tester Notes:**
_Test error announcement timing and clarity_

---

### Scenario 7: Multilingual Content - Language Selection

**User Goal:** Generate video in different language

**Steps:**
1. Navigate to language selection dropdown
2. Browse available languages
3. Select target language
4. Verify selection

**Expected Announcements:**
```
[Language Dropdown]:
"Language selection, combobox, English selected, press Alt+Down to open"

[Opening Dropdown]:
"List with 28 items"

[Navigating Options]:
"English, 1 of 28"
"Spanish, 2 of 28"
"French, 3 of 28"
...

[Selection]:
"Spanish selected"

[Confirmation]:
"Language changed to Spanish"
```

**Pass Criteria:**
- [ ] Dropdown announced with current selection
- [ ] Total number of options announced
- [ ] Each option announced with position (X of Y)
- [ ] Selection change announced
- [ ] Keyboard navigation works (Arrow keys, type-ahead)
- [ ] Can close dropdown with Escape
- [ ] Instructions for opening dropdown provided

**Tester Notes:**
_Test with both NVDA and JAWS for consistency_

---

### Scenario 8: Data Tables - Generated Video List

**User Goal:** Review list of previously generated videos

**Steps:**
1. Navigate to "My Videos" section
2. Navigate through video table
3. Access video actions

**Expected Table Announcements:**
```
[Table Region]:
"Table with 5 rows and 4 columns"

[Table Headers]:
Row 1: "Video Title, column header"
Row 2: "Language, column header"
Row 3: "Created Date, column header"
Row 4: "Actions, column header"

[Table Cells]:
Row 1, Cell 1: "Introduction to Python, row 1, column 1"
Row 1, Cell 2: "English, row 1, column 2"
Row 1, Cell 3: "November 15, 2025, row 1, column 3"
Row 1, Cell 4: "Actions, row 1, column 4, View, Edit, Delete buttons"

[Action Buttons]:
"View Introduction to Python, button"
"Edit Introduction to Python, button"
"Delete Introduction to Python, button"
```

**Pass Criteria:**
- [ ] Table dimensions announced (rows and columns)
- [ ] Column headers properly marked (<th scope="col">)
- [ ] Row headers if applicable (<th scope="row">)
- [ ] Cell position announced (row X, column Y)
- [ ] Action buttons have context (include video title)
- [ ] Table has caption or aria-label
- [ ] Can navigate by row/column (Ctrl+Alt+Arrows)

**Tester Notes:**
_Verify table navigation patterns_

---

### Scenario 9: Modal Dialogs - Confirming Actions

**User Goal:** Confirm video deletion safely

**Steps:**
1. Activate "Delete" button for a video
2. Interact with confirmation dialog
3. Confirm or cancel action

**Expected Dialog Announcements:**
```
[Dialog Opens]:
"Confirm Deletion, dialog"
[Focus moves to dialog]

[Dialog Content]:
"Are you sure you want to delete 'Introduction to Python'? This action cannot be undone."

[Buttons]:
"Cancel, button"
"Delete Video, button, danger"

[Background]:
Inert (cannot be accessed until dialog closed)

[Closing Dialog]:
"Dialog closed"
[Focus returns to Delete button]
```

**Pass Criteria:**
- [ ] Dialog announced as "dialog" role
- [ ] Focus moves to dialog on open
- [ ] Dialog title announced
- [ ] Background content inert (aria-hidden)
- [ ] Can close dialog with Escape key
- [ ] Focus returns to trigger element on close
- [ ] Tab key stays within dialog (focus trap)
- [ ] Destructive action clearly identified
- [ ] Confirmation question is clear

**Tester Notes:**
_Test focus management and keyboard traps_

---

### Scenario 10: ARIA Live Regions - Status Updates

**User Goal:** Receive non-intrusive status updates

**Steps:**
1. Perform action that triggers background process
2. Wait for status updates
3. Complete task

**Expected Live Region Behavior:**
```
[Polite Updates (aria-live="polite")]:
- Progress updates
- Success confirmations
- Info messages
[Announced after current speech completes]

[Assertive Updates (aria-live="assertive")]:
- Critical errors
- Time-sensitive warnings
- Security alerts
[Interrupts current speech]

[Off (aria-live="off")]:
- Visual-only decorative content
[Not announced]
```

**Test Cases:**
```
[File Upload]:
"File upload started" (polite)
"Uploading: 25%" (polite)
"Uploading: 50%" (polite)
"Upload complete" (polite)

[Error]:
"Upload failed: File too large" (assertive)

[Auto-save]:
"Draft saved" (polite)
```

**Pass Criteria:**
- [ ] Status updates use appropriate politeness level
- [ ] Critical errors use assertive
- [ ] Progress uses polite
- [ ] Updates are clear and concise
- [ ] No announcement spam (throttled updates)
- [ ] Success and error states clearly distinguished

**Tester Notes:**
_Monitor announcement frequency and appropriateness_

---

## Testing Checklist

### Pre-Testing Setup
- [ ] Screen reader installed and configured
- [ ] Browser extensions disabled (can interfere)
- [ ] Audio output tested
- [ ] Keyboard shortcuts reviewed
- [ ] Test environment accessible (localhost or staging)

### During Testing
- [ ] Test with keyboard only (unplug mouse)
- [ ] Record all announcements verbatim
- [ ] Note unexpected behavior
- [ ] Document workarounds found
- [ ] Take audio recordings if possible
- [ ] Screenshot visual focus indicators

### Post-Testing
- [ ] Document all issues found
- [ ] Rate severity (Critical, High, Medium, Low)
- [ ] Suggest fixes for each issue
- [ ] Create bug reports with WCAG references
- [ ] Share findings with development team

---

## Common Issues to Watch For

### Announcement Issues
- [ ] "Unlabeled" or "button" without context
- [ ] Missing alt text ("image" without description)
- [ ] Empty links or buttons
- [ ] Redundant announcements
- [ ] Cryptic abbreviations (unexpanded acronyms)

### Navigation Issues
- [ ] Keyboard traps (can't Tab out)
- [ ] Skip links missing or non-functional
- [ ] No focus indicator visible
- [ ] Illogical tab order
- [ ] Missing landmarks

### Form Issues
- [ ] Labels not associated with inputs
- [ ] Required fields not announced
- [ ] Error messages not connected to fields
- [ ] No error summary on validation failure
- [ ] Autocomplete suggestions not announced

### Dynamic Content Issues
- [ ] Updates not announced (missing aria-live)
- [ ] Focus lost after content change
- [ ] Loading states not communicated
- [ ] Modals don't trap focus properly

---

## Screen Reader Keyboard Shortcuts

### NVDA (Windows)
```
H: Next heading
Shift+H: Previous heading
D: Next landmark
Shift+D: Previous landmark
B: Next button
K: Next link
F: Next form field
T: Next table
Insert+F7: Elements list
Insert+Space: Focus/Browse mode toggle
```

### JAWS (Windows)
```
H: Next heading
Shift+H: Previous heading
R: Next region/landmark
T: Next table
F: Next form field
B: Next button
; (semicolon): Next landmark
Insert+F6: Headings list
Insert+F5: Form fields list
```

### VoiceOver (macOS)
```
VO+Command+H: Next heading
VO+Command+J: Next form control
VO+Command+L: Next link
VO+Command+X: Next list
VO+U: Rotor (navigation menu)
VO+Space: Activate element
```

---

## Reporting Format

### Issue Report Template
```markdown
**Issue ID:** ARIA-001
**Severity:** High
**Scenario:** Scenario 2 - Form Navigation
**Element:** Video title input field
**Expected:** "Video title, edit text, required"
**Actual:** "Edit text" (no label, not marked required)
**WCAG Criteria:** 4.1.2 Name, Role, Value (Level A)
**Impact:** User cannot identify field purpose
**Fix:** Add <label for="title">Video Title</label> and aria-required="true"
**Screenshot:** [attach screenshot]
**Audio Recording:** [attach recording]
```

---

## Success Criteria Summary

A page passes screen reader testing when:

1. **Structure**
   - Logical heading hierarchy
   - Proper landmarks
   - Skip to main content link

2. **Forms**
   - All fields labeled
   - Required fields marked
   - Errors properly announced and associated
   - Validation feedback immediate and clear

3. **Interactive Elements**
   - Buttons describe action
   - Links describe destination
   - States announced (pressed, expanded, selected)
   - Keyboard accessible

4. **Dynamic Content**
   - ARIA live regions for updates
   - Focus managed on changes
   - Loading states communicated

5. **Media**
   - Player controls labeled
   - Captions available
   - Transcript provided (where applicable)

---

## Resources

### WCAG Guidelines
- WCAG 2.1 Level AA: https://www.w3.org/WAI/WCAG21/quickref/?levels=a,aa
- ARIA Authoring Practices: https://www.w3.org/WAI/ARIA/apg/

### Testing Tools
- NVDA: https://www.nvaccess.org/
- JAWS: https://www.freedomscientific.com/products/software/jaws/
- WebAIM Articles: https://webaim.org/articles/

### Screen Reader Support
- NVDA User Guide: https://www.nvaccess.org/files/nvda/documentation/userGuide.html
- JAWS Support: https://support.freedomscientific.com/

---

*Document Version: 1.0*
*Last Updated: 2025-11-17*
*Next Review: After P0.1 fix completion*
