# Voice Preview Feature Integration Guide

## Overview
The voice preview feature allows users to test and hear voice samples before generating videos. It uses the Web Speech API for browser-based text-to-speech preview.

## Files Created/Modified

### 1. New Files
- **`app/static/voice-preview.js`** - Main voice preview JavaScript module
- **`docs/voice-preview-integration.md`** - This documentation file

### 2. Modified Files
- **`app/static/style.css`** - Added voice preview button styles
- **`app/templates/base.html`** - Added voice-preview.js script reference
- **`app/templates/create.html`** - Added preview buttons to voice selections

## Implementation Details

### JavaScript Module (`voice-preview.js`)

#### Core Features
1. **VoicePreview Class**: Main class managing all preview functionality
2. **Voice Mapping**: Maps our voice IDs to browser voice names
3. **Sample Texts**: Three sample text variants (short, medium, conversation)
4. **Web Speech API Integration**: Uses browser's built-in TTS engine

#### Key Methods
```javascript
// Preview a voice
window.voicePreview.preview(voiceId, sampleType, buttonElement)

// Stop current preview
window.voicePreview.stop()

// Create preview button
window.voicePreview.createPreviewButton(voiceId, compact)

// Initialize all previews on page
window.voicePreview.initializeAllPreviews()
```

#### Global Functions
```javascript
// Preview voice (called from Alpine.js)
previewVoice(voiceId, buttonElement)

// Stop preview
stopVoicePreview()
```

### CSS Styles (`style.css`)

#### Button Classes
- `.preview-btn` - Full preview button with icon and text
- `.preview-btn-compact` - Compact icon-only button
- `.voice-select-wrapper` - Wrapper for select + preview button

#### States
- Default: Blue gradient background
- Hover: Darker blue with shadow
- Playing: Orange gradient with pulse animation
- Disabled: Grayed out

### HTML Integration (`create.html`)

#### Locations with Preview Buttons

1. **Single Video Mode - Voice Tracks**
   - Location: Lines 355-378
   - Button type: Compact
   - Functionality: Preview each voice track individually

2. **Video Set Mode - Narrator Voice**
   - Location: Lines 701-720
   - Button type: Compact
   - Functionality: Preview the global narrator voice

3. **Multilingual Mode - Voice per Language**
   - Location: Lines 961-982
   - Button type: Compact
   - Functionality: Preview voice for each language

## Usage

### For Users

1. **Select a voice** from the dropdown
2. **Click the speaker icon (🔊)** next to the dropdown
3. **Listen to the preview** (3-5 second sample)
4. **Click again** to stop playback

### For Developers

#### Adding Preview to a New Voice Select

```html
<!-- Wrap select in flex container -->
<div class="flex items-center gap-2">
    <select x-model="yourVoiceVar" class="flex-1">
        <option value="male">Andrew (Male)</option>
        <option value="female">Aria (Female)</option>
    </select>

    <!-- Add preview button -->
    <button @click="previewVoice(yourVoiceVar, $event.target)"
            type="button"
            class="preview-btn-compact"
            title="Preview voice">
        <span class="preview-icon">🔊</span>
    </button>
</div>
```

#### Custom Sample Text

```javascript
// Modify in voice-preview.js
this.sampleTexts = {
    short: "Your short sample text",
    medium: "Your medium sample text",
    conversation: "Your conversational sample"
};
```

## Browser Compatibility

### Supported Browsers
- ✅ Chrome/Edge (Chromium) - Full support
- ✅ Firefox - Full support
- ✅ Safari - Full support
- ⚠️ IE11 - Not supported (no Web Speech API)

### Fallback Behavior
If Web Speech API is not available:
- Preview button remains visible
- Shows notification: "Voice preview not available in this browser"
- No error thrown

## Voice Mapping

The system maps our voice IDs to browser voices:

| Voice ID | Browser Voice Names | Fallback |
|----------|-------------------|----------|
| `male` | Google US English, Microsoft David, Alex | First male voice |
| `male_warm` | Google UK English Male, Microsoft Mark | First male voice |
| `female` | Google US English Female, Microsoft Zira, Samantha | First female voice |
| `female_friendly` | Google UK English Female, Microsoft Hazel, Victoria | First female voice |

## Testing

### Manual Testing Steps

1. **Open the create page**: Navigate to `/create`
2. **Test Single Video Mode**:
   - Add multiple voice tracks
   - Click preview on each track
   - Verify different voices play
3. **Test Video Set Mode**:
   - Select different narrator voices
   - Click preview button
   - Verify voice changes
4. **Test Multilingual Mode**:
   - Add multiple target languages
   - Preview voice for each language
   - Verify correct voice per language

### Automated Testing (Future)

```javascript
// Example test
test('Voice preview plays and stops', async () => {
    const preview = new VoicePreview();
    const button = document.createElement('button');

    preview.preview('male', 'short', button);
    expect(preview.isPlaying).toBe(true);

    preview.stop();
    expect(preview.isPlaying).toBe(false);
});
```

## Performance Considerations

1. **Lazy Loading**: Voice preview script loads after Alpine.js
2. **No External Dependencies**: Uses only browser APIs
3. **Minimal CSS**: ~100 lines of CSS for all styles
4. **Event Delegation**: Single global instance manages all buttons
5. **Auto-cleanup**: Stops previous preview when starting new one

## Accessibility

1. **Keyboard Support**: Preview buttons are keyboard accessible
2. **ARIA Labels**: Title attributes for screen readers
3. **Visual Feedback**: Clear playing state with animation
4. **Focus States**: Standard focus rings on buttons

## Known Limitations

1. **Voice Quality**: Browser TTS quality varies by platform
2. **Voice Availability**: Not all browser voices match our production voices
3. **Language Support**: Browser voice availability varies by OS
4. **No Streaming**: Cannot preview actual voice from production TTS service
5. **Network Independent**: Previews work offline (using local browser voices)

## Future Enhancements

### Short-term
- [ ] Add volume control
- [ ] Add speed control
- [ ] Save last preview preference
- [ ] Add more sample texts per voice type

### Long-term
- [ ] Server-side preview with actual production voices
- [ ] Cache audio samples for faster previews
- [ ] Custom sample text input
- [ ] Preview with actual scene text
- [ ] Multi-language sample text

## Troubleshooting

### Preview not working
1. Check browser console for errors
2. Verify Web Speech API support: `'speechSynthesis' in window`
3. Check browser permissions (some browsers require user interaction)

### Wrong voice playing
1. Check voice mapping in `voice-preview.js`
2. Verify browser has requested voice installed
3. Try refreshing the page to reload voices

### Button not appearing
1. Verify `voice-preview.js` is loaded
2. Check Alpine.js is initialized
3. Verify CSS classes are applied correctly

## Support

For issues or questions:
1. Check browser console for errors
2. Review this documentation
3. Test in different browser
4. Report issue with browser/OS details
