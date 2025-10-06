/**
 * Voice Preview System for Video Generator
 * Provides real-time voice previews using Web Speech API
 */

class VoicePreview {
    constructor() {
        this.synth = window.speechSynthesis;
        this.currentUtterance = null;
        this.isPlaying = false;
        this.voices = [];

        // Sample texts for different scenarios
        this.sampleTexts = {
            short: "Hello, this is a sample of this voice.",
            medium: "Welcome to our video tutorial. This voice will guide you through the content with clear and engaging narration.",
            conversation: "Hi there! I'm here to help you learn. Let's explore this topic together."
        };

        // Voice mapping (maps our voice IDs to browser voice names)
        this.voiceMapping = {
            'male': ['Google US English', 'Microsoft David', 'Alex', 'male'],
            'male_warm': ['Google UK English Male', 'Microsoft Mark', 'male'],
            'female': ['Google US English Female', 'Microsoft Zira', 'Samantha', 'female'],
            'female_friendly': ['Google UK English Female', 'Microsoft Hazel', 'Victoria', 'female']
        };

        // Load voices when ready
        this.loadVoices();
        if (this.synth.onvoiceschanged !== undefined) {
            this.synth.onvoiceschanged = () => this.loadVoices();
        }
    }

    /**
     * Load available browser voices
     */
    loadVoices() {
        this.voices = this.synth.getVoices();
    }

    /**
     * Get best matching voice from browser
     */
    getBestVoice(voiceId) {
        if (this.voices.length === 0) {
            this.loadVoices();
        }

        const preferredNames = this.voiceMapping[voiceId] || [];

        // Try to find exact match
        for (const name of preferredNames) {
            const voice = this.voices.find(v => v.name.includes(name));
            if (voice) return voice;
        }

        // Fallback to gender-based selection
        const isMale = voiceId.includes('male') && !voiceId.includes('fe');
        const fallback = this.voices.find(v => {
            const name = v.name.toLowerCase();
            return isMale ?
                (name.includes('male') && !name.includes('female')) || name.includes('david') || name.includes('mark') :
                name.includes('female') || name.includes('zira') || name.includes('samantha');
        });

        // Last resort: use first available voice
        return fallback || this.voices[0] || null;
    }

    /**
     * Preview a voice with sample text
     */
    preview(voiceId, sampleType = 'short', buttonElement = null) {
        // Stop any currently playing preview
        this.stop();

        // Get the best matching voice
        const voice = this.getBestVoice(voiceId);
        if (!voice) {
            this.showNotification('Voice preview not available in this browser', 'warning');
            return;
        }

        // Create utterance
        const text = this.sampleTexts[sampleType] || this.sampleTexts.short;
        this.currentUtterance = new SpeechSynthesisUtterance(text);
        this.currentUtterance.voice = voice;
        this.currentUtterance.rate = 1.0;
        this.currentUtterance.pitch = 1.0;
        this.currentUtterance.volume = 1.0;

        // Update UI on start
        this.currentUtterance.onstart = () => {
            this.isPlaying = true;
            if (buttonElement) {
                this.updateButtonState(buttonElement, 'playing');
            }
        };

        // Update UI on end
        this.currentUtterance.onend = () => {
            this.isPlaying = false;
            if (buttonElement) {
                this.updateButtonState(buttonElement, 'idle');
            }
        };

        // Handle errors
        this.currentUtterance.onerror = (event) => {
            this.isPlaying = false;
            if (buttonElement) {
                this.updateButtonState(buttonElement, 'idle');
            }
            this.showNotification('Voice preview failed', 'error');
        };

        // Speak
        this.synth.speak(this.currentUtterance);
    }

    /**
     * Stop current preview
     */
    stop() {
        if (this.synth.speaking) {
            this.synth.cancel();
        }
        this.isPlaying = false;
        this.currentUtterance = null;
    }

    /**
     * Update button visual state
     */
    updateButtonState(button, state) {
        const icon = button.querySelector('.preview-icon');
        const text = button.querySelector('.preview-text');

        if (state === 'playing') {
            button.classList.add('playing');
            button.disabled = false; // Allow clicking to stop
            if (icon) icon.textContent = '⏸️';
            if (text) text.textContent = 'Playing...';
        } else {
            button.classList.remove('playing');
            button.disabled = false;
            if (icon) icon.textContent = '🔊';
            if (text) text.textContent = 'Preview';
        }
    }

    /**
     * Show notification (integrates with existing notification system)
     */
    showNotification(message, type = 'info') {
        window.dispatchEvent(new CustomEvent('show-message', {
            detail: { message, type }
        }));
    }

    /**
     * Create preview button element
     */
    createPreviewButton(voiceId, compact = false) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = compact ?
            'preview-btn-compact' :
            'preview-btn';

        const icon = document.createElement('span');
        icon.className = 'preview-icon';
        icon.textContent = '🔊';

        const text = document.createElement('span');
        text.className = 'preview-text';
        text.textContent = compact ? '' : 'Preview';

        button.appendChild(icon);
        if (!compact) button.appendChild(text);

        // Add click handler
        button.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();

            if (this.isPlaying) {
                this.stop();
                this.updateButtonState(button, 'idle');
            } else {
                this.preview(voiceId, 'short', button);
            }
        });

        return button;
    }

    /**
     * Add preview buttons to all voice selects on page
     */
    initializeAllPreviews() {
        // Find all voice select elements
        const voiceSelects = document.querySelectorAll('select[x-model*="voice"]');

        voiceSelects.forEach(select => {
            const container = select.parentElement;

            // Check if preview button already exists
            if (container.querySelector('.preview-btn, .preview-btn-compact')) {
                return;
            }

            // Create wrapper if needed
            if (!container.classList.contains('voice-select-wrapper')) {
                const wrapper = document.createElement('div');
                wrapper.className = 'voice-select-wrapper';
                container.insertBefore(wrapper, select);
                wrapper.appendChild(select);

                // Add preview button
                const voiceId = select.value || 'male';
                const previewBtn = this.createPreviewButton(voiceId, true);
                wrapper.appendChild(previewBtn);

                // Update button when select changes
                select.addEventListener('change', (e) => {
                    const newVoiceId = e.target.value;
                    previewBtn.onclick = (btnEvent) => {
                        btnEvent.preventDefault();
                        btnEvent.stopPropagation();
                        if (this.isPlaying) {
                            this.stop();
                            this.updateButtonState(previewBtn, 'idle');
                        } else {
                            this.preview(newVoiceId, 'short', previewBtn);
                        }
                    };
                });
            }
        });
    }
}

// Initialize global instance
window.voicePreview = new VoicePreview();

// Auto-initialize on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        setTimeout(() => window.voicePreview.initializeAllPreviews(), 500);
    });
} else {
    setTimeout(() => window.voicePreview.initializeAllPreviews(), 500);
}

// Re-initialize when Alpine.js updates (for dynamic content)
document.addEventListener('alpine:initialized', () => {
    setTimeout(() => window.voicePreview.initializeAllPreviews(), 500);
});

// Export for use in Alpine.js components
window.previewVoice = function(voiceId, buttonElement = null) {
    window.voicePreview.preview(voiceId, 'short', buttonElement);
};

window.stopVoicePreview = function() {
    window.voicePreview.stop();
};
