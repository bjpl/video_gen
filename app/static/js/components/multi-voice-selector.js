/**
 * MultiVoiceSelector Alpine.js Component
 *
 * A feature-rich voice selection component with:
 * - Multiple voice selection per language
 * - Voice preview with audio playback
 * - Visual waveform animation during preview
 * - Voice rotation explanation
 * - Integration with MultiLanguageSelector
 * - Validation (minimum 1 voice per language)
 *
 * @requires Alpine.js
 * @requires /static/js/store/app-state.js
 * @requires /static/js/utils/voice-preview.js
 */

document.addEventListener('alpine:init', () => {
    Alpine.data('multiVoiceSelector', (config = {}) => ({
        // ==================== CONFIGURATION ====================

        // API endpoint for fetching voices
        voicesEndpointBase: config.voicesEndpointBase || '/api/languages',

        // Voice preview endpoint
        previewEndpoint: config.previewEndpoint || '/api/voice-preview',

        // Minimum/maximum voices per language
        minVoicesPerLang: config.minVoicesPerLang || 1,
        maxVoicesPerLang: config.maxVoicesPerLang || 4,

        // Callback functions
        onVoicesChanged: config.onVoicesChanged || null,
        onError: config.onError || null,

        // Cache configuration
        cacheTTL: config.cacheTTL || 5 * 60 * 1000, // 5 minutes default

        // ==================== STATE ====================

        // Selected languages (reactive from language selector)
        selectedLanguages: config.initialLanguages || ['en'],

        // Map of language code to selected voice IDs
        languageVoices: {},

        // Map of language code to available voice objects
        availableVoices: {},

        // Map of language code to loading state
        isLoading: {},

        // General error state
        error: null,

        // Voice preview state
        previewAudio: null,
        previewingVoice: null, // { lang, voiceId }
        previewState: 'idle', // 'idle', 'loading', 'playing', 'error'

        // ==================== INITIALIZATION ====================

        init() {
            console.log('[MultiVoiceSelector] Component initialized');

            // Watch for changes in language selector's global store
            if (Alpine.store('appState')?.languages) {
                // Get initial languages from store
                const storeLangs = Alpine.store('appState').languages.selected;
                if (storeLangs && storeLangs.length > 0) {
                    this.selectedLanguages = [...storeLangs];
                }

                // Watch store for changes
                this.$watch('$store.appState.languages.selected', (newLangs) => {
                    console.log('[MultiVoiceSelector] Languages changed from store:', newLangs);
                    if (newLangs && Array.isArray(newLangs)) {
                        this.handleLanguageChange(newLangs, this.selectedLanguages);
                        this.selectedLanguages = [...newLangs];
                    }
                });
            }

            // Initialize state for each selected language
            this.selectedLanguages.forEach(lang => {
                this.languageVoices[lang] = [];
                this.isLoading[lang] = false;
                this.fetchVoicesForLanguage(lang);
            });

            // Watch for changes in selected languages
            this.$watch('selectedLanguages', (newLangs, oldLangs) => {
                this.handleLanguageChange(newLangs, oldLangs || []);
            });

            // Listen for language-selector events (backup method)
            window.addEventListener('languages-changed', (event) => {
                console.log('[MultiVoiceSelector] languages-changed event:', event.detail);
                if (event.detail && event.detail.languages) {
                    this.selectedLanguages = event.detail.languages;
                }
            });

            // Restore voice state from global store if available
            if (Alpine.store('appState')?.videoConfig?.languageVoices) {
                const stored = Alpine.store('appState').videoConfig.languageVoices;
                Object.keys(stored).forEach(lang => {
                    if (this.selectedLanguages.includes(lang)) {
                        this.languageVoices[lang] = stored[lang];
                    }
                });
            }
        },

        // ==================== LANGUAGE CHANGE HANDLING ====================

        /**
         * Handle changes in selected languages
         */
        handleLanguageChange(newLangs, oldLangs) {
            // Fetch voices for newly added languages
            newLangs.forEach(lang => {
                if (!oldLangs.includes(lang)) {
                    if (!this.availableVoices[lang]) {
                        this.fetchVoicesForLanguage(lang);
                    }
                    if (!this.languageVoices[lang]) {
                        this.languageVoices[lang] = [];
                    }
                }
            });

            // Clean up removed languages
            oldLangs.forEach(lang => {
                if (!newLangs.includes(lang)) {
                    delete this.languageVoices[lang];
                    delete this.isLoading[lang];
                    // Keep availableVoices cached for potential re-selection
                }
            });

            this.updateGlobalStore();
        },

        // ==================== API METHODS ====================

        /**
         * Fetch available voices for a specific language with caching
         */
        async fetchVoicesForLanguage(langCode) {
            if (this.isLoading[langCode]) {
                console.log(`[MultiVoiceSelector] Already loading voices for ${langCode}`);
                return;
            }

            const cacheKey = `voices:${langCode}`;

            // Check cache first (via global voiceCache or apiCache)
            const cache = window.voiceCache || window.apiCache;
            if (cache) {
                const cached = cache.get(cacheKey);
                if (cached) {
                    this.availableVoices[langCode] = cached;

                    // Auto-select first voice if none selected
                    if (!this.languageVoices[langCode] || this.languageVoices[langCode].length === 0) {
                        if (this.availableVoices[langCode].length > 0) {
                            this.languageVoices[langCode] = [this.availableVoices[langCode][0].id];
                            this.emitVoicesChanged(langCode);
                        }
                    }

                    console.log(`[MultiVoiceSelector] Loaded ${this.availableVoices[langCode].length} voices for ${langCode} from cache`);
                    return;
                }
            }

            this.isLoading[langCode] = true;
            this.error = null;

            try {
                // Use centralized API client if available
                let data;
                if (window.api && window.api.languages) {
                    data = await window.api.languages.getVoices(langCode);
                } else {
                    const response = await fetch(`${this.voicesEndpointBase}/${langCode}/voices`);

                    if (!response.ok) {
                        throw new Error(`Failed to fetch voices: ${response.statusText}`);
                    }

                    data = await response.json();
                }

                const voices = data.voices || [];

                // Cache the result
                if (cache) {
                    cache.set(cacheKey, voices, this.cacheTTL);
                }

                this.availableVoices[langCode] = voices;

                // Auto-select first voice if none selected
                if (!this.languageVoices[langCode] || this.languageVoices[langCode].length === 0) {
                    if (this.availableVoices[langCode].length > 0) {
                        this.languageVoices[langCode] = [this.availableVoices[langCode][0].id];
                        this.emitVoicesChanged(langCode);
                    }
                }

                console.log(`[MultiVoiceSelector] Loaded ${this.availableVoices[langCode].length} voices for ${langCode} from API`);

            } catch (error) {
                console.error(`[MultiVoiceSelector] Error fetching voices for ${langCode}:`, error);
                this.error = `Failed to load voices for ${langCode}. ${error.message}`;

                // Fallback to default voices
                this.availableVoices[langCode] = this.getDefaultVoices(langCode);

                // Auto-select first default voice
                if (!this.languageVoices[langCode] || this.languageVoices[langCode].length === 0) {
                    this.languageVoices[langCode] = [this.availableVoices[langCode][0].id];
                }

                this.notifyError(this.error);
            } finally {
                this.isLoading[langCode] = false;
            }
        },

        /**
         * Get default voices as fallback
         */
        getDefaultVoices(langCode) {
            return [
                {
                    id: 'male',
                    name: 'Male Voice',
                    description: 'Professional male voice',
                    gender: 'male',
                    sample_url: null
                },
                {
                    id: 'female',
                    name: 'Female Voice',
                    description: 'Clear female voice',
                    gender: 'female',
                    sample_url: null
                }
            ];
        },

        // ==================== VOICE SELECTION METHODS ====================

        /**
         * Toggle a voice selection for a language
         */
        toggleVoice(langCode, voiceId) {
            if (!this.languageVoices[langCode]) {
                this.languageVoices[langCode] = [];
            }

            const voices = this.languageVoices[langCode];
            const index = voices.indexOf(voiceId);

            if (index > -1) {
                // Don't allow removing last voice (minimum 1 required)
                if (voices.length > this.minVoicesPerLang) {
                    voices.splice(index, 1);
                } else {
                    this.notifyError(`At least ${this.minVoicesPerLang} voice required for each language`);
                    this.$dispatch('voice-validation-error', {
                        lang: langCode,
                        error: 'minimum_voices'
                    });
                    return;
                }
            } else {
                // Don't exceed maximum voices
                if (voices.length < this.maxVoicesPerLang) {
                    voices.push(voiceId);
                } else {
                    this.notifyError(`Maximum ${this.maxVoicesPerLang} voices allowed per language`);
                    return;
                }
            }

            // Trigger reactivity by reassigning
            this.languageVoices[langCode] = [...voices];

            this.emitVoicesChanged(langCode);
            this.updateGlobalStore();
        },

        /**
         * Check if a voice is selected
         */
        isVoiceSelected(langCode, voiceId) {
            return (this.languageVoices[langCode] || []).includes(voiceId);
        },

        /**
         * Get count of selected voices for a language
         */
        getSelectedVoiceCount(langCode) {
            return (this.languageVoices[langCode] || []).length;
        },

        /**
         * Select all voices for a language
         */
        selectAllVoices(langCode) {
            const voices = this.availableVoices[langCode] || [];
            const maxToSelect = Math.min(voices.length, this.maxVoicesPerLang);
            this.languageVoices[langCode] = voices.slice(0, maxToSelect).map(v => v.id);

            this.emitVoicesChanged(langCode);
            this.updateGlobalStore();
        },

        /**
         * Clear all voices for a language (keeps minimum)
         */
        clearVoices(langCode) {
            const voices = this.availableVoices[langCode] || [];
            if (voices.length > 0) {
                this.languageVoices[langCode] = [voices[0].id];
            } else {
                this.languageVoices[langCode] = [];
            }

            this.emitVoicesChanged(langCode);
            this.updateGlobalStore();
        },

        // ==================== VOICE INFORMATION METHODS ====================

        /**
         * Get voice display name
         */
        getVoiceName(langCode, voiceId) {
            const voices = this.availableVoices[langCode] || [];
            const voice = voices.find(v => v.id === voiceId);
            return voice?.name || voiceId;
        },

        /**
         * Get voice description
         */
        getVoiceDescription(langCode, voiceId) {
            const voices = this.availableVoices[langCode] || [];
            const voice = voices.find(v => v.id === voiceId);
            return voice?.description || '';
        },

        /**
         * Get voice gender
         */
        getVoiceGender(langCode, voiceId) {
            const voices = this.availableVoices[langCode] || [];
            const voice = voices.find(v => v.id === voiceId);
            return voice?.gender || 'unknown';
        },

        /**
         * Get voice object by ID
         */
        getVoice(langCode, voiceId) {
            const voices = this.availableVoices[langCode] || [];
            return voices.find(v => v.id === voiceId);
        },

        /**
         * Get gender icon
         */
        getGenderIcon(gender) {
            switch (gender) {
                case 'male': return '♂';
                case 'female': return '♀';
                default: return '◎';
            }
        },

        // ==================== VOICE PREVIEW METHODS ====================

        /**
         * Preview a voice (play sample audio)
         */
        async previewVoice(langCode, voiceId) {
            // Stop any existing preview
            this.stopPreview();

            const voice = this.getVoice(langCode, voiceId);
            if (!voice) {
                console.warn(`[MultiVoiceSelector] Voice not found: ${langCode}/${voiceId}`);
                return;
            }

            this.previewingVoice = { lang: langCode, voiceId: voiceId };
            this.previewState = 'loading';

            try {
                let audioUrl = voice.sample_url;

                // If no sample URL, request from API
                if (!audioUrl) {
                    const response = await fetch(this.previewEndpoint, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            language: langCode,
                            voice: voiceId,
                            text: `This is a sample of the ${voice.name} voice.`
                        })
                    });

                    if (!response.ok) {
                        throw new Error('Voice preview not available');
                    }

                    const blob = await response.blob();
                    audioUrl = URL.createObjectURL(blob);
                }

                // Create and play audio
                this.previewAudio = new Audio(audioUrl);

                this.previewAudio.addEventListener('playing', () => {
                    this.previewState = 'playing';
                });

                this.previewAudio.addEventListener('ended', () => {
                    this.previewState = 'idle';
                    this.previewingVoice = null;
                });

                this.previewAudio.addEventListener('error', (e) => {
                    console.error('[MultiVoiceSelector] Audio playback error:', e);
                    this.previewState = 'error';
                    this.previewingVoice = null;
                });

                await this.previewAudio.play();

                // Dispatch preview event
                this.$dispatch('preview-voice', { lang: langCode, voice: voiceId });

            } catch (error) {
                console.error('[MultiVoiceSelector] Voice preview failed:', error);
                this.previewState = 'error';
                this.previewingVoice = null;
                this.notifyError('Voice preview is not available');
            }
        },

        /**
         * Stop voice preview
         */
        stopPreview() {
            if (this.previewAudio) {
                this.previewAudio.pause();
                this.previewAudio.currentTime = 0;

                // Revoke object URL if created
                if (this.previewAudio.src.startsWith('blob:')) {
                    URL.revokeObjectURL(this.previewAudio.src);
                }

                this.previewAudio = null;
            }

            this.previewState = 'idle';
            this.previewingVoice = null;
        },

        /**
         * Check if a specific voice is being previewed
         */
        isPreviewingVoice(langCode, voiceId) {
            return (
                this.previewingVoice?.lang === langCode &&
                this.previewingVoice?.voiceId === voiceId
            );
        },

        /**
         * Check if any voice is currently playing
         */
        isAnyVoicePlaying() {
            return this.previewState === 'playing';
        },

        // ==================== VALIDATION METHODS ====================

        /**
         * Validate all voice selections
         */
        validateVoices() {
            const errors = [];

            this.selectedLanguages.forEach(lang => {
                const voiceCount = this.getSelectedVoiceCount(lang);

                if (voiceCount < this.minVoicesPerLang) {
                    errors.push({
                        lang: lang,
                        error: `At least ${this.minVoicesPerLang} voice required for ${this.getLanguageName(lang)}`
                    });
                }
            });

            if (errors.length > 0) {
                this.$dispatch('voice-validation-error', { errors: errors });
            }

            return errors.length === 0;
        },

        /**
         * Check if a language has valid voice selection
         */
        isLanguageValid(langCode) {
            return this.getSelectedVoiceCount(langCode) >= this.minVoicesPerLang;
        },

        /**
         * Check if all languages have valid voice selections
         */
        allVoicesValid() {
            return this.selectedLanguages.every(lang => this.isLanguageValid(lang));
        },

        // ==================== ROTATION PREVIEW ====================

        /**
         * Get rotation preview text for a language
         */
        getRotationPreview(langCode) {
            const voices = this.languageVoices[langCode] || [];
            if (voices.length <= 1) return '';

            const voiceNames = voices.map(id => this.getVoiceName(langCode, id));
            return voiceNames.join(' → ');
        },

        // ==================== HELPER METHODS ====================

        /**
         * Get language display name
         */
        getLanguageName(langCode) {
            const languageNames = {
                'en': 'English',
                'es': 'Spanish',
                'fr': 'French',
                'de': 'German',
                'it': 'Italian',
                'pt': 'Portuguese',
                'ja': 'Japanese',
                'zh': 'Chinese',
                'ko': 'Korean',
                'ar': 'Arabic',
                'ru': 'Russian',
                'hi': 'Hindi'
            };
            return languageNames[langCode] || langCode.toUpperCase();
        },

        /**
         * Get language flag emoji
         */
        getLanguageFlag(langCode) {
            const flags = {
                'en': '🇺🇸',
                'es': '🇪🇸',
                'fr': '🇫🇷',
                'de': '🇩🇪',
                'it': '🇮🇹',
                'pt': '🇧🇷',
                'ja': '🇯🇵',
                'zh': '🇨🇳',
                'ko': '🇰🇷',
                'ar': '🇸🇦',
                'ru': '🇷🇺',
                'hi': '🇮🇳'
            };
            return flags[langCode] || '🌐';
        },

        // ==================== EVENT DISPATCHING ====================

        /**
         * Emit voices-changed event
         */
        emitVoicesChanged(langCode) {
            this.$dispatch('voices-changed', {
                lang: langCode,
                voices: this.languageVoices[langCode],
                allVoices: this.languageVoices
            });

            if (this.onVoicesChanged && typeof this.onVoicesChanged === 'function') {
                this.onVoicesChanged({
                    lang: langCode,
                    voices: this.languageVoices[langCode]
                });
            }
        },

        /**
         * Send error notification
         */
        notifyError(message) {
            if (this.onError && typeof this.onError === 'function') {
                this.onError(message);
            }

            // Also notify via global store
            if (Alpine.store('appState')?.addNotification) {
                Alpine.store('appState').addNotification('warning', message);
            }
        },

        // ==================== GLOBAL STORE SYNC ====================

        /**
         * Update global Alpine store
         */
        updateGlobalStore() {
            if (Alpine.store('appState')) {
                Alpine.store('appState').videoConfig.languageVoices = { ...this.languageVoices };
            }
        },

        // ==================== COMPUTED PROPERTIES ====================

        /**
         * Get total number of selected voices across all languages
         */
        get totalVoiceCount() {
            return Object.values(this.languageVoices).reduce(
                (sum, voices) => sum + (voices?.length || 0),
                0
            );
        },

        /**
         * Check if component is loading any voices
         */
        get isAnyLoading() {
            return Object.values(this.isLoading).some(loading => loading);
        }
    }));
});
