/**
 * MultiLanguageSelector Alpine.js Component
 *
 * A feature-rich multi-language selection component with:
 * - Multiple language selection with checkboxes
 * - Search/filter functionality
 * - Popular languages quick select
 * - Voice count display per language
 * - Minimum selection validation
 * - Global store integration
 * - Full accessibility support
 *
 * @requires Alpine.js
 * @requires /static/js/utils/language-data.js
 * @requires /static/js/store/app-state.js
 */

document.addEventListener('alpine:init', () => {
    Alpine.data('multiLanguageSelector', (config = {}) => ({
        // ==================== CONFIGURATION ====================

        // Maximum number of languages that can be selected
        maxSelections: config.maxSelections || 10,

        // Initial language selection
        initialSelection: config.initialSelection || ['en'],

        // API endpoints
        languagesEndpoint: config.languagesEndpoint || '/api/languages',

        // Callback functions
        onSelectionChange: config.onSelectionChange || null,
        onError: config.onError || null,

        // ==================== STATE ====================

        // All available languages from API
        languages: [],

        // Currently selected language codes
        selectedLanguages: [],

        // Search/filter query
        searchQuery: '',

        // Popular language codes (ordered by popularity)
        popularCodes: ['en', 'es', 'fr', 'de', 'zh', 'ja', 'pt', 'ar'],

        // Loading state
        isLoading: true,

        // Error state
        error: null,

        // Debounce timer for search
        searchDebounceTimer: null,

        // Unique component ID for ARIA
        componentId: null,

        // ==================== INITIALIZATION ====================

        init() {
            // Generate unique ID for ARIA references
            this.componentId = 'lang-selector-' + Math.random().toString(36).substr(2, 9);

            // Set initial selection
            this.selectedLanguages = [...this.initialSelection];

            // Fetch languages from API
            this.fetchLanguages();

            // Listen for external selection changes
            this.$watch('selectedLanguages', (newValue, oldValue) => {
                if (JSON.stringify(newValue) !== JSON.stringify(oldValue)) {
                    this.updateGlobalStore();
                    this.dispatchChangeEvent();
                }
            });

            console.log('[MultiLanguageSelector] Component initialized');
        },

        // ==================== API METHODS ====================

        /**
         * Fetch available languages from API
         */
        async fetchLanguages() {
            this.isLoading = true;
            this.error = null;

            try {
                const response = await fetch(this.languagesEndpoint);

                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }

                const data = await response.json();
                this.languages = this.sortLanguages(data.languages || data || []);

                // Validate initial selection against available languages
                this.validateSelection();

                console.log('[MultiLanguageSelector] Loaded', this.languages.length, 'languages');
            } catch (error) {
                console.error('[MultiLanguageSelector] Failed to fetch languages:', error);
                this.error = 'Failed to load languages. Using defaults.';

                // Use fallback default languages
                if (window.LanguageData && window.LanguageData.getDefaultLanguages) {
                    this.languages = window.LanguageData.getDefaultLanguages();
                } else {
                    this.languages = this.getDefaultLanguagesFallback();
                }

                if (this.onError && typeof this.onError === 'function') {
                    this.onError(error);
                }
            } finally {
                this.isLoading = false;
            }
        },

        /**
         * Sort languages alphabetically by English name
         */
        sortLanguages(langs) {
            return [...langs].sort((a, b) => {
                const nameA = (a.name || a.code || '').toLowerCase();
                const nameB = (b.name || b.code || '').toLowerCase();
                return nameA.localeCompare(nameB);
            });
        },

        /**
         * Validate current selection against available languages
         */
        validateSelection() {
            const availableCodes = this.languages.map(l => l.code);
            const validSelection = this.selectedLanguages.filter(code =>
                availableCodes.includes(code)
            );

            // Ensure at least one language is selected
            if (validSelection.length === 0 && this.languages.length > 0) {
                validSelection.push('en');
                if (!availableCodes.includes('en') && this.languages[0]) {
                    validSelection[0] = this.languages[0].code;
                }
            }

            this.selectedLanguages = validSelection;
        },

        // ==================== COMPUTED PROPERTIES ====================

        /**
         * Get filtered languages based on search query
         */
        get filteredLanguages() {
            if (!this.searchQuery || this.searchQuery.trim() === '') {
                return this.languages;
            }

            const query = this.searchQuery.toLowerCase().trim();
            return this.languages.filter(lang => {
                const code = (lang.code || '').toLowerCase();
                const name = (lang.name || '').toLowerCase();
                const nameLocal = (lang.name_local || '').toLowerCase();

                return (
                    code.includes(query) ||
                    name.includes(query) ||
                    nameLocal.includes(query)
                );
            });
        },

        /**
         * Get popular languages subset
         */
        get popularLanguages() {
            return this.popularCodes
                .map(code => this.languages.find(l => l.code === code))
                .filter(Boolean);
        },

        /**
         * Get count of selected languages
         */
        get selectedCount() {
            return this.selectedLanguages.length;
        },

        /**
         * Check if more languages can be added
         */
        get canAddMore() {
            return this.selectedCount < this.maxSelections;
        },

        /**
         * Get detailed info for selected languages
         */
        get selectedLanguageDetails() {
            return this.selectedLanguages
                .map(code => this.languages.find(l => l.code === code))
                .filter(Boolean);
        },

        /**
         * Check if selection is valid (at least one language)
         */
        get isSelectionValid() {
            return this.selectedCount >= 1;
        },

        // ==================== SELECTION METHODS ====================

        /**
         * Toggle language selection
         * @param {string} code - Language code to toggle
         */
        toggleLanguage(code) {
            if (this.isSelected(code)) {
                this.removeLanguage(code);
            } else {
                this.addLanguage(code);
            }
        },

        /**
         * Add language to selection
         * @param {string} code - Language code to add
         */
        addLanguage(code) {
            if (this.isSelected(code)) {
                return; // Already selected
            }

            if (!this.canAddMore) {
                this.notifyMaxReached();
                return;
            }

            this.selectedLanguages = [...this.selectedLanguages, code];
            this.announceChange(`${this.getLanguageName(code)} added`);
        },

        /**
         * Remove language from selection
         * @param {string} code - Language code to remove
         */
        removeLanguage(code) {
            // Don't allow removing the last language
            if (this.selectedCount <= 1) {
                this.announceChange('At least one language must be selected');
                return;
            }

            this.selectedLanguages = this.selectedLanguages.filter(c => c !== code);
            this.announceChange(`${this.getLanguageName(code)} removed`);
        },

        /**
         * Check if language is selected
         * @param {string} code - Language code to check
         * @returns {boolean}
         */
        isSelected(code) {
            return this.selectedLanguages.includes(code);
        },

        /**
         * Clear all selections except the first one
         */
        clearAll() {
            if (this.selectedLanguages.length > 1) {
                const first = this.selectedLanguages[0];
                this.selectedLanguages = [first];
                this.announceChange('Selection cleared, keeping ' + this.getLanguageName(first));
            }
        },

        /**
         * Select all popular languages
         */
        selectPopular() {
            const newSelection = [...this.selectedLanguages];

            for (const code of this.popularCodes) {
                if (!newSelection.includes(code) && newSelection.length < this.maxSelections) {
                    newSelection.push(code);
                }
            }

            this.selectedLanguages = newSelection;
            this.announceChange('Popular languages selected');
        },

        /**
         * Select a preset group of languages
         * @param {string} presetName - Name of preset (european, asian, nordic, global)
         */
        selectPreset(presetName) {
            let presetCodes = [];

            if (window.LanguageData && window.LanguageData.getPresetLanguages) {
                presetCodes = window.LanguageData.getPresetLanguages(presetName);
            } else {
                // Fallback presets
                const presets = {
                    european: ['en', 'es', 'fr', 'de', 'it', 'pt', 'nl', 'pl'],
                    asian: ['en', 'ja', 'zh', 'ko', 'vi', 'th', 'id'],
                    nordic: ['en', 'sv', 'da', 'no', 'fi'],
                    global: ['en', 'es', 'zh', 'ar', 'hi', 'pt', 'ru', 'ja']
                };
                presetCodes = presets[presetName] || [];
            }

            // Filter to available languages and respect max
            const availableCodes = this.languages.map(l => l.code);
            const validCodes = presetCodes
                .filter(code => availableCodes.includes(code))
                .slice(0, this.maxSelections);

            if (validCodes.length > 0) {
                this.selectedLanguages = validCodes;
                this.announceChange(`${presetName} preset selected`);
            }
        },

        // ==================== UTILITY METHODS ====================

        /**
         * Get display name for a language code
         * @param {string} code - Language code
         * @returns {string}
         */
        getLanguageName(code) {
            const lang = this.languages.find(l => l.code === code);
            return lang?.name || code.toUpperCase();
        },

        /**
         * Get native name for a language code
         * @param {string} code - Language code
         * @returns {string}
         */
        getLanguageNative(code) {
            const lang = this.languages.find(l => l.code === code);
            if (lang?.name_local && lang.name_local !== lang.name) {
                return lang.name_local;
            }
            return '';
        },

        /**
         * Get flag emoji for a language code
         * @param {string} code - Language code
         * @returns {string}
         */
        getLanguageFlag(code) {
            if (window.LanguageData && window.LanguageData.getLanguageFlag) {
                return window.LanguageData.getLanguageFlag(code);
            }

            // Fallback flag mappings
            const flags = {
                'en': '\uD83C\uDDFA\uD83C\uDDF8',
                'es': '\uD83C\uDDEA\uD83C\uDDF8',
                'fr': '\uD83C\uDDEB\uD83C\uDDF7',
                'de': '\uD83C\uDDE9\uD83C\uDDEA',
                'it': '\uD83C\uDDEE\uD83C\uDDF9',
                'pt': '\uD83C\uDDE7\uD83C\uDDF7',
                'ja': '\uD83C\uDDEF\uD83C\uDDF5',
                'zh': '\uD83C\uDDE8\uD83C\uDDF3',
                'ko': '\uD83C\uDDF0\uD83C\uDDF7',
                'ar': '\uD83C\uDDF8\uD83C\uDDE6'
            };
            return flags[code] || '\uD83C\uDF10';
        },

        /**
         * Get voice count for a language
         * @param {string} code - Language code
         * @returns {number}
         */
        getVoiceCount(code) {
            const lang = this.languages.find(l => l.code === code);
            return lang?.voice_count || lang?.voices?.length || 0;
        },

        /**
         * Clear search query
         */
        clearSearch() {
            this.searchQuery = '';
            // Focus back on search input
            this.$nextTick(() => {
                const searchInput = this.$refs.searchInput;
                if (searchInput) {
                    searchInput.focus();
                }
            });
        },

        /**
         * Handle search input with debouncing
         */
        handleSearchInput() {
            // Search is reactive, no debounce needed for filtering
            // But we can use it for analytics or API calls in the future
        },

        // ==================== STATE MANAGEMENT ====================

        /**
         * Update global Alpine store
         */
        updateGlobalStore() {
            if (Alpine.store('appState')) {
                // Update video config
                if (!Alpine.store('appState').videoConfig) {
                    Alpine.store('appState').videoConfig = {};
                }
                Alpine.store('appState').videoConfig.selectedLanguages = [...this.selectedLanguages];
                Alpine.store('appState').videoConfig.targetLanguages = [...this.selectedLanguages];
            }
        },

        /**
         * Dispatch custom event for language changes
         */
        dispatchChangeEvent() {
            this.$dispatch('languages-changed', {
                selectedLanguages: [...this.selectedLanguages],
                count: this.selectedCount
            });

            if (this.onSelectionChange && typeof this.onSelectionChange === 'function') {
                this.onSelectionChange(this.selectedLanguages);
            }
        },

        // ==================== ACCESSIBILITY ====================

        /**
         * Announce change to screen readers
         * @param {string} message - Message to announce
         */
        announceChange(message) {
            const announcer = document.getElementById(this.componentId + '-announcer');
            if (announcer) {
                announcer.textContent = message;
            }
        },

        /**
         * Notify user that max selection is reached
         */
        notifyMaxReached() {
            const message = `Maximum of ${this.maxSelections} languages can be selected`;
            this.announceChange(message);

            // Also show via notification system if available
            if (Alpine.store('appState')?.addNotification) {
                Alpine.store('appState').addNotification('warning', message);
            }
        },

        /**
         * Handle keyboard navigation in language list
         * @param {KeyboardEvent} event
         * @param {number} index - Current item index
         */
        handleKeyNav(event, index) {
            const items = this.$refs.languageList?.querySelectorAll('[role="option"]');
            if (!items || items.length === 0) return;

            let targetIndex = index;

            switch (event.key) {
                case 'ArrowDown':
                    event.preventDefault();
                    targetIndex = Math.min(index + 1, items.length - 1);
                    break;
                case 'ArrowUp':
                    event.preventDefault();
                    targetIndex = Math.max(index - 1, 0);
                    break;
                case 'Home':
                    event.preventDefault();
                    targetIndex = 0;
                    break;
                case 'End':
                    event.preventDefault();
                    targetIndex = items.length - 1;
                    break;
                case ' ':
                case 'Enter':
                    event.preventDefault();
                    const code = event.target.dataset.langCode;
                    if (code) {
                        this.toggleLanguage(code);
                    }
                    return;
                default:
                    return;
            }

            if (items[targetIndex]) {
                items[targetIndex].focus();
            }
        },

        // ==================== FALLBACK DATA ====================

        /**
         * Get default languages when API fails and LanguageData is not available
         */
        getDefaultLanguagesFallback() {
            return [
                { code: 'en', name: 'English', name_local: 'English', voice_count: 4 },
                { code: 'es', name: 'Spanish', name_local: 'Espanol', voice_count: 3 },
                { code: 'fr', name: 'French', name_local: 'Francais', voice_count: 3 },
                { code: 'de', name: 'German', name_local: 'Deutsch', voice_count: 3 },
                { code: 'it', name: 'Italian', name_local: 'Italiano', voice_count: 2 },
                { code: 'pt', name: 'Portuguese', name_local: 'Portugues', voice_count: 2 },
                { code: 'ja', name: 'Japanese', name_local: 'Nihongo', voice_count: 2 },
                { code: 'zh', name: 'Chinese', name_local: 'Zhongwen', voice_count: 2 }
            ];
        }
    }));
});
