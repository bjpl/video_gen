/**
 * PreviewPanel Alpine.js Component
 *
 * A feature-rich preview panel component with:
 * - Document preview with collapsible sections
 * - YouTube preview with thumbnail and metadata
 * - Loading and error states with retry functionality
 * - Smooth animations and transitions
 * - Full accessibility support (ARIA)
 * - Mobile-responsive layout
 * - Dark mode support
 *
 * @requires Alpine.js
 * @requires /static/js/store/app-state.js
 */

document.addEventListener('alpine:init', () => {
    Alpine.data('previewPanel', (config = {}) => ({
        // ==================== CONFIGURATION ====================

        // Preview type ('document' | 'youtube' | null)
        type: config.type || null,

        // API endpoints
        documentPreviewEndpoint: config.documentPreviewEndpoint || '/api/preview/document',
        youtubePreviewEndpoint: config.youtubePreviewEndpoint || '/api/youtube/preview',

        // Callbacks
        onPreviewLoaded: config.onPreviewLoaded || null,
        onPreviewCleared: config.onPreviewCleared || null,
        onSectionToggle: config.onSectionToggle || null,
        onError: config.onError || null,

        // Initial collapsed state
        initialCollapsed: config.initialCollapsed || false,

        // ==================== STATE ====================

        // Preview data
        preview: null,
        previewType: null,

        // UI state
        isLoading: false,
        isExpanded: true,
        isCollapsed: false,
        error: null,
        errorRetryCount: 0,
        maxRetries: 3,

        // Section expansion tracking
        expandedSections: [],

        // Lazy loading state for thumbnails
        thumbnailLoaded: false,

        // ==================== INITIALIZATION ====================

        init() {
            console.log('[PreviewPanel] Component initialized');

            // Set initial collapsed state
            this.isCollapsed = this.initialCollapsed;
            this.isExpanded = !this.initialCollapsed;

            // Listen for preview events
            this.$watch('preview', (newPreview) => {
                if (newPreview && newPreview.sections && newPreview.sections.length > 0) {
                    // Expand first section by default
                    this.expandedSections = [0];
                }
            });

            // Listen for external preview-ready events
            window.addEventListener('preview-ready', (event) => {
                if (event.detail && event.detail.preview) {
                    this.loadPreview(event.detail.preview, event.detail.type || 'document');
                }
            });

            // Listen for clear preview events
            window.addEventListener('preview-clear', () => {
                this.clearPreview();
            });

            // Restore state from global store if available
            // Fixed: Store has preview at root level, not under input
            if (Alpine.store('appState')?.preview?.data) {
                const storedPreview = Alpine.store('appState').preview;
                if (storedPreview.loaded && storedPreview.data) {
                    this.preview = storedPreview.data;
                    this.previewType = storedPreview.type || 'document';
                }
            }
        },

        // ==================== COMPUTED PROPERTIES ====================

        /**
         * Check if preview data exists
         */
        get hasPreview() {
            return this.preview !== null && Object.keys(this.preview).length > 0;
        },

        /**
         * Get display title
         */
        get title() {
            if (!this.preview) return '';
            if (this.previewType === 'youtube') {
                return this.preview.title || 'YouTube Video';
            }
            return this.preview.title || 'Untitled Document';
        },

        /**
         * Get section count
         */
        get sectionCount() {
            if (!this.preview) return 0;
            if (this.previewType === 'youtube') {
                return this.preview.chapters?.length || 0;
            }
            return this.preview.sections?.length || this.preview.section_count || 0;
        },

        /**
         * Get estimated duration formatted
         */
        get estimatedDuration() {
            if (!this.preview) return '--:--';
            const duration = this.preview.estimated_duration_seconds || this.preview.estimated_duration || this.preview.duration || 0;
            return this.formatDuration(duration);
        },

        /**
         * Get recommendations list
         */
        get recommendations() {
            return this.preview?.recommendations || [];
        },

        /**
         * Get word count
         */
        get wordCount() {
            return this.preview?.word_count || 0;
        },

        /**
         * Get estimated scenes
         */
        get estimatedScenes() {
            if (!this.preview) return 0;
            return this.preview.estimated_scenes || this.preview.scene_count || 0;
        },

        /**
         * Check if it's a document preview
         */
        get isDocumentPreview() {
            return this.previewType === 'document';
        },

        /**
         * Check if it's a YouTube preview
         */
        get isYouTubePreview() {
            return this.previewType === 'youtube';
        },

        // ==================== METHODS ====================

        /**
         * Load preview data
         * @param {Object} data - Preview data from API
         * @param {string} type - Preview type ('document' | 'youtube')
         */
        loadPreview(data, type = 'document') {
            console.log('[PreviewPanel] Loading preview:', type, data);

            this.preview = data;
            this.previewType = type;
            this.error = null;
            this.errorRetryCount = 0;
            this.thumbnailLoaded = false;

            // Reset expanded sections
            if (data.sections && data.sections.length > 0) {
                this.expandedSections = [0]; // Expand first section by default
            } else {
                this.expandedSections = [];
            }

            // Update global store
            this.updateGlobalStore();

            // Notify callback
            if (this.onPreviewLoaded && typeof this.onPreviewLoaded === 'function') {
                this.onPreviewLoaded({ preview: data, type });
            }

            // Dispatch custom event
            this.$dispatch('preview-loaded', { preview: data, type });
        },

        /**
         * Toggle section expand/collapse
         * @param {number} sectionId - Section index
         */
        toggleSection(sectionId) {
            const index = this.expandedSections.indexOf(sectionId);
            if (index > -1) {
                this.expandedSections.splice(index, 1);
            } else {
                this.expandedSections.push(sectionId);
            }

            // Notify callback
            if (this.onSectionToggle && typeof this.onSectionToggle === 'function') {
                this.onSectionToggle(sectionId, this.isSectionExpanded(sectionId));
            }
        },

        /**
         * Check if section is expanded
         * @param {number} sectionId - Section index
         */
        isSectionExpanded(sectionId) {
            return this.expandedSections.includes(sectionId);
        },

        /**
         * Expand all sections
         */
        expandAll() {
            if (this.preview?.sections) {
                this.expandedSections = this.preview.sections.map((_, i) => i);
            } else if (this.preview?.chapters) {
                this.expandedSections = this.preview.chapters.map((_, i) => i);
            }
        },

        /**
         * Collapse all sections
         */
        collapseAll() {
            this.expandedSections = [];
        },

        /**
         * Clear preview data and reset state
         */
        clearPreview() {
            console.log('[PreviewPanel] Clearing preview');

            this.preview = null;
            this.previewType = null;
            this.error = null;
            this.expandedSections = [];
            this.thumbnailLoaded = false;

            // Update global store
            this.updateGlobalStore();

            // Notify callback
            if (this.onPreviewCleared && typeof this.onPreviewCleared === 'function') {
                this.onPreviewCleared();
            }

            // Dispatch custom event
            this.$dispatch('preview-cleared');
        },

        /**
         * Toggle panel collapse state
         */
        toggleCollapse() {
            this.isCollapsed = !this.isCollapsed;
            this.isExpanded = !this.isCollapsed;
            this.$dispatch('collapse-changed', { collapsed: this.isCollapsed });
        },

        /**
         * Set loading state
         * @param {boolean} loading - Loading state
         */
        setLoading(loading) {
            this.isLoading = loading;
        },

        /**
         * Set error state
         * @param {string} message - Error message
         */
        setError(message) {
            this.error = message;
            this.isLoading = false;

            // Notify callback
            if (this.onError && typeof this.onError === 'function') {
                this.onError(message);
            }

            // Also notify via global store
            if (Alpine.store('appState')?.addNotification) {
                Alpine.store('appState').addNotification('error', message);
            }
        },

        /**
         * Retry loading preview after error
         */
        async retry() {
            if (this.errorRetryCount >= this.maxRetries) {
                this.setError('Maximum retry attempts reached. Please try again later.');
                return;
            }

            this.errorRetryCount++;
            this.error = null;
            this.isLoading = true;

            // Dispatch retry event for parent components to handle
            this.$dispatch('preview-retry', { retryCount: this.errorRetryCount });
        },

        // ==================== FORMATTING UTILITIES ====================

        /**
         * Format duration in seconds to MM:SS or HH:MM:SS
         * @param {number} seconds - Duration in seconds
         */
        formatDuration(seconds) {
            if (!seconds || isNaN(seconds)) return '--:--';

            const hours = Math.floor(seconds / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            const secs = Math.floor(seconds % 60);

            if (hours > 0) {
                return `${hours}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
            }
            return `${minutes}:${secs.toString().padStart(2, '0')}`;
        },

        /**
         * Estimate reading time based on word count
         * @param {number} wordCount - Number of words
         * @returns {string} - Estimated reading time
         */
        estimateReadTime(wordCount) {
            if (!wordCount || wordCount <= 0) return '< 1 min';

            const wordsPerMinute = 200; // Average reading speed
            const minutes = Math.ceil(wordCount / wordsPerMinute);

            if (minutes < 1) return '< 1 min';
            if (minutes === 1) return '1 min';
            return `${minutes} mins`;
        },

        /**
         * Format number with locale formatting
         * @param {number} num - Number to format
         */
        formatNumber(num) {
            if (!num && num !== 0) return '-';
            return new Intl.NumberFormat().format(num);
        },

        /**
         * Format view count (e.g., 1.2M views)
         * Handles both view_count and views property names from API
         * @param {number} views - View count
         */
        formatViewCount(views) {
            // Handle view_count or views from API response
            const count = views || this.preview?.view_count || 0;
            if (!count) return '-';
            if (count >= 1000000) {
                return (count / 1000000).toFixed(1) + 'M views';
            }
            if (count >= 1000) {
                return (count / 1000).toFixed(1) + 'K views';
            }
            return count + ' views';
        },

        /**
         * Truncate text with ellipsis
         * @param {string} text - Text to truncate
         * @param {number} maxLength - Maximum length
         */
        truncateText(text, maxLength = 100) {
            if (!text) return '';
            if (text.length <= maxLength) return text;
            return text.substring(0, maxLength - 3) + '...';
        },

        // ==================== YOUTUBE-SPECIFIC METHODS ====================

        /**
         * Get YouTube thumbnail URL
         */
        get thumbnailUrl() {
            if (!this.preview || this.previewType !== 'youtube') return '';
            return this.preview.thumbnail || this.preview.thumbnail_url || '';
        },

        /**
         * Get YouTube channel name
         */
        get channelName() {
            return this.preview?.channel || this.preview?.channel_name || '';
        },

        /**
         * Check if transcript is available
         */
        get hasTranscript() {
            return this.preview?.has_transcript || false;
        },

        /**
         * Get transcript languages
         */
        get transcriptLanguages() {
            return this.preview?.transcript_languages || [];
        },

        /**
         * Get generation time estimate
         */
        get generationEstimate() {
            return this.preview?.generation_estimate || 'Unknown';
        },

        /**
         * Handle thumbnail load
         */
        onThumbnailLoad() {
            this.thumbnailLoaded = true;
        },

        /**
         * Handle thumbnail error
         */
        onThumbnailError() {
            console.warn('[PreviewPanel] Thumbnail failed to load');
            this.thumbnailLoaded = false;
        },

        // ==================== DOCUMENT-SPECIFIC METHODS ====================

        /**
         * Check if document has code blocks
         */
        get hasCode() {
            return this.preview?.has_code || false;
        },

        /**
         * Check if document has lists
         */
        get hasLists() {
            return this.preview?.has_lists || false;
        },

        /**
         * Get document sections with details
         */
        get sections() {
            if (!this.preview?.sections) return [];

            // Handle both array of strings and array of objects
            return this.preview.sections.map((section, index) => {
                if (typeof section === 'string') {
                    return {
                        title: section,
                        content_preview: '',
                        has_code: false,
                        has_list: false,
                        index
                    };
                }
                return { ...section, index };
            });
        },

        // ==================== STATE MANAGEMENT ====================

        /**
         * Update global Alpine store
         */
        updateGlobalStore() {
            if (Alpine.store('appState')) {
                Alpine.store('appState').input.preview = {
                    loaded: this.hasPreview,
                    data: this.preview,
                    type: this.previewType,
                    error: this.error
                };
            }
        },

        /**
         * Get panel container classes
         */
        getPanelClasses() {
            const classes = ['preview-panel'];
            if (this.isLoading) classes.push('preview-panel--loading');
            if (this.error) classes.push('preview-panel--error');
            if (this.isCollapsed) classes.push('preview-panel--collapsed');
            if (this.previewType) classes.push(`preview-panel--${this.previewType}`);
            return classes.join(' ');
        },

        /**
         * Get header toggle icon rotation class
         */
        getToggleIconClass() {
            return this.isCollapsed ? '' : 'rotate-180';
        }
    }));
});
