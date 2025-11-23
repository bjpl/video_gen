/**
 * ValidationFeedback Component - Phase 2.2 Implementation
 *
 * Real-time validation feedback for document and YouTube inputs.
 * Features:
 * - Debounced input validation (500ms)
 * - API integration (/api/validate/document, /api/youtube/validate)
 * - Visual indicators (success/error/warning/loading)
 * - Inline error messages with suggestions
 * - Auto-recovery hints
 *
 * @module components/validation-feedback
 */

/**
 * API Client for validation endpoints
 * Centralized API calls with error handling
 */
const ValidationAPI = {
    /**
     * Validate a document file
     * @param {File} file - File to validate
     * @returns {Promise<Object>} Validation result
     */
    async validateDocument(file) {
        const formData = new FormData();
        formData.append('file', file);

        const response = await fetch('/api/validate/document', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.detail || `Validation failed: ${response.status}`);
        }

        return response.json();
    },

    /**
     * Validate a YouTube URL
     * @param {string} url - YouTube URL to validate
     * @returns {Promise<Object>} Validation result
     */
    async validateYouTube(url) {
        const response = await fetch('/api/youtube/validate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.detail || `Validation failed: ${response.status}`);
        }

        return response.json();
    },

    /**
     * Get YouTube preview data
     * @param {string} url - YouTube URL
     * @param {boolean} includeTranscript - Include transcript preview
     * @returns {Promise<Object>} Preview data
     */
    async getYouTubePreview(url, includeTranscript = false) {
        const response = await fetch('/api/youtube/preview', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url,
                include_transcript_preview: includeTranscript
            })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.detail || `Preview failed: ${response.status}`);
        }

        return response.json();
    },

    /**
     * Get document preview data
     * @param {File} file - Document file
     * @returns {Promise<Object>} Preview data
     */
    async getDocumentPreview(file) {
        const formData = new FormData();
        formData.append('file', file);

        const response = await fetch('/api/preview/document', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.detail || `Preview failed: ${response.status}`);
        }

        return response.json();
    }
};


/**
 * Debounce utility function
 * @param {Function} func - Function to debounce
 * @param {number} wait - Debounce delay in milliseconds
 * @returns {Function} Debounced function
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}


/**
 * Validation state enum
 */
const ValidationState = {
    IDLE: 'idle',
    VALIDATING: 'validating',
    VALID: 'valid',
    INVALID: 'invalid',
    WARNING: 'warning',
    ERROR: 'error'
};


/**
 * Alpine.js component for YouTube URL validation feedback
 *
 * Usage:
 * <div x-data="youtubeValidation()">
 *   <input x-model="url" @input="onInput">
 *   <!-- Feedback displays automatically -->
 * </div>
 */
function youtubeValidation() {
    return {
        // State
        url: '',
        state: ValidationState.IDLE,
        isValidating: false,
        isValid: false,
        hasError: false,
        hasWarning: false,

        // Validation result data
        videoId: null,
        normalizedUrl: null,
        errorMessage: '',
        warningMessage: '',
        suggestion: '',

        // Preview data (populated after validation)
        preview: null,

        // Debounced validator (500ms)
        _debouncedValidate: null,

        /**
         * Initialize component
         */
        init() {
            this._debouncedValidate = debounce(this.validateURL.bind(this), 500);
            console.log('[ValidationFeedback] YouTube validation component initialized');
        },

        /**
         * Handle input changes (debounced)
         */
        onInput() {
            // Reset state immediately for feedback
            this.resetState();

            // Skip validation for empty input
            if (!this.url.trim()) {
                return;
            }

            // Show validating state
            this.state = ValidationState.VALIDATING;
            this.isValidating = true;

            // Trigger debounced validation
            this._debouncedValidate();
        },

        /**
         * Reset validation state
         */
        resetState() {
            this.state = ValidationState.IDLE;
            this.isValidating = false;
            this.isValid = false;
            this.hasError = false;
            this.hasWarning = false;
            this.videoId = null;
            this.normalizedUrl = null;
            this.errorMessage = '';
            this.warningMessage = '';
            this.suggestion = '';
            this.preview = null;
        },

        /**
         * Perform YouTube URL validation via API
         */
        async validateURL() {
            const url = this.url.trim();

            // Skip if empty
            if (!url) {
                this.resetState();
                return;
            }

            // Client-side pre-validation for quick feedback
            const quickCheck = this.quickValidate(url);
            if (!quickCheck.valid) {
                this.state = ValidationState.INVALID;
                this.isValidating = false;
                this.hasError = true;
                this.errorMessage = quickCheck.error;
                this.suggestion = quickCheck.suggestion;
                return;
            }

            try {
                // Call API for full validation
                const result = await ValidationAPI.validateYouTube(url);

                this.isValidating = false;

                if (result.is_valid) {
                    // Success state
                    this.state = ValidationState.VALID;
                    this.isValid = true;
                    this.videoId = result.video_id;
                    this.normalizedUrl = result.normalized_url;

                    // Dispatch success event for other components
                    this.$dispatch('youtube-validated', {
                        videoId: result.video_id,
                        url: result.normalized_url
                    });

                    // Update global store if available
                    if (window.Alpine?.store('appState')) {
                        const store = Alpine.store('appState');
                        store.formData.youtube.validated = true;
                        store.formData.youtube.videoInfo = {
                            videoId: result.video_id,
                            url: result.normalized_url
                        };
                    }
                } else {
                    // Invalid state
                    this.state = ValidationState.INVALID;
                    this.hasError = true;
                    this.errorMessage = result.error || 'Invalid YouTube URL';
                    this.suggestion = this.getSuggestionForError(result.error);
                }

            } catch (error) {
                // Error state (network/server error)
                this.state = ValidationState.ERROR;
                this.isValidating = false;
                this.hasError = true;
                this.errorMessage = 'Validation service unavailable';
                this.suggestion = 'Please check your internet connection and try again';
                console.error('[ValidationFeedback] YouTube validation error:', error);
            }
        },

        /**
         * Quick client-side validation before API call
         * @param {string} url - URL to validate
         * @returns {Object} Validation result {valid, error, suggestion}
         */
        quickValidate(url) {
            // Empty check
            if (!url) {
                return { valid: false, error: 'URL cannot be empty', suggestion: 'Enter a YouTube video URL' };
            }

            // Basic URL structure check
            try {
                const parsed = new URL(url);

                // Must be HTTP/HTTPS
                if (!['http:', 'https:'].includes(parsed.protocol)) {
                    return {
                        valid: false,
                        error: 'Invalid URL protocol',
                        suggestion: 'URL must start with http:// or https://'
                    };
                }

                // Check if it's a YouTube domain
                const ytDomains = ['youtube.com', 'www.youtube.com', 'youtu.be', 'm.youtube.com'];
                if (!ytDomains.includes(parsed.hostname)) {
                    return {
                        valid: false,
                        error: 'Not a YouTube URL',
                        suggestion: 'Enter a URL from youtube.com or youtu.be'
                    };
                }

            } catch (e) {
                return {
                    valid: false,
                    error: 'Invalid URL format',
                    suggestion: 'Check the URL format and try again'
                };
            }

            return { valid: true };
        },

        /**
         * Get suggestion for common error types
         * @param {string} error - Error message from API
         * @returns {string} Helpful suggestion
         */
        getSuggestionForError(error) {
            const errorLower = (error || '').toLowerCase();

            if (errorLower.includes('video id')) {
                return 'Make sure the URL contains a valid video ID (11 characters)';
            }
            if (errorLower.includes('private') || errorLower.includes('unavailable')) {
                return 'The video may be private or removed. Try a different video.';
            }
            if (errorLower.includes('age') || errorLower.includes('restricted')) {
                return 'Age-restricted videos cannot be processed. Try a different video.';
            }
            if (errorLower.includes('live') || errorLower.includes('stream')) {
                return 'Live streams are not supported. Use a regular video URL.';
            }
            if (errorLower.includes('playlist')) {
                return 'For playlists, use the individual video URL instead';
            }

            return 'Supported formats: youtube.com/watch?v=..., youtu.be/..., youtube.com/embed/...';
        },

        /**
         * Get CSS class for input border based on state
         */
        get inputClass() {
            switch (this.state) {
                case ValidationState.VALID:
                    return 'border-green-500 focus:ring-green-500';
                case ValidationState.INVALID:
                case ValidationState.ERROR:
                    return 'border-red-500 focus:ring-red-500';
                case ValidationState.WARNING:
                    return 'border-yellow-500 focus:ring-yellow-500';
                case ValidationState.VALIDATING:
                    return 'border-blue-400 focus:ring-blue-400';
                default:
                    return 'border-gray-300 focus:ring-blue-500';
            }
        },

        /**
         * Get icon for current state
         */
        get stateIcon() {
            switch (this.state) {
                case ValidationState.VALID:
                    return '<span class="text-green-600">&#10003;</span>'; // Checkmark
                case ValidationState.INVALID:
                case ValidationState.ERROR:
                    return '<span class="text-red-600">&#10007;</span>'; // X mark
                case ValidationState.WARNING:
                    return '<span class="text-yellow-600">&#9888;</span>'; // Warning
                case ValidationState.VALIDATING:
                    return '<span class="animate-spin inline-block">&#8635;</span>'; // Spinner
                default:
                    return '';
            }
        },

        /**
         * Fetch preview data after successful validation
         */
        async fetchPreview() {
            if (!this.isValid || !this.normalizedUrl) return;

            try {
                const preview = await ValidationAPI.getYouTubePreview(this.normalizedUrl, true);
                this.preview = preview;

                // Dispatch preview event
                this.$dispatch('youtube-preview-loaded', preview);

            } catch (error) {
                console.error('[ValidationFeedback] Failed to load preview:', error);
                this.warningMessage = 'Could not load video preview';
            }
        }
    };
}


/**
 * Alpine.js component for Document validation feedback
 *
 * Usage:
 * <div x-data="documentValidation()">
 *   <input type="file" @change="onFileSelect">
 *   <!-- Feedback displays automatically -->
 * </div>
 */
function documentValidation() {
    return {
        // State
        file: null,
        fileName: '',
        fileSize: 0,
        state: ValidationState.IDLE,
        isValidating: false,
        isValid: false,
        hasError: false,
        hasWarning: false,

        // Validation result data
        sanitizedFilename: null,
        errorMessage: '',
        warningMessage: '',
        warnings: [],
        suggestion: '',

        // Preview data
        preview: null,

        // Supported file types
        supportedTypes: ['.md', '.txt', '.markdown', '.rst'],
        maxFileSize: 10 * 1024 * 1024, // 10MB

        /**
         * Initialize component
         */
        init() {
            console.log('[ValidationFeedback] Document validation component initialized');
        },

        /**
         * Handle file selection
         * @param {Event} event - File input change event
         */
        async onFileSelect(event) {
            const file = event.target.files[0];
            if (!file) {
                this.resetState();
                return;
            }

            this.file = file;
            this.fileName = file.name;
            this.fileSize = file.size;

            // Quick client-side validation
            const quickCheck = this.quickValidate(file);
            if (!quickCheck.valid) {
                this.state = ValidationState.INVALID;
                this.hasError = true;
                this.errorMessage = quickCheck.error;
                this.suggestion = quickCheck.suggestion;
                return;
            }

            // Start API validation
            await this.validateFile();
        },

        /**
         * Reset validation state
         */
        resetState() {
            this.file = null;
            this.fileName = '';
            this.fileSize = 0;
            this.state = ValidationState.IDLE;
            this.isValidating = false;
            this.isValid = false;
            this.hasError = false;
            this.hasWarning = false;
            this.sanitizedFilename = null;
            this.errorMessage = '';
            this.warningMessage = '';
            this.warnings = [];
            this.suggestion = '';
            this.preview = null;
        },

        /**
         * Quick client-side validation
         * @param {File} file - File to validate
         * @returns {Object} Validation result
         */
        quickValidate(file) {
            // Check file size
            if (file.size > this.maxFileSize) {
                const sizeMB = (file.size / (1024 * 1024)).toFixed(1);
                return {
                    valid: false,
                    error: `File too large (${sizeMB}MB)`,
                    suggestion: 'Maximum file size is 10MB. Try splitting the document.'
                };
            }

            // Check file extension
            const ext = '.' + file.name.split('.').pop().toLowerCase();
            if (!this.supportedTypes.includes(ext)) {
                return {
                    valid: false,
                    error: `Unsupported file type (${ext})`,
                    suggestion: `Supported formats: ${this.supportedTypes.join(', ')}`
                };
            }

            // Check for empty file
            if (file.size === 0) {
                return {
                    valid: false,
                    error: 'File is empty',
                    suggestion: 'Please select a file with content'
                };
            }

            return { valid: true };
        },

        /**
         * Validate file via API
         */
        async validateFile() {
            if (!this.file) return;

            this.state = ValidationState.VALIDATING;
            this.isValidating = true;

            try {
                const result = await ValidationAPI.validateDocument(this.file);

                this.isValidating = false;

                if (result.valid) {
                    // Success state
                    this.state = ValidationState.VALID;
                    this.isValid = true;
                    this.sanitizedFilename = result.sanitized_filename;

                    // Handle warnings
                    if (result.warnings && result.warnings.length > 0) {
                        this.state = ValidationState.WARNING;
                        this.hasWarning = true;
                        this.warnings = result.warnings;
                        this.warningMessage = result.warnings[0];
                    }

                    // Dispatch success event
                    this.$dispatch('document-validated', {
                        file: this.file,
                        filename: this.sanitizedFilename
                    });

                    // Update global store if available
                    if (window.Alpine?.store('appState')) {
                        const store = Alpine.store('appState');
                        store.formData.document.file = this.file;
                        store.formData.document.fileName = this.sanitizedFilename;
                    }

                } else {
                    // Invalid state
                    this.state = ValidationState.INVALID;
                    this.hasError = true;
                    this.errorMessage = result.errors?.[0] || 'Document validation failed';
                    this.suggestion = this.getSuggestionForError(result.errors?.[0]);
                }

            } catch (error) {
                // Error state
                this.state = ValidationState.ERROR;
                this.isValidating = false;
                this.hasError = true;
                this.errorMessage = error.message || 'Validation service unavailable';
                this.suggestion = 'Please check your connection and try again';
                console.error('[ValidationFeedback] Document validation error:', error);
            }
        },

        /**
         * Get suggestion for common document errors
         * @param {string} error - Error message
         * @returns {string} Suggestion
         */
        getSuggestionForError(error) {
            const errorLower = (error || '').toLowerCase();

            if (errorLower.includes('encoding')) {
                return 'Try saving the file as UTF-8 encoding';
            }
            if (errorLower.includes('binary') || errorLower.includes('corrupted')) {
                return 'The file appears corrupted. Try re-exporting from your editor.';
            }
            if (errorLower.includes('empty')) {
                return 'Add some content to the document before uploading';
            }
            if (errorLower.includes('heading') || errorLower.includes('structure')) {
                return 'Add headings (# or ##) to structure your document for better video scenes';
            }

            return 'Check the file content and ensure it is a valid text document';
        },

        /**
         * Get CSS class for current state
         */
        get stateClass() {
            switch (this.state) {
                case ValidationState.VALID:
                    return 'validation-success';
                case ValidationState.INVALID:
                case ValidationState.ERROR:
                    return 'validation-error';
                case ValidationState.WARNING:
                    return 'validation-warning';
                default:
                    return '';
            }
        },

        /**
         * Format file size for display
         */
        get formattedFileSize() {
            if (this.fileSize < 1024) {
                return `${this.fileSize} B`;
            } else if (this.fileSize < 1024 * 1024) {
                return `${(this.fileSize / 1024).toFixed(1)} KB`;
            } else {
                return `${(this.fileSize / (1024 * 1024)).toFixed(1)} MB`;
            }
        },

        /**
         * Fetch document preview after validation
         */
        async fetchPreview() {
            if (!this.isValid || !this.file) return;

            try {
                const preview = await ValidationAPI.getDocumentPreview(this.file);
                this.preview = preview;

                // Dispatch preview event
                this.$dispatch('document-preview-loaded', preview);

            } catch (error) {
                console.error('[ValidationFeedback] Failed to load preview:', error);
                this.warningMessage = 'Could not load document preview';
            }
        }
    };
}


/**
 * Alpine.js component for inline validation feedback display
 *
 * Usage:
 * <div x-data="validationFeedback()" x-bind="container">
 *   <!-- Feedback content auto-renders based on state -->
 * </div>
 */
function validationFeedback() {
    return {
        state: ValidationState.IDLE,
        message: '',
        suggestion: '',
        details: null,

        /**
         * Container bindings
         */
        container: {
            'x-show'() { return this.state !== ValidationState.IDLE; },
            ':class'() { return this.containerClass; },
            'role': 'alert',
            'aria-live': 'polite'
        },

        /**
         * Update feedback state
         * @param {string} newState - New validation state
         * @param {string} message - Feedback message
         * @param {string} suggestion - Optional suggestion
         * @param {Object} details - Optional additional details
         */
        update(newState, message = '', suggestion = '', details = null) {
            this.state = newState;
            this.message = message;
            this.suggestion = suggestion;
            this.details = details;
        },

        /**
         * Show success feedback
         */
        success(message, details = null) {
            this.update(ValidationState.VALID, message, '', details);
        },

        /**
         * Show error feedback
         */
        error(message, suggestion = '') {
            this.update(ValidationState.INVALID, message, suggestion);
        },

        /**
         * Show warning feedback
         */
        warning(message, suggestion = '') {
            this.update(ValidationState.WARNING, message, suggestion);
        },

        /**
         * Show loading state
         */
        loading(message = 'Validating...') {
            this.update(ValidationState.VALIDATING, message);
        },

        /**
         * Clear feedback
         */
        clear() {
            this.update(ValidationState.IDLE);
        },

        /**
         * Get container CSS class based on state
         */
        get containerClass() {
            const baseClass = 'validation-feedback p-3 rounded-lg text-sm mb-2 flex items-start gap-2';

            switch (this.state) {
                case ValidationState.VALID:
                    return `${baseClass} bg-green-50 border border-green-200 text-green-800`;
                case ValidationState.INVALID:
                case ValidationState.ERROR:
                    return `${baseClass} bg-red-50 border border-red-200 text-red-800`;
                case ValidationState.WARNING:
                    return `${baseClass} bg-yellow-50 border border-yellow-200 text-yellow-800`;
                case ValidationState.VALIDATING:
                    return `${baseClass} bg-blue-50 border border-blue-200 text-blue-800`;
                default:
                    return baseClass;
            }
        },

        /**
         * Get icon for current state
         */
        get icon() {
            switch (this.state) {
                case ValidationState.VALID:
                    return '&#10003;'; // Checkmark
                case ValidationState.INVALID:
                case ValidationState.ERROR:
                    return '&#10007;'; // X mark
                case ValidationState.WARNING:
                    return '&#9888;'; // Warning triangle
                case ValidationState.VALIDATING:
                    return '&#8635;'; // Refresh/spinner
                default:
                    return '';
            }
        },

        /**
         * Check if showing loading state
         */
        get isLoading() {
            return this.state === ValidationState.VALIDATING;
        }
    };
}


/**
 * Register Alpine.js components
 */
document.addEventListener('alpine:init', () => {
    // Register data components
    Alpine.data('youtubeValidation', youtubeValidation);
    Alpine.data('documentValidation', documentValidation);
    Alpine.data('validationFeedback', validationFeedback);

    console.log('[ValidationFeedback] Alpine.js components registered');
});


// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        ValidationAPI,
        ValidationState,
        youtubeValidation,
        documentValidation,
        validationFeedback,
        debounce
    };
}

// Export to window for direct usage
window.ValidationAPI = ValidationAPI;
window.ValidationState = ValidationState;
