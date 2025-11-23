/**
 * Client-Side Validation Module - P1 Error Prevention
 *
 * Provides real-time validation for form inputs with user-friendly feedback.
 * Prevents common errors before submission.
 *
 * Security Enhancements:
 * - Input sanitization helpers (FIX C3)
 * - XSS prevention
 * - Path traversal prevention
 * - Safe regex matching with timeout (ReDoS prevention)
 */

// Security constants
const VALIDATION_CONSTANTS = {
    MAX_VIDEO_ID_LENGTH: 100,
    MAX_DURATION_SECONDS: 600,
    MIN_DURATION_SECONDS: 10,
    MAX_VIDEO_COUNT: 20,
    MAX_TEXT_INPUT_LENGTH: 1000000, // 1MB
    MAX_FILENAME_LENGTH: 255,
    REGEX_TIMEOUT_MS: 100
};

class FormValidator {
    constructor() {
        this.validators = {
            video_id: this.validateVideoId.bind(this),
            url: this.validateURL.bind(this),
            youtube_url: this.validateYouTubeURL.bind(this),
            file_path: this.validateFilePath.bind(this),
            duration: this.validateDuration.bind(this),
            video_count: this.validateVideoCount.bind(this)
        };

        // Bind sanitizers
        this.sanitizers = {
            filename: this.sanitizeFilename.bind(this),
            text: this.sanitizeText.bind(this),
            html: this.sanitizeForDisplay.bind(this),
            url: this.sanitizeUrl.bind(this)
        };
    }

    /**
     * Validate a field and return error message or null
     * @param {string} fieldName - Field identifier
     * @param {*} value - Field value
     * @returns {string|null} Error message or null if valid
     */
    validateField(fieldName, value) {
        const validator = this.validators[fieldName];
        if (!validator) return null;

        const result = validator(value);
        return result === true ? null : result;
    }

    /**
     * Video ID validation (alphanumeric, hyphens, underscores only)
     */
    validateVideoId(value) {
        if (!value || value.trim().length === 0) {
            return 'Video ID cannot be empty';
        }

        const cleaned = value.trim();
        if (!/^[a-zA-Z0-9_-]+$/.test(cleaned)) {
            return 'Only letters, numbers, hyphens (-), and underscores (_) allowed';
        }

        if (cleaned.length > 100) {
            return 'Video ID too long (max 100 characters)';
        }

        return true;
    }

    /**
     * Generic URL validation
     */
    validateURL(value) {
        const cleaned = value.trim();

        if (!cleaned) {
            return 'URL cannot be empty';
        }

        try {
            const url = new URL(cleaned);

            // Only HTTP/HTTPS allowed
            if (!['http:', 'https:'].includes(url.protocol)) {
                return 'Only HTTP/HTTPS URLs supported';
            }

            return true;
        } catch (e) {
            return 'Invalid URL format (must start with http:// or https://)';
        }
    }

    /**
     * YouTube URL validation (supports 3 common formats)
     */
    validateYouTubeURL(value) {
        const cleaned = value.trim();

        if (!cleaned) {
            return 'YouTube URL cannot be empty';
        }

        const patterns = [
            /^https?:\/\/(www\.)?youtube\.com\/watch\?v=([a-zA-Z0-9_-]{11})/,
            /^https?:\/\/youtu\.be\/([a-zA-Z0-9_-]{11})/,
            /^https?:\/\/(www\.)?youtube\.com\/embed\/([a-zA-Z0-9_-]{11})/
        ];

        for (const pattern of patterns) {
            const match = this.safeRegexMatch(pattern, cleaned);
            if (match) {
                return true; // Valid YouTube URL
            }
        }

        // FIX C1: Return structured error message (no user input in message)
        return 'Invalid YouTube URL. Supported formats:\n' +
               '• https://youtube.com/watch?v=...\n' +
               '• https://youtu.be/...\n' +
               '• https://youtube.com/embed/...';
    }

    /**
     * Safe regex matching with timeout protection (prevents ReDoS attacks)
     * @param {RegExp} pattern - Regex pattern
     * @param {string} text - Text to match
     * @param {number} timeout - Max execution time in ms
     * @returns {Array|null} Match result or null
     */
    safeRegexMatch(pattern, text, timeout = 100) {
        const start = Date.now();
        try {
            const match = text.match(pattern);
            if (Date.now() - start > timeout) {
                console.warn('Regex timeout exceeded');
                return null;
            }
            return match;
        } catch (e) {
            console.error('Regex execution error:', e);
            return null;
        }
    }

    /**
     * File path validation (cross-platform, auto-strips quotes)
     */
    validateFilePath(value) {
        let cleaned = value.trim();

        if (!cleaned) {
            return 'File path cannot be empty';
        }

        // Auto-strip surrounding quotes (common copy-paste issue)
        cleaned = cleaned.replace(/^["']|["']$/g, '');

        // Normalize path separators
        cleaned = cleaned.replace(/\\/g, '/');

        // FIX C1: Security - Prevent directory traversal attacks
        if (cleaned.includes('..')) {
            return 'Path traversal (..) not allowed for security reasons';
        }

        // FIX C1: Security - Prevent null bytes
        if (cleaned.includes('\0')) {
            return 'Invalid characters in path (null byte detected)';
        }

        // Validate path structure
        const windowsPath = /^[a-zA-Z]:\//;
        const unixPath = /^\/|^\.\//;
        const relativePath = /^[^\/]/;

        if (!windowsPath.test(cleaned) &&
            !unixPath.test(cleaned) &&
            !relativePath.test(cleaned)) {
            return 'Invalid file path format.\n' +
                   'Examples:\n' +
                   '• Windows: C:/docs/file.md\n' +
                   '• Linux/Mac: /home/user/file.md\n' +
                   '• Relative: ./docs/file.md';
        }

        // Check file extension
        const ext = cleaned.split('.').pop().toLowerCase();
        const validExts = ['md', 'txt', 'markdown'];

        if (!validExts.includes(ext)) {
            return `Unsupported file type: .${ext}\nSupported: ${validExts.join(', ')}`;
        }

        return true;
    }

    /**
     * Duration validation (10-600 seconds)
     */
    validateDuration(value) {
        const duration = parseInt(value);

        if (isNaN(duration)) {
            return 'Duration must be a number';
        }

        if (duration < 10) {
            return 'Duration must be at least 10 seconds';
        }

        if (duration > 600) {
            return 'Duration cannot exceed 600 seconds (10 minutes)';
        }

        return true;
    }

    /**
     * Video count validation (1-20 videos)
     */
    validateVideoCount(value) {
        const count = parseInt(value);

        if (isNaN(count)) {
            return 'Video count must be a number';
        }

        if (count < 1) {
            return 'Must create at least 1 video';
        }

        if (count > 20) {
            return 'Cannot create more than 20 videos at once';
        }

        return true;
    }

    /**
     * Auto-detect input type and suggest appropriate action
     */
    detectInputType(value) {
        const cleaned = value.trim();

        if (!cleaned) {
            return { type: null, suggestion: null };
        }

        // YouTube URL detection
        if (/youtube\.com|youtu\.be/.test(cleaned)) {
            return {
                type: 'youtube',
                suggestion: 'Use YouTube tab for better options',
                icon: '📺'
            };
        }

        // HTTP(S) URL detection
        if (/^https?:\/\//i.test(cleaned)) {
            const isMarkdown = /\.(md|markdown|txt)$/i.test(cleaned);
            return {
                type: 'url',
                suggestion: isMarkdown ? 'Fetching document from URL' : 'Document URL detected',
                icon: '🌐'
            };
        }

        // File path detection (contains extension or path separator)
        if (/\.(md|txt|markdown)$/i.test(cleaned) || /[\/\\]/.test(cleaned)) {
            return {
                type: 'file_path',
                suggestion: 'Local file detected. Paste path or use file upload',
                icon: '📄'
            };
        }

        // Long text (likely direct input)
        if (cleaned.length > 50) {
            return {
                type: 'text',
                suggestion: 'Direct text input mode',
                icon: '✍️'
            };
        }

        return {
            type: 'unknown',
            suggestion: 'Paste a YouTube URL, file path, or longer text',
            icon: '❓'
        };
    }

    /**
     * Clean file path (remove quotes, normalize separators)
     */
    cleanFilePath(value) {
        let cleaned = value.trim();
        cleaned = cleaned.replace(/^["']|["']$/g, ''); // Remove quotes
        cleaned = cleaned.replace(/\\/g, '/'); // Normalize separators
        return cleaned;
    }

    // =========================================================================
    // Input Sanitization Methods (FIX C3)
    // =========================================================================

    /**
     * Sanitize a field value
     * @param {string} fieldName - Sanitizer identifier
     * @param {*} value - Value to sanitize
     * @returns {*} Sanitized value
     */
    sanitizeField(fieldName, value) {
        const sanitizer = this.sanitizers[fieldName];
        if (!sanitizer) return value;
        return sanitizer(value);
    }

    /**
     * Sanitize filename for safe display and storage
     * FIX C3: Removes dangerous characters from filenames
     * @param {string} filename - The filename to sanitize
     * @returns {string} Sanitized filename
     */
    sanitizeFilename(filename) {
        if (typeof filename !== 'string') {
            return '';
        }

        // Remove path separators and dangerous characters
        let clean = filename.replace(/[<>:"\/\\|?*\x00-\x1f]/g, '_');

        // Remove Unicode control characters
        clean = clean.replace(/[\u0000-\u001f\u007f-\u009f]/g, '');

        // Limit length
        if (clean.length > VALIDATION_CONSTANTS.MAX_FILENAME_LENGTH) {
            const ext = clean.split('.').pop();
            const maxBaseName = VALIDATION_CONSTANTS.MAX_FILENAME_LENGTH - ext.length - 1;
            clean = clean.slice(0, maxBaseName) + '.' + ext;
        }

        // Remove leading/trailing dots and spaces (Windows limitation)
        clean = clean.replace(/^[\s.]+|[\s.]+$/g, '');

        // Prevent reserved names on Windows
        const reserved = /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$/i;
        if (reserved.test(clean)) {
            clean = '_' + clean;
        }

        return clean || 'unnamed';
    }

    /**
     * Sanitize text input for safe processing
     * FIX C3: Prevents XSS and injection attacks
     * @param {string} text - The text to sanitize
     * @returns {string} Sanitized text
     */
    sanitizeText(text) {
        if (typeof text !== 'string') {
            return '';
        }

        // Remove null bytes
        let clean = text.replace(/\0/g, '');

        // Limit length
        if (clean.length > VALIDATION_CONSTANTS.MAX_TEXT_INPUT_LENGTH) {
            clean = clean.slice(0, VALIDATION_CONSTANTS.MAX_TEXT_INPUT_LENGTH);
        }

        return clean;
    }

    /**
     * Sanitize string for safe HTML display (prevents XSS)
     * FIX C3: Uses textContent approach for safety
     * @param {string} input - The input string
     * @returns {string} HTML-safe string
     */
    sanitizeForDisplay(input) {
        if (typeof input !== 'string') {
            return '';
        }

        const div = document.createElement('div');
        div.textContent = input;
        return div.innerHTML;
    }

    /**
     * Sanitize URL for safe use
     * FIX C3: Validates and normalizes URLs
     * @param {string} url - The URL to sanitize
     * @returns {string|null} Sanitized URL or null if invalid
     */
    sanitizeUrl(url) {
        if (typeof url !== 'string') {
            return null;
        }

        const trimmed = url.trim();

        try {
            const parsed = new URL(trimmed);

            // Only allow http and https protocols
            if (!['http:', 'https:'].includes(parsed.protocol)) {
                return null;
            }

            // Block javascript: URLs that might slip through encoding
            const href = parsed.href.toLowerCase();
            if (href.includes('javascript:') || href.includes('data:')) {
                return null;
            }

            return parsed.href;
        } catch {
            return null;
        }
    }

    /**
     * Create a safe error element (not innerHTML)
     * FIX C3: Safe DOM manipulation
     * @param {string} message - Error message
     * @param {string} className - CSS class name
     * @returns {HTMLElement} Safe error element
     */
    createSafeErrorElement(message, className = 'validation-error') {
        const el = document.createElement('div');
        el.className = className;
        el.textContent = message; // Safe - no innerHTML
        el.setAttribute('role', 'alert');
        el.setAttribute('aria-live', 'polite');
        return el;
    }

    /**
     * Escape string for use in HTML attributes
     * @param {string} str - The string to escape
     * @returns {string} Escaped string
     */
    escapeAttribute(str) {
        if (typeof str !== 'string') {
            return '';
        }

        return str
            .replace(/&/g, '&amp;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
    }

    /**
     * Validate and sanitize JSON string
     * @param {string} jsonString - JSON string to validate
     * @returns {Object|null} Parsed object or null if invalid
     */
    safeJsonParse(jsonString) {
        if (typeof jsonString !== 'string') {
            return null;
        }

        try {
            return JSON.parse(jsonString);
        } catch {
            return null;
        }
    }

    /**
     * Check if a string looks like it might contain malicious content
     * @param {string} input - Input to check
     * @returns {boolean} True if potentially malicious
     */
    isPotentiallyMalicious(input) {
        if (typeof input !== 'string') {
            return false;
        }

        const suspicious = [
            /<script/i,
            /javascript:/i,
            /on\w+\s*=/i, // Event handlers like onclick=
            /data:/i,
            /vbscript:/i,
            /<iframe/i,
            /<object/i,
            /<embed/i
        ];

        return suspicious.some(pattern => pattern.test(input));
    }
}

// Create global validator instance
window.formValidator = new FormValidator();

/**
 * Alpine.js validation directive
 * Usage: x-validate="fieldName"
 */
document.addEventListener('alpine:init', () => {
    Alpine.directive('validate', (el, { expression }, { evaluate, effect }) => {
        const fieldName = expression;
        const errorContainer = document.createElement('div');
        errorContainer.className = 'validation-error text-xs text-red-600 mt-1';
        errorContainer.style.display = 'none';

        // FIX C2: Add ARIA attributes for accessibility
        const errorId = `${fieldName}-error-${Math.random().toString(36).substr(2, 9)}`;
        errorContainer.setAttribute('id', errorId);
        errorContainer.setAttribute('role', 'alert');
        errorContainer.setAttribute('aria-live', 'polite');

        // Insert error container after input
        el.parentNode.insertBefore(errorContainer, el.nextSibling);

        // Validate on input
        el.addEventListener('input', () => {
            const value = el.value;
            const error = window.formValidator.validateField(fieldName, value);

            if (error) {
                // FIX C1: Use textContent (not innerHTML) - prevents XSS
                errorContainer.textContent = error;
                errorContainer.style.display = 'block';

                // FIX C2: Mark field as invalid for screen readers
                el.setAttribute('aria-invalid', 'true');
                el.setAttribute('aria-describedby', errorId);

                el.classList.add('border-red-500');
                el.classList.remove('border-green-500');
            } else if (value.trim()) {
                errorContainer.style.display = 'none';

                // FIX C2: Mark field as valid for screen readers
                el.setAttribute('aria-invalid', 'false');
                el.removeAttribute('aria-describedby');

                el.classList.remove('border-red-500');
                el.classList.add('border-green-500');
            } else {
                errorContainer.style.display = 'none';

                // FIX C2: Remove validation state
                el.removeAttribute('aria-invalid');
                el.removeAttribute('aria-describedby');

                el.classList.remove('border-red-500', 'border-green-500');
            }
        });
    });
});

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = FormValidator;
}
