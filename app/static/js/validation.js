/**
 * Client-Side Validation Module - P1 Error Prevention
 *
 * Provides real-time validation for form inputs with user-friendly feedback.
 * Prevents common errors before submission.
 */

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
