/**
 * Security Utility Module
 *
 * Provides security-related utilities for the frontend:
 * - CSRF token management
 * - Input sanitization
 * - Secure fetch wrapper
 * - XSS prevention helpers
 *
 * @module security
 */

(function(global) {
    'use strict';

    /**
     * Security utilities class
     */
    class SecurityUtils {
        constructor() {
            this._csrfToken = null;
            this._csrfTokenExpiry = null;
            this._tokenRefreshInterval = null;
            this._abortControllers = new Map();

            // Token refresh interval (50 minutes to ensure token is fresh before 1 hour expiry)
            this.TOKEN_REFRESH_INTERVAL = 50 * 60 * 1000;

            // Initialize on construction
            this._init();
        }

        /**
         * Initialize security utilities
         * @private
         */
        async _init() {
            // Fetch initial CSRF token
            await this.refreshCsrfToken();

            // Setup automatic token refresh
            this._tokenRefreshInterval = setInterval(() => {
                this.refreshCsrfToken();
            }, this.TOKEN_REFRESH_INTERVAL);

            // Clean up on page unload
            window.addEventListener('beforeunload', () => {
                this.cleanup();
            });
        }

        /**
         * Fetch a fresh CSRF token from the server
         * @returns {Promise<string>} The CSRF token
         */
        async refreshCsrfToken() {
            try {
                const response = await fetch('/api/csrf-token', {
                    method: 'GET',
                    credentials: 'same-origin'
                });

                if (response.ok) {
                    const data = await response.json();
                    this._csrfToken = data.csrf_token;
                    this._csrfTokenExpiry = Date.now() + (55 * 60 * 1000); // 55 minutes

                    // Update meta tag if present
                    this._updateMetaTag();

                    return this._csrfToken;
                } else {
                    console.error('Failed to fetch CSRF token:', response.status);
                    return null;
                }
            } catch (error) {
                console.error('Error fetching CSRF token:', error);
                return null;
            }
        }

        /**
         * Get the current CSRF token, refreshing if needed
         * @returns {Promise<string>} The CSRF token
         */
        async getCsrfToken() {
            // Check if token needs refresh
            if (!this._csrfToken || (this._csrfTokenExpiry && Date.now() > this._csrfTokenExpiry)) {
                await this.refreshCsrfToken();
            }
            return this._csrfToken;
        }

        /**
         * Get CSRF token synchronously (may be stale)
         * @returns {string|null} The cached CSRF token
         */
        getCsrfTokenSync() {
            return this._csrfToken;
        }

        /**
         * Update the CSRF meta tag in the document head
         * @private
         */
        _updateMetaTag() {
            let meta = document.querySelector('meta[name="csrf-token"]');
            if (!meta) {
                meta = document.createElement('meta');
                meta.name = 'csrf-token';
                document.head.appendChild(meta);
            }
            meta.content = this._csrfToken || '';
        }

        /**
         * Secure fetch wrapper that automatically includes CSRF token
         * @param {string} url - The URL to fetch
         * @param {Object} options - Fetch options
         * @returns {Promise<Response>} The fetch response
         */
        async secureFetch(url, options = {}) {
            const method = (options.method || 'GET').toUpperCase();

            // Only add CSRF token for state-changing methods
            if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
                const token = await this.getCsrfToken();

                options.headers = {
                    ...options.headers,
                    'X-CSRF-Token': token
                };
            }

            // Always include credentials for same-origin requests
            options.credentials = options.credentials || 'same-origin';

            return fetch(url, options);
        }

        /**
         * Create a fetch request with abort controller for cancellation
         * @param {string} requestId - Unique identifier for this request
         * @param {string} url - The URL to fetch
         * @param {Object} options - Fetch options
         * @returns {Promise<Response>} The fetch response
         */
        async secureFetchWithAbort(requestId, url, options = {}) {
            // Cancel any existing request with this ID
            this.abortRequest(requestId);

            // Create new abort controller
            const controller = new AbortController();
            this._abortControllers.set(requestId, controller);

            // Add signal to options
            options.signal = controller.signal;

            try {
                const response = await this.secureFetch(url, options);
                return response;
            } finally {
                // Clean up controller after request completes
                this._abortControllers.delete(requestId);
            }
        }

        /**
         * Abort a pending request
         * @param {string} requestId - The request identifier
         */
        abortRequest(requestId) {
            const controller = this._abortControllers.get(requestId);
            if (controller) {
                controller.abort();
                this._abortControllers.delete(requestId);
            }
        }

        /**
         * Abort all pending requests
         */
        abortAllRequests() {
            for (const [id, controller] of this._abortControllers) {
                controller.abort();
            }
            this._abortControllers.clear();
        }

        // =====================================================================
        // Input Sanitization
        // =====================================================================

        /**
         * Sanitize a string for safe display (prevents XSS)
         * @param {string} input - The input string
         * @returns {string} Sanitized string
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
         * Sanitize filename for display (removes dangerous characters)
         * @param {string} filename - The filename
         * @returns {string} Sanitized filename
         */
        sanitizeFilename(filename) {
            if (typeof filename !== 'string') {
                return '';
            }

            // Remove path separators and dangerous characters
            let clean = filename.replace(/[<>:"\/\\|?*\x00-\x1f]/g, '_');

            // Limit length
            if (clean.length > 255) {
                const ext = clean.split('.').pop();
                clean = clean.slice(0, 250 - ext.length) + '.' + ext;
            }

            // Remove leading/trailing dots and spaces
            clean = clean.replace(/^[\s.]+|[\s.]+$/g, '');

            return clean || 'unnamed';
        }

        /**
         * Sanitize URL (validates and normalizes)
         * @param {string} url - The URL to sanitize
         * @returns {string|null} Sanitized URL or null if invalid
         */
        sanitizeUrl(url) {
            if (typeof url !== 'string') {
                return null;
            }

            try {
                const parsed = new URL(url.trim());

                // Only allow http and https protocols
                if (!['http:', 'https:'].includes(parsed.protocol)) {
                    return null;
                }

                // Block javascript: URLs that might slip through
                if (parsed.href.toLowerCase().includes('javascript:')) {
                    return null;
                }

                return parsed.href;
            } catch {
                return null;
            }
        }

        /**
         * Sanitize HTML content using allowlist approach
         * @param {string} html - The HTML content
         * @param {string[]} allowedTags - List of allowed tag names
         * @returns {string} Sanitized HTML
         */
        sanitizeHtml(html, allowedTags = ['b', 'i', 'em', 'strong', 'br']) {
            if (typeof html !== 'string') {
                return '';
            }

            const doc = new DOMParser().parseFromString(html, 'text/html');
            const walker = document.createTreeWalker(doc.body, NodeFilter.SHOW_ALL);

            const nodesToRemove = [];
            let node;

            while ((node = walker.nextNode())) {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    const tagName = node.tagName.toLowerCase();

                    if (!allowedTags.includes(tagName)) {
                        nodesToRemove.push(node);
                    } else {
                        // Remove all attributes except safe ones
                        const attrs = Array.from(node.attributes);
                        for (const attr of attrs) {
                            // Remove event handlers and dangerous attributes
                            if (attr.name.startsWith('on') ||
                                attr.name === 'href' && attr.value.toLowerCase().startsWith('javascript:') ||
                                attr.name === 'src' && attr.value.toLowerCase().startsWith('javascript:')) {
                                node.removeAttribute(attr.name);
                            }
                        }
                    }
                }
            }

            // Remove disallowed nodes (replace with text content)
            for (const node of nodesToRemove) {
                const text = document.createTextNode(node.textContent || '');
                node.parentNode.replaceChild(text, node);
            }

            return doc.body.innerHTML;
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
         * Validate and sanitize JSON input
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

        // =====================================================================
        // Error Message Handling
        // =====================================================================

        /**
         * Create a user-friendly error message (no sensitive data)
         * @param {string} errorCode - Error code
         * @param {string} fallbackMessage - Default message
         * @returns {string} User-friendly error message
         */
        getUserFriendlyError(errorCode, fallbackMessage = 'An error occurred. Please try again.') {
            const errorMessages = {
                'CSRF_FAILED': 'Session expired. Please refresh the page and try again.',
                'UNAUTHORIZED': 'You are not authorized to perform this action.',
                'NOT_FOUND': 'The requested resource was not found.',
                'VALIDATION_ERROR': 'Please check your input and try again.',
                'RATE_LIMITED': 'Too many requests. Please wait a moment and try again.',
                'SERVER_ERROR': 'A server error occurred. Please try again later.',
                'NETWORK_ERROR': 'Network error. Please check your connection.',
                'TIMEOUT': 'Request timed out. Please try again.'
            };

            return errorMessages[errorCode] || fallbackMessage;
        }

        // =====================================================================
        // Cleanup
        // =====================================================================

        /**
         * Clean up resources
         */
        cleanup() {
            // Clear token refresh interval
            if (this._tokenRefreshInterval) {
                clearInterval(this._tokenRefreshInterval);
                this._tokenRefreshInterval = null;
            }

            // Abort all pending requests
            this.abortAllRequests();
        }
    }

    // Create singleton instance
    const securityUtils = new SecurityUtils();

    // Export for different module systems
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = { SecurityUtils, securityUtils };
    }

    // Always attach to global
    global.SecurityUtils = SecurityUtils;
    global.securityUtils = securityUtils;

})(typeof window !== 'undefined' ? window : this);
