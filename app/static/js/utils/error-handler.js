/**
 * Global Error Handler - Centralized error handling and reporting
 *
 * Features:
 * - Error categorization (network, validation, server, etc.)
 * - User-friendly error messages
 * - Toast notifications
 * - Error logging and reporting
 * - Recovery suggestions
 */

class ErrorHandler {
    constructor(options = {}) {
        this.debug = options.debug || false;
        this.reportEndpoint = options.reportEndpoint || null;
        this.toastDuration = options.toastDuration || 5000;

        // Error history for debugging
        this.errorHistory = [];
        this.maxHistory = 50;

        // User-friendly messages by category
        this.messages = {
            network: 'Unable to connect. Please check your internet connection.',
            timeout: 'The request timed out. Please try again.',
            validation: 'Please fix the errors highlighted above.',
            server: 'Something went wrong on our end. Please try again later.',
            notFound: 'The requested resource was not found.',
            forbidden: 'You do not have permission to perform this action.',
            unauthorized: 'Please log in to continue.',
            rateLimit: 'Too many requests. Please wait a moment and try again.',
            fileTooLarge: 'The file is too large. Please choose a smaller file.',
            invalidFormat: 'Invalid file format. Please check the supported formats.',
            unknown: 'An unexpected error occurred. Please try again.'
        };

        // Recovery suggestions
        this.suggestions = {
            network: 'Check your internet connection and try again.',
            timeout: 'The server may be busy. Wait a moment and retry.',
            validation: 'Review the form fields and correct any errors.',
            server: 'If the problem persists, contact support.',
            notFound: 'The resource may have been moved or deleted.',
            rateLimit: 'Wait 30 seconds before trying again.',
            fileTooLarge: 'Maximum file size is 10MB.',
            invalidFormat: 'Supported formats: MD, TXT, PDF, DOCX.'
        };

        // Setup global error handlers
        this._setupGlobalHandlers();
    }

    /**
     * Handle an error with appropriate logging and user feedback
     * @param {Error|string} error - The error to handle
     * @param {Object} context - Additional context
     * @returns {Object} Processed error info
     */
    handle(error, context = {}) {
        const errorInfo = this._processError(error, context);

        // Log the error
        this._logError(errorInfo);

        // Show user notification if requested
        if (context.showToast !== false) {
            this.showToast(errorInfo.message, 'error', errorInfo.suggestion);
        }

        // Report to backend if configured
        if (this.reportEndpoint && errorInfo.category !== 'validation') {
            this._reportError(errorInfo);
        }

        // Emit error event
        if (window.eventBus) {
            window.eventBus.emit('error:occurred', errorInfo);
        }

        return errorInfo;
    }

    /**
     * Process error into standardized format
     * @param {Error|string} error
     * @param {Object} context
     * @returns {Object}
     */
    _processError(error, context) {
        const errorInfo = {
            id: this._generateId(),
            timestamp: new Date().toISOString(),
            category: 'unknown',
            code: null,
            message: this.messages.unknown,
            suggestion: null,
            originalError: error,
            context: context,
            stack: null
        };

        // Handle string errors
        if (typeof error === 'string') {
            errorInfo.message = error;
            errorInfo.category = 'custom';
            return errorInfo;
        }

        // Get stack trace
        if (error.stack) {
            errorInfo.stack = error.stack;
        }

        // Handle APIError (from api-client.js)
        if (error.name === 'APIError') {
            errorInfo.code = error.status;
            errorInfo.category = this._categorizeHttpError(error.status);
            errorInfo.message = error.message || this.messages[errorInfo.category];
            errorInfo.suggestion = this.suggestions[errorInfo.category];

            // Use server-provided message if available
            if (error.details && error.details.detail) {
                errorInfo.message = error.details.detail;
            }

            return errorInfo;
        }

        // Handle fetch/network errors
        if (error.message && error.message.includes('fetch')) {
            errorInfo.category = 'network';
            errorInfo.message = this.messages.network;
            errorInfo.suggestion = this.suggestions.network;
            return errorInfo;
        }

        // Handle timeout errors
        if (error.name === 'TimeoutError' || (error.message && error.message.includes('timeout'))) {
            errorInfo.category = 'timeout';
            errorInfo.message = this.messages.timeout;
            errorInfo.suggestion = this.suggestions.timeout;
            return errorInfo;
        }

        // Handle TypeError (often from null references)
        if (error.name === 'TypeError') {
            errorInfo.category = 'runtime';
            errorInfo.message = 'An application error occurred.';
            return errorInfo;
        }

        // Handle SyntaxError (JSON parsing, etc.)
        if (error.name === 'SyntaxError') {
            errorInfo.category = 'parse';
            errorInfo.message = 'Invalid data format received.';
            return errorInfo;
        }

        // Default - use error message if available
        if (error.message) {
            errorInfo.message = error.message;
        }

        return errorInfo;
    }

    /**
     * Categorize HTTP status codes
     * @param {number} status
     * @returns {string}
     */
    _categorizeHttpError(status) {
        if (status === 0) return 'network';
        if (status === 400) return 'validation';
        if (status === 401) return 'unauthorized';
        if (status === 403) return 'forbidden';
        if (status === 404) return 'notFound';
        if (status === 413) return 'fileTooLarge';
        if (status === 429) return 'rateLimit';
        if (status >= 500) return 'server';
        return 'unknown';
    }

    /**
     * Show a toast notification
     * @param {string} message - Message to display
     * @param {string} type - Toast type ('success', 'error', 'warning', 'info')
     * @param {string} suggestion - Optional suggestion
     */
    showToast(message, type = 'info', suggestion = null) {
        const toast = {
            id: this._generateId(),
            message,
            type,
            suggestion,
            timestamp: Date.now()
        };

        // Try Alpine store first
        if (window.Alpine && Alpine.store('appState')) {
            Alpine.store('appState').addNotification(type, message, this.toastDuration);
            return;
        }

        // Fallback: dispatch custom event for toast display
        window.dispatchEvent(new CustomEvent('show-toast', {
            detail: toast
        }));

        // Also emit on event bus if available
        if (window.eventBus) {
            window.eventBus.emit(window.EventTypes?.UI_TOAST_SHOW || 'ui:toast-show', toast);
        }

        // Console fallback for debugging
        if (this.debug) {
            const icon = { success: '[OK]', error: '[ERR]', warning: '[WARN]', info: '[INFO]' }[type];
            console.log(`${icon} Toast: ${message}`);
        }
    }

    /**
     * Log error to console with formatting
     * @param {Object} errorInfo
     */
    _logError(errorInfo) {
        // Add to history
        this.errorHistory.push(errorInfo);
        if (this.errorHistory.length > this.maxHistory) {
            this.errorHistory.shift();
        }

        // Console logging
        const component = errorInfo.context.component || 'App';

        if (this.debug) {
            console.group(`[ErrorHandler] ${errorInfo.category.toUpperCase()}`);
            console.error(`Component: ${component}`);
            console.error(`Message: ${errorInfo.message}`);
            if (errorInfo.suggestion) {
                console.info(`Suggestion: ${errorInfo.suggestion}`);
            }
            if (errorInfo.stack) {
                console.error('Stack:', errorInfo.stack);
            }
            console.log('Context:', errorInfo.context);
            console.groupEnd();
        } else {
            console.error(`[${component}] ${errorInfo.message}`);
        }
    }

    /**
     * Report error to backend
     * @param {Object} errorInfo
     */
    async _reportError(errorInfo) {
        if (!this.reportEndpoint) return;

        try {
            const reportData = {
                id: errorInfo.id,
                timestamp: errorInfo.timestamp,
                category: errorInfo.category,
                code: errorInfo.code,
                message: errorInfo.message,
                component: errorInfo.context.component,
                url: window.location.href,
                userAgent: navigator.userAgent,
                stack: errorInfo.stack
            };

            await fetch(this.reportEndpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(reportData)
            });
        } catch (e) {
            // Silently fail - don't create error loops
            if (this.debug) {
                console.warn('[ErrorHandler] Failed to report error:', e);
            }
        }
    }

    /**
     * Setup global error handlers
     */
    _setupGlobalHandlers() {
        // Unhandled errors
        window.addEventListener('error', (event) => {
            this.handle(event.error || event.message, {
                component: 'Global',
                showToast: false, // Don't spam toasts for every error
                type: 'uncaught'
            });
        });

        // Unhandled promise rejections
        window.addEventListener('unhandledrejection', (event) => {
            this.handle(event.reason, {
                component: 'Promise',
                showToast: false,
                type: 'unhandledRejection'
            });
        });
    }

    /**
     * Generate unique error ID
     * @returns {string}
     */
    _generateId() {
        return `err_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    /**
     * Get error history
     * @param {number} count - Number of recent errors
     * @returns {Object[]}
     */
    getHistory(count = 10) {
        return this.errorHistory.slice(-count);
    }

    /**
     * Clear error history
     */
    clearHistory() {
        this.errorHistory = [];
    }

    /**
     * Create a validation error
     * @param {string} field - Field name
     * @param {string} message - Error message
     * @returns {Object}
     */
    validationError(field, message) {
        return {
            category: 'validation',
            field,
            message,
            suggestion: this.suggestions.validation
        };
    }

    /**
     * Enable/disable debug mode
     * @param {boolean} enabled
     */
    setDebug(enabled) {
        this.debug = enabled;
        console.log(`[ErrorHandler] Debug mode: ${enabled ? 'enabled' : 'disabled'}`);
    }
}

// Create and export global instance
window.ErrorHandler = ErrorHandler;
window.errorHandler = new ErrorHandler({ debug: false });

// Convenience function for handling errors
window.handleError = (error, context = {}) => {
    return window.errorHandler.handle(error, context);
};

// Convenience function for showing toasts
window.showToast = (message, type = 'info') => {
    window.errorHandler.showToast(message, type);
};
