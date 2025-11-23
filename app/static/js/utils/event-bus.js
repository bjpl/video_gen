/**
 * Event Bus - Cross-component communication
 *
 * Features:
 * - Event namespacing
 * - Type-safe event definitions
 * - Once listeners
 * - Event logging in dev mode
 * - Wildcard subscriptions
 */

class EventBus {
    constructor(options = {}) {
        this.listeners = new Map();
        this.debug = options.debug || false;
        this.maxListeners = options.maxListeners || 100;

        // Track event counts for debugging
        this.eventCounts = new Map();
    }

    /**
     * Emit an event
     * @param {string} event - Event name (supports namespacing with ':')
     * @param {*} data - Event data
     * @returns {boolean} Whether any listeners were called
     */
    emit(event, data = null) {
        if (this.debug) {
            console.log(`[EventBus] Emit: ${event}`, data);
            this._trackEvent(event);
        }

        let handled = false;

        // Direct event listeners
        const listeners = this.listeners.get(event);
        if (listeners && listeners.size > 0) {
            listeners.forEach(({ handler, once }) => {
                try {
                    handler(data, event);
                    handled = true;

                    if (once) {
                        this.off(event, handler);
                    }
                } catch (error) {
                    console.error(`[EventBus] Error in handler for "${event}":`, error);
                }
            });
        }

        // Wildcard listeners (namespace:*)
        const namespace = event.split(':')[0];
        const wildcardEvent = `${namespace}:*`;
        const wildcardListeners = this.listeners.get(wildcardEvent);
        if (wildcardListeners && wildcardListeners.size > 0) {
            wildcardListeners.forEach(({ handler, once }) => {
                try {
                    handler(data, event);
                    handled = true;

                    if (once) {
                        this.off(wildcardEvent, handler);
                    }
                } catch (error) {
                    console.error(`[EventBus] Error in wildcard handler for "${event}":`, error);
                }
            });
        }

        // Global wildcard listeners (*)
        const globalListeners = this.listeners.get('*');
        if (globalListeners && globalListeners.size > 0) {
            globalListeners.forEach(({ handler, once }) => {
                try {
                    handler(data, event);
                    handled = true;

                    if (once) {
                        this.off('*', handler);
                    }
                } catch (error) {
                    console.error(`[EventBus] Error in global handler for "${event}":`, error);
                }
            });
        }

        return handled;
    }

    /**
     * Subscribe to an event
     * @param {string} event - Event name
     * @param {Function} handler - Event handler
     * @returns {Function} Unsubscribe function
     */
    on(event, handler) {
        if (typeof handler !== 'function') {
            throw new Error('Handler must be a function');
        }

        if (!this.listeners.has(event)) {
            this.listeners.set(event, new Set());
        }

        const listeners = this.listeners.get(event);

        // Check listener limit
        if (listeners.size >= this.maxListeners) {
            console.warn(`[EventBus] Max listeners (${this.maxListeners}) exceeded for "${event}"`);
        }

        const listenerObj = { handler, once: false };
        listeners.add(listenerObj);

        if (this.debug) {
            console.log(`[EventBus] Subscribe: ${event} (${listeners.size} listeners)`);
        }

        // Return unsubscribe function
        return () => this.off(event, handler);
    }

    /**
     * Unsubscribe from an event
     * @param {string} event - Event name
     * @param {Function} handler - Event handler to remove
     * @returns {boolean} Whether handler was found and removed
     */
    off(event, handler) {
        const listeners = this.listeners.get(event);
        if (!listeners) {
            return false;
        }

        let removed = false;
        listeners.forEach(listenerObj => {
            if (listenerObj.handler === handler) {
                listeners.delete(listenerObj);
                removed = true;
            }
        });

        if (this.debug && removed) {
            console.log(`[EventBus] Unsubscribe: ${event} (${listeners.size} listeners remaining)`);
        }

        // Cleanup empty sets
        if (listeners.size === 0) {
            this.listeners.delete(event);
        }

        return removed;
    }

    /**
     * Subscribe to an event once
     * @param {string} event - Event name
     * @param {Function} handler - Event handler
     * @returns {Function} Unsubscribe function
     */
    once(event, handler) {
        if (typeof handler !== 'function') {
            throw new Error('Handler must be a function');
        }

        if (!this.listeners.has(event)) {
            this.listeners.set(event, new Set());
        }

        const listenerObj = { handler, once: true };
        this.listeners.get(event).add(listenerObj);

        if (this.debug) {
            console.log(`[EventBus] Subscribe (once): ${event}`);
        }

        return () => this.off(event, handler);
    }

    /**
     * Remove all listeners for an event or all events
     * @param {string} [event] - Optional event name
     */
    clear(event = null) {
        if (event) {
            this.listeners.delete(event);
            if (this.debug) {
                console.log(`[EventBus] Cleared listeners for: ${event}`);
            }
        } else {
            this.listeners.clear();
            if (this.debug) {
                console.log('[EventBus] Cleared all listeners');
            }
        }
    }

    /**
     * Get listener count for an event
     * @param {string} event - Event name
     * @returns {number}
     */
    listenerCount(event) {
        const listeners = this.listeners.get(event);
        return listeners ? listeners.size : 0;
    }

    /**
     * Get all registered events
     * @returns {string[]}
     */
    eventNames() {
        return Array.from(this.listeners.keys());
    }

    /**
     * Track event counts for debugging
     * @param {string} event
     */
    _trackEvent(event) {
        const count = (this.eventCounts.get(event) || 0) + 1;
        this.eventCounts.set(event, count);
    }

    /**
     * Get event statistics
     * @returns {Object}
     */
    getStats() {
        const stats = {
            totalEvents: this.listeners.size,
            listeners: {},
            eventCounts: Object.fromEntries(this.eventCounts)
        };

        this.listeners.forEach((set, event) => {
            stats.listeners[event] = set.size;
        });

        return stats;
    }

    /**
     * Enable/disable debug mode
     * @param {boolean} enabled
     */
    setDebug(enabled) {
        this.debug = enabled;
        console.log(`[EventBus] Debug mode: ${enabled ? 'enabled' : 'disabled'}`);
    }
}

// Define standard event types for type safety
const EventTypes = {
    // Input events
    INPUT_FILE_SELECTED: 'input:file-selected',
    INPUT_FILE_VALIDATED: 'input:file-validated',
    INPUT_URL_CHANGED: 'input:url-changed',
    INPUT_URL_VALIDATED: 'input:url-validated',
    INPUT_TEXT_CHANGED: 'input:text-changed',
    INPUT_CLEARED: 'input:cleared',

    // Preview events
    PREVIEW_LOADING: 'preview:loading',
    PREVIEW_LOADED: 'preview:loaded',
    PREVIEW_ERROR: 'preview:error',
    PREVIEW_CLEARED: 'preview:cleared',

    // Language events
    LANGUAGE_SELECTED: 'language:selected',
    LANGUAGE_DESELECTED: 'language:deselected',
    LANGUAGES_LOADED: 'languages:loaded',

    // Voice events
    VOICE_SELECTED: 'voice:selected',
    VOICE_DESELECTED: 'voice:deselected',
    VOICE_PREVIEW_START: 'voice:preview-start',
    VOICE_PREVIEW_END: 'voice:preview-end',
    VOICES_LOADED: 'voices:loaded',

    // Progress events
    PROGRESS_STARTED: 'progress:started',
    PROGRESS_UPDATED: 'progress:updated',
    PROGRESS_STAGE_CHANGED: 'progress:stage-changed',
    PROGRESS_COMPLETED: 'progress:completed',
    PROGRESS_FAILED: 'progress:failed',
    PROGRESS_CANCELLED: 'progress:cancelled',

    // Configuration events
    CONFIG_CHANGED: 'config:changed',
    CONFIG_RESET: 'config:reset',
    CONFIG_LOADED: 'config:loaded',

    // Validation events
    VALIDATION_SUCCESS: 'validation:success',
    VALIDATION_ERROR: 'validation:error',
    VALIDATION_WARNING: 'validation:warning',

    // UI events
    UI_TOAST_SHOW: 'ui:toast-show',
    UI_TOAST_HIDE: 'ui:toast-hide',
    UI_MODAL_OPEN: 'ui:modal-open',
    UI_MODAL_CLOSE: 'ui:modal-close',
    UI_STEP_CHANGED: 'ui:step-changed',

    // API events
    API_REQUEST_START: 'api:request-start',
    API_REQUEST_END: 'api:request-end',
    API_ERROR: 'api:error',

    // Storage events
    STORAGE_SAVED: 'storage:saved',
    STORAGE_LOADED: 'storage:loaded',
    STORAGE_CLEARED: 'storage:cleared'
};

// Create and export global instances
window.EventBus = EventBus;
window.EventTypes = EventTypes;
window.eventBus = new EventBus({ debug: false });

// Integration with Alpine.js - allow dispatching events from Alpine components
document.addEventListener('alpine:init', () => {
    Alpine.magic('emit', () => {
        return (event, data) => window.eventBus.emit(event, data);
    });

    Alpine.magic('on', () => {
        return (event, handler) => window.eventBus.on(event, handler);
    });
});
