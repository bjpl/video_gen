/**
 * SSE Client Utility
 *
 * A robust Server-Sent Events client with:
 * - Auto-reconnect with exponential backoff
 * - Connection state management
 * - Error handling and recovery
 * - Event callbacks
 *
 * @requires Browser EventSource API
 */

class SSEClient {
    /**
     * Create an SSE client instance
     * @param {Object} options - Configuration options
     * @param {number} options.maxRetries - Maximum reconnection attempts (default: 5)
     * @param {number} options.baseDelay - Base delay for exponential backoff in ms (default: 1000)
     * @param {number} options.maxDelay - Maximum delay between retries in ms (default: 30000)
     * @param {boolean} options.autoReconnect - Enable auto-reconnect on error (default: true)
     */
    constructor(options = {}) {
        this.options = {
            maxRetries: options.maxRetries || 5,
            baseDelay: options.baseDelay || 1000,
            maxDelay: options.maxDelay || 30000,
            autoReconnect: options.autoReconnect !== false
        };

        this.eventSource = null;
        this.url = null;
        this.retryCount = 0;
        this.reconnectTimer = null;

        // Callbacks
        this._onMessage = null;
        this._onError = null;
        this._onClose = null;
        this._onOpen = null;
        this._onReconnecting = null;

        // State
        this.state = 'disconnected'; // 'disconnected', 'connecting', 'connected', 'reconnecting', 'closed'
    }

    /**
     * Connect to an SSE endpoint
     * @param {string} url - The SSE endpoint URL
     * @param {Object} options - Connection options
     * @returns {SSEClient} - Returns this for chaining
     */
    connect(url, options = {}) {
        if (this.state === 'connected' || this.state === 'connecting') {
            console.warn('[SSEClient] Already connected or connecting');
            return this;
        }

        this.url = url;
        this.state = 'connecting';
        this.retryCount = 0;

        this._createConnection();

        return this;
    }

    /**
     * Create the EventSource connection
     * @private
     */
    _createConnection() {
        try {
            // Close any existing connection
            if (this.eventSource) {
                this.eventSource.close();
            }

            this.eventSource = new EventSource(this.url);

            // Handle connection open
            this.eventSource.onopen = (event) => {
                console.log('[SSEClient] Connection established');
                this.state = 'connected';
                this.retryCount = 0;

                if (this._onOpen) {
                    this._onOpen(event);
                }
            };

            // Handle incoming messages
            this.eventSource.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);

                    if (this._onMessage) {
                        this._onMessage(data, event);
                    }

                    // Check for completion signals
                    if (data.status === 'complete' || data.status === 'failed') {
                        this.close();
                    }
                } catch (parseError) {
                    console.error('[SSEClient] Failed to parse message:', parseError);
                    // Still pass raw data if parsing fails
                    if (this._onMessage) {
                        this._onMessage(event.data, event);
                    }
                }
            };

            // Handle errors
            this.eventSource.onerror = (error) => {
                console.error('[SSEClient] Connection error:', error);

                // EventSource automatically reconnects on some errors
                // We handle our own reconnection for more control
                if (this.eventSource.readyState === EventSource.CLOSED) {
                    this._handleDisconnect(error);
                }
            };

        } catch (error) {
            console.error('[SSEClient] Failed to create connection:', error);
            this._handleDisconnect(error);
        }
    }

    /**
     * Handle disconnection and attempt reconnect
     * @private
     * @param {Event|Error} error - The error that caused disconnection
     */
    _handleDisconnect(error) {
        this.state = 'disconnected';

        if (this._onError) {
            this._onError(error);
        }

        // Attempt reconnection if enabled
        if (this.options.autoReconnect && this.retryCount < this.options.maxRetries) {
            this._attemptReconnect();
        } else if (this.retryCount >= this.options.maxRetries) {
            console.error('[SSEClient] Max retries reached, giving up');
            this.state = 'closed';

            if (this._onClose) {
                this._onClose({ reason: 'max_retries_exceeded' });
            }
        }
    }

    /**
     * Attempt to reconnect with exponential backoff
     * @private
     */
    _attemptReconnect() {
        if (this.state === 'closed') {
            return;
        }

        this.state = 'reconnecting';
        this.retryCount++;

        // Calculate delay with exponential backoff
        const delay = Math.min(
            this.options.baseDelay * Math.pow(2, this.retryCount - 1),
            this.options.maxDelay
        );

        console.log(`[SSEClient] Reconnecting in ${delay}ms (attempt ${this.retryCount}/${this.options.maxRetries})`);

        if (this._onReconnecting) {
            this._onReconnecting({
                attempt: this.retryCount,
                maxRetries: this.options.maxRetries,
                delay: delay
            });
        }

        // Clear any existing timer
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
        }

        this.reconnectTimer = setTimeout(() => {
            if (this.state !== 'closed') {
                this._createConnection();
            }
        }, delay);
    }

    /**
     * Register message callback
     * @param {Function} callback - Function to call on message (data, event)
     * @returns {SSEClient} - Returns this for chaining
     */
    onMessage(callback) {
        this._onMessage = callback;
        return this;
    }

    /**
     * Register error callback
     * @param {Function} callback - Function to call on error
     * @returns {SSEClient} - Returns this for chaining
     */
    onError(callback) {
        this._onError = callback;
        return this;
    }

    /**
     * Register close callback
     * @param {Function} callback - Function to call when connection closes
     * @returns {SSEClient} - Returns this for chaining
     */
    onClose(callback) {
        this._onClose = callback;
        return this;
    }

    /**
     * Register open callback
     * @param {Function} callback - Function to call when connection opens
     * @returns {SSEClient} - Returns this for chaining
     */
    onOpen(callback) {
        this._onOpen = callback;
        return this;
    }

    /**
     * Register reconnecting callback
     * @param {Function} callback - Function to call when attempting reconnection
     * @returns {SSEClient} - Returns this for chaining
     */
    onReconnecting(callback) {
        this._onReconnecting = callback;
        return this;
    }

    /**
     * Close the connection
     */
    close() {
        console.log('[SSEClient] Closing connection');

        this.state = 'closed';

        // Clear reconnect timer
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }

        // Close EventSource
        if (this.eventSource) {
            this.eventSource.close();
            this.eventSource = null;
        }

        if (this._onClose) {
            this._onClose({ reason: 'manual_close' });
        }
    }

    /**
     * Get current connection state
     * @returns {string} - Current state
     */
    getState() {
        return this.state;
    }

    /**
     * Get EventSource ready state
     * @returns {number|null} - EventSource.readyState or null if not connected
     */
    getReadyState() {
        if (!this.eventSource) {
            return null;
        }
        return this.eventSource.readyState;
    }

    /**
     * Check if currently connected
     * @returns {boolean}
     */
    isConnected() {
        return this.state === 'connected' &&
               this.eventSource &&
               this.eventSource.readyState === EventSource.OPEN;
    }

    /**
     * Force a reconnection attempt
     */
    reconnect() {
        if (this.state === 'closed') {
            this.state = 'disconnected';
            this.retryCount = 0;
        }

        if (this.eventSource) {
            this.eventSource.close();
        }

        this._createConnection();
    }
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { SSEClient };
}

// Make available globally
window.SSEClient = SSEClient;
