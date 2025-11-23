/**
 * API Client - Centralized API communication
 *
 * Features:
 * - All endpoint methods
 * - Error handling with retry logic
 * - Request/response interceptors
 * - Caching layer with TTL
 * - CSRF token handling
 * - Request timeout
 */

class APIError extends Error {
    constructor(message, status, details = {}) {
        super(message);
        this.name = 'APIError';
        this.status = status;
        this.details = details;
    }

    get isValidationError() { return this.status === 400; }
    get isAuthError() { return this.status === 401 || this.status === 403; }
    get isNotFound() { return this.status === 404; }
    get isServerError() { return this.status >= 500; }
    get isNetworkError() { return this.status === 0; }
}

class APIClient {
    constructor(options = {}) {
        this.baseURL = options.baseURL || '';
        this.timeout = options.timeout || 30000;
        this.retryAttempts = options.retryAttempts || 3;
        this.retryDelay = options.retryDelay || 1000;

        // Request/response interceptors
        this.requestInterceptors = [];
        this.responseInterceptors = [];

        // Cache configuration
        this.cache = new Map();
        this.cacheEnabled = options.cacheEnabled !== false;
        this.defaultCacheTTL = options.defaultCacheTTL || 60000; // 1 minute

        // Request tracking
        this.activeRequests = new Map();
        this.requestId = 0;

        // Setup default interceptors
        this._setupDefaultInterceptors();
    }

    /**
     * Setup default request/response interceptors
     */
    _setupDefaultInterceptors() {
        // Add CSRF token to requests
        this.addRequestInterceptor((config) => {
            const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
            if (csrfToken) {
                config.headers['X-CSRF-Token'] = csrfToken;
            }
            return config;
        });

        // Add request ID
        this.addRequestInterceptor((config) => {
            config.headers['X-Request-ID'] = `req_${++this.requestId}`;
            return config;
        });

        // Log requests in debug mode
        this.addRequestInterceptor((config) => {
            if (window.errorHandler?.debug) {
                console.log(`[API] ${config.method} ${config.url}`, config);
            }
            return config;
        });
    }

    /**
     * Add request interceptor
     * @param {Function} interceptor
     */
    addRequestInterceptor(interceptor) {
        this.requestInterceptors.push(interceptor);
    }

    /**
     * Add response interceptor
     * @param {Function} interceptor
     */
    addResponseInterceptor(interceptor) {
        this.responseInterceptors.push(interceptor);
    }

    /**
     * Core request method
     * @param {string} endpoint - API endpoint
     * @param {Object} options - Fetch options
     * @returns {Promise}
     */
    async _request(endpoint, options = {}) {
        const url = this.baseURL + endpoint;

        // Default config
        let config = {
            method: options.method || 'GET',
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            url,
            ...options
        };

        // Run request interceptors
        for (const interceptor of this.requestInterceptors) {
            config = await interceptor(config);
        }

        // Remove url from config (not a fetch option)
        const { url: _, ...fetchOptions } = config;

        // Create abort controller for timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        fetchOptions.signal = controller.signal;

        // Emit request start event
        if (window.eventBus) {
            window.eventBus.emit(window.EventTypes?.API_REQUEST_START || 'api:request-start', { url, method: config.method });
        }

        try {
            let response = await fetch(url, fetchOptions);
            clearTimeout(timeoutId);

            // Run response interceptors
            for (const interceptor of this.responseInterceptors) {
                response = await interceptor(response);
            }

            // Handle non-OK responses
            if (!response.ok) {
                let errorDetails = {};
                try {
                    errorDetails = await response.json();
                } catch (e) {
                    // Response might not be JSON
                }

                throw new APIError(
                    errorDetails.detail || errorDetails.message || `HTTP ${response.status}`,
                    response.status,
                    errorDetails
                );
            }

            // Parse JSON response
            const data = await response.json();

            // Emit request end event
            if (window.eventBus) {
                window.eventBus.emit(window.EventTypes?.API_REQUEST_END || 'api:request-end', { url, method: config.method, success: true });
            }

            return data;

        } catch (error) {
            clearTimeout(timeoutId);

            // Emit error event
            if (window.eventBus) {
                window.eventBus.emit(window.EventTypes?.API_ERROR || 'api:error', { url, error });
            }

            // Handle abort (timeout)
            if (error.name === 'AbortError') {
                throw new APIError('Request timeout', 0, { type: 'timeout' });
            }

            // Handle network errors
            if (error instanceof TypeError && error.message.includes('fetch')) {
                throw new APIError('Network error', 0, { type: 'network' });
            }

            // Re-throw APIError
            if (error instanceof APIError) {
                throw error;
            }

            // Wrap unknown errors
            throw new APIError(error.message || 'Unknown error', 0, { originalError: error });
        }
    }

    /**
     * Request with retry logic
     * @param {string} endpoint
     * @param {Object} options
     * @param {number} attempt
     * @returns {Promise}
     */
    async _requestWithRetry(endpoint, options = {}, attempt = 1) {
        try {
            return await this._request(endpoint, options);
        } catch (error) {
            // Don't retry validation errors or client errors
            if (error.status >= 400 && error.status < 500) {
                throw error;
            }

            // Retry on network/server errors
            if (attempt < this.retryAttempts) {
                const delay = this.retryDelay * Math.pow(2, attempt - 1); // Exponential backoff
                console.log(`[API] Retrying in ${delay}ms (attempt ${attempt + 1}/${this.retryAttempts})`);

                await new Promise(resolve => setTimeout(resolve, delay));
                return this._requestWithRetry(endpoint, options, attempt + 1);
            }

            throw error;
        }
    }

    /**
     * GET request with caching
     * @param {string} endpoint
     * @param {Object} options
     * @returns {Promise}
     */
    async get(endpoint, options = {}) {
        const cacheKey = `GET:${endpoint}`;
        const cacheTTL = options.cacheTTL ?? this.defaultCacheTTL;

        // Check cache
        if (this.cacheEnabled && options.useCache !== false) {
            const cached = this._getFromCache(cacheKey);
            if (cached !== null) {
                return cached;
            }
        }

        const data = await this._requestWithRetry(endpoint, { ...options, method: 'GET' });

        // Store in cache
        if (this.cacheEnabled && cacheTTL > 0) {
            this._setCache(cacheKey, data, cacheTTL);
        }

        return data;
    }

    /**
     * POST request
     * @param {string} endpoint
     * @param {Object} body
     * @param {Object} options
     * @returns {Promise}
     */
    async post(endpoint, body, options = {}) {
        return this._requestWithRetry(endpoint, {
            ...options,
            method: 'POST',
            body: JSON.stringify(body)
        });
    }

    /**
     * POST with FormData (for file uploads)
     * @param {string} endpoint
     * @param {FormData} formData
     * @param {Object} options
     * @returns {Promise}
     */
    async postForm(endpoint, formData, options = {}) {
        return this._requestWithRetry(endpoint, {
            ...options,
            method: 'POST',
            headers: {}, // Let browser set Content-Type for FormData
            body: formData
        });
    }

    /**
     * PUT request
     * @param {string} endpoint
     * @param {Object} body
     * @param {Object} options
     * @returns {Promise}
     */
    async put(endpoint, body, options = {}) {
        return this._requestWithRetry(endpoint, {
            ...options,
            method: 'PUT',
            body: JSON.stringify(body)
        });
    }

    /**
     * DELETE request
     * @param {string} endpoint
     * @param {Object} options
     * @returns {Promise}
     */
    async delete(endpoint, options = {}) {
        return this._requestWithRetry(endpoint, {
            ...options,
            method: 'DELETE'
        });
    }

    // ==================== Cache Methods ====================

    _getFromCache(key) {
        const cached = this.cache.get(key);
        if (!cached) return null;

        if (Date.now() > cached.expires) {
            this.cache.delete(key);
            return null;
        }

        return cached.data;
    }

    _setCache(key, data, ttl) {
        this.cache.set(key, {
            data,
            expires: Date.now() + ttl
        });
    }

    invalidateCache(pattern = null) {
        if (pattern === null) {
            this.cache.clear();
            return;
        }

        // Invalidate matching keys
        const regex = new RegExp(pattern);
        for (const key of this.cache.keys()) {
            if (regex.test(key)) {
                this.cache.delete(key);
            }
        }
    }

    // ==================== Document APIs ====================

    document = {
        validate: async (file) => {
            const formData = new FormData();
            formData.append('file', file);
            return this.postForm('/api/validate/document', formData);
        },

        preview: async (file) => {
            const formData = new FormData();
            formData.append('file', file);
            return this.postForm('/api/preview/document', formData);
        },

        parse: async (content, config = {}) => {
            return this.post('/api/parse/document', { content, ...config });
        }
    };

    // ==================== YouTube APIs ====================

    youtube = {
        validate: async (url) => {
            return this.post('/api/youtube/validate', { url });
        },

        preview: async (url, includeTranscript = false) => {
            return this.post('/api/youtube/preview', {
                url,
                include_transcript_preview: includeTranscript
            });
        },

        parse: async (url, config = {}) => {
            return this.post('/api/parse/youtube', { url, ...config });
        }
    };

    // ==================== YAML APIs ====================

    yaml = {
        validate: async (content) => {
            return this.post('/api/validate/yaml', { content });
        },

        parse: async (content, config = {}) => {
            return this.post('/api/parse/yaml', { content, ...config });
        }
    };

    // ==================== Language APIs ====================

    languages = {
        list: async () => {
            return this.get('/api/languages', { cacheTTL: 300000 }); // 5 min cache
        },

        getVoices: async (langCode) => {
            return this.get(`/api/languages/${langCode}/voices`, { cacheTTL: 300000 });
        },

        previewVoice: async (langCode, voiceId, text) => {
            return this.post('/api/voice-preview', {
                language: langCode,
                voice: voiceId,
                text
            });
        }
    };

    // ==================== Task APIs ====================

    tasks = {
        getStatus: async (taskId) => {
            return this.get(`/api/tasks/${taskId}`, { useCache: false });
        },

        cancel: async (taskId) => {
            return this.post(`/api/tasks/${taskId}/cancel`, {});
        },

        create: async (config) => {
            return this.post('/api/tasks', config);
        },

        list: async (status = null) => {
            const endpoint = status ? `/api/tasks?status=${status}` : '/api/tasks';
            return this.get(endpoint, { useCache: false });
        }
    };

    // ==================== Health/Status APIs ====================

    health = {
        check: async () => {
            return this.get('/api/health', { useCache: false, cacheTTL: 0 });
        },

        status: async () => {
            return this.get('/api/status', { useCache: false });
        }
    };
}

// SSE Client for streaming progress
class SSEClient {
    constructor(url) {
        this.url = url;
        this.eventSource = null;
        this.callbacks = {
            message: null,
            error: null,
            complete: null,
            stage: null
        };
        this.retryCount = 0;
        this.maxRetries = 3;
        this.connected = false;
    }

    connect() {
        if (this.eventSource) {
            this.disconnect();
        }

        this.eventSource = new EventSource(this.url);
        this.connected = true;

        this.eventSource.onopen = () => {
            console.log('[SSE] Connected');
            this.retryCount = 0;
        };

        this.eventSource.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);

                // Handle completion
                if (data.status === 'complete' || data.status === 'completed') {
                    this.callbacks.complete?.(data);
                    this.disconnect();
                    return;
                }

                // Handle errors
                if (data.status === 'error' || data.status === 'failed') {
                    this.callbacks.error?.(new Error(data.error || 'Task failed'));
                    this.disconnect();
                    return;
                }

                // Handle stage changes
                if (data.stage && this.callbacks.stage) {
                    this.callbacks.stage(data.stage, data);
                }

                // General message
                this.callbacks.message?.(data);

            } catch (error) {
                console.error('[SSE] Parse error:', error);
            }
        };

        this.eventSource.onerror = (error) => {
            console.error('[SSE] Error:', error);
            this.connected = false;

            if (this.retryCount < this.maxRetries) {
                this.retryCount++;
                const delay = 1000 * this.retryCount;
                console.log(`[SSE] Retrying in ${delay}ms...`);
                setTimeout(() => this.connect(), delay);
            } else {
                this.callbacks.error?.(new Error('SSE connection failed after retries'));
                this.disconnect();
            }
        };

        return this;
    }

    disconnect() {
        if (this.eventSource) {
            this.eventSource.close();
            this.eventSource = null;
        }
        this.connected = false;
        console.log('[SSE] Disconnected');
    }

    onMessage(callback) {
        this.callbacks.message = callback;
        return this;
    }

    onError(callback) {
        this.callbacks.error = callback;
        return this;
    }

    onComplete(callback) {
        this.callbacks.complete = callback;
        return this;
    }

    onStage(callback) {
        this.callbacks.stage = callback;
        return this;
    }

    isConnected() {
        return this.connected && this.eventSource?.readyState === EventSource.OPEN;
    }
}

// Create and export global instances
window.APIClient = APIClient;
window.APIError = APIError;
window.SSEClient = SSEClient;
window.api = new APIClient();

// Backward compatibility with existing code
window.API = {
    document: window.api.document,
    youtube: window.api.youtube,
    yaml: window.api.yaml,
    languages: window.api.languages,
    tasks: window.api.tasks,
    health: window.api.health
};
