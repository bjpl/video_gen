/**
 * API Cache Utility
 *
 * A shared caching utility for reducing redundant API calls.
 * Provides TTL-based caching with automatic expiration.
 *
 * Features:
 * - Configurable TTL per cache entry
 * - Automatic cache expiration
 * - Cache invalidation by key or pattern
 * - Memory-efficient with automatic cleanup
 * - Debug logging support
 *
 * @example
 * // Basic usage
 * const cache = new APICache(5 * 60 * 1000); // 5 minute TTL
 * cache.set('languages', data);
 * const cached = cache.get('languages');
 *
 * // With custom TTL per entry
 * cache.set('voices:en', voices, 10 * 60 * 1000); // 10 minute TTL
 */

class APICache {
    /**
     * Create a new API cache instance
     * @param {number} defaultTTL - Default time-to-live in milliseconds (default: 5 minutes)
     */
    constructor(defaultTTL = 5 * 60 * 1000) {
        this.cache = new Map();
        this.defaultTTL = defaultTTL;
        this.debug = false;

        // Start periodic cleanup (every 60 seconds)
        this._cleanupInterval = setInterval(() => this._cleanup(), 60000);
    }

    /**
     * Set a value in the cache
     * @param {string} key - Cache key
     * @param {*} value - Value to cache
     * @param {number} [ttl] - Optional TTL override in milliseconds
     */
    set(key, value, ttl = null) {
        const expiresAt = Date.now() + (ttl ?? this.defaultTTL);

        this.cache.set(key, {
            value,
            timestamp: Date.now(),
            expiresAt
        });

        if (this.debug) {
            console.log(`[APICache] SET ${key}, expires in ${(ttl ?? this.defaultTTL) / 1000}s`);
        }
    }

    /**
     * Get a value from the cache
     * @param {string} key - Cache key
     * @returns {*} Cached value or null if not found/expired
     */
    get(key) {
        const cached = this.cache.get(key);

        if (!cached) {
            if (this.debug) {
                console.log(`[APICache] MISS ${key} (not found)`);
            }
            return null;
        }

        // Check if expired
        if (Date.now() > cached.expiresAt) {
            this.cache.delete(key);
            if (this.debug) {
                console.log(`[APICache] MISS ${key} (expired)`);
            }
            return null;
        }

        if (this.debug) {
            const remainingTTL = Math.round((cached.expiresAt - Date.now()) / 1000);
            console.log(`[APICache] HIT ${key}, ${remainingTTL}s remaining`);
        }

        return cached.value;
    }

    /**
     * Check if a key exists and is valid (not expired)
     * @param {string} key - Cache key
     * @returns {boolean}
     */
    has(key) {
        const cached = this.cache.get(key);
        if (!cached) return false;

        if (Date.now() > cached.expiresAt) {
            this.cache.delete(key);
            return false;
        }

        return true;
    }

    /**
     * Delete a specific key from the cache
     * @param {string} key - Cache key
     * @returns {boolean} True if key existed and was deleted
     */
    delete(key) {
        const existed = this.cache.has(key);
        this.cache.delete(key);

        if (this.debug && existed) {
            console.log(`[APICache] DELETE ${key}`);
        }

        return existed;
    }

    /**
     * Clear all cached values
     */
    clear() {
        const size = this.cache.size;
        this.cache.clear();

        if (this.debug) {
            console.log(`[APICache] CLEAR (${size} entries removed)`);
        }
    }

    /**
     * Invalidate cache entries matching a pattern
     * @param {string|RegExp} pattern - Pattern to match against keys
     * @returns {number} Number of entries invalidated
     */
    invalidate(pattern) {
        let count = 0;
        const regex = pattern instanceof RegExp ? pattern : new RegExp(pattern);

        for (const key of this.cache.keys()) {
            if (regex.test(key)) {
                this.cache.delete(key);
                count++;
            }
        }

        if (this.debug && count > 0) {
            console.log(`[APICache] INVALIDATE pattern:${pattern}, ${count} entries removed`);
        }

        return count;
    }

    /**
     * Get cache statistics
     * @returns {Object} Cache statistics
     */
    getStats() {
        let validCount = 0;
        let expiredCount = 0;
        const now = Date.now();

        for (const [key, entry] of this.cache) {
            if (now > entry.expiresAt) {
                expiredCount++;
            } else {
                validCount++;
            }
        }

        return {
            totalEntries: this.cache.size,
            validEntries: validCount,
            expiredEntries: expiredCount,
            defaultTTL: this.defaultTTL
        };
    }

    /**
     * Get or set a value with a fetcher function
     * Useful for wrapping async API calls
     * @param {string} key - Cache key
     * @param {Function} fetcher - Async function to fetch value if not cached
     * @param {number} [ttl] - Optional TTL override
     * @returns {Promise<*>} Cached or fetched value
     */
    async getOrFetch(key, fetcher, ttl = null) {
        const cached = this.get(key);
        if (cached !== null) {
            return cached;
        }

        const value = await fetcher();
        this.set(key, value, ttl);
        return value;
    }

    /**
     * Clean up expired entries
     * @private
     */
    _cleanup() {
        const now = Date.now();
        let cleaned = 0;

        for (const [key, entry] of this.cache) {
            if (now > entry.expiresAt) {
                this.cache.delete(key);
                cleaned++;
            }
        }

        if (this.debug && cleaned > 0) {
            console.log(`[APICache] CLEANUP ${cleaned} expired entries`);
        }
    }

    /**
     * Destroy the cache and stop cleanup interval
     */
    destroy() {
        if (this._cleanupInterval) {
            clearInterval(this._cleanupInterval);
            this._cleanupInterval = null;
        }
        this.cache.clear();
    }

    /**
     * Enable or disable debug logging
     * @param {boolean} enabled
     */
    setDebug(enabled) {
        this.debug = enabled;
    }
}

// ==================== Singleton Instances ====================

/**
 * Global API cache instance with 5-minute default TTL
 * Used by components for caching API responses
 */
window.apiCache = new APICache(5 * 60 * 1000);

/**
 * Specialized cache for language data (longer TTL - 10 minutes)
 * Languages don't change frequently
 */
window.languageCache = new APICache(10 * 60 * 1000);

/**
 * Specialized cache for voice data (5 minutes)
 * Voice lists are relatively stable
 */
window.voiceCache = new APICache(5 * 60 * 1000);

// Export class for custom instances
window.APICache = APICache;

// Enable debug in development
if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    // Optionally enable debug mode
    // window.apiCache.setDebug(true);
}

console.log('[APICache] Utility loaded');
