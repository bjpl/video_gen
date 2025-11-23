/**
 * Storage Manager - localStorage wrapper with TTL and migration support
 *
 * Features:
 * - JSON serialization/deserialization
 * - TTL (time-to-live) support
 * - Storage quota handling
 * - Migration support for schema changes
 * - Optional encryption for sensitive data
 */

class StorageManager {
    constructor(options = {}) {
        this.prefix = options.prefix || 'vg_';
        this.version = options.version || '1.0.0';
        this.encryptionKey = options.encryptionKey || null;

        // Check localStorage availability
        this.available = this._checkAvailability();

        if (this.available) {
            this._runMigrations();
        }
    }

    /**
     * Check if localStorage is available
     * @returns {boolean}
     */
    _checkAvailability() {
        try {
            const test = '__storage_test__';
            localStorage.setItem(test, test);
            localStorage.removeItem(test);
            return true;
        } catch (e) {
            console.warn('[StorageManager] localStorage not available:', e.message);
            return false;
        }
    }

    /**
     * Get prefixed key
     * @param {string} key
     * @returns {string}
     */
    _getKey(key) {
        return `${this.prefix}${key}`;
    }

    /**
     * Set a value in storage
     * @param {string} key - Storage key
     * @param {*} value - Value to store (will be JSON serialized)
     * @param {number} [ttl] - Time-to-live in milliseconds (optional)
     * @param {boolean} [encrypt] - Whether to encrypt the value
     * @returns {boolean} Success status
     */
    set(key, value, ttl = null, encrypt = false) {
        if (!this.available) {
            console.warn('[StorageManager] Storage not available');
            return false;
        }

        try {
            const wrapper = {
                value: value,
                timestamp: Date.now(),
                version: this.version
            };

            if (ttl !== null && ttl > 0) {
                wrapper.expires = Date.now() + ttl;
            }

            let data = JSON.stringify(wrapper);

            if (encrypt && this.encryptionKey) {
                data = this._encrypt(data);
            }

            localStorage.setItem(this._getKey(key), data);
            return true;
        } catch (error) {
            if (this._isQuotaError(error)) {
                console.warn('[StorageManager] Quota exceeded, clearing expired items');
                this._clearExpired();

                // Retry once after clearing
                try {
                    const wrapper = {
                        value: value,
                        timestamp: Date.now(),
                        version: this.version
                    };
                    if (ttl !== null && ttl > 0) {
                        wrapper.expires = Date.now() + ttl;
                    }
                    localStorage.setItem(this._getKey(key), JSON.stringify(wrapper));
                    return true;
                } catch (retryError) {
                    console.error('[StorageManager] Failed to store after cleanup:', retryError);
                    return false;
                }
            }
            console.error('[StorageManager] Failed to store:', error);
            return false;
        }
    }

    /**
     * Get a value from storage
     * @param {string} key - Storage key
     * @param {*} [defaultValue] - Default value if not found or expired
     * @param {boolean} [decrypt] - Whether to decrypt the value
     * @returns {*} The stored value or default
     */
    get(key, defaultValue = null, decrypt = false) {
        if (!this.available) {
            return defaultValue;
        }

        try {
            let data = localStorage.getItem(this._getKey(key));

            if (data === null) {
                return defaultValue;
            }

            if (decrypt && this.encryptionKey) {
                data = this._decrypt(data);
            }

            const wrapper = JSON.parse(data);

            // Check expiration
            if (wrapper.expires && Date.now() > wrapper.expires) {
                this.remove(key);
                return defaultValue;
            }

            return wrapper.value;
        } catch (error) {
            console.error('[StorageManager] Failed to retrieve:', error);
            return defaultValue;
        }
    }

    /**
     * Remove a value from storage
     * @param {string} key - Storage key
     * @returns {boolean} Success status
     */
    remove(key) {
        if (!this.available) {
            return false;
        }

        try {
            localStorage.removeItem(this._getKey(key));
            return true;
        } catch (error) {
            console.error('[StorageManager] Failed to remove:', error);
            return false;
        }
    }

    /**
     * Check if a key exists and is not expired
     * @param {string} key - Storage key
     * @returns {boolean}
     */
    has(key) {
        if (!this.available) {
            return false;
        }

        try {
            const data = localStorage.getItem(this._getKey(key));
            if (data === null) {
                return false;
            }

            const wrapper = JSON.parse(data);

            // Check expiration
            if (wrapper.expires && Date.now() > wrapper.expires) {
                this.remove(key);
                return false;
            }

            return true;
        } catch (error) {
            return false;
        }
    }

    /**
     * Clear all items with this prefix
     * @returns {boolean} Success status
     */
    clear() {
        if (!this.available) {
            return false;
        }

        try {
            const keysToRemove = [];

            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (key && key.startsWith(this.prefix)) {
                    keysToRemove.push(key);
                }
            }

            keysToRemove.forEach(key => localStorage.removeItem(key));
            console.log(`[StorageManager] Cleared ${keysToRemove.length} items`);
            return true;
        } catch (error) {
            console.error('[StorageManager] Failed to clear:', error);
            return false;
        }
    }

    /**
     * Clear all expired items
     * @returns {number} Number of items cleared
     */
    _clearExpired() {
        if (!this.available) {
            return 0;
        }

        let cleared = 0;
        const now = Date.now();

        try {
            const keysToCheck = [];

            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (key && key.startsWith(this.prefix)) {
                    keysToCheck.push(key);
                }
            }

            keysToCheck.forEach(key => {
                try {
                    const data = JSON.parse(localStorage.getItem(key));
                    if (data.expires && now > data.expires) {
                        localStorage.removeItem(key);
                        cleared++;
                    }
                } catch (e) {
                    // Invalid JSON, remove it
                    localStorage.removeItem(key);
                    cleared++;
                }
            });

            if (cleared > 0) {
                console.log(`[StorageManager] Cleared ${cleared} expired items`);
            }
        } catch (error) {
            console.error('[StorageManager] Error clearing expired items:', error);
        }

        return cleared;
    }

    /**
     * Get storage statistics
     * @returns {Object} Storage stats
     */
    getStats() {
        if (!this.available) {
            return { available: false };
        }

        let totalSize = 0;
        let itemCount = 0;
        let expiredCount = 0;
        const now = Date.now();

        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith(this.prefix)) {
                itemCount++;
                const value = localStorage.getItem(key);
                totalSize += (key.length + value.length) * 2; // UTF-16

                try {
                    const wrapper = JSON.parse(value);
                    if (wrapper.expires && now > wrapper.expires) {
                        expiredCount++;
                    }
                } catch (e) {
                    // Ignore parse errors
                }
            }
        }

        return {
            available: true,
            itemCount,
            expiredCount,
            totalSize,
            totalSizeKB: (totalSize / 1024).toFixed(2),
            estimatedQuota: '5MB',
            version: this.version
        };
    }

    /**
     * List all keys with this prefix
     * @returns {string[]} Array of keys (without prefix)
     */
    keys() {
        if (!this.available) {
            return [];
        }

        const keys = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith(this.prefix)) {
                keys.push(key.substring(this.prefix.length));
            }
        }
        return keys;
    }

    /**
     * Check if error is a quota exceeded error
     * @param {Error} error
     * @returns {boolean}
     */
    _isQuotaError(error) {
        return (
            error instanceof DOMException &&
            (error.code === 22 || // Legacy
             error.code === 1014 || // Firefox
             error.name === 'QuotaExceededError' ||
             error.name === 'NS_ERROR_DOM_QUOTA_REACHED')
        );
    }

    /**
     * Run migrations for schema changes
     */
    _runMigrations() {
        const versionKey = this._getKey('_version');
        const storedVersion = localStorage.getItem(versionKey);

        if (storedVersion !== this.version) {
            console.log(`[StorageManager] Migrating from ${storedVersion || 'none'} to ${this.version}`);

            // Run migration handlers
            this._migrateData(storedVersion, this.version);

            localStorage.setItem(versionKey, this.version);
        }
    }

    /**
     * Migrate data between versions
     * @param {string} fromVersion
     * @param {string} toVersion
     */
    _migrateData(fromVersion, toVersion) {
        // Add migration logic here as needed
        // Example migrations:

        if (!fromVersion) {
            // First time setup - nothing to migrate
            return;
        }

        // Example: migrate from 0.x to 1.x
        // if (fromVersion.startsWith('0.') && toVersion.startsWith('1.')) {
        //     // Transform old data format to new
        // }

        console.log('[StorageManager] Migration complete');
    }

    /**
     * Simple XOR encryption (for basic obfuscation, not secure)
     * @param {string} data
     * @returns {string}
     */
    _encrypt(data) {
        if (!this.encryptionKey) return data;

        const key = this.encryptionKey;
        let result = '';
        for (let i = 0; i < data.length; i++) {
            result += String.fromCharCode(
                data.charCodeAt(i) ^ key.charCodeAt(i % key.length)
            );
        }
        return btoa(result);
    }

    /**
     * Simple XOR decryption
     * @param {string} data
     * @returns {string}
     */
    _decrypt(data) {
        if (!this.encryptionKey) return data;

        const decoded = atob(data);
        const key = this.encryptionKey;
        let result = '';
        for (let i = 0; i < decoded.length; i++) {
            result += String.fromCharCode(
                decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length)
            );
        }
        return result;
    }
}

// Create and export global instance
window.StorageManager = StorageManager;
window.storage = new StorageManager({ prefix: 'vg_', version: '1.0.0' });
