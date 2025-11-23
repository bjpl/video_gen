/**
 * P1 Cognitive Load Reduction Enhancements
 * Week 2 Implementation
 *
 * This file extends the videoCreator Alpine component with:
 * - Preset package support
 * - Smart defaults based on content detection
 * - Time estimation
 * - Recommended option badges
 */

/**
 * Extend videoCreator function with P1 enhancements
 * Call this AFTER videoCreator() returns its object
 */
function addP1Enhancements(baseCreator) {
    // Add new state properties
    const enhancements = {
        // Preset state
        selectedPreset: null,
        showPresetCustomize: false,
        detectedContentType: null,

        // Time estimation
        estimatedTime: null,

        /**
         * Apply preset configuration
         */
        applyPreset(presetId) {
            if (!window.PresetPackages) {
                console.error('PresetPackages not loaded');
                return;
            }

            const success = window.PresetPackages.applyPreset(this, presetId, this.mode);
            if (success) {
                this.selectedPreset = presetId;
                this.updateTimeEstimate();
            }
        },

        /**
         * Update estimated generation time
         */
        updateTimeEstimate() {
            if (!window.SmartDefaults) {
                console.error('SmartDefaults not loaded');
                return;
            }

            const config = this.mode === 'single' ? this.single : this.set;
            this.estimatedTime = window.SmartDefaults.estimateGenerationTime(config);
        },

        /**
         * Detect content type and apply smart defaults
         */
        detectAndApplyDefaults(text) {
            if (!window.SmartDefaults) {
                console.error('SmartDefaults not loaded');
                return;
            }

            const contentType = window.SmartDefaults.detectContentType(text);
            this.detectedContentType = contentType;

            // Apply smart defaults
            window.SmartDefaults.applySmartDefaults(this, contentType, this.mode);

            // Update time estimate
            this.updateTimeEstimate();
        },

        /**
         * Check if an option is recommended
         */
        isRecommended(optionType, optionValue) {
            if (!window.PresetPackages) return false;
            return window.PresetPackages.isRecommended(optionType, optionValue);
        },

        /**
         * Get recommendation reason
         */
        getRecommendationReason(optionType, optionValue) {
            if (!window.PresetPackages) return '';
            return window.PresetPackages.getRecommendationReason(optionType, optionValue);
        },

        /**
         * Get formatted time breakdown
         */
        getTimeBreakdown() {
            if (!this.estimatedTime || !window.SmartDefaults) return '';
            return window.SmartDefaults.getTimeBreakdownText(this.estimatedTime);
        }
    };

    // Merge enhancements into base creator
    return Object.assign({}, baseCreator, enhancements);
}

// Export for use in Alpine component
if (typeof window !== 'undefined') {
    window.addP1Enhancements = addP1Enhancements;
}
