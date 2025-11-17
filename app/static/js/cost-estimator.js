/**
 * AI Cost Estimator - P1 Error Prevention
 *
 * Provides real-time cost estimation for AI operations:
 * - AI narration enhancement
 * - Translation to multiple languages
 * - TTS (always free via Edge-TTS)
 */

class CostEstimator {
    constructor() {
        // Claude Sonnet 4.5 pricing (as of 2025)
        this.pricing = {
            input_per_million: 3.00,    // $3 per 1M input tokens
            output_per_million: 15.00   // $15 per 1M output tokens
        };

        // Average token usage per operation
        this.tokenAverages = {
            narration: {
                input: 100,   // Prompt + scene content
                output: 30    // Enhanced narration
            },
            translation: {
                input: 200,   // Source text + translation prompt
                output: 150   // Translated text
            }
        };
    }

    /**
     * Calculate cost for single operation
     * @param {number} inputTokens - Input tokens
     * @param {number} outputTokens - Output tokens
     * @returns {number} Cost in USD
     */
    calculateOperationCost(inputTokens, outputTokens) {
        const inputCost = (inputTokens / 1_000_000) * this.pricing.input_per_million;
        const outputCost = (outputTokens / 1_000_000) * this.pricing.output_per_million;
        return inputCost + outputCost;
    }

    /**
     * Estimate cost per scene for AI narration
     * @returns {number} Cost in USD
     */
    costPerSceneNarration() {
        return this.calculateOperationCost(
            this.tokenAverages.narration.input,
            this.tokenAverages.narration.output
        );
    }

    /**
     * Estimate cost per scene for translation
     * @returns {number} Cost in USD
     */
    costPerSceneTranslation() {
        return this.calculateOperationCost(
            this.tokenAverages.translation.input,
            this.tokenAverages.translation.output
        );
    }

    /**
     * Estimate total cost for video configuration
     * @param {Object} config - Video configuration
     * @returns {Object} Cost breakdown
     */
    estimateVideoSetCost(config) {
        const estimate = {
            ai_narration: 0,
            translation: 0,
            tts: 0, // Always free
            total: 0,
            breakdown: []
        };

        // Count scenes across all videos
        const sceneCount = config.videos?.reduce((sum, video) => {
            return sum + (video.scenes?.length || config.estimatedScenesPerVideo || 5);
        }, 0) || (config.estimatedScenesPerVideo || 5);

        // AI Narration Cost
        if (config.use_ai_narration) {
            const costPerScene = this.costPerSceneNarration();
            estimate.ai_narration = sceneCount * costPerScene;
            estimate.breakdown.push({
                item: 'AI Narration Enhancement',
                details: `${sceneCount} scenes × $${costPerScene.toFixed(5)}`,
                cost: estimate.ai_narration,
                savingsPossible: true
            });
        }

        // Translation Cost (exclude source language)
        const languages = config.target_languages || ['en'];
        if (languages.length > 1) {
            // If using Claude translation (Google Translate is free)
            if (config.translation_method === 'claude') {
                const targetLanguages = languages.length - 1; // Exclude source
                const costPerTranslation = this.costPerSceneTranslation();
                estimate.translation = sceneCount * targetLanguages * costPerTranslation;
                estimate.breakdown.push({
                    item: 'Claude Translation',
                    details: `${sceneCount} scenes × ${targetLanguages} languages × $${costPerTranslation.toFixed(5)}`,
                    cost: estimate.translation,
                    savingsPossible: true
                });
            } else {
                estimate.breakdown.push({
                    item: 'Google Translate',
                    details: `${languages.length} languages (FREE)`,
                    cost: 0,
                    savingsPossible: false
                });
            }
        }

        // TTS is always free
        estimate.breakdown.push({
            item: 'Neural Text-to-Speech (Edge-TTS)',
            details: 'Unlimited usage (FREE)',
            cost: 0,
            savingsPossible: false
        });

        estimate.total = estimate.ai_narration + estimate.translation;

        return estimate;
    }

    /**
     * Get cost optimization suggestions
     * @param {Object} estimate - Cost estimate from estimateVideoSetCost
     * @param {Object} config - Video configuration
     * @returns {Array} Optimization tips
     */
    getOptimizationTips(estimate, config) {
        const tips = [];

        // AI Narration optimization
        if (estimate.ai_narration > 0.01) {
            tips.push({
                icon: '💡',
                category: 'AI Narration',
                tip: 'AI narration costs can be avoided by using template-based narration',
                savings: estimate.ai_narration,
                action: 'Disable AI enhancement',
                priority: 'medium'
            });
        }

        // Translation optimization
        if (estimate.translation > 0.05) {
            const languageCount = (config.target_languages || ['en']).length;
            tips.push({
                icon: '🌍',
                category: 'Translation',
                tip: `Translating to ${languageCount} languages with Claude. Consider Google Translate (free) or reduce language count`,
                savings: estimate.translation, // Full savings if switch to Google
                action: 'Use Google Translate or reduce languages',
                priority: 'high'
            });
        }

        // Batch processing tip (no cost savings, but time savings)
        if (estimate.total > 0.10) {
            tips.push({
                icon: '⚡',
                category: 'Performance',
                tip: 'Consider batch processing - costs are the same but saves time with parallel execution',
                savings: 0,
                action: 'Use video sets for multiple videos',
                priority: 'low'
            });
        }

        // Free tier recommendation
        if (estimate.total === 0) {
            tips.push({
                icon: '✅',
                category: 'Optimization',
                tip: 'You\'re using the free tier! Template-based narration + Edge-TTS = $0.00',
                savings: 0,
                action: 'Keep current settings',
                priority: 'info'
            });
        }

        return tips;
    }

    /**
     * Format cost for display
     * @param {number} cost - Cost in USD
     * @returns {string} Formatted cost
     */
    formatCost(cost) {
        if (cost === 0) return 'FREE';
        if (cost < 0.001) return '< $0.001';
        if (cost < 0.01) return `$${cost.toFixed(4)}`;
        if (cost < 1) return `$${cost.toFixed(3)}`;
        return `$${cost.toFixed(2)}`;
    }

    /**
     * Get color class based on cost
     * @param {number} cost - Cost in USD
     * @returns {string} Tailwind color class
     */
    getCostColorClass(cost) {
        if (cost === 0) return 'text-green-600';
        if (cost < 0.05) return 'text-blue-600';
        if (cost < 0.20) return 'text-yellow-600';
        return 'text-orange-600';
    }
}

// Create global cost estimator instance
window.costEstimator = new CostEstimator();

/**
 * Alpine.js cost estimator component
 */
document.addEventListener('alpine:init', () => {
    Alpine.data('costEstimator', () => ({
        estimate: {
            ai_narration: 0,
            translation: 0,
            tts: 0,
            total: 0,
            breakdown: []
        },
        tips: [],

        // FIX C3: Add debounced update method (300ms delay)
        updateEstimate: Alpine.debounce(function(config) {
            this.estimate = window.costEstimator.estimateVideoSetCost(config);
            this.tips = window.costEstimator.getOptimizationTips(this.estimate, config);
        }, 300),

        formatCost(cost) {
            return window.costEstimator.formatCost(cost);
        },

        getCostColor(cost) {
            return window.costEstimator.getCostColorClass(cost);
        }
    }));
});

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CostEstimator;
}
