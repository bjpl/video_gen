/**
 * Smart Defaults and Content Type Detection
 * Week 2 P1 Implementation
 *
 * Automatically detects content type and applies intelligent defaults
 * to reduce cognitive load and decision fatigue.
 */

/**
 * Content type definitions and their optimal configurations
 */
const CONTENT_TYPES = {
    business: {
        id: 'business',
        name: 'Business/Corporate',
        keywords: ['business', 'corporate', 'company', 'enterprise', 'roi', 'revenue', 'market', 'strategy', 'sales'],

        defaults: {
            languageMode: 'multiple',
            targetLanguages: ['en', 'es', 'fr', 'de'],
            primaryVoice: 'en-US-GuyNeural',
            color: 'blue',
            duration: 150, // 2.5 minutes
            useAI: true,
            translationMethod: 'claude'
        },

        rationale: 'Corporate content benefits from multi-language support and professional tone'
    },

    technical: {
        id: 'technical',
        name: 'Technical Documentation',
        keywords: ['api', 'function', 'class', 'method', 'code', 'programming', 'software', 'documentation', 'developer', 'technical'],

        defaults: {
            languageMode: 'single',
            primaryLanguage: 'en',
            primaryVoice: 'en-US-GuyNeural',
            color: 'cyan',
            duration: 180, // 3 minutes
            useAI: true,
            translationMethod: 'google'
        },

        rationale: 'Technical content is typically in English with clear, professional narration'
    },

    educational: {
        id: 'educational',
        name: 'Educational/Tutorial',
        keywords: ['learn', 'tutorial', 'guide', 'how to', 'lesson', 'course', 'teach', 'student', 'education', 'training'],

        defaults: {
            languageMode: 'multiple',
            targetLanguages: ['en', 'es'],
            primaryVoice: 'en-US-JennyNeural',
            color: 'green',
            duration: 270, // 4.5 minutes
            useAI: true,
            translationMethod: 'claude'
        },

        rationale: 'Educational content works best with engaging voice and bilingual support'
    },

    creative: {
        id: 'creative',
        name: 'Creative/Marketing',
        keywords: ['creative', 'design', 'art', 'marketing', 'brand', 'campaign', 'content', 'social', 'media', 'viral'],

        defaults: {
            languageMode: 'single',
            primaryLanguage: 'en',
            primaryVoice: 'en-US-JennyNeural',
            color: 'purple',
            duration: 90, // 1.5 minutes
            useAI: true,
            translationMethod: 'google'
        },

        rationale: 'Creative content needs punchy, engaging narration and striking visuals'
    },

    general: {
        id: 'general',
        name: 'General Content',
        keywords: [],

        defaults: {
            languageMode: 'single',
            primaryLanguage: 'en',
            primaryVoice: 'en-US-JennyNeural',
            color: 'blue',
            duration: 120, // 2 minutes
            useAI: false, // Save cost for general content
            translationMethod: 'google'
        },

        rationale: 'Balanced defaults for general-purpose videos'
    }
};

/**
 * Detect content type from text
 */
function detectContentType(text) {
    if (!text || text.trim().length === 0) {
        return CONTENT_TYPES.general;
    }

    const lowerText = text.toLowerCase();

    // Score each content type based on keyword matches
    const scores = Object.entries(CONTENT_TYPES).map(([id, type]) => {
        if (id === 'general') return { id, type, score: 0 };

        const matchCount = type.keywords.filter(keyword =>
            lowerText.includes(keyword)
        ).length;

        return { id, type, score: matchCount };
    });

    // Sort by score (highest first)
    scores.sort((a, b) => b.score - a.score);

    // If no matches, return general
    if (scores[0].score === 0) {
        return CONTENT_TYPES.general;
    }

    return scores[0].type;
}

/**
 * Detect content type from document path/URL
 */
function detectFromPath(path) {
    if (!path) return CONTENT_TYPES.general;

    const lowerPath = path.toLowerCase();

    // Check for specific indicators in path
    if (lowerPath.includes('readme') || lowerPath.includes('docs')) {
        return CONTENT_TYPES.technical;
    }

    if (lowerPath.includes('tutorial') || lowerPath.includes('guide')) {
        return CONTENT_TYPES.educational;
    }

    if (lowerPath.includes('marketing') || lowerPath.includes('blog')) {
        return CONTENT_TYPES.creative;
    }

    return CONTENT_TYPES.general;
}

/**
 * Estimate generation time based on configuration
 */
function estimateGenerationTime(config) {
    // Base time per scene (in seconds)
    const BASE_TIME_PER_SCENE = 3;

    // Get scene count (estimate if not available)
    const sceneCount = config.scenes?.length || 10; // Default estimate

    // Calculate base time
    let totalSeconds = sceneCount * BASE_TIME_PER_SCENE;

    // AI narration adds 30% time
    if (config.useAI) {
        totalSeconds *= 1.3;
    }

    // Multiply by language count
    const languageCount = config.languageMode === 'multiple'
        ? (config.targetLanguages?.length || 1)
        : 1;
    totalSeconds *= languageCount;

    // Multiply by video count (for video sets)
    const videoCount = config.videoCount || 1;
    totalSeconds *= videoCount;

    // Convert to readable format
    if (totalSeconds < 60) {
        return {
            seconds: Math.ceil(totalSeconds),
            display: `~${Math.ceil(totalSeconds)} seconds`,
            breakdown: {
                scenes: sceneCount,
                languages: languageCount,
                videos: videoCount,
                aiBonus: config.useAI ? '+30%' : 'none'
            }
        };
    }

    const minutes = Math.ceil(totalSeconds / 60);
    return {
        seconds: totalSeconds,
        display: `~${minutes} minute${minutes > 1 ? 's' : ''}`,
        breakdown: {
            scenes: sceneCount,
            languages: languageCount,
            videos: videoCount,
            aiBonus: config.useAI ? '+30%' : 'none'
        }
    };
}

/**
 * Apply smart defaults to configuration
 */
function applySmartDefaults(component, contentType, mode = 'single') {
    const targetConfig = mode === 'single' ? component.single : component.set;
    const defaults = contentType.defaults;

    // Only apply if user hasn't customized yet
    // (check if still has default values)
    const isDefaultConfig =
        targetConfig.primaryLanguage === 'en' &&
        targetConfig.color === 'blue' &&
        targetConfig.duration === 120;

    if (!isDefaultConfig) {
        // User has customized, don't override
        return false;
    }

    // Apply smart defaults
    Object.assign(targetConfig, defaults);

    // Initialize language voices if needed
    if (defaults.languageMode === 'multiple' && defaults.targetLanguages) {
        defaults.targetLanguages.forEach(lang => {
            if (!targetConfig.languageVoices[lang]) {
                component.initializeLanguageVoice(mode, lang);
            }
        });
    }

    // Show notification
    window.dispatchEvent(new CustomEvent('show-message', {
        detail: {
            message: `Applied smart defaults for ${contentType.name}. ${contentType.rationale}`,
            type: 'info'
        }
    }));

    return true;
}

/**
 * Get time estimate breakdown as text
 */
function getTimeBreakdownText(estimate) {
    const { breakdown } = estimate;
    return `${breakdown.scenes} scenes × ${breakdown.languages} language${breakdown.languages > 1 ? 's' : ''}${breakdown.videos > 1 ? ` × ${breakdown.videos} videos` : ''}${breakdown.aiBonus !== 'none' ? ` (${breakdown.aiBonus} AI enhancement)` : ''}`;
}

// Export for use in Alpine component
if (typeof window !== 'undefined') {
    window.SmartDefaults = {
        detectContentType,
        detectFromPath,
        estimateGenerationTime,
        applySmartDefaults,
        getTimeBreakdownText,
        CONTENT_TYPES
    };
}
