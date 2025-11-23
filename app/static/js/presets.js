/**
 * Preset Packages for Cognitive Load Reduction
 * Week 2 P1 Implementation
 *
 * Provides pre-configured video generation workflows for common use cases:
 * - Corporate (💼): Professional business videos in 4 languages
 * - Creative (🎨): Engaging tutorial content
 * - Educational (🎓): Structured learning materials
 */

const PRESET_PACKAGES = {
    corporate: {
        id: 'corporate',
        name: 'Corporate Presentation',
        icon: '💼',
        description: 'Professional multi-language business videos',
        estimatedCost: '$0.02-0.05 per video',

        config: {
            // Language settings
            languageMode: 'multiple',
            sourceLanguage: 'en',
            targetLanguages: ['en', 'es', 'fr', 'de'],
            translationMethod: 'claude',

            // Voice settings
            primaryVoice: 'en-US-GuyNeural',
            languageVoices: {
                'en': 'en-US-GuyNeural',
                'es': 'es-ES-AlvaroNeural',
                'fr': 'fr-FR-HenriNeural',
                'de': 'de-DE-ConradNeural'
            },

            // Video settings
            duration: 120, // 2 minutes (1.5-3 min range)
            useAI: true,
            color: 'blue',

            // Scene preferences
            recommendedScenes: ['title', 'list', 'quote', 'outro']
        },

        useCases: [
            'Company updates and announcements',
            'Product launches and demos',
            'Training and onboarding',
            'Investor presentations',
            'Marketing collateral'
        ],

        features: [
            '4 languages (EN/ES/FR/DE)',
            'Professional male voice',
            'Blue theme (corporate)',
            '1.5-3 min duration',
            'AI-enhanced narration'
        ]
    },

    creative: {
        id: 'creative',
        name: 'Creative Tutorial',
        icon: '🎨',
        description: 'Engaging, visual educational content',
        estimatedCost: '$0.03-0.06 per video',

        config: {
            // Language settings
            languageMode: 'single',
            primaryLanguage: 'en',
            sourceLanguage: 'en',
            targetLanguages: ['en'],
            translationMethod: 'google',

            // Voice settings
            primaryVoice: 'en-US-JennyNeural',
            languageVoices: {
                'en': 'en-US-JennyNeural'
            },

            // Video settings
            duration: 240, // 4 minutes (3-5 min range)
            useAI: true,
            color: 'purple',

            // Scene preferences
            recommendedScenes: ['title', 'learning_objectives', 'problem', 'solution', 'exercise', 'checkpoint', 'outro']
        },

        useCases: [
            'How-to tutorials and guides',
            'Educational course content',
            'Creative skill sharing',
            'DIY and craft instructions',
            'Cooking and recipe videos'
        ],

        features: [
            '1 language (English)',
            'Warm female voice',
            'Purple theme (creative)',
            '3-5 min duration',
            'AI-enhanced scripts'
        ]
    },

    educational: {
        id: 'educational',
        name: 'Educational Course',
        icon: '🎓',
        description: 'Structured learning content for courses',
        estimatedCost: '$0.04-0.08 per video',

        config: {
            // Language settings
            languageMode: 'multiple',
            sourceLanguage: 'en',
            targetLanguages: ['en', 'es'],
            translationMethod: 'claude',

            // Voice settings
            primaryVoice: 'en-US-JennyNeural',
            languageVoices: {
                'en': 'en-US-JennyNeural',
                'es': 'es-ES-ElviraNeural'
            },

            // Video settings
            duration: 300, // 5 minutes (4-6 min range)
            useAI: true,
            color: 'green',

            // Scene preferences
            recommendedScenes: ['title', 'learning_objectives', 'list', 'code_comparison', 'checkpoint', 'quiz', 'outro']
        },

        useCases: [
            'Online course modules',
            'Lecture supplements',
            'Student assignments',
            'Educational YouTube content',
            'Training programs'
        ],

        features: [
            '2 languages (EN/ES)',
            'Friendly female voice',
            'Green theme (learning)',
            '4-6 min duration',
            'Quiz & checkpoint scenes'
        ]
    }
};

/**
 * Get all available preset packages
 */
function getAllPresets() {
    return Object.values(PRESET_PACKAGES);
}

/**
 * Get preset by ID
 */
function getPresetById(id) {
    return PRESET_PACKAGES[id] || null;
}

/**
 * Apply preset configuration to Alpine component
 */
function applyPreset(component, presetId, mode = 'single') {
    const preset = getPresetById(presetId);
    if (!preset) {
        console.error(`Preset not found: ${presetId}`);
        return false;
    }

    // Set mode
    component.mode = mode;
    component.step = 2;

    // Apply configuration to appropriate mode
    const targetConfig = mode === 'single' ? component.single : component.set;

    // Apply preset config
    Object.assign(targetConfig, preset.config);

    // Initialize language voices if needed
    if (preset.config.languageMode === 'multiple') {
        preset.config.targetLanguages.forEach(lang => {
            if (!targetConfig.languageVoices[lang]) {
                component.initializeLanguageVoice(mode, lang);
            }
        });
    }

    // Show success message
    window.dispatchEvent(new CustomEvent('show-message', {
        detail: {
            message: `Applied ${preset.name} preset! Customize as needed.`,
            type: 'success'
        }
    }));

    return true;
}

/**
 * Get recommended options for each configuration choice
 */
const RECOMMENDED_OPTIONS = {
    voice: {
        'en-US-JennyNeural': { reason: 'Most versatile and natural-sounding' },
        'en-US-GuyNeural': { reason: 'Professional and clear for business' }
    },

    color: {
        'blue': { reason: 'Professional and universally appropriate' }
    },

    duration: {
        120: { reason: 'Optimal for engagement (2 minutes)' },
        180: { reason: 'Good for tutorials (3 minutes)' }
    },

    aiNarration: {
        true: { reason: 'Significantly improves script quality' }
    },

    languageCount: {
        1: { reason: 'Cost-effective for testing' },
        2: { reason: 'Good balance of reach and cost' }
    }
};

/**
 * Check if an option is recommended
 */
function isRecommended(optionType, optionValue) {
    return RECOMMENDED_OPTIONS[optionType]?.[optionValue] !== undefined;
}

/**
 * Get recommendation reason
 */
function getRecommendationReason(optionType, optionValue) {
    return RECOMMENDED_OPTIONS[optionType]?.[optionValue]?.reason || '';
}

// Export for use in Alpine component
if (typeof window !== 'undefined') {
    window.PresetPackages = {
        getAllPresets,
        getPresetById,
        applyPreset,
        isRecommended,
        getRecommendationReason,
        PRESET_PACKAGES
    };
}
