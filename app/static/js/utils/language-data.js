/**
 * Language Data Utilities
 *
 * Provides language name mappings, flag emojis, and search/filter utilities
 * for the MultiLanguageSelector component.
 *
 * @module language-data
 */

// Language name mappings (code -> native name)
const LANGUAGE_NATIVE_NAMES = {
    'en': 'English',
    'es': 'Espanol',
    'fr': 'Francais',
    'de': 'Deutsch',
    'it': 'Italiano',
    'pt': 'Portugues',
    'nl': 'Nederlands',
    'pl': 'Polski',
    'ru': 'Russkiy',
    'ja': 'Nihongo',
    'zh': 'Zhongwen',
    'ko': 'Hangugeo',
    'ar': 'Arabiya',
    'hi': 'Hindi',
    'bn': 'Bangla',
    'tr': 'Turkce',
    'vi': 'Tieng Viet',
    'th': 'Phasa Thai',
    'id': 'Bahasa Indonesia',
    'ms': 'Bahasa Melayu',
    'sv': 'Svenska',
    'da': 'Dansk',
    'no': 'Norsk',
    'fi': 'Suomi',
    'cs': 'Cestina',
    'el': 'Ellinika',
    'he': 'Ivrit',
    'uk': 'Ukrainska',
    'ro': 'Romana',
    'hu': 'Magyar'
};

// English name mappings
const LANGUAGE_ENGLISH_NAMES = {
    'en': 'English',
    'es': 'Spanish',
    'fr': 'French',
    'de': 'German',
    'it': 'Italian',
    'pt': 'Portuguese',
    'nl': 'Dutch',
    'pl': 'Polish',
    'ru': 'Russian',
    'ja': 'Japanese',
    'zh': 'Chinese',
    'ko': 'Korean',
    'ar': 'Arabic',
    'hi': 'Hindi',
    'bn': 'Bengali',
    'tr': 'Turkish',
    'vi': 'Vietnamese',
    'th': 'Thai',
    'id': 'Indonesian',
    'ms': 'Malay',
    'sv': 'Swedish',
    'da': 'Danish',
    'no': 'Norwegian',
    'fi': 'Finnish',
    'cs': 'Czech',
    'el': 'Greek',
    'he': 'Hebrew',
    'uk': 'Ukrainian',
    'ro': 'Romanian',
    'hu': 'Hungarian'
};

// Flag emoji mappings (ISO 3166-1 alpha-2 to regional indicator symbols)
const LANGUAGE_FLAGS = {
    'en': '\uD83C\uDDFA\uD83C\uDDF8', // US flag
    'es': '\uD83C\uDDEA\uD83C\uDDF8', // Spain
    'fr': '\uD83C\uDDEB\uD83C\uDDF7', // France
    'de': '\uD83C\uDDE9\uD83C\uDDEA', // Germany
    'it': '\uD83C\uDDEE\uD83C\uDDF9', // Italy
    'pt': '\uD83C\uDDE7\uD83C\uDDF7', // Brazil
    'nl': '\uD83C\uDDF3\uD83C\uDDF1', // Netherlands
    'pl': '\uD83C\uDDF5\uD83C\uDDF1', // Poland
    'ru': '\uD83C\uDDF7\uD83C\uDDFA', // Russia
    'ja': '\uD83C\uDDEF\uD83C\uDDF5', // Japan
    'zh': '\uD83C\uDDE8\uD83C\uDDF3', // China
    'ko': '\uD83C\uDDF0\uD83C\uDDF7', // South Korea
    'ar': '\uD83C\uDDF8\uD83C\uDDE6', // Saudi Arabia
    'hi': '\uD83C\uDDEE\uD83C\uDDF3', // India
    'bn': '\uD83C\uDDE7\uD83C\uDDE9', // Bangladesh
    'tr': '\uD83C\uDDF9\uD83C\uDDF7', // Turkey
    'vi': '\uD83C\uDDFB\uD83C\uDDF3', // Vietnam
    'th': '\uD83C\uDDF9\uD83C\uDDED', // Thailand
    'id': '\uD83C\uDDEE\uD83C\uDDE9', // Indonesia
    'ms': '\uD83C\uDDF2\uD83C\uDDFE', // Malaysia
    'sv': '\uD83C\uDDF8\uD83C\uDDEA', // Sweden
    'da': '\uD83C\uDDE9\uD83C\uDDF0', // Denmark
    'no': '\uD83C\uDDF3\uD83C\uDDF4', // Norway
    'fi': '\uD83C\uDDEB\uD83C\uDDEE', // Finland
    'cs': '\uD83C\uDDE8\uD83C\uDDFF', // Czech Republic
    'el': '\uD83C\uDDEC\uD83C\uDDF7', // Greece
    'he': '\uD83C\uDDEE\uD83C\uDDF1', // Israel
    'uk': '\uD83C\uDDFA\uD83C\uDDE6', // Ukraine
    'ro': '\uD83C\uDDF7\uD83C\uDDF4', // Romania
    'hu': '\uD83C\uDDED\uD83C\uDDFA'  // Hungary
};

// Popular language presets
const POPULAR_LANGUAGE_CODES = ['en', 'es', 'fr', 'de', 'zh', 'ja', 'pt', 'ar'];

const LANGUAGE_PRESETS = {
    european: ['en', 'es', 'fr', 'de', 'it', 'pt', 'nl', 'pl'],
    asian: ['en', 'ja', 'zh', 'ko', 'vi', 'th', 'id'],
    nordic: ['en', 'sv', 'da', 'no', 'fi'],
    global: ['en', 'es', 'zh', 'ar', 'hi', 'pt', 'ru', 'ja']
};

/**
 * Get the native name for a language code
 * @param {string} code - ISO 639-1 language code
 * @returns {string} Native language name or code in uppercase
 */
function getLanguageNativeName(code) {
    return LANGUAGE_NATIVE_NAMES[code] || code.toUpperCase();
}

/**
 * Get the English name for a language code
 * @param {string} code - ISO 639-1 language code
 * @returns {string} English language name or code in uppercase
 */
function getLanguageEnglishName(code) {
    return LANGUAGE_ENGLISH_NAMES[code] || code.toUpperCase();
}

/**
 * Get the flag emoji for a language code
 * @param {string} code - ISO 639-1 language code
 * @returns {string} Flag emoji or globe emoji as fallback
 */
function getLanguageFlag(code) {
    return LANGUAGE_FLAGS[code] || '\uD83C\uDF10'; // Globe emoji as fallback
}

/**
 * Check if a language matches a search query
 * @param {Object} language - Language object with code, name, name_local properties
 * @param {string} query - Search query string
 * @returns {boolean} True if language matches query
 */
function languageMatchesSearch(language, query) {
    if (!query || query.trim() === '') {
        return true;
    }

    const normalizedQuery = query.toLowerCase().trim();
    const code = (language.code || '').toLowerCase();
    const name = (language.name || '').toLowerCase();
    const nameLocal = (language.name_local || '').toLowerCase();

    return (
        code.includes(normalizedQuery) ||
        name.includes(normalizedQuery) ||
        nameLocal.includes(normalizedQuery)
    );
}

/**
 * Filter languages by search query
 * @param {Array} languages - Array of language objects
 * @param {string} query - Search query string
 * @returns {Array} Filtered array of languages
 */
function filterLanguages(languages, query) {
    if (!Array.isArray(languages)) {
        return [];
    }

    return languages.filter(lang => languageMatchesSearch(lang, query));
}

/**
 * Sort languages alphabetically by English name (locale-aware)
 * @param {Array} languages - Array of language objects
 * @returns {Array} Sorted array of languages
 */
function sortLanguagesByName(languages) {
    if (!Array.isArray(languages)) {
        return [];
    }

    return [...languages].sort((a, b) => {
        const nameA = (a.name || a.code || '').toLowerCase();
        const nameB = (b.name || b.code || '').toLowerCase();
        return nameA.localeCompare(nameB);
    });
}

/**
 * Get popular languages from a list
 * @param {Array} languages - Array of language objects
 * @returns {Array} Popular languages subset
 */
function getPopularLanguages(languages) {
    if (!Array.isArray(languages)) {
        return [];
    }

    return languages.filter(lang =>
        POPULAR_LANGUAGE_CODES.includes(lang.code)
    ).sort((a, b) => {
        // Sort by position in popular array
        return POPULAR_LANGUAGE_CODES.indexOf(a.code) - POPULAR_LANGUAGE_CODES.indexOf(b.code);
    });
}

/**
 * Get preset language codes by preset name
 * @param {string} presetName - Name of the preset (european, asian, nordic, global)
 * @returns {Array} Array of language codes
 */
function getPresetLanguages(presetName) {
    return LANGUAGE_PRESETS[presetName] || [];
}

/**
 * Default language list fallback (when API fails)
 * @returns {Array} Default language objects
 */
function getDefaultLanguages() {
    return [
        { code: 'en', name: 'English', name_local: 'English', voice_count: 4, voices: ['male', 'female'] },
        { code: 'es', name: 'Spanish', name_local: 'Espanol', voice_count: 3, voices: ['male', 'female'] },
        { code: 'fr', name: 'French', name_local: 'Francais', voice_count: 3, voices: ['male', 'female'] },
        { code: 'de', name: 'German', name_local: 'Deutsch', voice_count: 3, voices: ['male', 'female'] },
        { code: 'it', name: 'Italian', name_local: 'Italiano', voice_count: 2, voices: ['male', 'female'] },
        { code: 'pt', name: 'Portuguese', name_local: 'Portugues', voice_count: 2, voices: ['male', 'female'] },
        { code: 'ja', name: 'Japanese', name_local: 'Nihongo', voice_count: 2, voices: ['male', 'female'] },
        { code: 'zh', name: 'Chinese', name_local: 'Zhongwen', voice_count: 2, voices: ['male', 'female'] },
        { code: 'ko', name: 'Korean', name_local: 'Hangugeo', voice_count: 2, voices: ['male', 'female'] },
        { code: 'ar', name: 'Arabic', name_local: 'Arabiya', voice_count: 2, voices: ['male', 'female'] }
    ];
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        LANGUAGE_NATIVE_NAMES,
        LANGUAGE_ENGLISH_NAMES,
        LANGUAGE_FLAGS,
        POPULAR_LANGUAGE_CODES,
        LANGUAGE_PRESETS,
        getLanguageNativeName,
        getLanguageEnglishName,
        getLanguageFlag,
        languageMatchesSearch,
        filterLanguages,
        sortLanguagesByName,
        getPopularLanguages,
        getPresetLanguages,
        getDefaultLanguages
    };
}

// Make available globally for browser usage
if (typeof window !== 'undefined') {
    window.LanguageData = {
        LANGUAGE_NATIVE_NAMES,
        LANGUAGE_ENGLISH_NAMES,
        LANGUAGE_FLAGS,
        POPULAR_LANGUAGE_CODES,
        LANGUAGE_PRESETS,
        getLanguageNativeName,
        getLanguageEnglishName,
        getLanguageFlag,
        languageMatchesSearch,
        filterLanguages,
        sortLanguagesByName,
        getPopularLanguages,
        getPresetLanguages,
        getDefaultLanguages
    };
}
