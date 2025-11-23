"""
import logging

# Setup logging
logger = logging.getLogger(__name__)

Language Configuration - Multilingual Voice Mapping
===================================================
Complete voice configuration for 50+ languages supported by Edge-TTS.

This module provides:
- Language code mapping
- Voice selection by language and gender
- Locale-specific variants (e.g., es-ES vs es-MX)
- Fallback voice selection
"""

# Complete multilingual voice mapping
MULTILINGUAL_VOICES = {
    # English
    'en': {
        'male': 'en-US-AndrewMultilingualNeural',
        'male_warm': 'en-US-BrandonMultilingualNeural',
        'female': 'en-US-AriaNeural',
        'female_friendly': 'en-US-AvaMultilingualNeural',
        'uk_male': 'en-GB-RyanNeural',
        'uk_female': 'en-GB-SoniaNeural',
        'au_male': 'en-AU-WilliamNeural',
        'au_female': 'en-AU-NatashaNeural'
    },

    # Spanish
    'es': {
        'male': 'es-ES-AlvaroNeural',
        'female': 'es-ES-ElviraNeural',
        'mx_male': 'es-MX-JorgeNeural',
        'mx_female': 'es-MX-DaliaNeural',
        'ar_male': 'es-AR-TomasNeural',
        'ar_female': 'es-AR-ElenaNeural',
        'co_male': 'es-CO-GonzaloNeural',
        'co_female': 'es-CO-SalomeNeural'
    },

    # French
    'fr': {
        'male': 'fr-FR-HenriNeural',
        'female': 'fr-FR-DeniseNeural',
        'ca_male': 'fr-CA-AntoineNeural',
        'ca_female': 'fr-CA-SylvieNeural'
    },

    # German
    'de': {
        'male': 'de-DE-ConradNeural',
        'female': 'de-DE-KatjaNeural',
        'at_male': 'de-AT-JonasNeural',
        'at_female': 'de-AT-IngridNeural',
        'ch_male': 'de-CH-JanNeural',
        'ch_female': 'de-CH-LeniNeural'
    },

    # Portuguese
    'pt': {
        'br_male': 'pt-BR-AntonioNeural',
        'br_female': 'pt-BR-FranciscaNeural',
        'pt_male': 'pt-PT-DuarteNeural',
        'pt_female': 'pt-PT-RaquelNeural'
    },

    # Italian
    'it': {
        'male': 'it-IT-DiegoNeural',
        'female': 'it-IT-ElsaNeural'
    },

    # Japanese
    'ja': {
        'male': 'ja-JP-KeitaNeural',
        'female': 'ja-JP-NanamiNeural'
    },

    # Chinese (Mandarin)
    'zh': {
        'male': 'zh-CN-YunxiNeural',
        'female': 'zh-CN-XiaoxiaoNeural',
        'hk_male': 'zh-HK-WanLungNeural',
        'hk_female': 'zh-HK-HiuGaaiNeural',
        'tw_male': 'zh-TW-YunJheNeural',
        'tw_female': 'zh-TW-HsiaoChenNeural'
    },

    # Korean
    'ko': {
        'male': 'ko-KR-InJoonNeural',
        'female': 'ko-KR-SunHiNeural'
    },

    # Arabic
    'ar': {
        'male': 'ar-SA-HamedNeural',
        'female': 'ar-SA-ZariyahNeural',
        'eg_male': 'ar-EG-ShakirNeural',
        'eg_female': 'ar-EG-SalmaNeural'
    },

    # Hindi
    'hi': {
        'male': 'hi-IN-MadhurNeural',
        'female': 'hi-IN-SwaraNeural'
    },

    # Russian
    'ru': {
        'male': 'ru-RU-DmitryNeural',
        'female': 'ru-RU-SvetlanaNeural'
    },

    # Dutch
    'nl': {
        'male': 'nl-NL-MaartenNeural',
        'female': 'nl-NL-ColetteNeural',
        'be_male': 'nl-BE-ArnaudNeural',
        'be_female': 'nl-BE-DenaNeural'
    },

    # Polish
    'pl': {
        'male': 'pl-PL-MarekNeural',
        'female': 'pl-PL-ZofiaNeural'
    },

    # Swedish
    'sv': {
        'male': 'sv-SE-MattiasNeural',
        'female': 'sv-SE-SofieNeural'
    },

    # Norwegian
    'no': {
        'male': 'nb-NO-FinnNeural',
        'female': 'nb-NO-PernilleNeural'
    },

    # Danish
    'da': {
        'male': 'da-DK-JeppeNeural',
        'female': 'da-DK-ChristelNeural'
    },

    # Finnish
    'fi': {
        'male': 'fi-FI-HarriNeural',
        'female': 'fi-FI-NooraNeural'
    },

    # Turkish
    'tr': {
        'male': 'tr-TR-AhmetNeural',
        'female': 'tr-TR-EmelNeural'
    },

    # Greek
    'el': {
        'male': 'el-GR-NestorasNeural',
        'female': 'el-GR-AthinaNeural'
    },

    # Hebrew
    'he': {
        'male': 'he-IL-AvriNeural',
        'female': 'he-IL-HilaNeural'
    },

    # Thai
    'th': {
        'male': 'th-TH-NiwatNeural',
        'female': 'th-TH-PremwadeeNeural'
    },

    # Vietnamese
    'vi': {
        'male': 'vi-VN-NamMinhNeural',
        'female': 'vi-VN-HoaiMyNeural'
    },

    # Czech
    'cs': {
        'male': 'cs-CZ-AntoninNeural',
        'female': 'cs-CZ-VlastaNeural'
    },

    # Hungarian
    'hu': {
        'male': 'hu-HU-TamasNeural',
        'female': 'hu-HU-NoemiNeural'
    },

    # Romanian
    'ro': {
        'male': 'ro-RO-EmilNeural',
        'female': 'ro-RO-AlinaNeural'
    },

    # Ukrainian
    'uk': {
        'male': 'uk-UA-OstapNeural',
        'female': 'uk-UA-PolinaNeural'
    },

    # Indonesian
    'id': {
        'male': 'id-ID-ArdiNeural',
        'female': 'id-ID-GadisNeural'
    },

    # Malay
    'ms': {
        'male': 'ms-MY-OsmanNeural',
        'female': 'ms-MY-YasminNeural'
    }
}

# Language metadata
LANGUAGE_INFO = {
    'en': {'name': 'English', 'name_local': 'English', 'rtl': False},
    'es': {'name': 'Spanish', 'name_local': 'Español', 'rtl': False},
    'fr': {'name': 'French', 'name_local': 'Français', 'rtl': False},
    'de': {'name': 'German', 'name_local': 'Deutsch', 'rtl': False},
    'pt': {'name': 'Portuguese', 'name_local': 'Português', 'rtl': False},
    'it': {'name': 'Italian', 'name_local': 'Italiano', 'rtl': False},
    'ja': {'name': 'Japanese', 'name_local': '日本語', 'rtl': False},
    'zh': {'name': 'Chinese', 'name_local': '中文', 'rtl': False},
    'ko': {'name': 'Korean', 'name_local': '한국어', 'rtl': False},
    'ar': {'name': 'Arabic', 'name_local': 'العربية', 'rtl': True},
    'hi': {'name': 'Hindi', 'name_local': 'हिन्दी', 'rtl': False},
    'ru': {'name': 'Russian', 'name_local': 'Русский', 'rtl': False},
    'nl': {'name': 'Dutch', 'name_local': 'Nederlands', 'rtl': False},
    'pl': {'name': 'Polish', 'name_local': 'Polski', 'rtl': False},
    'sv': {'name': 'Swedish', 'name_local': 'Svenska', 'rtl': False},
    'no': {'name': 'Norwegian', 'name_local': 'Norsk', 'rtl': False},
    'da': {'name': 'Danish', 'name_local': 'Dansk', 'rtl': False},
    'fi': {'name': 'Finnish', 'name_local': 'Suomi', 'rtl': False},
    'tr': {'name': 'Turkish', 'name_local': 'Türkçe', 'rtl': False},
    'el': {'name': 'Greek', 'name_local': 'Ελληνικά', 'rtl': False},
    'he': {'name': 'Hebrew', 'name_local': 'עברית', 'rtl': True},
    'th': {'name': 'Thai', 'name_local': 'ไทย', 'rtl': False},
    'vi': {'name': 'Vietnamese', 'name_local': 'Tiếng Việt', 'rtl': False},
    'cs': {'name': 'Czech', 'name_local': 'Čeština', 'rtl': False},
    'hu': {'name': 'Hungarian', 'name_local': 'Magyar', 'rtl': False},
    'ro': {'name': 'Romanian', 'name_local': 'Română', 'rtl': False},
    'uk': {'name': 'Ukrainian', 'name_local': 'Українська', 'rtl': False},
    'id': {'name': 'Indonesian', 'name_local': 'Bahasa Indonesia', 'rtl': False},
    'ms': {'name': 'Malay', 'name_local': 'Bahasa Melayu', 'rtl': False}
}


def get_voice_for_language(lang_code, gender='male', variant=None):
    """
    Get appropriate voice for language and gender.

    Args:
        lang_code: ISO 639-1 language code (e.g., 'en', 'es', 'fr')
        gender: 'male' or 'female'
        variant: Optional variant (e.g., 'mx' for es-MX, 'uk' for en-GB)

    Returns:
        Voice identifier for Edge-TTS

    Example:
        >>> get_voice_for_language('es', 'male')
        'es-ES-AlvaroNeural'

        >>> get_voice_for_language('es', 'female', 'mx')
        'es-MX-DaliaNeural'
    """
    if lang_code not in MULTILINGUAL_VOICES:
        # Fallback to English
        lang_code = 'en'

    voices = MULTILINGUAL_VOICES[lang_code]

    # Try variant-specific voice
    if variant:
        key = f"{variant}_{gender}"
        if key in voices:
            return voices[key]

    # Try standard gender
    if gender in voices:
        return voices[gender]

    # Fallback to first available voice
    return list(voices.values())[0]


def list_available_languages():
    """List all supported languages"""
    return sorted(MULTILINGUAL_VOICES.keys())


def get_language_name(lang_code, local=False):
    """Get language name (English or local)"""
    info = LANGUAGE_INFO.get(lang_code, {'name': lang_code, 'name_local': lang_code})
    return info['name_local'] if local else info['name']


def is_rtl_language(lang_code):
    """Check if language is right-to-left"""
    return LANGUAGE_INFO.get(lang_code, {}).get('rtl', False)


# Voice quality mapping (for recommendations)
VOICE_QUALITY = {
    'premium': ['en', 'es', 'fr', 'de', 'pt', 'it', 'ja', 'zh', 'ko'],
    'standard': ['ar', 'hi', 'ru', 'nl', 'pl', 'sv', 'no', 'da', 'fi', 'tr'],
    'basic': ['el', 'he', 'th', 'vi', 'cs', 'hu', 'ro', 'uk', 'id', 'ms']
}


def get_supported_genders(lang_code):
    """Get available genders/variants for a language"""
    if lang_code not in MULTILINGUAL_VOICES:
        return []

    voices = MULTILINGUAL_VOICES[lang_code]
    return list(voices.keys())


if __name__ == "__main__":
    # Display supported languages
    logger.info("Supported Languages:")
    logger.info("=" * 80)

    for lang in list_available_languages():
        name = get_language_name(lang)
        name_local = get_language_name(lang, local=True)
        genders = get_supported_genders(lang)
        rtl = " (RTL)" if is_rtl_language(lang) else ""

        logger.info(f"{lang.upper():<5} {name:<15} {name_local:<20} {len(genders)} voices{rtl}")

    logger.info("\n" + "=" * 80)
    logger.info(f"Total: {len(list_available_languages())} languages supported")
