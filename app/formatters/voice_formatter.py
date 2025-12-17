"""
Voice name formatting utilities.

Provides extraction of friendly names from Edge-TTS voice IDs.
"""


def _extract_friendly_voice_name(edge_tts_voice_id: str) -> str:
    """
    Extract a friendly display name from an Edge-TTS voice ID.

    Examples:
        'en-US-AndrewMultilingualNeural' -> 'Andrew'
        'en-US-AriaNeural' -> 'Aria'
        'es-ES-AlvaroNeural' -> 'Alvaro'
        'zh-CN-XiaoxiaoNeural' -> 'Xiaoxiao'
    """
    # Split by dash and get the last part (name + suffix)
    parts = edge_tts_voice_id.split('-')
    if len(parts) >= 3:
        name_part = parts[-1]  # e.g., 'AndrewMultilingualNeural' or 'AriaNeural'
    else:
        name_part = edge_tts_voice_id

    # Remove common suffixes
    for suffix in ['MultilingualNeural', 'Neural', 'Multilingual']:
        if name_part.endswith(suffix):
            name_part = name_part[:-len(suffix)]
            break

    return name_part if name_part else edge_tts_voice_id
