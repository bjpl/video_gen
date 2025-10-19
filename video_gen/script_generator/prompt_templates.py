"""Scene-specific prompt templates for AI narration generation.

This module contains the ORIGINAL working prompts from commit 31e0299c that
produced high-quality, technical documentation-style narration.

Key characteristics:
- Tight word count constraints (10-20 words)
- Explicit anti-marketing language
- Technical documentation tone
- Scene-specific optimization
- "Developer colleague" persona

History:
- Oct 4, 2025 (31e0299c): Original working prompts
- Oct 18, 2025: Restored from git history after analysis
"""

from typing import Dict, Any, List


# Anti-marketing banned words list (from OLD system)
BANNED_MARKETING_WORDS = [
    "powerful", "amazing", "revolutionary", "game-changing",
    "transform", "unleash", "empower", "elevate",
    "journey", "explore", "discover", "instantly",
    "seamlessly", "effortlessly", "cutting-edge", "state-of-the-art"
]

# Preferred technical alternatives
TECHNICAL_ALTERNATIVES = [
    "Direct descriptions of functionality",
    "Technical accuracy and precision",
    "Factual benefits and capabilities",
    "Straightforward explanations"
]


def get_title_scene_prompt(scene_data: Dict[str, Any], position_context: str = "") -> str:
    """Generate prompt for title scene narration.

    Original specs: 1-2 sentences, ~10 words, technical and direct.
    """
    title = scene_data.get('title', '')
    subtitle = scene_data.get('subtitle', '')
    key_message = scene_data.get('key_message', '')

    return f"""Create technical video narration for a title scene.

Title: {title}
Subtitle: {subtitle}
Key message: {key_message}
{position_context}

Create a brief, direct introduction (1-2 sentences, ~10 words).
Style: Technical, factual, educational - NOT marketing/sales language.
Avoid: "powerful", "amazing", "transform", "instantly", "revolutionary"
Use: Direct statements about what it is and does.

Requirements:
- Target: 10 words total
- Tone: Technical documentation
- Voice: Direct, factual
- Avoid marketing buzzwords entirely

Return ONLY the narration text, nothing else."""


def get_command_scene_prompt(scene_data: Dict[str, Any], position_context: str = "") -> str:
    """Generate prompt for command/code scene narration.

    Original specs: 2-3 sentences, 15-20 words, instructional.
    """
    topic = scene_data.get('topic', '')
    header = scene_data.get('header', '')
    commands = scene_data.get('commands', [])
    key_points = scene_data.get('key_points', [])

    cmd_count = len([c for c in commands if c.strip() and not c.startswith('#')])

    return f"""Create technical tutorial narration for a command/code scene.

Topic: {topic}
Header: {header}
Commands shown: {cmd_count} commands
Key points: {', '.join(key_points)}
{position_context}

Create clear, instructional narration (2-3 sentences, 15-20 words).
Style: Technical documentation, straightforward, educational.
Avoid: Marketing language, hype, superlatives.
Focus: What the commands do and why you'd use them.
Tone: Like explaining to a developer colleague, not selling a product.

Requirements:
- Target: 15-20 words total
- Structure: 2-3 short sentences
- Voice: Developer-to-developer
- No promotional language

Return ONLY the narration text, nothing else."""


def get_list_scene_prompt(scene_data: Dict[str, Any], position_context: str = "") -> str:
    """Generate prompt for list scene narration.

    Original specs: 2 sentences, 15-20 words, factual.
    """
    topic = scene_data.get('topic', '')
    header = scene_data.get('header', '')
    items = scene_data.get('items', [])

    # Extract item titles
    item_titles = []
    for item in items[:5]:
        if isinstance(item, dict):
            item_titles.append(item.get('title', ''))
        else:
            item_titles.append(str(item))

    return f"""Create technical documentation narration for a list scene.

Topic: {topic}
Header: {header}
Items to mention: {', '.join(item_titles)}
{position_context}

Create narration that introduces the list (2 sentences, 15-20 words).
Style: Technical documentation, factual, clear.
Avoid: Promotional language, excitement, hype.
Focus: Factual description of what each item is/does.
Tone: Educational reference material, not sales copy.

Requirements:
- Target: 15-20 words total
- Structure: 2 sentences exactly
- Voice: Reference documentation
- Factual descriptions only

Return ONLY the narration text, nothing else."""


def get_outro_scene_prompt(scene_data: Dict[str, Any], position_context: str = "") -> str:
    """Generate prompt for outro scene narration.

    Original specs: 1-2 sentences, 10-15 words, factual closing.
    """
    main_text = scene_data.get('main_text', '')
    sub_text = scene_data.get('sub_text', '')
    key_message = scene_data.get('key_message', '')

    return f"""Create technical documentation outro narration.

Main message: {main_text}
Documentation link: {sub_text}
Key message: {key_message}
{position_context}

Create a brief, factual closing (1-2 sentences, 10-15 words).
Style: Direct, helpful, informative - NOT motivational/sales language.
Avoid: "journey", "transform", "unleash", "empower"
Focus: Point to documentation/resources factually.
Tone: End of technical documentation, not marketing pitch.

Requirements:
- Target: 10-15 words total
- Structure: 1-2 sentences
- Voice: Helpful but direct
- No motivational language

Return ONLY the narration text, nothing else."""


def get_code_comparison_prompt(scene_data: Dict[str, Any], position_context: str = "") -> str:
    """Generate prompt for code comparison scene narration.

    Original specs: 2 sentences, 12-18 words, technical explanation.
    """
    header = scene_data.get('header', '')
    improvement = scene_data.get('improvement', '')
    key_points = scene_data.get('key_points', [])

    return f"""Create technical narration for a code comparison scene.

Header: {header}
Improvement: {improvement}
Key points: {', '.join(key_points)}
{position_context}

Create narration explaining the code difference (2 sentences, 12-18 words).
Style: Technical explanation, factual comparison.
Avoid: Subjective language like "better", "cleaner" unless technically justified.
Focus: What changed and the technical reason why.
Tone: Code review, not product pitch.

Requirements:
- Target: 12-18 words total
- Structure: 2 sentences
- Voice: Technical code review
- Objective language only

Return ONLY the narration text, nothing else."""


def get_quote_scene_prompt(scene_data: Dict[str, Any], position_context: str = "") -> str:
    """Generate prompt for quote scene narration.

    Original specs: 15-25 words, straightforward introduction.
    """
    quote_text = scene_data.get('quote_text', '')
    attribution = scene_data.get('attribution', '')
    context = scene_data.get('context', '')

    return f"""Create technical narration for a quote scene.

Quote: "{quote_text}"
Attribution: {attribution}
Context: {context}
{position_context}

Create narration that introduces and reads the quote (15-25 words).
Style: Straightforward, factual introduction to the quote.
Avoid: Flowery language, excessive buildup.
Focus: Brief context, then the quote itself, then attribution.
Tone: Academic reference, not inspirational speech.

Requirements:
- Target: 15-25 words total
- Structure: Context + quote + attribution
- Voice: Academic reference
- No flowery language

Return ONLY the narration text, nothing else."""


def get_generic_scene_prompt(scene_data: Dict[str, Any], scene_type: str, position_context: str = "") -> str:
    """Fallback prompt for scene types without specific templates.

    Uses tighter constraints than NEW system generic prompt.
    """
    return f"""Create technical educational narration for a {scene_type} scene.

Scene data: {scene_data}
{position_context}

Create clear, concise narration (15-25 words).
Style: Technical documentation, straightforward, educational.
Avoid: Marketing language, hype, promotional tone.
Focus: Factual information delivery.
Tone: Like explaining to a developer colleague.

Requirements:
- Target: 15-25 words
- Voice: Technical, factual
- No marketing language
- Developer-to-developer tone

Return ONLY the narration text, nothing else."""


def get_anti_marketing_suffix() -> str:
    """Get the anti-marketing language suffix to append to prompts.

    This enforces the constraints that made OLD prompts work.
    """
    banned_list = ', '.join(BANNED_MARKETING_WORDS[:8])  # First 8 most common

    return f"""

CRITICAL CONSTRAINTS:
- Avoid these marketing words: {banned_list}
- Use instead: Direct descriptions, technical accuracy, factual benefits
- Target pace: 135 words per minute (2.25 words per second)
- Temperature: 0.5 (for consistency)
- Tone: Developer colleague, NOT professional narrator
- Style: Technical documentation, NOT engaging storytelling

Quality over engagement. Facts over excitement. Precision over promotion."""


def get_scene_prompt(scene_type: str, scene_data: Dict[str, Any], position_context: str = "") -> str:
    """Get the appropriate prompt template for a scene type.

    This is the main entry point - routes to scene-specific prompts.

    Args:
        scene_type: Type of scene (title, command, list, outro, etc.)
        scene_data: Scene data dictionary
        position_context: Optional position context from NEW system

    Returns:
        Complete prompt string ready for API call
    """
    # Route to scene-specific prompt
    prompt_map = {
        'title': get_title_scene_prompt,
        'command': get_command_scene_prompt,
        'list': get_list_scene_prompt,
        'outro': get_outro_scene_prompt,
        'code_comparison': get_code_comparison_prompt,
        'quote': get_quote_scene_prompt,
    }

    prompt_func = prompt_map.get(scene_type, get_generic_scene_prompt)

    if scene_type in prompt_map:
        base_prompt = prompt_func(scene_data, position_context)
    else:
        base_prompt = prompt_func(scene_data, scene_type, position_context)

    # Append anti-marketing constraints
    return base_prompt + get_anti_marketing_suffix()


# Educational scene types (for reference)
EDUCATIONAL_SCENE_PROMPTS = {
    'quiz': """Create narration for an educational quiz question (15-20 words).
Style: Clear question delivery, neutral tone.
Focus: Present the question and options clearly.""",

    'problem': """Create narration for a technical problem scenario (20-30 words).
Style: Problem statement, technical context.
Focus: Describe the challenge factually.""",

    'exercise': """Create narration for practice instructions (15-25 words).
Style: Clear instructions, technical guidance.
Focus: What to do and why.""",

    'checkpoint': """Create narration for a learning checkpoint (15-20 words).
Style: Progress review, factual summary.
Focus: What was covered, what's next."""
}
