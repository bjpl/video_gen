"""
Script Generator - YAML to Video Script
========================================
Converts user-friendly YAML input into professional video narration scripts.

This is the MISSING PIECE in the workflow:
- Users provide topics/outlines in YAML
- System generates professional narration
- User reviews editable scripts
- Then proceeds to audio/video generation

Usage:
    python generate_script_from_yaml.py inputs/my_video.yaml
"""

import yaml
import json
import os
from datetime import datetime
from pathlib import Path

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    # Load from parent directory (project root) if running from scripts/
    env_path = Path(__file__).parent.parent / '.env'
    load_dotenv(dotenv_path=env_path)
except ImportError:
    pass  # dotenv not installed, will use system environment variables
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


# Import color constants
import sys
sys.path.append('.')
from unified_video_system import (
    ACCENT_ORANGE, ACCENT_BLUE, ACCENT_PURPLE,
    ACCENT_GREEN, ACCENT_PINK
)

# Define CYAN if not in unified_video_system
ACCENT_CYAN = (34, 211, 238)

COLOR_MAP = {
    'orange': ACCENT_ORANGE,
    'blue': ACCENT_BLUE,
    'purple': ACCENT_PURPLE,
    'green': ACCENT_GREEN,
    'pink': ACCENT_PINK,
    'cyan': ACCENT_CYAN
}

class NarrationGenerator:
    """Generate professional narration from structured input"""

    def __init__(self, target_wpm=135, use_ai=False, target_duration=None):
        self.target_wpm = target_wpm  # Words per minute
        self.words_per_second = target_wpm / 60.0  # ~2.25 WPS
        self.use_ai = use_ai
        self.ai_client = None
        self.target_duration = target_duration  # Target video duration in seconds

        # Calculate target word count if duration specified
        if target_duration:
            self.target_word_count = int(target_duration * self.words_per_second)
        else:
            self.target_word_count = None

        # Initialize AI client if requested
        if use_ai:
            try:
                import anthropic
                import os
                api_key = os.environ.get('ANTHROPIC_API_KEY')
                if api_key:
                    self.ai_client = anthropic.Anthropic(api_key=api_key)
                    logger.info("✅ AI narration enabled (Claude API)")
                else:
                    logger.warning("⚠️  ANTHROPIC_API_KEY not found, falling back to template-based")
                    self.use_ai = False
            except ImportError:
                logger.warning("⚠️  anthropic package not installed, falling back to template-based")
                logger.info("   Install: pip install anthropic")
                self.use_ai = False

    def generate_title_narration(self, scene_data, scene_num=1, total_scenes=4):
        """Generate narration for title scenes"""
        if self.use_ai and self.ai_client:
            return self._generate_ai_narration(scene_data, 'title', scene_num, total_scenes)

        # Template-based generation
        title = scene_data.get('title', '')
        subtitle = scene_data.get('subtitle', '')
        message = scene_data.get('key_message', '')

        if message:
            narration = f"{title}. {message}"
        else:
            narration = f"{title}. {subtitle}."

        return narration.strip()

    def generate_command_narration(self, scene_data, scene_num=2, total_scenes=4):
        """Generate narration for command scenes"""
        if self.use_ai and self.ai_client:
            return self._generate_ai_narration(scene_data, 'command', scene_num, total_scenes)

        header = scene_data.get('header', '')
        topic = scene_data.get('topic', '')
        key_points = scene_data.get('key_points', [])
        commands = scene_data.get('commands', [])

        # Build narration
        parts = []

        # Introduction
        if topic:
            parts.append(f"{topic}.")

        # Describe commands
        if commands and len(commands) > 0:
            cmd_count = len([c for c in commands if c.strip() and not c.startswith('#')])
            if cmd_count == 1:
                parts.append("Run this command to get started.")
            elif cmd_count > 1:
                parts.append(f"Run these {cmd_count} commands to get started.")

        # Key benefits
        if key_points:
            if len(key_points) == 1:
                parts.append(key_points[0])
            else:
                # List first few points naturally
                point_text = ", ".join(key_points[:2])
                parts.append(f"This gives you {point_text}.")

        narration = " ".join(parts)
        return narration.strip()

    def generate_list_narration(self, scene_data, scene_num=2, total_scenes=4):
        """Generate narration for list scenes"""
        if self.use_ai and self.ai_client:
            return self._generate_ai_narration(scene_data, 'list', scene_num, total_scenes)

        header = scene_data.get('header', '')
        topic = scene_data.get('topic', '')
        items = scene_data.get('items', [])

        parts = []

        # Introduction
        if topic:
            parts.append(f"{topic}.")
        elif header:
            parts.append(f"{header}.")

        # Describe items
        if items:
            item_count = len(items)
            if item_count == 1:
                item_text = items[0]['title'] if isinstance(items[0], dict) else items[0]
                parts.append(f"Key feature: {item_text}.")
            else:
                # List first 3 items
                item_titles = []
                for item in items[:3]:
                    title = item['title'] if isinstance(item, dict) else item
                    item_titles.append(title)

                items_text = ", ".join(item_titles[:-1]) + f", and {item_titles[-1]}"
                parts.append(f"Key features include {items_text}.")

                if item_count > 3:
                    parts.append(f"Plus {item_count - 3} more capabilities.")

        narration = " ".join(parts)
        return narration.strip()

    def generate_outro_narration(self, scene_data, scene_num=4, total_scenes=4):
        """Generate narration for outro scenes"""
        if self.use_ai and self.ai_client:
            return self._generate_ai_narration(scene_data, 'outro', scene_num, total_scenes)

        main_text = scene_data.get('main_text', '')
        sub_text = scene_data.get('sub_text', '')
        message = scene_data.get('key_message', '')

        if message:
            narration = f"{main_text}. {message}"
        else:
            narration = f"{main_text}. See {sub_text} for complete documentation."

        return narration.strip()

    def generate_code_comparison_narration(self, scene_data, scene_num=2, total_scenes=4):
        """Generate narration for code comparison scenes"""
        if self.use_ai and self.ai_client:
            return self._generate_ai_narration(scene_data, 'code_comparison', scene_num, total_scenes)

        header = scene_data.get('header', '')
        key_points = scene_data.get('key_points', [])
        improvement = scene_data.get('improvement', '')

        parts = []

        if header:
            parts.append(f"{header}.")

        if improvement:
            parts.append(improvement)
        elif key_points:
            points_text = ", ".join(key_points[:2])
            parts.append(f"The improved version provides {points_text}.")

        narration = " ".join(parts)
        return narration.strip()

    def generate_quote_narration(self, scene_data, scene_num=2, total_scenes=4):
        """Generate narration for quote scenes"""
        if self.use_ai and self.ai_client:
            return self._generate_ai_narration(scene_data, 'quote', scene_num, total_scenes)

        quote_text = scene_data.get('quote_text', '')
        attribution = scene_data.get('attribution', '')
        context = scene_data.get('context', '')

        parts = []

        if context:
            parts.append(f"{context}.")

        # Read the quote
        if quote_text:
            parts.append(quote_text)

        # Attribution
        if attribution:
            parts.append(f"As {attribution} said.")

        narration = " ".join(parts)
        return narration.strip()

    def estimate_duration(self, narration):
        """Estimate narration duration"""
        word_count = len(narration.split())
        duration = word_count / self.words_per_second
        return duration, word_count

    def _generate_ai_narration(self, scene_data, scene_type, scene_num=1, total_scenes=4):
        """Generate narration using Claude AI"""

        # Calculate word budget for this scene
        if self.target_word_count:
            # Distribute word count across scenes (title/outro get less)
            if scene_type == 'title':
                word_budget = int(self.target_word_count * 0.15)  # 15% for title
            elif scene_type == 'outro':
                word_budget = int(self.target_word_count * 0.15)  # 15% for outro
            else:
                # Divide remaining 70% among content scenes
                content_scenes = max(1, total_scenes - 2)  # Subtract title and outro
                word_budget = int(self.target_word_count * 0.7 / content_scenes)
        else:
            # Default word budgets if no target duration
            word_budget = {'title': 10, 'outro': 15, 'command': 20, 'list': 20,
                          'code_comparison': 18, 'quote': 25}.get(scene_type, 20)

        # Build context based on scene type
        if scene_type == 'title':
            context = f"""
            Create technical video narration for a title scene.

            Title: {scene_data.get('title', '')}
            Subtitle: {scene_data.get('subtitle', '')}
            Key message: {scene_data.get('key_message', '')}

            Create a brief, direct introduction (EXACTLY {word_budget} words).
            Style: Technical, factual, educational - NOT marketing/sales language.
            Avoid: "powerful", "amazing", "transform", "instantly", "revolutionary"
            Use: Direct statements about what it is and does.
            """

        elif scene_type == 'command':
            context = f"""
            Create technical tutorial narration for a command/code scene.

            Topic: {scene_data.get('topic', '')}
            Header: {scene_data.get('header', '')}
            Commands shown: {len(scene_data.get('commands', []))} commands
            Key points: {', '.join(scene_data.get('key_points', []))}

            Create clear, instructional narration (EXACTLY {word_budget} words).
            Style: Technical documentation, straightforward, educational.
            Avoid: Marketing language, hype, superlatives.
            Focus: What the commands do and why you'd use them.
            Tone: Like explaining to a developer colleague, not selling a product.
            """

        elif scene_type == 'list':
            items = scene_data.get('items', [])
            item_titles = []
            for item in items[:5]:
                if isinstance(item, dict):
                    item_titles.append(item.get('title', ''))
                else:
                    item_titles.append(str(item))

            context = f"""
            Create technical documentation narration for a list scene.

            Topic: {scene_data.get('topic', '')}
            Header: {scene_data.get('header', '')}
            Items to mention: {', '.join(item_titles)}

            Create narration that introduces the list (EXACTLY {word_budget} words).
            Style: Technical documentation, factual, clear.
            Avoid: Promotional language, excitement, hype.
            Focus: Factual description of what each item is/does.
            Tone: Educational reference material, not sales copy.
            """

        elif scene_type == 'code_comparison':
            context = f"""
            Create technical narration for a code comparison scene.

            Header: {scene_data.get('header', '')}
            Improvement: {scene_data.get('improvement', '')}
            Key points: {', '.join(scene_data.get('key_points', []))}

            Create narration explaining the code difference (EXACTLY {word_budget} words).
            Style: Technical explanation, factual comparison.
            Avoid: Subjective language like "better", "cleaner" unless technically justified.
            Focus: What changed and the technical reason why.
            Tone: Code review, not product pitch.
            """

        elif scene_type == 'quote':
            context = f"""
            Create technical narration for a quote scene.

            Quote: "{scene_data.get('quote_text', '')}"
            Attribution: {scene_data.get('attribution', '')}
            Context: {scene_data.get('context', '')}

            Create narration that introduces and reads the quote (EXACTLY {word_budget} words).
            Style: Straightforward, factual introduction to the quote.
            Avoid: Flowery language, excessive buildup.
            Focus: Brief context, then the quote itself, then attribution.
            Tone: Academic reference, not inspirational speech.
            """

        elif scene_type == 'outro':
            context = f"""
            Create technical documentation outro narration.

            Main message: {scene_data.get('main_text', '')}
            Documentation link: {scene_data.get('sub_text', '')}
            Key message: {scene_data.get('key_message', '')}

            Create a brief, factual closing (EXACTLY {word_budget} words).
            Style: Direct, helpful, informative - NOT motivational/sales language.
            Avoid: "journey", "transform", "unleash", "empower"
            Focus: Point to documentation/resources factually.
            Tone: End of technical documentation, not marketing pitch.
            """

        else:
            # Fallback to template
            return ""

        try:
            # Calculate max tokens based on word budget (1 token ≈ 0.75 words)
            max_tokens = int(word_budget * 1.5)  # Add buffer for token conversion

            # Call Claude API with latest Sonnet 4.5
            response = self.ai_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=max_tokens,
                temperature=0.5,  # Lower temperature for more consistent, less creative output
                messages=[{
                    "role": "user",
                    "content": f"""{context}

Requirements:
- STRICT: Write EXACTLY {word_budget} words (no more, no less)
- Technical documentation tone (NOT marketing/promotional)
- Target pace: {self.target_wpm} words per minute
- Clear, direct language (avoid hype and superlatives)
- No filler words or marketing buzzwords
- Factual, educational content
- Like explaining to a developer colleague

Avoid these marketing words:
- "powerful", "amazing", "revolutionary", "game-changing"
- "transform", "unleash", "empower", "elevate"
- "journey", "explore", "discover" (unless literally exploring)
- Excessive adjectives and adverbs

Use instead:
- Direct descriptions of functionality
- Technical accuracy
- Factual benefits
- Straightforward explanations

Generate ONLY the narration text, nothing else."""
                }]
            )

            narration = response.content[0].text.strip()

            # Remove quotes if AI added them
            narration = narration.strip('"\'')

            return narration

        except Exception as e:
            logger.error(f"⚠️  AI generation failed for {scene_type}: {e}")
            logger.info("   Falling back to template-based narration")

            # Fallback to template-based
            self.use_ai = False
            if scene_type == 'title':
                return self.generate_title_narration(scene_data)
            elif scene_type == 'command':
                return self.generate_command_narration(scene_data)
            elif scene_type == 'list':
                return self.generate_list_narration(scene_data)
            elif scene_type == 'outro':
                return self.generate_outro_narration(scene_data)
            elif scene_type == 'code_comparison':
                return self.generate_code_comparison_narration(scene_data)
            elif scene_type == 'quote':
                return self.generate_quote_narration(scene_data)

            return ""


class ScriptGenerator:
    """Main script generator from YAML input"""

    def __init__(self, use_ai=False, target_duration=None):
        self.narration_gen = NarrationGenerator(use_ai=use_ai, target_duration=target_duration)
        self.target_duration = target_duration

    def load_yaml(self, yaml_file):
        """Load and parse YAML input"""
        with open(yaml_file, 'r') as f:
            return yaml.safe_load(f)

    def generate_unified_video(self, yaml_data):
        """Convert YAML to UnifiedVideo object structure"""
        video_config = yaml_data.get('video', {})
        scenes_config = yaml_data.get('scenes', [])

        video_id = video_config.get('id', 'generated_video')
        title = video_config.get('title', 'Generated Video')
        description = video_config.get('description', '')
        accent_color_name = video_config.get('accent_color', 'blue')
        accent_color = COLOR_MAP.get(accent_color_name, ACCENT_BLUE)
        version = video_config.get('version', 'v2.0')
        default_voice = video_config.get('voice', 'male')

        # Extract target_duration from YAML
        target_duration = video_config.get('target_duration', self.target_duration)
        if target_duration and not self.target_duration:
            # Update narration generator with duration from YAML
            self.narration_gen.target_duration = target_duration
            self.narration_gen.target_word_count = int(target_duration * self.narration_gen.words_per_second)

        scenes = []
        total_scenes = len(scenes_config)

        for scene_num, scene_data in enumerate(scenes_config, 1):
            scene_type = scene_data.get('type', 'title')
            scene_id = scene_data.get('id', f"scene_{len(scenes)+1:02d}")

            # Generate visual content
            visual_content = self._generate_visual_content(scene_type, scene_data)

            # Generate narration with scene number and total scenes for word budget calculation
            narration = self._generate_narration(scene_type, scene_data, scene_num, total_scenes)

            # Get duration constraints
            min_dur = scene_data.get('min_duration', 3.0)
            max_dur = scene_data.get('max_duration', 15.0)
            voice = scene_data.get('voice', default_voice)

            # Estimate duration
            est_duration, word_count = self.narration_gen.estimate_duration(narration)

            # Validation: warn if narration exceeds target for individual scenes
            if self.target_duration:
                expected_scene_duration = self.target_duration / max(total_scenes, 1)
                if est_duration > expected_scene_duration * 1.2:  # 20% tolerance
                    logger.warning(f"⚠️  Scene {scene_num}/{total_scenes} narration ({word_count} words, {est_duration:.1f}s) exceeds target ({expected_scene_duration:.1f}s)")

            scene_dict = {
                'scene_id': scene_id,
                'scene_type': scene_type,
                'visual_content': visual_content,
                'narration': narration,
                'voice': voice,
                'min_duration': min_dur,
                'max_duration': max_dur,
                'estimated_duration': round(est_duration, 1),
                'word_count': word_count
            }

            scenes.append(scene_dict)

        unified_video = {
            'video_id': video_id,
            'title': title,
            'description': description,
            'accent_color': accent_color,
            'accent_color_name': accent_color_name,
            'version': version,
            'default_voice': default_voice,
            'scenes': scenes
        }

        return unified_video

    def _generate_visual_content(self, scene_type, scene_data):
        """Generate visual_content dictionary"""
        if scene_type == 'title':
            return {
                'title': scene_data.get('title', ''),
                'subtitle': scene_data.get('subtitle', '')
            }
        elif scene_type == 'command':
            return {
                'header': scene_data.get('header', ''),
                'description': scene_data.get('description', ''),
                'commands': scene_data.get('commands', [])
            }
        elif scene_type == 'list':
            items = scene_data.get('items', [])
            # Convert to tuple format if dict
            formatted_items = []
            for item in items:
                if isinstance(item, dict):
                    formatted_items.append((item['title'], item.get('description', '')))
                else:
                    formatted_items.append(item)

            return {
                'header': scene_data.get('header', ''),
                'description': scene_data.get('description', ''),
                'items': formatted_items
            }
        elif scene_type == 'outro':
            return {
                'main_text': scene_data.get('main_text', ''),
                'sub_text': scene_data.get('sub_text', '')
            }
        elif scene_type == 'code_comparison':
            return {
                'header': scene_data.get('header', ''),
                'before_code': scene_data.get('before_code', ''),
                'after_code': scene_data.get('after_code', ''),
                'before_label': scene_data.get('before_label', 'Before'),
                'after_label': scene_data.get('after_label', 'After')
            }
        elif scene_type == 'quote':
            return {
                'quote_text': scene_data.get('quote_text', ''),
                'attribution': scene_data.get('attribution', '')
            }
        else:
            return {}

    def _generate_narration(self, scene_type, scene_data, scene_num=1, total_scenes=4):
        """Generate narration based on scene type"""
        # Check if user provided custom narration
        if 'narration' in scene_data and scene_data['narration']:
            return scene_data['narration']

        # Otherwise, generate from structure
        if scene_type == 'title':
            return self.narration_gen.generate_title_narration(scene_data, scene_num, total_scenes)
        elif scene_type == 'command':
            return self.narration_gen.generate_command_narration(scene_data, scene_num, total_scenes)
        elif scene_type == 'list':
            return self.narration_gen.generate_list_narration(scene_data, scene_num, total_scenes)
        elif scene_type == 'outro':
            return self.narration_gen.generate_outro_narration(scene_data, scene_num, total_scenes)
        elif scene_type == 'code_comparison':
            return self.narration_gen.generate_code_comparison_narration(scene_data, scene_num, total_scenes)
        elif scene_type == 'quote':
            return self.narration_gen.generate_quote_narration(scene_data, scene_num, total_scenes)
        else:
            return ""

    def export_markdown_script(self, unified_video, output_file):
        """Export human-readable markdown script for review"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"# {unified_video['title']} - Narration Script\n\n")
            f.write(f"**Video ID:** {unified_video['video_id']}\n")
            f.write(f"**Version:** {unified_video['version']}\n")
            f.write(f"**Accent Color:** {unified_video['accent_color_name']}\n")
            f.write(f"**Default Voice:** {unified_video['default_voice']}\n\n")

            total_words = sum(s['word_count'] for s in unified_video['scenes'])
            total_duration = sum(s['estimated_duration'] for s in unified_video['scenes'])

            f.write(f"**Estimated Total Duration:** {total_duration:.1f}s ({total_duration/60:.1f} minutes)\n")
            f.write(f"**Total Words:** {total_words}\n")
            f.write(f"**Average Pace:** {(total_words / total_duration) * 60:.0f} WPM\n\n")
            f.write("---\n\n")

            for i, scene in enumerate(unified_video['scenes'], 1):
                f.write(f"## Scene {i}: {scene['scene_id']} ({scene['scene_type'].upper()})\n\n")

                f.write(f"**Duration:** {scene['min_duration']:.1f}s - {scene['max_duration']:.1f}s ")
                f.write(f"(estimated: {scene['estimated_duration']:.1f}s)\n")
                f.write(f"**Voice:** {scene['voice']}\n\n")

                f.write(f"**Narration:**\n")
                f.write(f'> "{scene["narration"]}"\n\n')

                f.write(f"**Word Count:** {scene['word_count']} words\n")
                f.write(f"**Pacing:** {(scene['word_count'] / scene['estimated_duration']) * 60:.0f} WPM\n\n")

                f.write("**Visual Content:**\n")
                for key, value in scene['visual_content'].items():
                    if isinstance(value, list):
                        f.write(f"- {key}:\n")
                        for item in value:
                            f.write(f"  - {item}\n")
                    else:
                        f.write(f"- {key}: {value}\n")

                f.write("\n---\n\n")

            f.write(f"\n*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n")
            f.write(f"*Edit this script, then regenerate code with: python import_script.py*\n")

        logger.info(f"✅ Markdown script saved: {output_file}")
        return output_file

    def export_python_code(self, unified_video, output_file):
        """Export ready-to-use Python code"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('"""\n')
            f.write(f"Generated Video Code: {unified_video['title']}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write('"""\n\n')

            f.write("from unified_video_system import UnifiedVideo, UnifiedScene\n")
            f.write(f"from unified_video_system import ACCENT_{unified_video['accent_color_name'].upper()}\n\n")

            f.write(f"VIDEO = UnifiedVideo(\n")
            f.write(f"    video_id=\"{unified_video['video_id']}\",\n")
            f.write(f"    title=\"{unified_video['title']}\",\n")
            f.write(f"    description=\"{unified_video['description']}\",\n")
            f.write(f"    accent_color=ACCENT_{unified_video['accent_color_name'].upper()},\n")
            f.write(f"    version=\"{unified_video['version']}\",\n")
            f.write(f"    scenes=[\n")

            for scene in unified_video['scenes']:
                f.write(f"        UnifiedScene(\n")
                f.write(f"            scene_id=\"{scene['scene_id']}\",\n")
                f.write(f"            scene_type=\"{scene['scene_type']}\",\n")
                f.write(f"            visual_content={{\n")

                for key, value in scene['visual_content'].items():
                    if isinstance(value, list):
                        f.write(f"                \"{key}\": [\n")
                        for item in value:
                            if isinstance(item, tuple):
                                f.write(f"                    {repr(item)},\n")
                            else:
                                # Escape strings properly
                                f.write(f"                    {repr(item)},\n")
                        f.write(f"                ],\n")
                    else:
                        # Escape string values properly
                        f.write(f"                \"{key}\": {repr(value)},\n")

                f.write(f"            }},\n")
                # Use repr() to properly escape quotes, newlines, and special characters
                f.write(f"            narration={repr(scene['narration'])},\n")
                f.write(f"            voice={repr(scene['voice'])},\n")
                f.write(f"            min_duration={scene['min_duration']},\n")
                f.write(f"            max_duration={scene['max_duration']}\n")
                f.write(f"        ),\n")

            f.write(f"    ]\n")
            f.write(f")\n\n")

            f.write("# Add this VIDEO object to ALL_VIDEOS list in generate_all_videos_unified_v2.py\n")
            f.write("# Then run: python generate_all_videos_unified_v2.py\n")

        logger.info(f"✅ Python code saved: {output_file}")
        return output_file

    def generate(self, yaml_file, output_dir="drafts"):
        """Main generation function"""
        logger.info(f"\n{'='*80}")
        logger.info("SCRIPT GENERATOR - YAML to Video")
        logger.info(f"{'='*80}\n")

        # Load YAML
        logger.info(f"Loading: {yaml_file}")
        yaml_data = self.load_yaml(yaml_file)

        # Generate UnifiedVideo structure
        logger.info("Generating video structure...")
        unified_video = self.generate_unified_video(yaml_data)

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Generate filenames
        video_id = unified_video['video_id']
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        md_file = os.path.join(output_dir, f"{video_id}_SCRIPT_{timestamp}.md")
        py_file = os.path.join(output_dir, f"{video_id}_CODE_{timestamp}.py")

        # Export both formats
        self.export_markdown_script(unified_video, md_file)
        self.export_python_code(unified_video, py_file)

        # Print summary
        total_scenes = len(unified_video['scenes'])
        total_duration = sum(s['estimated_duration'] for s in unified_video['scenes'])
        total_words = sum(s['word_count'] for s in unified_video['scenes'])

        # Validate total duration against target
        if self.target_duration:
            if total_duration > self.target_duration * 1.2:  # 20% tolerance
                logger.warning(f"\n⚠️  WARNING: Total duration ({total_duration:.1f}s) exceeds target ({self.target_duration}s) by {((total_duration/self.target_duration - 1) * 100):.0f}%")
                logger.warning(f"   Consider splitting into more videos or reducing content\n")
            elif total_duration < self.target_duration * 0.8:  # 20% tolerance
                logger.warning(f"\n⚠️  WARNING: Total duration ({total_duration:.1f}s) is below target ({self.target_duration}s) by {((1 - total_duration/self.target_duration) * 100):.0f}%")
                logger.warning(f"   Consider adding more content or reducing video count\n")

        logger.info(f"\n{'='*80}")
        logger.info("SCRIPT GENERATION COMPLETE")
        logger.info(f"{'='*80}\n")
        logger.info(f"Video: {unified_video['title']}")
        logger.info(f"Scenes: {total_scenes}")
        logger.info(f"Estimated Duration: {total_duration:.1f}s ({total_duration/60:.1f} min)")
        logger.info(f"Total Words: {total_words}")
        logger.info(f"Average WPM: {(total_words / total_duration) * 60:.0f}\n")

        logger.info("Generated files:")
        logger.info(f"  📝 Script (review/edit): {md_file}")
        logger.info(f"  🐍 Code (ready to use):  {py_file}\n")

        logger.info("Next steps:")
        logger.info("  1. Review and edit the markdown script if needed")
        logger.info("  2. Copy VIDEO object from Python file to generate_all_videos_unified_v2.py")
        logger.info("  3. Run: python generate_all_videos_unified_v2.py")
        logger.info(f"\n{'='*80}\n")

        return unified_video, md_file, py_file


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='Generate video script from YAML input')
    parser.add_argument('yaml_file', help='Path to YAML input file')
    parser.add_argument('--use-ai', action='store_true',
                       help='Use Claude AI for enhanced narration generation (requires ANTHROPIC_API_KEY)')
    parser.add_argument('--output-dir', default='drafts',
                       help='Output directory for generated scripts (default: drafts)')

    args = parser.parse_args()

    if not os.path.exists(args.yaml_file):
        logger.error(f"❌ File not found: {args.yaml_file}")
        sys.exit(1)

    # Pre-load YAML to check for target_duration
    with open(args.yaml_file, 'r') as f:
        yaml_data = yaml.safe_load(f)
    target_duration = yaml_data.get('video', {}).get('target_duration')

    generator = ScriptGenerator(use_ai=args.use_ai, target_duration=target_duration)
    generator.generate(args.yaml_file, output_dir=args.output_dir)
