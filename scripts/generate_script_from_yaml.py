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

    def __init__(self, target_wpm=135):
        self.target_wpm = target_wpm  # Words per minute
        self.words_per_second = target_wpm / 60.0  # ~2.25 WPS

    def generate_title_narration(self, scene_data):
        """Generate narration for title scenes"""
        title = scene_data.get('title', '')
        subtitle = scene_data.get('subtitle', '')
        message = scene_data.get('key_message', '')

        # Template-based generation
        if message:
            narration = f"{title}. {message}"
        else:
            narration = f"{title}. {subtitle}."

        return narration.strip()

    def generate_command_narration(self, scene_data):
        """Generate narration for command scenes"""
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

    def generate_list_narration(self, scene_data):
        """Generate narration for list scenes"""
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

    def generate_outro_narration(self, scene_data):
        """Generate narration for outro scenes"""
        main_text = scene_data.get('main_text', '')
        sub_text = scene_data.get('sub_text', '')
        message = scene_data.get('key_message', '')

        if message:
            narration = f"{main_text}. {message}"
        else:
            narration = f"{main_text}. See {sub_text} for complete documentation."

        return narration.strip()

    def generate_code_comparison_narration(self, scene_data):
        """Generate narration for code comparison scenes"""
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

    def generate_quote_narration(self, scene_data):
        """Generate narration for quote scenes"""
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


class ScriptGenerator:
    """Main script generator from YAML input"""

    def __init__(self):
        self.narration_gen = NarrationGenerator()

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

        scenes = []

        for scene_data in scenes_config:
            scene_type = scene_data.get('type', 'title')
            scene_id = scene_data.get('id', f"scene_{len(scenes)+1:02d}")

            # Generate visual content
            visual_content = self._generate_visual_content(scene_type, scene_data)

            # Generate narration
            narration = self._generate_narration(scene_type, scene_data)

            # Get duration constraints
            min_dur = scene_data.get('min_duration', 3.0)
            max_dur = scene_data.get('max_duration', 15.0)
            voice = scene_data.get('voice', default_voice)

            # Estimate duration
            est_duration, word_count = self.narration_gen.estimate_duration(narration)

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

    def _generate_narration(self, scene_type, scene_data):
        """Generate narration based on scene type"""
        # Check if user provided custom narration
        if 'narration' in scene_data and scene_data['narration']:
            return scene_data['narration']

        # Otherwise, generate from structure
        if scene_type == 'title':
            return self.narration_gen.generate_title_narration(scene_data)
        elif scene_type == 'command':
            return self.narration_gen.generate_command_narration(scene_data)
        elif scene_type == 'list':
            return self.narration_gen.generate_list_narration(scene_data)
        elif scene_type == 'outro':
            return self.narration_gen.generate_outro_narration(scene_data)
        elif scene_type == 'code_comparison':
            return self.narration_gen.generate_code_comparison_narration(scene_data)
        elif scene_type == 'quote':
            return self.narration_gen.generate_quote_narration(scene_data)
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

        print(f"✅ Markdown script saved: {output_file}")
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
                                f.write(f"                    \"{item}\",\n")
                        f.write(f"                ],\n")
                    else:
                        f.write(f"                \"{key}\": \"{value}\",\n")

                f.write(f"            }},\n")
                f.write(f"            narration=\"{scene['narration']}\",\n")
                f.write(f"            voice=\"{scene['voice']}\",\n")
                f.write(f"            min_duration={scene['min_duration']},\n")
                f.write(f"            max_duration={scene['max_duration']}\n")
                f.write(f"        ),\n")

            f.write(f"    ]\n")
            f.write(f")\n\n")

            f.write("# Add this VIDEO object to ALL_VIDEOS list in generate_all_videos_unified_v2.py\n")
            f.write("# Then run: python generate_all_videos_unified_v2.py\n")

        print(f"✅ Python code saved: {output_file}")
        return output_file

    def generate(self, yaml_file, output_dir="drafts"):
        """Main generation function"""
        print(f"\n{'='*80}")
        print("SCRIPT GENERATOR - YAML to Video")
        print(f"{'='*80}\n")

        # Load YAML
        print(f"Loading: {yaml_file}")
        yaml_data = self.load_yaml(yaml_file)

        # Generate UnifiedVideo structure
        print("Generating video structure...")
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

        print(f"\n{'='*80}")
        print("SCRIPT GENERATION COMPLETE")
        print(f"{'='*80}\n")
        print(f"Video: {unified_video['title']}")
        print(f"Scenes: {total_scenes}")
        print(f"Estimated Duration: {total_duration:.1f}s ({total_duration/60:.1f} min)")
        print(f"Total Words: {total_words}")
        print(f"Average WPM: {(total_words / total_duration) * 60:.0f}\n")

        print("Generated files:")
        print(f"  📝 Script (review/edit): {md_file}")
        print(f"  🐍 Code (ready to use):  {py_file}\n")

        print("Next steps:")
        print("  1. Review and edit the markdown script if needed")
        print("  2. Copy VIDEO object from Python file to generate_all_videos_unified_v2.py")
        print("  3. Run: python generate_all_videos_unified_v2.py")
        print(f"\n{'='*80}\n")

        return unified_video, md_file, py_file


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python generate_script_from_yaml.py <input.yaml>")
        print("\nExample:")
        print("  python generate_script_from_yaml.py inputs/my_video.yaml")
        sys.exit(1)

    yaml_file = sys.argv[1]

    if not os.path.exists(yaml_file):
        print(f"❌ File not found: {yaml_file}")
        sys.exit(1)

    generator = ScriptGenerator()
    generator.generate(yaml_file)
