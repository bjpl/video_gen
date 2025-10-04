"""
Interactive Video Creation Wizard
==================================
Guided step-by-step video script creation through CLI interface.

Perfect for:
- Starting from just ideas/topics
- Technical tutorials and guides
- Software development content
- Learning-focused videos

Usage:
    python generate_script_wizard.py
    python generate_script_wizard.py --type tutorial
    python generate_script_wizard.py --resume drafts/my_video_draft.json
"""

import os
import sys
import json
from datetime import datetime

# ANSI color codes for better UX
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    """Print section header"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{text}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'─'*80}{Colors.END}\n")

def print_success(text):
    """Print success message"""
    print(f"{Colors.GREEN}✓{Colors.END} {text}")

def print_info(text):
    """Print info message"""
    print(f"{Colors.BLUE}ℹ{Colors.END} {text}")

def print_prompt(text):
    """Print input prompt"""
    return input(f"{Colors.YELLOW}▸{Colors.END} {text}")

def print_section(number, title):
    """Print step section"""
    print(f"\n{Colors.BOLD}STEP {number}: {title}{Colors.END}")
    print(f"{Colors.CYAN}{'─'*80}{Colors.END}\n")


class VideoWizard:
    """Interactive wizard for video creation"""

    def __init__(self):
        self.video_data = {
            'video': {},
            'scenes': []
        }

        # Content type templates
        self.templates = {
            'tutorial': {
                'description': 'Step-by-step how-to guide',
                'scene_pattern': ['title', 'command', 'command', 'command', 'list', 'outro'],
                'suggestions': {
                    'title_subtitle': 'Step-by-Step Guide',
                    'outro_main': 'Start Building Today'
                }
            },
            'overview': {
                'description': 'Feature showcase and overview',
                'scene_pattern': ['title', 'list', 'command', 'list', 'outro'],
                'suggestions': {
                    'title_subtitle': 'Complete Overview',
                    'outro_main': 'Try These Features'
                }
            },
            'troubleshooting': {
                'description': 'Problem-solution guide',
                'scene_pattern': ['title', 'list', 'command', 'command', 'list', 'outro'],
                'suggestions': {
                    'title_subtitle': 'Common Issues & Solutions',
                    'outro_main': 'Solve Problems Fast'
                }
            },
            'comparison': {
                'description': 'Compare options or approaches',
                'scene_pattern': ['title', 'list', 'list', 'command', 'outro'],
                'suggestions': {
                    'title_subtitle': 'Making the Right Choice',
                    'outro_main': 'Choose Wisely'
                }
            },
            'best_practices': {
                'description': 'Tips, techniques, and recommendations',
                'scene_pattern': ['title', 'list', 'list', 'command', 'outro'],
                'suggestions': {
                    'title_subtitle': 'Expert Tips & Techniques',
                    'outro_main': 'Code Like a Pro'
                }
            }
        }

    def run(self):
        """Run the complete wizard"""
        print_header("VIDEO CREATION WIZARD")
        print("This wizard guides you through creating professional video scripts.")
        print("Answer questions and we'll generate narration automatically!\n")
        print_info("Press Ctrl+C at any time to cancel")
        print_info("Press Enter to use suggested defaults\n")

        try:
            # Step 1: Basics
            self.step_basics()

            # Step 2: Content Type
            self.step_content_type()

            # Step 3: Structure
            self.step_structure()

            # Step 4: Scene Details
            self.step_scene_details()

            # Step 5: Review
            self.step_review()

            # Step 6: Generate
            self.step_generate()

        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}⚠️  Wizard cancelled{Colors.END}")
            self.save_draft()
            sys.exit(0)

    def step_basics(self):
        """Gather basic video information"""
        print_section(1, "VIDEO BASICS")

        # Topic
        topic = print_prompt("What's your video about?\n> ")
        if not topic:
            print(f"{Colors.RED}✗ Topic required{Colors.END}")
            sys.exit(1)

        # Title
        suggested_title = topic.title()
        title = print_prompt(f"\nVideo title? (or press Enter for: \"{suggested_title}\")\n> ") or suggested_title

        # Accent color
        print("\nChoose an accent color:")
        colors = [
            ('orange', '🟠 Orange (energetic, creative)'),
            ('blue', '🔵 Blue (professional, trustworthy)'),
            ('purple', '🟣 Purple (innovative, creative)'),
            ('green', '🟢 Green (growth, success)'),
            ('pink', '🌸 Pink (friendly, approachable)'),
            ('cyan', '🔷 Cyan (modern, technical)')
        ]

        for i, (color, desc) in enumerate(colors, 1):
            print(f"  {i}. {desc}")

        color_choice = print_prompt("\nSelect (1-6): ") or '2'
        accent_color = colors[int(color_choice) - 1][0]

        # Voice
        print("\nChoose voice:")
        print("  1. Male (Andrew - confident, professional)")
        print("  2. Female (Aria - clear, crisp)")

        voice_choice = print_prompt("\nSelect (1-2): ") or '1'
        voice = 'male' if voice_choice == '1' else 'female'

        # Duration
        print("\nTarget duration (common options):")
        print("  1. ~30 seconds (quick overview)")
        print("  2. ~60 seconds (standard guide)")
        print("  3. ~90 seconds (detailed tutorial)")
        print("  4. ~120 seconds (comprehensive)")

        dur_choice = print_prompt("\nSelect (1-4) or enter seconds: ") or '2'
        duration_map = {'1': 30, '2': 60, '3': 90, '4': 120}
        duration = duration_map.get(dur_choice, int(dur_choice))

        # Save
        video_id = self._slugify(title)
        self.video_data['video'] = {
            'id': video_id,
            'title': title,
            'topic': topic,
            'description': f'Video about {topic}',
            'accent_color': accent_color,
            'voice': voice,
            'version': 'v2.0',
            'target_duration': duration
        }

        print_success(f"Video: \"{title}\" | {accent_color.title()} | {voice.title()} voice | ~{duration}s\n")

    def step_content_type(self):
        """Select content type and template"""
        print_section(2, "CONTENT TYPE")

        print("What type of video are you creating?\n")

        for i, (key, template) in enumerate(self.templates.items(), 1):
            print(f"  {i}. {key.replace('_', ' ').title():<20} - {template['description']}")

        print(f"  {len(self.templates)+1}. Custom (build your own structure)")

        choice = print_prompt(f"\nSelect (1-{len(self.templates)+1}): ") or '1'
        choice_idx = int(choice) - 1

        if choice_idx < len(self.templates):
            template_key = list(self.templates.keys())[choice_idx]
            self.video_data['template'] = template_key
            print_success(f"Using template: {template_key.replace('_', ' ').title()}\n")
        else:
            self.video_data['template'] = 'custom'
            print_success("Custom structure selected\n")

    def step_structure(self):
        """Define scene structure"""
        print_section(3, "CONTENT STRUCTURE")

        template_key = self.video_data.get('template', 'custom')

        if template_key != 'custom':
            template = self.templates[template_key]
            scene_pattern = template['scene_pattern']

            print(f"Template structure: {len(scene_pattern)} scenes")
            print()

            for i, scene_type in enumerate(scene_pattern, 1):
                print(f"  Scene {i}: {scene_type.title()}")

            print()

            modify = print_prompt("Use this structure? (y/n, default=y): ") or 'y'

            if modify.lower() == 'y':
                self.video_data['scene_pattern'] = scene_pattern
                print_success("Structure confirmed\n")
                return

        # Custom structure
        print("How many sections/topics do you want to cover? (2-6 recommended)")
        num_topics = int(print_prompt("> ") or '3')

        topics = []
        for i in range(num_topics):
            topic = print_prompt(f"\nTopic {i+1}: ")
            topics.append(topic)

        # Build pattern: title + topics as scenes + outro
        scene_pattern = ['title']
        for _ in topics:
            scene_pattern.append('command')  # Default to command scenes
        scene_pattern.append('outro')

        self.video_data['topics'] = topics
        self.video_data['scene_pattern'] = scene_pattern

        print_success(f"Structure: {len(scene_pattern)} scenes total\n")

    def step_scene_details(self):
        """Gather details for each scene"""
        print_section(4, "SCENE DETAILS")

        scene_pattern = self.video_data['scene_pattern']
        template = self.templates.get(self.video_data.get('template', 'custom'), {})
        topics = self.video_data.get('topics', [])

        scenes = []
        topic_idx = 0

        for i, scene_type in enumerate(scene_pattern):
            print(f"\n{Colors.BOLD}━━━ SCENE {i+1}: {scene_type.upper()} ━━━{Colors.END}\n")

            if scene_type == 'title':
                scene = self._wizard_title_scene(template)
            elif scene_type == 'command':
                topic = topics[topic_idx] if topic_idx < len(topics) else None
                scene = self._wizard_command_scene(i+1, topic)
                if topic:
                    topic_idx += 1
            elif scene_type == 'list':
                topic = topics[topic_idx] if topic_idx < len(topics) else None
                scene = self._wizard_list_scene(i+1, topic)
                if topic:
                    topic_idx += 1
            elif scene_type == 'outro':
                scene = self._wizard_outro_scene(template)

            scenes.append(scene)
            print_success(f"Scene {i+1} configured\n")

        self.video_data['scenes'] = scenes

    def _wizard_title_scene(self, template):
        """Create title scene"""
        title = self.video_data['video']['title']
        suggested_subtitle = template.get('suggestions', {}).get('title_subtitle', 'Complete Guide')

        subtitle = print_prompt(f"Subtitle? (or Enter for: \"{suggested_subtitle}\")\n> ") or suggested_subtitle

        key_message = print_prompt("\nKey message for introduction? (what viewers will learn)\n> ")

        return {
            'type': 'title',
            'id': 'scene_01_title',
            'title': title,
            'subtitle': subtitle,
            'key_message': key_message or f"Master {title}"
        }

    def _wizard_command_scene(self, scene_num, suggested_topic=None):
        """Create command scene"""
        topic_prompt = f"Topic for this scene? (suggested: \"{suggested_topic}\")\n> " if suggested_topic else "Topic for this scene?\n> "
        topic = print_prompt(topic_prompt) or suggested_topic

        header = print_prompt("\nHeader text? (or Enter for topic)\n> ") or topic

        # Key points
        print("\nWhat are the key points about this topic? (one per line, empty line when done)")
        key_points = []
        while True:
            point = print_prompt("> ")
            if not point:
                break
            key_points.append(point)

        # Commands
        has_commands = print_prompt("\nDo you have commands/code to show? (y/n): ").lower() == 'y'

        commands = []
        if has_commands:
            print("\nEnter commands (one per line, empty line when done):")
            while len(commands) < 10:
                cmd = print_prompt("> ")
                if not cmd:
                    break
                # Auto-format
                if not cmd.startswith('$') and not cmd.startswith('#') and not cmd.startswith('→'):
                    cmd = '$ ' + cmd
                commands.append(cmd)

        return {
            'type': 'command',
            'id': f'scene_{scene_num:02d}_{self._slugify(topic or "command")}',
            'header': header,
            'description': self._summarize_points(key_points),
            'topic': topic,
            'commands': commands,
            'key_points': key_points
        }

    def _wizard_list_scene(self, scene_num, suggested_topic=None):
        """Create list scene"""
        topic_prompt = f"Topic for this list? (suggested: \"{suggested_topic}\")\n> " if suggested_topic else "Topic for this list?\n> "
        topic = print_prompt(topic_prompt) or suggested_topic

        header = print_prompt("\nHeader text? (or Enter for topic)\n> ") or topic

        # List items
        print("\nList items (one per line, empty line when done)")
        print("Format: \"Title: Description\" or just \"Title\"")

        items = []
        while len(items) < 6:
            item_text = print_prompt("> ")
            if not item_text:
                break

            # Parse title:description format
            if ':' in item_text:
                parts = item_text.split(':', 1)
                items.append({
                    'title': parts[0].strip(),
                    'description': parts[1].strip()
                })
            else:
                items.append(item_text)

        return {
            'type': 'list',
            'id': f'scene_{scene_num:02d}_{self._slugify(topic or "list")}',
            'header': header,
            'description': f'{len(items)} Key Points',
            'topic': topic,
            'items': items
        }

    def _wizard_outro_scene(self, template):
        """Create outro scene"""
        suggested_main = template.get('suggestions', {}).get('outro_main', 'Get Started Today')

        main_text = print_prompt(f"Closing message? (or Enter for: \"{suggested_main}\")\n> ") or suggested_main

        doc_link = print_prompt("\nLink to documentation? (filename or URL)\n> ") or "Documentation"

        return {
            'type': 'outro',
            'id': f'scene_{len(self.video_data.get("scenes", [])) + 1:02d}_outro',
            'main_text': main_text,
            'sub_text': doc_link,
            'key_message': 'Everything you need to succeed'
        }

    def _summarize_points(self, points):
        """Summarize key points into description"""
        if not points:
            return ""
        if len(points) == 1:
            return points[0][:40]
        elif len(points) == 2:
            return f"{points[0][:20]} & {points[1][:20]}"
        else:
            return f"{points[0][:30]}..."

    def _slugify(self, text):
        """Convert text to slug"""
        import re
        slug = text.lower()
        slug = re.sub(r'[^\w\s-]', '', slug)
        slug = re.sub(r'[\s_-]+', '_', slug)
        return slug[:30]

    def step_review(self):
        """Review and confirm"""
        print_section(5, "REVIEW")

        video = self.video_data['video']
        scenes = self.video_data['scenes']

        print(f"{Colors.BOLD}Video:{Colors.END} {video['title']}")
        print(f"{Colors.BOLD}Scenes:{Colors.END} {len(scenes)}")
        print(f"{Colors.BOLD}Accent:{Colors.END} {video['accent_color'].title()}")
        print(f"{Colors.BOLD}Voice:{Colors.END} {video['voice'].title()}")
        print(f"{Colors.BOLD}Target:{Colors.END} ~{video['target_duration']}s\n")

        print(f"{Colors.BOLD}Topics Covered:{Colors.END}")
        for i, scene in enumerate(scenes, 1):
            if scene['type'] == 'title':
                print(f"  {i}. Introduction")
            elif scene['type'] == 'outro':
                print(f"  {i}. Closing")
            else:
                topic = scene.get('header', scene.get('topic', f'Scene {i}'))
                print(f"  {i}. {topic}")

        print()
        proceed = print_prompt("Generate script? (y/n): ").lower() or 'y'

        if proceed != 'y':
            print_info("Cancelled. Run wizard again to restart.")
            sys.exit(0)

    def step_generate(self):
        """Generate YAML and script"""
        print_section(6, "GENERATING SCRIPT")

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        video_id = self.video_data['video']['id']

        # Save YAML
        yaml_file = f"inputs/{video_id}_wizard_{timestamp}.yaml"
        os.makedirs('inputs', exist_ok=True)

        import yaml
        with open(yaml_file, 'w') as f:
            yaml.dump(self.video_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

        print_success(f"YAML saved: {yaml_file}\n")

        # Generate script using existing script generator
        print("Generating professional narration...")

        # Import and run script generator
        from generate_script_from_yaml import ScriptGenerator

        generator = ScriptGenerator()
        try:
            unified_video, md_file, py_file = generator.generate(yaml_file, output_dir='drafts')

            print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*80}{Colors.END}")
            print(f"{Colors.BOLD}{Colors.GREEN}✓ WIZARD COMPLETE{Colors.END}")
            print(f"{Colors.BOLD}{Colors.GREEN}{'='*80}{Colors.END}\n")

            print("Files created:")
            print(f"  📋 {yaml_file}")
            print(f"  📝 {md_file}")
            print(f"  🐍 {py_file}\n")

            print("Next steps:")
            print(f"  1. Review narration: cat {md_file}")
            print(f"  2. Copy VIDEO object from {py_file} to generate_all_videos_unified_v2.py")
            print(f"  3. Generate video: python generate_all_videos_unified_v2.py\n")

        except Exception as e:
            print(f"{Colors.RED}❌ Error generating script: {e}{Colors.END}")
            print(f"   YAML saved, you can manually run:")
            print(f"   python generate_script_from_yaml.py {yaml_file}\n")

    def save_draft(self):
        """Save draft for resuming later"""
        if not self.video_data.get('video'):
            return

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        video_id = self.video_data['video'].get('id', 'untitled')

        draft_file = f"drafts/{video_id}_draft_{timestamp}.json"
        os.makedirs('drafts', exist_ok=True)

        with open(draft_file, 'w') as f:
            json.dump(self.video_data, f, indent=2)

        print(f"\n{Colors.YELLOW}💾 Draft saved: {draft_file}{Colors.END}")
        print(f"   Resume with: python generate_script_wizard.py --resume {draft_file}\n")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Interactive video creation wizard')
    parser.add_argument('--type', choices=['tutorial', 'overview', 'troubleshooting', 'comparison', 'best_practices'],
                       help='Start with content type preset')
    parser.add_argument('--resume', help='Resume from draft file')

    args = parser.parse_args()

    wizard = VideoWizard()

    if args.resume:
        print(f"⚠️  Resume functionality not yet implemented")
        print(f"   Planned feature: Load {args.resume}")

    wizard.run()
