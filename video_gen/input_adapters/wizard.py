"""Interactive wizard for guided video creation.

This adapter provides an interactive command-line interface for creating
video content through guided prompts and questions.
"""

import sys
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime

from .base import InputAdapter, InputAdapterResult
from ..shared.models import VideoSet, VideoConfig, SceneConfig


# ANSI color codes for better UX
class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'


class InteractiveWizard(InputAdapter):
    """Interactive wizard for creating video content.

    This adapter guides users through creating video content via an
    interactive command-line interface with prompts and questions.

    Features:
    - Step-by-step guided creation
    - Multiple content type templates
    - Customizable scene structures
    - Save/resume capability
    - Context-aware suggestions
    """

    def __init__(self):
        """Initialize the interactive wizard."""
        super().__init__(
            name="wizard",
            description="Interactive guided video creation"
        )

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
            },
            'custom': {
                'description': 'Custom structure (build your own)',
                'scene_pattern': [],
                'suggestions': {}
            }
        }

    async def adapt(self, source: Any = None, **kwargs) -> InputAdapterResult:
        """Run interactive wizard to create VideoSet.

        Args:
            source: Optional resume file path
            **kwargs: Additional parameters
                - resume_from: Path to draft file to resume from
                - template: Pre-select template type
                - non_interactive: For testing (uses defaults)

        Returns:
            InputAdapterResult with VideoSet
        """
        try:
            # Check for resume file
            resume_from = kwargs.get('resume_from') or source
            if resume_from:
                return await self._resume_from_draft(resume_from, **kwargs)

            # Run wizard steps
            if kwargs.get('non_interactive'):
                # For testing - use defaults
                video_data = self._create_default_video()
            else:
                self._print_header("VIDEO CREATION WIZARD")
                print("This wizard guides you through creating professional video scripts.")
                print("Answer questions and we'll generate narration automatically!\n")
                self._print_info("Press Ctrl+C at any time to cancel\n")

                try:
                    video_data = await self._run_wizard_steps(**kwargs)
                except KeyboardInterrupt:
                    print(f"\n\n{Colors.YELLOW}⚠️  Wizard cancelled{Colors.END}")
                    self._save_draft(video_data)
                    return InputAdapterResult(
                        success=False,
                        error="Wizard cancelled by user"
                    )

            # Convert to VideoSet
            video_set = self._convert_to_video_set(video_data)

            return InputAdapterResult(
                success=True,
                video_set=video_set,
                metadata={
                    'source': 'wizard',
                    'template': video_data.get('template', 'custom'),
                    'scenes_generated': len(video_data.get('scenes', []))
                }
            )

        except Exception as e:
            return InputAdapterResult(
                success=False,
                error=f"Wizard failed: {e}"
            )

    async def _run_wizard_steps(self, **kwargs) -> Dict[str, Any]:
        """Run all wizard steps and collect video data.

        Args:
            **kwargs: Wizard parameters

        Returns:
            Complete video data dictionary
        """
        video_data = {'video': {}, 'scenes': []}

        # Step 1: Basics
        self._step_basics(video_data, **kwargs)

        # Step 2: Content Type
        self._step_content_type(video_data, **kwargs)

        # Step 3: Structure
        self._step_structure(video_data, **kwargs)

        # Step 4: Scene Details
        self._step_scene_details(video_data, **kwargs)

        # Step 5: Review
        self._step_review(video_data)

        return video_data

    def _step_basics(self, video_data: Dict[str, Any], **kwargs):
        """Gather basic video information."""
        self._print_section(1, "VIDEO BASICS")

        # Topic
        topic = self._prompt("What's your video about?\n> ")
        if not topic:
            print(f"{Colors.RED}✗ Topic required{Colors.END}")
            sys.exit(1)

        # Title
        suggested_title = topic.title()
        title = self._prompt(f"\nVideo title? (or press Enter for: \"{suggested_title}\")\n> ") or suggested_title

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

        color_choice = self._prompt("\nSelect (1-6): ") or '2'
        accent_color = colors[int(color_choice) - 1][0]

        # Voice
        print("\nChoose voice:")
        print("  1. Male (Andrew - confident, professional)")
        print("  2. Female (Aria - clear, crisp)")

        voice_choice = self._prompt("\nSelect (1-2): ") or '1'
        voice = 'male' if voice_choice == '1' else 'female'

        # Save
        video_id = self._slugify(title)
        video_data['video'] = {
            'id': video_id,
            'title': title,
            'topic': topic,
            'description': f'Video about {topic}',
            'accent_color': accent_color,
            'voice': voice,
            'timestamp': datetime.now().isoformat()
        }

        self._print_success(f"Video: \"{title}\" | {accent_color.title()} | {voice.title()} voice\n")

    def _step_content_type(self, video_data: Dict[str, Any], **kwargs):
        """Select content type and template."""
        self._print_section(2, "CONTENT TYPE")

        # Check for pre-selected template
        if kwargs.get('template'):
            template_key = kwargs['template']
            if template_key in self.templates:
                video_data['template'] = template_key
                self._print_success(f"Using template: {template_key.replace('_', ' ').title()}\n")
                return

        print("What type of video are you creating?\n")

        for i, (key, template) in enumerate(self.templates.items(), 1):
            print(f"  {i}. {key.replace('_', ' ').title():<20} - {template['description']}")

        choice = self._prompt(f"\nSelect (1-{len(self.templates)}): ") or '1'
        choice_idx = int(choice) - 1

        template_key = list(self.templates.keys())[choice_idx]
        video_data['template'] = template_key
        self._print_success(f"Using template: {template_key.replace('_', ' ').title()}\n")

    def _step_structure(self, video_data: Dict[str, Any], **kwargs):
        """Define scene structure."""
        self._print_section(3, "CONTENT STRUCTURE")

        template_key = video_data.get('template', 'custom')
        template = self.templates[template_key]
        scene_pattern = template['scene_pattern'].copy()

        if template_key != 'custom' and scene_pattern:
            print(f"Template structure: {len(scene_pattern)} scenes\n")

            for i, scene_type in enumerate(scene_pattern, 1):
                print(f"  Scene {i}: {scene_type.title()}")

            print()

            modify = self._prompt("Use this structure? (y/n, default=y): ") or 'y'

            if modify.lower() == 'y':
                video_data['scene_pattern'] = scene_pattern
                self._print_success("Structure confirmed\n")
                return

        # Custom structure
        print("How many sections/topics do you want to cover? (2-6 recommended)")
        num_topics = int(self._prompt("> ") or '3')

        topics = []
        for i in range(num_topics):
            topic = self._prompt(f"\nTopic {i+1}: ")
            topics.append(topic)

        # Build pattern: title + topics as scenes + outro
        scene_pattern = ['title']
        for _ in topics:
            scene_pattern.append('command')
        scene_pattern.append('outro')

        video_data['topics'] = topics
        video_data['scene_pattern'] = scene_pattern

        self._print_success(f"Structure: {len(scene_pattern)} scenes total\n")

    def _step_scene_details(self, video_data: Dict[str, Any], **kwargs):
        """Gather details for each scene."""
        self._print_section(4, "SCENE DETAILS")

        scene_pattern = video_data.get('scene_pattern', ['title', 'outro'])
        template = self.templates.get(video_data.get('template', 'custom'), {})
        topics = video_data.get('topics', [])

        scenes = []
        topic_idx = 0

        for i, scene_type in enumerate(scene_pattern):
            print(f"\n{Colors.BOLD}━━━ SCENE {i+1}: {scene_type.upper()} ━━━{Colors.END}\n")

            if scene_type == 'title':
                scene = self._wizard_title_scene(video_data, template)
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
            else:
                scene = self._wizard_generic_scene(i+1, scene_type)

            scenes.append(scene)
            self._print_success(f"Scene {i+1} configured\n")

        video_data['scenes'] = scenes

    def _wizard_title_scene(self, video_data: Dict[str, Any], template: Dict[str, Any]) -> Dict[str, Any]:
        """Create title scene."""
        title = video_data['video']['title']
        suggested_subtitle = template.get('suggestions', {}).get('title_subtitle', 'Complete Guide')

        subtitle = self._prompt(f"Subtitle? (or Enter for: \"{suggested_subtitle}\")\n> ") or suggested_subtitle
        key_message = self._prompt("\nKey message for introduction? (what viewers will learn)\n> ")

        return {
            'scene_id': 'scene_01_title',
            'scene_type': 'title',
            'narration': f"Welcome to {title}. {key_message or f'Master {title}'}",
            'visual_content': {
                'title': title,
                'subtitle': subtitle
            }
        }

    def _wizard_command_scene(self, scene_num: int, suggested_topic: Optional[str] = None) -> Dict[str, Any]:
        """Create command scene."""
        topic_prompt = f"Topic for this scene? (suggested: \"{suggested_topic}\")\n> " if suggested_topic else "Topic for this scene?\n> "
        topic = self._prompt(topic_prompt) or suggested_topic or "Command"

        header = self._prompt("\nHeader text? (or Enter for topic)\n> ") or topic

        # Commands
        print("\nEnter commands (one per line, empty line when done):")
        commands = []
        while len(commands) < 10:
            cmd = self._prompt("> ")
            if not cmd:
                break
            # Auto-format
            if not cmd.startswith('$') and not cmd.startswith('#') and not cmd.startswith('→'):
                cmd = '$ ' + cmd
            commands.append(cmd)

        return {
            'scene_id': f'scene_{scene_num:02d}_{self._slugify(topic)}',
            'scene_type': 'command',
            'narration': f"Let's look at {header}. Here are the key commands.",
            'visual_content': {
                'header': header,
                'commands': commands
            }
        }

    def _wizard_list_scene(self, scene_num: int, suggested_topic: Optional[str] = None) -> Dict[str, Any]:
        """Create list scene."""
        topic_prompt = f"Topic for this list? (suggested: \"{suggested_topic}\")\n> " if suggested_topic else "Topic for this list?\n> "
        topic = self._prompt(topic_prompt) or suggested_topic or "List"

        header = self._prompt("\nHeader text? (or Enter for topic)\n> ") or topic

        # List items
        print("\nList items (one per line, empty line when done)")
        print("Format: \"Title: Description\" or just \"Title\"")

        items = []
        while len(items) < 6:
            item_text = self._prompt("> ")
            if not item_text:
                break
            items.append(item_text)

        return {
            'scene_id': f'scene_{scene_num:02d}_{self._slugify(topic)}',
            'scene_type': 'list',
            'narration': f"Here are the key points about {header}",
            'visual_content': {
                'header': header,
                'items': items
            }
        }

    def _wizard_outro_scene(self, template: Dict[str, Any]) -> Dict[str, Any]:
        """Create outro scene."""
        suggested_main = template.get('suggestions', {}).get('outro_main', 'Get Started Today')

        main_text = self._prompt(f"Closing message? (or Enter for: \"{suggested_main}\")\n> ") or suggested_main

        return {
            'scene_id': 'scene_outro',
            'scene_type': 'outro',
            'narration': f"{main_text}. Thank you for watching!",
            'visual_content': {
                'main_text': main_text,
                'sub_text': 'Visit our documentation'
            }
        }

    def _wizard_generic_scene(self, scene_num: int, scene_type: str) -> Dict[str, Any]:
        """Create generic scene."""
        narration = self._prompt(f"Narration for {scene_type} scene:\n> ")

        return {
            'scene_id': f'scene_{scene_num:02d}_{scene_type}',
            'scene_type': scene_type,
            'narration': narration or f"This is the {scene_type} scene",
            'visual_content': {}
        }

    def _step_review(self, video_data: Dict[str, Any]):
        """Review and confirm."""
        self._print_section(5, "REVIEW")

        video = video_data['video']
        scenes = video_data.get('scenes', [])

        print(f"{Colors.BOLD}Video:{Colors.END} {video['title']}")
        print(f"{Colors.BOLD}Scenes:{Colors.END} {len(scenes)}")
        print(f"{Colors.BOLD}Accent:{Colors.END} {video['accent_color'].title()}")
        print(f"{Colors.BOLD}Voice:{Colors.END} {video['voice'].title()}\n")

        print(f"{Colors.BOLD}Topics Covered:{Colors.END}")
        for i, scene in enumerate(scenes, 1):
            if scene['scene_type'] == 'title':
                print(f"  {i}. Introduction")
            elif scene['scene_type'] == 'outro':
                print(f"  {i}. Closing")
            else:
                topic = scene.get('visual_content', {}).get('header', f'Scene {i}')
                print(f"  {i}. {topic}")

        print()
        proceed = self._prompt("Generate video? (y/n): ").lower() or 'y'

        if proceed != 'y':
            self._print_info("Cancelled. Run wizard again to restart.")
            sys.exit(0)

    def _convert_to_video_set(self, video_data: Dict[str, Any]) -> VideoSet:
        """Convert wizard data to VideoSet."""
        video_info = video_data['video']

        # Convert scenes
        scenes = []
        for scene_data in video_data.get('scenes', []):
            scene = SceneConfig(
                scene_id=scene_data['scene_id'],
                scene_type=scene_data['scene_type'],
                narration=scene_data.get('narration', ''),
                visual_content=scene_data.get('visual_content', {}),
                voice=video_info.get('voice', 'male')
            )
            scenes.append(scene)

        # Create video config
        video = VideoConfig(
            video_id=video_info['id'],
            title=video_info['title'],
            description=video_info.get('description', ''),
            scenes=scenes,
            accent_color=video_info.get('accent_color', 'blue'),
            voices=[video_info.get('voice', 'male')]
        )

        # Create video set
        return VideoSet(
            set_id=f"{video_info['id']}_set",
            name=video_info['title'],
            description=video_info.get('description', ''),
            videos=[video],
            metadata={
                'source': 'wizard',
                'template': video_data.get('template', 'custom'),
                'created': video_info.get('timestamp', datetime.now().isoformat())
            }
        )

    def _create_default_video(self) -> Dict[str, Any]:
        """Create default video for testing."""
        return {
            'video': {
                'id': 'test_video',
                'title': 'Test Video',
                'topic': 'Testing',
                'description': 'Test video description',
                'accent_color': 'blue',
                'voice': 'male',
                'timestamp': datetime.now().isoformat()
            },
            'template': 'tutorial',
            'scenes': [
                {
                    'scene_id': 'scene_01_title',
                    'scene_type': 'title',
                    'narration': 'Welcome to Test Video',
                    'visual_content': {'title': 'Test Video', 'subtitle': 'Step-by-Step Guide'}
                },
                {
                    'scene_id': 'scene_02_outro',
                    'scene_type': 'outro',
                    'narration': 'Thank you for watching!',
                    'visual_content': {'main_text': 'Get Started Today', 'sub_text': 'Visit our docs'}
                }
            ]
        }

    async def _resume_from_draft(self, resume_path: Any, **kwargs) -> InputAdapterResult:
        """Resume wizard from draft file."""
        import json

        try:
            with open(resume_path, 'r') as f:
                video_data = json.load(f)

            video_set = self._convert_to_video_set(video_data)

            return InputAdapterResult(
                success=True,
                video_set=video_set,
                metadata={
                    'source': 'wizard_resume',
                    'resumed_from': str(resume_path)
                }
            )
        except Exception as e:
            return InputAdapterResult(
                success=False,
                error=f"Failed to resume from draft: {e}"
            )

    def _save_draft(self, video_data: Dict[str, Any]):
        """Save draft for resuming later."""
        import json

        if not video_data.get('video'):
            return

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        video_id = video_data['video'].get('id', 'untitled')

        draft_file = Path("drafts") / f"{video_id}_draft_{timestamp}.json"
        draft_file.parent.mkdir(parents=True, exist_ok=True)

        with open(draft_file, 'w') as f:
            json.dump(video_data, f, indent=2)

        print(f"\n{Colors.YELLOW}💾 Draft saved: {draft_file}{Colors.END}")
        print(f"   Resume with: wizard --resume {draft_file}\n")

    def _slugify(self, text: str) -> str:
        """Convert text to slug."""
        slug = text.lower()
        slug = re.sub(r'[^\w\s-]', '', slug)
        slug = re.sub(r'[\s_-]+', '_', slug)
        return slug[:30]

    def _print_header(self, text: str):
        """Print section header."""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{text}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'─'*80}{Colors.END}\n")

    def _print_section(self, number: int, title: str):
        """Print step section."""
        print(f"\n{Colors.BOLD}STEP {number}: {title}{Colors.END}")
        print(f"{Colors.CYAN}{'─'*80}{Colors.END}\n")

    def _print_success(self, text: str):
        """Print success message."""
        print(f"{Colors.GREEN}✓{Colors.END} {text}")

    def _print_info(self, text: str):
        """Print info message."""
        print(f"{Colors.BLUE}ℹ{Colors.END} {text}")

    def _prompt(self, text: str) -> str:
        """Print input prompt."""
        return input(f"{Colors.YELLOW}▸{Colors.END} {text}")

    async def validate_source(self, source: Any) -> bool:
        """Validate source (always True for wizard).

        Args:
            source: Not used

        Returns:
            True (wizard doesn't need validation)
        """
        return True

    def supports_format(self, format_type: str) -> bool:
        """Check if format is supported.

        Args:
            format_type: Format type

        Returns:
            True if "interactive" or "wizard"
        """
        return format_type.lower() in {"interactive", "wizard"}
