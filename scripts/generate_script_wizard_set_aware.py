"""
Set-Aware Interactive Video Creation Wizard
============================================
Enhanced wizard that can:
- Create standalone videos
- Create videos within sets
- Create entire new sets
- Add to existing sets

Usage:
    python generate_script_wizard_set_aware.py
    python generate_script_wizard_set_aware.py --set my_existing_set
"""

import os
import sys
import yaml
from pathlib import Path

sys.path.append('.')

from generate_script_wizard import VideoWizard, Colors, print_header, print_prompt, print_success, print_info


class SetAwareWizard(VideoWizard):
    """Enhanced wizard with set awareness"""

    def __init__(self):
        super().__init__()
        self.set_mode = None  # 'standalone', 'new_set', 'existing_set'
        self.set_config = None
        self.set_dir = None

    def run(self):
        """Run set-aware wizard"""
        print_header("SET-AWARE VIDEO CREATION WIZARD")
        print("Create standalone videos or organize them into sets!")
        print()
        print_info("Press Ctrl+C at any time to cancel\n")

        try:
            # Step 0: Set or Standalone?
            self.step_set_mode()

            # Original wizard steps (slightly modified)
            self.step_basics()
            self.step_content_type()
            self.step_structure()
            self.step_scene_details()
            self.step_review()
            self.step_generate()

        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}⚠️  Wizard cancelled{Colors.END}")
            self.save_draft()
            sys.exit(0)

    def step_set_mode(self):
        """Ask if creating standalone or set video"""
        print(f"\n{Colors.BOLD}STEP 0: VIDEO ORGANIZATION{Colors.END}")
        print(f"{Colors.CYAN}{'─'*80}{Colors.END}\n")

        print("How do you want to organize this video?\n")
        print("  1. Standalone video (single independent video)")
        print("  2. Create new video set (new collection)")
        print("  3. Add to existing set (extend existing collection)")

        choice = print_prompt("\nSelect (1-3): ") or '1'

        if choice == '1':
            self.set_mode = 'standalone'
            print_success("Creating standalone video\n")

        elif choice == '2':
            self.set_mode = 'new_set'
            print_success("Creating new video set\n")
            self.configure_new_set()

        elif choice == '3':
            self.set_mode = 'existing_set'
            print_success("Adding to existing set\n")
            self.select_existing_set()

    def configure_new_set(self):
        """Configure a new video set"""
        print(f"\n{Colors.BOLD}NEW SET CONFIGURATION{Colors.END}")
        print(f"{Colors.CYAN}{'─'*80}{Colors.END}\n")

        # Set ID
        set_id = print_prompt("Set ID (e.g., 'tutorial_series_2024'): ")
        if not set_id:
            print(f"{Colors.RED}✗ Set ID required{Colors.END}")
            sys.exit(1)

        # Set name
        suggested_name = set_id.replace('_', ' ').title()
        set_name = print_prompt(f"Set name? (or Enter for: \"{suggested_name}\")\n> ") or suggested_name

        # Description
        description = print_prompt("Set description: ") or f"{set_name} video collection"

        # Set defaults
        print("\nSet-level defaults (applied to all videos):")

        # Accent color
        print("\nDefault accent color:")
        colors = [
            ('orange', 'Orange'), ('blue', 'Blue'), ('purple', 'Purple'),
            ('green', 'Green'), ('pink', 'Pink'), ('cyan', 'Cyan')
        ]
        for i, (color, name) in enumerate(colors, 1):
            print(f"  {i}. {name}")

        color_choice = print_prompt("\nSelect (1-6, default=2): ") or '2'
        accent_color = colors[int(color_choice) - 1][0]

        # Voice
        print("\nDefault voice:")
        print("  1. Male (Andrew)")
        print("  2. Female (Aria)")
        voice_choice = print_prompt("\nSelect (1-2, default=1): ") or '1'
        voice = 'male' if voice_choice == '1' else 'female'

        # Target duration
        duration = int(print_prompt("\nDefault target duration (seconds, default=60): ") or '60')

        # Naming convention
        print("\nNaming convention:")
        print("  1. Numbered (tutorial-01, tutorial-02, ...)")
        print("  2. Descriptive (quick_start, advanced_features, ...)")
        naming_choice = print_prompt("\nSelect (1-2, default=1): ") or '1'

        prefix = print_prompt("Filename prefix (or Enter for none): ") or ''

        self.set_config = {
            'set': {
                'id': set_id,
                'name': set_name,
                'description': description,
                'version': 'v2.0',
                'defaults': {
                    'accent_color': accent_color,
                    'voice': voice,
                    'target_duration': duration,
                    'min_scene_duration': 3.0,
                    'max_scene_duration': 15.0
                },
                'output': {
                    'base_dir': f'../output/{set_id}',
                    'audio_dir': 'audio',
                    'video_dir': 'videos',
                    'script_dir': 'scripts',
                    'report_dir': 'reports'
                },
                'naming': {
                    'prefix': prefix,
                    'use_numbers': naming_choice == '1',
                    'separator': '-' if naming_choice == '1' else '_'
                },
                'processing': {
                    'parallel_audio': True,
                    'auto_cleanup': False,
                    'gpu_encoding': True
                },
                'videos': [],
                'metadata': {}
            }
        }

        # Set directory
        self.set_dir = Path(f"../sets/{set_id}")

        print_success(f"\nSet configured: {set_name}")
        print(f"  Location: {self.set_dir}\n")

    def select_existing_set(self):
        """Select an existing set to add to"""
        sets_dir = Path("../sets")

        if not sets_dir.exists():
            print(f"{Colors.RED}✗ No sets directory found{Colors.END}")
            print("  Creating first set instead...")
            self.set_mode = 'new_set'
            self.configure_new_set()
            return

        # Find existing sets
        existing_sets = []
        for item in sets_dir.iterdir():
            if item.is_dir():
                config_file = item / "set_config.yaml"
                if config_file.exists():
                    existing_sets.append(item)

        if not existing_sets:
            print(f"{Colors.YELLOW}⚠️  No existing sets found{Colors.END}")
            print("  Creating first set instead...")
            self.set_mode = 'new_set'
            self.configure_new_set()
            return

        print(f"\n{Colors.BOLD}EXISTING SETS{Colors.END}")
        print(f"{Colors.CYAN}{'─'*80}{Colors.END}\n")

        for i, set_path in enumerate(existing_sets, 1):
            # Load set config to get name
            with open(set_path / "set_config.yaml", 'r') as f:
                config = yaml.safe_load(f)

            set_name = config['set'].get('name', set_path.name)
            video_count = len(config['set'].get('videos', []))

            print(f"  {i}. {set_name}")
            print(f"     ({video_count} video(s), {set_path.name})")

        choice = int(print_prompt(f"\nSelect set (1-{len(existing_sets)}): ") or '1')
        selected_set = existing_sets[choice - 1]

        # Load configuration
        with open(selected_set / "set_config.yaml", 'r') as f:
            self.set_config = yaml.safe_load(f)

        self.set_dir = selected_set

        print_success(f"Adding to: {self.set_config['set']['name']}\n")

    def step_generate(self):
        """Enhanced generation with set support"""
        print(f"\n{Colors.BOLD}STEP 6: GENERATING{Colors.END}")
        print(f"{Colors.CYAN}{'─'*80}{Colors.END}\n")

        timestamp = self.video_data['video'].get('timestamp') or \
                   __import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')

        video_id = self.video_data['video']['id']

        if self.set_mode == 'standalone':
            # Original wizard behavior - standalone YAML
            yaml_file = f"inputs/{video_id}_wizard_{timestamp}.yaml"
            os.makedirs('inputs', exist_ok=True)

            with open(yaml_file, 'w') as f:
                yaml.dump(self.video_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

            print_success(f"YAML saved: {yaml_file}\n")

            # Generate script
            print("Generating professional narration...")

            from generate_script_from_yaml import ScriptGenerator

            generator = ScriptGenerator()
            try:
                unified_video, md_file, py_file = generator.generate(yaml_file, output_dir='drafts')

                print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*80}{Colors.END}")
                print(f"{Colors.BOLD}{Colors.GREEN}✓ STANDALONE VIDEO CREATED{Colors.END}")
                print(f"{Colors.BOLD}{Colors.GREEN}{'='*80}{Colors.END}\n")

                print("Files created:")
                print(f"  📋 {yaml_file}")
                print(f"  📝 {md_file}")
                print(f"  🐍 {py_file}\n")

                print("Next steps:")
                print(f"  1. Review narration: cat {md_file}")
                print(f"  2. Generate as standalone:")
                print(f"     python generate_all_videos_unified_v2.py")
                print(f"  3. Or convert to set later\n")

            except Exception as e:
                print(f"{Colors.RED}❌ Error: {e}{Colors.END}\n")

        else:  # new_set or existing_set
            # Create/update set
            self.set_dir.mkdir(parents=True, exist_ok=True)

            # Save video YAML
            video_file = self.set_dir / f"{video_id}.yaml"
            with open(video_file, 'w') as f:
                yaml.dump(self.video_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

            print_success(f"Video YAML saved: {video_file}")

            # Update set config
            if self.set_mode == 'new_set' or not (self.set_dir / 'set_config.yaml').exists():
                # Initialize videos list
                self.set_config['set']['videos'] = []

            # Add video to set
            video_entry = {
                'file': f"{video_id}.yaml",
                'priority': len(self.set_config['set'].get('videos', [])) + 1
            }

            self.set_config['set']['videos'].append(video_entry)

            # Save set config
            config_file = self.set_dir / 'set_config.yaml'
            with open(config_file, 'w') as f:
                yaml.dump(self.set_config, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

            print_success(f"Set config updated: {config_file}")

            print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*80}{Colors.END}")
            print(f"{Colors.BOLD}{Colors.GREEN}✓ VIDEO ADDED TO SET{Colors.END}")
            print(f"{Colors.BOLD}{Colors.GREEN}{'='*80}{Colors.END}\n")

            print("Set details:")
            print(f"  Set: {self.set_config['set']['name']}")
            print(f"  Location: {self.set_dir}")
            print(f"  Total videos: {len(self.set_config['set']['videos'])}\n")

            print("Next steps:")
            print(f"  1. Add more videos to this set (run wizard again)")
            print(f"  2. Generate the entire set:")
            print(f"     python generate_video_set.py {self.set_dir}")
            print(f"  3. Render videos:")
            print(f"     python generate_videos_from_set.py {self.set_dir.parent.parent / 'output' / self.set_config['set']['id']}\n")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Set-aware interactive video creation wizard'
    )

    parser.add_argument(
        '--set',
        help='Add to specific set (set directory path)'
    )

    parser.add_argument(
        '--standalone',
        action='store_true',
        help='Create standalone video (skip set selection)'
    )

    args = parser.parse_args()

    wizard = SetAwareWizard()

    # Pre-configure based on arguments
    if args.standalone:
        wizard.set_mode = 'standalone'
        print(f"{Colors.BOLD}Creating standalone video{Colors.END}\n")
        wizard.video_data = {'video': {}, 'scenes': []}
        wizard.step_basics()
        wizard.step_content_type()
        wizard.step_structure()
        wizard.step_scene_details()
        wizard.step_review()
        wizard.step_generate()

    elif args.set:
        set_path = Path(args.set)
        if not set_path.exists() or not (set_path / 'set_config.yaml').exists():
            print(f"{Colors.RED}✗ Invalid set: {set_path}{Colors.END}")
            sys.exit(1)

        wizard.set_mode = 'existing_set'
        wizard.set_dir = set_path

        with open(set_path / 'set_config.yaml', 'r') as f:
            wizard.set_config = yaml.safe_load(f)

        print(f"{Colors.BOLD}Adding to set: {wizard.set_config['set']['name']}{Colors.END}\n")

        wizard.video_data = {'video': {}, 'scenes': []}
        wizard.step_basics()
        wizard.step_content_type()
        wizard.step_structure()
        wizard.step_scene_details()
        wizard.step_review()
        wizard.step_generate()

    else:
        # Full wizard with set selection
        wizard.run()


if __name__ == "__main__":
    main()
