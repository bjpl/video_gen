"""
Unified Video Creation Entry Point
===================================
Single command to create videos from ANY source:
- Documents (README, guides, markdown)
- YouTube transcripts (with search)
- Interactive wizard (guided Q&A)
- YAML files (existing method)

Usage:
    python create_video.py --document README.md
    python create_video.py --youtube "python tutorial"
    python create_video.py --wizard
    python create_video.py --yaml inputs/my_video.yaml

This is the MASTER COMMAND - one entry point for all input methods!
"""

import os
import sys
import argparse
from datetime import datetime
import logging

# Setup logging
logger = logging.getLogger(__name__)


class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'


def print_banner():
    """Print welcome banner"""
    logger.info(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}")
    logger.info(f"{Colors.BOLD}{Colors.CYAN}           VIDEO CREATION SYSTEM - Unified Entry Point{Colors.END}")
    logger.info(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}\n")


def print_workflow():
    """Print workflow diagram"""
    logger.info(f"{Colors.BOLD}Complete Workflow:{Colors.END}\n")
    logger.info("  INPUT METHOD → Script Generation → Review → Audio → Video → DONE!\n")
    logger.info("  Available input methods:")
    logger.info(f"    {Colors.GREEN}✓{Colors.END} Document (README, guides, markdown)")
    logger.info(f"    {Colors.GREEN}✓{Colors.END} YouTube (transcripts with search)")
    logger.info(f"    {Colors.GREEN}✓{Colors.END} Wizard (guided Q&A)")
    logger.info(f"    {Colors.GREEN}✓{Colors.END} YAML (direct input)\n")


def main():
    parser = argparse.ArgumentParser(
        description='Create professional videos from any source',
        epilog='''
Examples:
  # From documentation
  python create_video.py --document README.md
  python create_video.py --document https://github.com/user/repo/blob/main/README.md

  # From YouTube
  python create_video.py --youtube "python async tutorial"
  python create_video.py --youtube-url "https://youtube.com/watch?v=VIDEO_ID"

  # Interactive wizard
  python create_video.py --wizard

  # Direct YAML
  python create_video.py --yaml inputs/my_video.yaml
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Input method (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--document', metavar='FILE', help='Parse document (README, guide, markdown)')
    input_group.add_argument('--youtube', metavar='QUERY', help='Search YouTube and fetch transcript')
    input_group.add_argument('--youtube-url', metavar='URL', help='YouTube video URL')
    input_group.add_argument('--youtube-id', metavar='ID', help='YouTube video ID')
    input_group.add_argument('--wizard', action='store_true', help='Launch interactive wizard')
    input_group.add_argument('--yaml', metavar='FILE', help='Use YAML input file')

    # Common options
    parser.add_argument('--accent-color', default='blue',
                       choices=['orange', 'blue', 'purple', 'green', 'pink', 'cyan'],
                       help='Accent color for video')
    parser.add_argument('--voice', default='male', choices=['male', 'female'],
                       help='Default narration voice')
    parser.add_argument('--duration', type=int, default=60,
                       help='Target duration in seconds')
    parser.add_argument('--auto', action='store_true',
                       help='Auto-proceed through all steps (no review)')
    parser.add_argument('--use-ai', action='store_true',
                       help='Use Claude AI for enhanced narration (requires ANTHROPIC_API_KEY)')

    args = parser.parse_args()

    print_banner()

    # Route to appropriate generator
    yaml_file = None

    try:
        if args.document:
            logger.info(f"{Colors.BOLD}INPUT METHOD:{Colors.END} Document Parser\n")
            logger.info(f"Source: {args.document}\n")

            from generate_script_from_document import generate_yaml_from_document

            yaml_file = generate_yaml_from_document(
                args.document,
                accent_color=args.accent_color,
                voice=args.voice,
                target_duration=args.duration
            )

        elif args.youtube or args.youtube_url or args.youtube_id:
            logger.info(f"{Colors.BOLD}INPUT METHOD:{Colors.END} YouTube Transcript\n")

            # Determine video ID/query
            if args.youtube_id:
                video_ref = f"--video-id {args.youtube_id}"
            elif args.youtube_url:
                video_ref = f"--url {args.youtube_url}"
            else:
                video_ref = f"--search \"{args.youtube}\""

            logger.warning(f"⚠️  Running YouTube generator...\n")
            os.system(f"python generate_script_from_youtube.py {video_ref} "
                     f"--accent-color {args.accent_color} --voice {args.voice} --duration {args.duration}")
            return

        elif args.wizard:
            logger.info(f"{Colors.BOLD}INPUT METHOD:{Colors.END} Interactive Wizard\n")
            os.system("python generate_script_wizard.py")
            return

        elif args.yaml:
            logger.info(f"{Colors.BOLD}INPUT METHOD:{Colors.END} Direct YAML\n")
            yaml_file = args.yaml

        # If we have YAML file, proceed to script generation
        if yaml_file and os.path.exists(yaml_file):
            if not args.auto:
                logger.info(f"\n{Colors.YELLOW}Review the YAML file before proceeding:{Colors.END}")
                logger.info(f"  cat {yaml_file}\n")

                proceed = input("Generate script now? (y/n): ").lower()
                if proceed != 'y':
                    logger.info(f"\n{Colors.YELLOW}Stopped.{Colors.END} Run when ready:")
                    logger.info(f"  python generate_script_from_yaml.py {yaml_file}\n")
                    return

            # Generate script
            logger.info(f"\n{Colors.BOLD}Generating script from YAML...{Colors.END}\n")
            ai_flag = '--use-ai' if args.use_ai else ''
            os.system(f"python generate_script_from_yaml.py {yaml_file} {ai_flag}")

    except Exception as e:
        logger.error(f"\n{Colors.RED}❌ Error: {e}{Colors.END}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
