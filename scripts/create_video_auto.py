"""
Auto-Orchestrator for Complete Video Generation Pipeline
==========================================================
Single command to run entire workflow using the modern pipeline architecture.

This script provides a CLI interface to the production-ready pipeline system:
- Uses proper pipeline orchestrator with 6 stages
- Supports all input methods (document, YouTube, YAML, wizard, programmatic)
- Integrates with template builders
- Provides progress tracking and state management
- Handles errors gracefully with recovery options

Usage:
    # From document
    python create_video_auto.py --from README.md --type document

    # From YouTube
    python create_video_auto.py --from "python tutorial" --type youtube

    # Interactive wizard
    python create_video_auto.py --type wizard

    # With options
    python create_video_auto.py --from README.md --type document \
        --voice male --color blue --duration 120 --use-ai
"""

import os
import sys
import argparse
import asyncio
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Import modern pipeline components
from video_gen.pipeline.complete_pipeline import create_complete_pipeline
from video_gen.pipeline.events import EventType
from video_gen.shared.models import InputConfig
from video_gen.shared.config import config

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'


class ModernPipelineOrchestrator:
    """Modern orchestrator using the production pipeline architecture"""

    def __init__(self, args):
        self.args = args
        self.pipeline = create_complete_pipeline()
        self.task_id = None

        # Setup logging
        log_level = logging.DEBUG if args.verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def print_banner(self):
        """Print welcome banner"""
        self.logger.info(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}")
        self.logger.info(f"{Colors.BOLD}{Colors.CYAN}   AUTO VIDEO GENERATOR - Modern Pipeline v2.0{Colors.END}")
        self.logger.info(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}\n")

    def print_success(self, message):
        """Print success message"""
        self.logger.info(f"{Colors.GREEN}✓{Colors.END} {message}")

    def print_error(self, message):
        """Print error message"""
        self.logger.error(f"{Colors.RED}✗{Colors.END} {message}")

    def print_info(self, message):
        """Print info message"""
        self.logger.info(f"  {message}")

    def create_input_config(self) -> InputConfig:
        """Create InputConfig from command line arguments"""

        # Determine input type
        input_type = self.args.type
        if input_type == 'wizard':
            input_type = 'wizard'
            source = 'interactive'
        else:
            source = self.args.source

        # Create config
        config_dict = {
            'input_type': input_type,
            'source': source,
            'accent_color': self.args.color,
            'voice': self.args.voice,
            'languages': self.args.languages if hasattr(self.args, 'languages') else ['en'],
        }

        # Add optional parameters
        if self.args.output_dir:
            config_dict['output_dir'] = Path(self.args.output_dir)

        if hasattr(self.args, 'duration'):
            config_dict['video_count'] = 1  # Single video

        return InputConfig(**config_dict)

    def setup_event_listeners(self):
        """Setup event listeners for progress tracking"""

        def print_event(event):
            """Print pipeline events"""
            if event.type == EventType.PIPELINE_STARTED:
                self.logger.info(f"\n{Colors.BOLD}{Colors.BLUE}>>> Pipeline Started{Colors.END}")
                self.logger.info(f"  Task ID: {event.task_id}")

            elif event.type == EventType.PIPELINE_COMPLETED:
                self.logger.info(f"\n{Colors.BOLD}{Colors.GREEN}>>> Pipeline Completed Successfully ✓{Colors.END}")

            elif event.type == EventType.PIPELINE_FAILED:
                self.logger.error(f"\n{Colors.BOLD}{Colors.RED}>>> Pipeline Failed ✗{Colors.END}")
                self.logger.error(f"  {event.message}")

            elif event.type == EventType.STAGE_STARTED:
                stage_name = event.data.get('stage', event.stage) if event.data else event.stage
                self.logger.info(f"\n{Colors.BLUE}[{stage_name}]{Colors.END} Starting...")

            elif event.type == EventType.STAGE_PROGRESS:
                stage_name = event.data.get('stage', event.stage) if event.data else event.stage
                progress = event.data.get('progress', 0) if event.data else 0
                if progress > 0:
                    self.logger.info(f"{Colors.BLUE}[{stage_name}]{Colors.END} Progress: {progress:.0%} - {event.message}")

            elif event.type == EventType.STAGE_COMPLETED:
                stage_name = event.data.get('stage', event.stage) if event.data else event.stage
                self.logger.info(f"{Colors.GREEN}[{stage_name}]{Colors.END} Completed ✓")

            elif event.type == EventType.STAGE_FAILED:
                stage_name = event.data.get('stage', event.stage) if event.data else event.stage
                self.logger.error(f"{Colors.RED}[{stage_name}]{Colors.END} Failed ✗")
                self.logger.error(f"  Error: {event.message}")

        self.pipeline.event_emitter.on_all(print_event)

    async def run(self):
        """Run the complete pipeline"""
        self.print_banner()

        # Create input configuration
        try:
            input_config = self.create_input_config()
            self.print_success("Configuration created")
            self.print_info(f"Input type: {input_config.input_type}")
            self.print_info(f"Source: {input_config.source}")
            self.print_info(f"Voice: {input_config.voice}")
            self.print_info(f"Color: {input_config.accent_color}")

        except Exception as e:
            self.print_error(f"Failed to create configuration: {e}")
            return False

        # Setup event tracking
        self.setup_event_listeners()

        # Execute pipeline
        try:
            self.logger.info(f"\n{Colors.BOLD}Starting pipeline execution...{Colors.END}")
            self.logger.info(f"{Colors.BOLD}{'─'*80}{Colors.END}\n")

            result = await self.pipeline.execute(
                input_config=input_config,
                task_id=f"auto_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                resume=False
            )

            # Print summary
            self.print_summary(result)

            return result.success

        except Exception as e:
            self.print_error(f"Pipeline execution failed: {e}")
            self.logger.exception("Pipeline error")
            return False

    def print_summary(self, result):
        """Print final summary"""
        self.logger.info(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}")

        if result.success:
            self.logger.info(f"{Colors.BOLD}{Colors.GREEN}✓ PIPELINE COMPLETE{Colors.END}")
        else:
            self.logger.error(f"{Colors.BOLD}{Colors.RED}✗ PIPELINE FAILED{Colors.END}")

        self.logger.info(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}\n")

        # Output details
        self.logger.info(f"{Colors.BOLD}Results:{Colors.END}")
        self.logger.info(f"  Task ID: {result.task_id}")
        self.logger.info(f"  Generation Time: {result.generation_time:.2f}s")

        if result.video_config:
            self.logger.info(f"  Title: {result.video_config.title}")
            self.logger.info(f"  Total Duration: {result.total_duration:.1f}s")
            self.logger.info(f"  Scene Count: {result.scene_count}")

        if result.video_path:
            self.logger.info(f"\n{Colors.BOLD}Output Files:{Colors.END}")
            self.logger.info(f"  Video: {result.video_path}")

        if result.audio_dir:
            self.logger.info(f"  Audio: {result.audio_dir}")

        if result.timing_report:
            self.logger.info(f"  Timing Report: {result.timing_report}")

        # Warnings
        if result.warnings:
            self.logger.warning(f"\n{Colors.YELLOW}Warnings ({len(result.warnings)}):{Colors.END}")
            for warning in result.warnings[:5]:  # Limit to first 5
                self.logger.warning(f"  ⚠ {warning}")
            if len(result.warnings) > 5:
                self.logger.warning(f"  ... and {len(result.warnings) - 5} more")

        # Errors
        if result.errors:
            self.logger.error(f"\n{Colors.RED}Errors ({len(result.errors)}):{Colors.END}")
            for error in result.errors[:5]:  # Limit to first 5
                self.logger.error(f"  ✗ {error}")
            if len(result.errors) > 5:
                self.logger.error(f"  ... and {len(result.errors) - 5} more")

        # Success message
        if result.success and result.video_path:
            self.logger.info(f"\n{Colors.GREEN}{Colors.BOLD}Your video is ready!{Colors.END}")
            self.logger.info(f"  {Colors.CYAN}Open: {result.video_path}{Colors.END}")
        elif not result.success:
            self.logger.error(f"\n{Colors.RED}Pipeline failed. Check errors above.{Colors.END}")

            # Show task state for debugging
            task_state = self.pipeline.get_status(result.task_id)
            if task_state:
                self.logger.info(f"\n{Colors.YELLOW}Debug Info:{Colors.END}")
                self.logger.info(f"  Current Stage: {task_state.current_stage}")
                self.logger.info(f"  Completed: {', '.join(task_state.get_completed_stages())}")
                failed = task_state.get_failed_stages()
                if failed:
                    self.logger.info(f"  Failed: {', '.join(failed)}")
                self.logger.info(f"\n{Colors.YELLOW}Tip: You can resume from the last successful stage{Colors.END}")

        self.logger.info("")


def main():
    parser = argparse.ArgumentParser(
        description='Auto-orchestrator for complete video generation pipeline (v2.0)',
        epilog='''
Examples:
  # From document
  python create_video_auto.py --from README.md --type document

  # From YouTube
  python create_video_auto.py --from "python tutorial" --type youtube

  # From YAML
  python create_video_auto.py --from inputs/my_video.yaml --type yaml

  # Interactive wizard
  python create_video_auto.py --type wizard

  # With custom options
  python create_video_auto.py --from README.md --type document \\
      --voice male --color blue --duration 120 --use-ai --verbose
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Input specification
    parser.add_argument('--from', dest='source',
                       help='Input source (file path, URL, or search query)')
    parser.add_argument('--type', required=True,
                       choices=['document', 'youtube', 'yaml', 'wizard', 'programmatic'],
                       help='Input type')

    # Video options
    parser.add_argument('--voice', default='male',
                       choices=['male', 'male_warm', 'female', 'female_friendly'],
                       help='Narration voice (default: male)')
    parser.add_argument('--color', default='blue',
                       choices=['orange', 'blue', 'purple', 'green', 'pink', 'cyan'],
                       help='Accent color (default: blue)')
    parser.add_argument('--duration', type=int, default=60,
                       help='Target duration in seconds (default: 60)')
    parser.add_argument('--languages', nargs='+', default=['en'],
                       help='Target languages (default: en)')

    # AI options
    parser.add_argument('--use-ai', action='store_true',
                       help='Use Claude AI for enhanced narration (requires ANTHROPIC_API_KEY)')

    # Output options
    parser.add_argument('--output-dir',
                       help='Custom output directory (default: auto-generated)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')

    args = parser.parse_args()

    # Validation
    if args.type != 'wizard' and not args.source:
        parser.error("--from is required for document, youtube, yaml, and programmatic types")

    # Create orchestrator and run
    orchestrator = ModernPipelineOrchestrator(args)

    # Run async pipeline
    success = asyncio.run(orchestrator.run())

    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
