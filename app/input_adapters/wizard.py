"""
Wizard Input Adapter
====================
Interactive wizard for creating videos.

This adapter wraps the wizard functionality to provide
a unified interface for video creation.
"""

from typing import Dict, Any
from .base import BaseInputAdapter, VideoSet, VideoConfig


class WizardAdapter(BaseInputAdapter):
    """Adapter for interactive wizard input"""

    def parse(self, source: str = None, **options) -> VideoSet:
        """
        Run interactive wizard and return VideoSet.

        Args:
            source: Not used (wizard is interactive)
            **options: Wizard configuration options

        Returns:
            VideoSet from wizard input
        """
        # Import wizard functionality
        try:
            import sys
            sys.path.append('scripts')
            from generate_script_wizard_set_aware import SetAwareWizard
        except ImportError:
            raise ImportError(
                "Wizard functionality not available. "
                "Ensure generate_script_wizard_set_aware.py is in scripts/"
            )

        # Create wizard
        wizard = SetAwareWizard()

        # Pre-configure if options provided
        if options.get('standalone'):
            wizard.set_mode = 'standalone'
        elif options.get('set_id'):
            wizard.set_mode = 'existing_set'
            # Load existing set
            # (Implementation would go here)

        # Run wizard (this is interactive)
        # Note: This adapter is primarily for API integration
        # The actual wizard should be run directly from CLI

        raise NotImplementedError(
            "Wizard adapter is for API integration. "
            "Run wizard directly: python scripts/generate_script_wizard_set_aware.py"
        )

    def parse_wizard_data(self, wizard_data: Dict[str, Any]) -> VideoSet:
        """
        Parse wizard output data into VideoSet.

        Args:
            wizard_data: Data from wizard (video + scenes)

        Returns:
            VideoSet from wizard data
        """
        video_data = wizard_data.get('video', {})
        scenes = wizard_data.get('scenes', [])

        # Create video config
        video = VideoConfig(
            video_id=video_data.get('id', 'wizard_video'),
            title=video_data.get('title', 'Wizard Created Video'),
            description=video_data.get('description', ''),
            scenes=scenes,
            accent_color=video_data.get('accent_color'),
            voice=video_data.get('voice'),
            target_duration=video_data.get('target_duration')
        )

        # Create set
        set_id = video_data.get('id', 'wizard_video')
        set_name = video_data.get('title', 'Wizard Video')

        return self.create_video_set(
            set_id=set_id,
            set_name=set_name,
            videos=[video],
            description='Video created with interactive wizard',
            defaults={
                'accent_color': video_data.get('accent_color', 'blue'),
                'voice': video_data.get('voice', 'male'),
                'target_duration': video_data.get('target_duration', 60)
            }
        )
