"""
Base Input Adapter
==================
Abstract base class for all input adapters providing unified interface.

All adapters must:
1. Inherit from BaseInputAdapter
2. Implement parse() method
3. Return VideoSet or compatible structure
4. Handle errors gracefully
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import dataclass, field
import yaml


@dataclass
class VideoSetConfig:
    """Configuration for a video set"""
    set_id: str
    set_name: str
    description: str = ""
    defaults: Dict[str, Any] = field(default_factory=lambda: {
        'accent_color': 'blue',
        'voice': 'male',
        'target_duration': 60,
        'min_scene_duration': 3.0,
        'max_scene_duration': 15.0
    })
    naming: Dict[str, Any] = field(default_factory=lambda: {
        'prefix': '',
        'use_numbers': False,
        'separator': '_'
    })
    output: Dict[str, str] = field(default_factory=dict)
    processing: Dict[str, Any] = field(default_factory=lambda: {
        'parallel_audio': True,
        'auto_cleanup': False,
        'gpu_encoding': True
    })
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VideoConfig:
    """Configuration for a single video"""
    video_id: str
    title: str
    description: str = ""
    scenes: List[Dict[str, Any]] = field(default_factory=list)
    accent_color: Optional[str] = None
    voice: Optional[str] = None
    target_duration: Optional[int] = None


@dataclass
class VideoSet:
    """Unified video set structure returned by all adapters"""
    config: VideoSetConfig
    videos: List[VideoConfig]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for YAML export"""
        return {
            'set': {
                'id': self.config.set_id,
                'name': self.config.set_name,
                'description': self.config.description,
                'version': 'v2.0',
                'defaults': self.config.defaults,
                'output': self.config.output or {
                    'base_dir': f'output/{self.config.set_id}',
                    'audio_dir': 'audio',
                    'video_dir': 'videos',
                    'script_dir': 'scripts',
                    'report_dir': 'reports'
                },
                'naming': self.config.naming,
                'processing': self.config.processing,
                'videos': [
                    {
                        'file': f"{video.video_id}.yaml",
                        'priority': i,
                        **(
                            {'overrides': {
                                k: v for k, v in {
                                    'accent_color': video.accent_color,
                                    'voice': video.voice,
                                    'target_duration': video.target_duration
                                }.items() if v is not None
                            }} if any([video.accent_color, video.voice, video.target_duration]) else {}
                        )
                    }
                    for i, video in enumerate(self.videos, 1)
                ],
                'metadata': self.config.metadata
            }
        }

    def export_to_yaml(self, output_dir: str) -> Path:
        """Export video set to YAML files"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Save set_config.yaml
        config_file = output_path / 'set_config.yaml'
        with open(config_file, 'w') as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, sort_keys=False)

        print(f"✓ Created: {config_file}")

        # Save individual video YAML files
        for video in self.videos:
            video_file = output_path / f"{video.video_id}.yaml"
            video_data = {
                'video': {
                    'id': video.video_id,
                    'title': video.title,
                    'description': video.description
                },
                'scenes': video.scenes
            }

            # Add video-level overrides
            if video.accent_color:
                video_data['video']['accent_color'] = video.accent_color
            if video.voice:
                video_data['video']['voice'] = video.voice
            if video.target_duration:
                video_data['video']['target_duration'] = video.target_duration

            with open(video_file, 'w') as f:
                yaml.dump(video_data, f, default_flow_style=False, sort_keys=False)

            print(f"✓ Created: {video_file}")

        print(f"\n✓ Set exported to: {output_path}")
        print(f"  Videos: {len(self.videos)}")

        return output_path


class BaseInputAdapter(ABC):
    """Abstract base class for all input adapters"""

    def __init__(self, **kwargs):
        """
        Initialize adapter with common options.

        Args:
            **kwargs: Adapter-specific configuration
        """
        self.config = kwargs

    @abstractmethod
    def parse(self, source: str, **options) -> VideoSet:
        """
        Parse input source into VideoSet.

        Args:
            source: Input source (file path, URL, etc.)
            **options: Adapter-specific parsing options

        Returns:
            VideoSet object

        Raises:
            ValueError: If source is invalid
            FileNotFoundError: If source file not found
            Exception: For other parsing errors
        """

    def validate_source(self, source: str) -> bool:
        """
        Validate input source before parsing.

        Args:
            source: Input source to validate

        Returns:
            True if valid, False otherwise
        """
        return bool(source)

    def create_video_set(
        self,
        set_id: str,
        set_name: str,
        videos: List[VideoConfig],
        **config_overrides
    ) -> VideoSet:
        """
        Helper to create VideoSet with defaults.

        Args:
            set_id: Set identifier
            set_name: Human-readable set name
            videos: List of VideoConfig objects
            **config_overrides: Override default config

        Returns:
            VideoSet object
        """
        set_config = VideoSetConfig(
            set_id=set_id,
            set_name=set_name,
            **config_overrides
        )

        return VideoSet(
            config=set_config,
            videos=videos
        )

    def create_scene(
        self,
        scene_type: str,
        visual_content: Dict[str, Any],
        narration: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Helper to create scene dictionary.

        Args:
            scene_type: Type of scene (title, command, list, etc.)
            visual_content: Visual content for the scene
            narration: Optional narration text
            **kwargs: Additional scene properties

        Returns:
            Scene dictionary
        """
        scene = {
            'type': scene_type,
            **visual_content
        }

        if narration:
            scene['narration'] = narration

        # Add any additional properties
        scene.update(kwargs)

        return scene

    def get_default_config(self) -> Dict[str, Any]:
        """Get default adapter configuration"""
        return {
            'accent_color': 'blue',
            'voice': 'male',
            'target_duration': 60,
            'min_scene_duration': 3.0,
            'max_scene_duration': 15.0
        }
