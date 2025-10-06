"""
YAML File Input Adapter
=======================
Parse YAML files into video sets.

Supports:
- Single video YAML files
- Video set configuration files
- Scene validation
- Automatic narration generation
"""

import yaml
from pathlib import Path
from typing import Dict, Optional

from .base import BaseInputAdapter, VideoSet, VideoConfig


class YAMLAdapter(BaseInputAdapter):
    """Adapter for parsing YAML files"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.generate_narration = kwargs.get('generate_narration', False)
        self.use_ai = kwargs.get('use_ai', False)

    def parse(self, source: str, **options) -> VideoSet:
        """
        Parse YAML file into VideoSet.

        Args:
            source: Path to YAML file
            **options: Parsing options

        Returns:
            VideoSet with parsed content
        """
        # Load YAML
        with open(source, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        # Determine if it's a set config or single video
        if 'set' in data:
            return self._parse_set_config(data, source, options)
        elif 'video' in data:
            return self._parse_single_video(data, source, options)
        else:
            raise ValueError(f"Invalid YAML structure in {source}")

    def _parse_set_config(
        self,
        data: Dict,
        source: str,
        options: Dict
    ) -> VideoSet:
        """Parse set configuration YAML"""
        set_config = data['set']

        # Load video files
        videos = []
        source_path = Path(source).parent

        for video_entry in set_config.get('videos', []):
            video_file = source_path / video_entry['file']

            with open(video_file, 'r') as f:
                video_data = yaml.safe_load(f)

            video = self._create_video_config(video_data, video_entry.get('overrides', {}))
            videos.append(video)

        # Create VideoSet
        from .base import VideoSetConfig

        config = VideoSetConfig(
            set_id=set_config['id'],
            set_name=set_config.get('name', set_config['id']),
            description=set_config.get('description', ''),
            defaults=set_config.get('defaults', {}),
            naming=set_config.get('naming', {}),
            output=set_config.get('output', {}),
            processing=set_config.get('processing', {}),
            metadata=set_config.get('metadata', {})
        )

        return VideoSet(config=config, videos=videos)

    def _parse_single_video(
        self,
        data: Dict,
        source: str,
        options: Dict
    ) -> VideoSet:
        """Parse single video YAML into VideoSet"""
        video = self._create_video_config(data)

        # Generate set ID from filename
        set_id = options.get('set_id') or Path(source).stem
        set_name = options.get('set_name') or data['video'].get('title', 'Video Set')

        return self.create_video_set(
            set_id=set_id,
            set_name=set_name,
            videos=[video],
            description=data['video'].get('description', ''),
            defaults={
                'accent_color': data['video'].get('accent_color', 'blue'),
                'voice': data['video'].get('voice', 'male'),
                'target_duration': data['video'].get('target_duration', 60)
            }
        )

    def _create_video_config(
        self,
        data: Dict,
        overrides: Optional[Dict] = None
    ) -> VideoConfig:
        """Create VideoConfig from YAML data"""
        video_data = data['video']
        scenes = data.get('scenes', [])

        # Process scenes (optionally generate narration)
        processed_scenes = []
        for scene in scenes:
            processed_scene = dict(scene)

            # Generate narration if needed and not present
            if self.generate_narration and not processed_scene.get('narration'):
                processed_scene['narration'] = self._generate_scene_narration(processed_scene)

            processed_scenes.append(processed_scene)

        # Apply overrides
        config_data = {
            'video_id': video_data['id'],
            'title': video_data['title'],
            'description': video_data.get('description', ''),
            'scenes': processed_scenes,
            'accent_color': video_data.get('accent_color'),
            'voice': video_data.get('voice'),
            'target_duration': video_data.get('target_duration')
        }

        if overrides:
            config_data.update(overrides)

        return VideoConfig(**config_data)

    def _generate_scene_narration(self, scene: Dict) -> str:
        """Generate narration for a scene (if needed)"""
        scene_type = scene.get('type', 'title')

        if scene_type == 'title':
            title = scene.get('title', '')
            subtitle = scene.get('subtitle', '')
            return f"{title}. {subtitle}."

        elif scene_type == 'command':
            header = scene.get('header', '')
            description = scene.get('description', '')
            commands = scene.get('commands', [])
            cmd_count = len([c for c in commands if c.strip()])

            if cmd_count > 0:
                return f"{header}. {description}. Run these commands to get started."
            return f"{header}. {description}."

        elif scene_type == 'list':
            header = scene.get('header', '')
            items = scene.get('items', [])

            if items:
                item_count = len(items)
                if item_count == 1:
                    return f"{header}. Key feature: {items[0]}."
                else:
                    return f"{header}. Includes {item_count} key features."

            return f"{header}."

        elif scene_type == 'outro':
            main_text = scene.get('main_text', '')
            sub_text = scene.get('sub_text', '')
            return f"{main_text}. {sub_text}."

        return ""
