"""
Programmatic Input Adapter
===========================
Use Python code to programmatically create video sets.

This adapter integrates with the VideoSetBuilder to allow
pure Python video creation without YAML.
"""

from typing import Dict, Any, List

from .base import BaseInputAdapter, VideoSet, VideoConfig, VideoSetConfig


class ProgrammaticAdapter(BaseInputAdapter):
    """Adapter for programmatic Python video creation"""

    def parse(self, source: str, **options) -> VideoSet:
        """
        Execute Python file to generate VideoSet.

        Args:
            source: Path to Python file with VideoSetBuilder code
            **options: Execution options

        Returns:
            VideoSet from Python code

        Note:
            The Python file should define a 'builder' variable
            that is a VideoSetBuilder instance.
        """
        # Import and execute Python file
        import importlib.util

        spec = importlib.util.spec_from_file_location("video_module", source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Get builder
        if not hasattr(module, 'builder'):
            raise ValueError(f"Python file {source} must define a 'builder' variable")

        builder = module.builder

        # Convert VideoSetBuilder to VideoSet
        return self._convert_builder_to_videoset(builder)

    def parse_builder(self, builder) -> VideoSet:
        """
        Convert VideoSetBuilder directly to VideoSet.

        Args:
            builder: VideoSetBuilder instance

        Returns:
            VideoSet
        """
        return self._convert_builder_to_videoset(builder)

    def _convert_builder_to_videoset(self, builder) -> VideoSet:
        """Convert VideoSetBuilder to VideoSet format"""
        # Create VideoSetConfig
        config = VideoSetConfig(
            set_id=builder.set_id,
            set_name=builder.set_name,
            description=builder.description,
            defaults=builder.defaults,
            naming=builder.naming,
            output=builder.output_config,
            processing={
                'parallel_audio': True,
                'auto_cleanup': False,
                'gpu_encoding': True
            },
            metadata=builder.metadata
        )

        # Convert videos
        videos = []
        for video in builder.videos:
            # Convert scenes
            scenes = []
            for scene in video.scenes:
                scene_dict = scene.to_dict() if hasattr(scene, 'to_dict') else dict(scene)
                scenes.append(scene_dict)

            video_config = VideoConfig(
                video_id=video.video_id,
                title=video.title,
                description=video.description,
                scenes=scenes,
                accent_color=video.accent_color,
                voice=video.voice,
                target_duration=video.target_duration
            )
            videos.append(video_config)

        return VideoSet(config=config, videos=videos)

    def create_from_dict(self, data: Dict[str, Any]) -> VideoSet:
        """
        Create VideoSet from dictionary.

        Args:
            data: Dictionary with set configuration and videos

        Returns:
            VideoSet
        """
        # Extract set config
        set_data = data.get('set', {})

        config = VideoSetConfig(
            set_id=set_data.get('id', 'programmatic_set'),
            set_name=set_data.get('name', 'Programmatic Set'),
            description=set_data.get('description', ''),
            defaults=set_data.get('defaults', {}),
            naming=set_data.get('naming', {}),
            output=set_data.get('output', {}),
            processing=set_data.get('processing', {}),
            metadata=set_data.get('metadata', {})
        )

        # Extract videos
        videos = []
        for video_data in data.get('videos', []):
            video_config = VideoConfig(
                video_id=video_data.get('video_id', 'video'),
                title=video_data.get('title', 'Video'),
                description=video_data.get('description', ''),
                scenes=video_data.get('scenes', []),
                accent_color=video_data.get('accent_color'),
                voice=video_data.get('voice'),
                target_duration=video_data.get('target_duration')
            )
            videos.append(video_config)

        return VideoSet(config=config, videos=videos)


# Helper functions for creating scenes programmatically

def create_title_scene(
    title: str,
    subtitle: str,
    narration: str = None,
    **kwargs
) -> Dict[str, Any]:
    """Create a title scene"""
    scene = {
        'type': 'title',
        'title': title,
        'subtitle': subtitle
    }
    if narration:
        scene['narration'] = narration
    scene.update(kwargs)
    return scene


def create_command_scene(
    header: str,
    description: str,
    commands: List[str],
    narration: str = None,
    **kwargs
) -> Dict[str, Any]:
    """Create a command scene"""
    scene = {
        'type': 'command',
        'header': header,
        'description': description,
        'commands': commands
    }
    if narration:
        scene['narration'] = narration
    scene.update(kwargs)
    return scene


def create_list_scene(
    header: str,
    description: str,
    items: List[Any],
    narration: str = None,
    **kwargs
) -> Dict[str, Any]:
    """Create a list scene"""
    scene = {
        'type': 'list',
        'header': header,
        'description': description,
        'items': items
    }
    if narration:
        scene['narration'] = narration
    scene.update(kwargs)
    return scene


def create_outro_scene(
    main_text: str,
    sub_text: str,
    narration: str = None,
    **kwargs
) -> Dict[str, Any]:
    """Create an outro scene"""
    scene = {
        'type': 'outro',
        'main_text': main_text,
        'sub_text': sub_text
    }
    if narration:
        scene['narration'] = narration
    scene.update(kwargs)
    return scene
