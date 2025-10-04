"""
Python Set Builder - Define Video Sets Programmatically
========================================================
Create video sets using pure Python (no YAML needed).

This allows you to:
- Define sets programmatically in Python
- Use variables, loops, functions for generation
- Integrate with existing Python workflows
- Export to YAML for the standard pipeline

Usage:
    from python_set_builder import VideoSetBuilder, VideoConfig

    # Create set
    builder = VideoSetBuilder(
        set_id="my_tutorial_series",
        set_name="My Tutorial Series",
        defaults={'accent_color': 'blue', 'voice': 'male'}
    )

    # Add videos
    builder.add_video(
        video_id="intro",
        title="Introduction",
        scenes=[...]
    )

    # Export to YAML (for standard pipeline)
    builder.export_to_yaml("../sets/my_tutorial_series")

    # Or generate directly
    await builder.generate_set()
"""

import os
import yaml
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict

import sys
sys.path.append('.')

from unified_video_system import (
    UnifiedVideo, UnifiedScene,
    ACCENT_ORANGE, ACCENT_BLUE, ACCENT_PURPLE,
    ACCENT_GREEN, ACCENT_PINK
)


@dataclass
class SceneConfig:
    """Scene configuration"""
    scene_type: str
    visual_content: Dict[str, Any]
    narration: Optional[str] = None
    voice: Optional[str] = None
    min_duration: float = 3.0
    max_duration: float = 15.0
    scene_id: Optional[str] = None

    def to_dict(self):
        """Convert to dictionary for YAML export"""
        data = {
            'type': self.scene_type
        }

        # Add visual content fields at top level
        data.update(self.visual_content)

        # Add optional fields
        if self.narration:
            data['narration'] = self.narration
        if self.voice:
            data['voice'] = self.voice
        if self.scene_id:
            data['id'] = self.scene_id

        data['min_duration'] = self.min_duration
        data['max_duration'] = self.max_duration

        return data


@dataclass
class VideoConfig:
    """Video configuration"""
    video_id: str
    title: str
    description: str = ""
    scenes: List[SceneConfig] = field(default_factory=list)
    accent_color: Optional[str] = None
    voice: Optional[str] = None
    target_duration: Optional[int] = None

    def add_scene(self, scene: SceneConfig):
        """Add a scene to this video"""
        self.scenes.append(scene)
        return self

    def to_dict(self):
        """Convert to dictionary for YAML export"""
        data = {
            'video': {
                'id': self.video_id,
                'title': self.title,
                'description': self.description
            },
            'scenes': [scene.to_dict() for scene in self.scenes]
        }

        # Add optional video-level overrides
        if self.accent_color:
            data['video']['accent_color'] = self.accent_color
        if self.voice:
            data['video']['voice'] = self.voice
        if self.target_duration:
            data['video']['target_duration'] = self.target_duration

        return data


class VideoSetBuilder:
    """Build video sets programmatically in Python"""

    def __init__(
        self,
        set_id: str,
        set_name: str,
        description: str = "",
        defaults: Optional[Dict[str, Any]] = None,
        naming: Optional[Dict[str, Any]] = None,
        output_config: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.set_id = set_id
        self.set_name = set_name
        self.description = description

        # Set defaults
        self.defaults = defaults or {
            'accent_color': 'blue',
            'voice': 'male',
            'target_duration': 60,
            'min_scene_duration': 3.0,
            'max_scene_duration': 15.0
        }

        # Naming configuration
        self.naming = naming or {
            'prefix': '',
            'use_numbers': False,
            'separator': '_'
        }

        # Output configuration
        self.output_config = output_config or {
            'base_dir': f'../output/{set_id}',
            'audio_dir': 'audio',
            'video_dir': 'videos',
            'script_dir': 'scripts',
            'report_dir': 'reports'
        }

        # Metadata
        self.metadata = metadata or {}

        # Videos
        self.videos: List[VideoConfig] = []

    def add_video(
        self,
        video_id: str,
        title: str,
        description: str = "",
        scenes: Optional[List[SceneConfig]] = None,
        **overrides
    ) -> 'VideoSetBuilder':
        """
        Add a video to the set.

        Args:
            video_id: Video identifier
            title: Video title
            description: Video description
            scenes: List of SceneConfig objects
            **overrides: Video-specific overrides (accent_color, voice, etc.)

        Returns:
            Self for chaining
        """
        video = VideoConfig(
            video_id=video_id,
            title=title,
            description=description,
            scenes=scenes or [],
            **overrides
        )

        self.videos.append(video)
        return self

    def create_title_scene(
        self,
        title: str,
        subtitle: str,
        narration: Optional[str] = None,
        **kwargs
    ) -> SceneConfig:
        """Helper: Create a title scene"""
        return SceneConfig(
            scene_type='title',
            visual_content={
                'title': title,
                'subtitle': subtitle
            },
            narration=narration,
            **kwargs
        )

    def create_command_scene(
        self,
        header: str,
        description: str,
        commands: List[str],
        narration: Optional[str] = None,
        **kwargs
    ) -> SceneConfig:
        """Helper: Create a command scene"""
        return SceneConfig(
            scene_type='command',
            visual_content={
                'header': header,
                'description': description,
                'commands': commands
            },
            narration=narration,
            **kwargs
        )

    def create_list_scene(
        self,
        header: str,
        description: str,
        items: List[Any],
        narration: Optional[str] = None,
        **kwargs
    ) -> SceneConfig:
        """Helper: Create a list scene"""
        # Convert items to proper format
        formatted_items = []
        for item in items:
            if isinstance(item, dict):
                formatted_items.append(item)
            elif isinstance(item, tuple):
                formatted_items.append({
                    'title': item[0],
                    'description': item[1] if len(item) > 1 else ''
                })
            else:
                formatted_items.append(str(item))

        return SceneConfig(
            scene_type='list',
            visual_content={
                'header': header,
                'description': description,
                'items': formatted_items
            },
            narration=narration,
            **kwargs
        )

    def create_outro_scene(
        self,
        main_text: str,
        sub_text: str,
        narration: Optional[str] = None,
        **kwargs
    ) -> SceneConfig:
        """Helper: Create an outro scene"""
        return SceneConfig(
            scene_type='outro',
            visual_content={
                'main_text': main_text,
                'sub_text': sub_text
            },
            narration=narration,
            **kwargs
        )

    def create_problem_scene(
        self,
        problem_number: int,
        title: str,
        problem_text: str,
        difficulty: str = 'medium',
        narration: Optional[str] = None,
        **kwargs
    ) -> SceneConfig:
        """Helper: Create a coding problem scene"""
        return SceneConfig(
            scene_type='problem',
            visual_content={
                'problem_number': problem_number,
                'title': title,
                'problem_text': problem_text,
                'difficulty': difficulty
            },
            narration=narration,
            **kwargs
        )

    def create_solution_scene(
        self,
        title: str,
        solution_code: List[str],
        explanation: str = "",
        narration: Optional[str] = None,
        **kwargs
    ) -> SceneConfig:
        """Helper: Create a solution scene"""
        return SceneConfig(
            scene_type='solution',
            visual_content={
                'title': title,
                'solution_code': solution_code,
                'explanation': explanation
            },
            narration=narration,
            **kwargs
        )

    def create_checkpoint_scene(
        self,
        checkpoint_number: int,
        completed_topics: List[str],
        review_questions: List[str],
        next_topics: List[str],
        narration: Optional[str] = None,
        **kwargs
    ) -> SceneConfig:
        """Helper: Create a learning checkpoint scene"""
        return SceneConfig(
            scene_type='checkpoint',
            visual_content={
                'checkpoint_number': checkpoint_number,
                'completed_topics': completed_topics,
                'review_questions': review_questions,
                'next_topics': next_topics
            },
            narration=narration,
            **kwargs
        )

    def create_quiz_scene(
        self,
        question: str,
        options: List[str],
        correct_answer: str,
        show_answer: bool = True,
        narration: Optional[str] = None,
        **kwargs
    ) -> SceneConfig:
        """Helper: Create a quiz question scene"""
        return SceneConfig(
            scene_type='quiz',
            visual_content={
                'question': question,
                'options': options,
                'correct_answer': correct_answer,
                'show_answer': show_answer
            },
            narration=narration,
            **kwargs
        )

    def create_learning_objectives_scene(
        self,
        lesson_title: str,
        objectives: List[Any],
        lesson_info: Optional[Dict[str, Any]] = None,
        narration: Optional[str] = None,
        **kwargs
    ) -> SceneConfig:
        """Helper: Create a learning objectives scene"""
        return SceneConfig(
            scene_type='learning_objectives',
            visual_content={
                'lesson_title': lesson_title,
                'objectives': objectives,
                'lesson_info': lesson_info or {}
            },
            narration=narration,
            **kwargs
        )

    def create_exercise_scene(
        self,
        title: str,
        instructions: List[str],
        difficulty: str = 'medium',
        estimated_time: str = None,
        narration: Optional[str] = None,
        **kwargs
    ) -> SceneConfig:
        """Helper: Create an exercise instructions scene"""
        return SceneConfig(
            scene_type='exercise',
            visual_content={
                'title': title,
                'instructions': instructions,
                'difficulty': difficulty,
                'estimated_time': estimated_time
            },
            narration=narration,
            **kwargs
        )

    def export_to_yaml(self, output_dir: str):
        """
        Export set to YAML files for standard pipeline.

        Creates:
        - {output_dir}/set_config.yaml
        - {output_dir}/{video_id}.yaml for each video
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Create set_config.yaml
        set_config = {
            'set': {
                'id': self.set_id,
                'name': self.set_name,
                'description': self.description,
                'version': 'v2.0',
                'defaults': self.defaults,
                'output': self.output_config,
                'naming': self.naming,
                'processing': {
                    'parallel_audio': True,
                    'auto_cleanup': False,
                    'gpu_encoding': True
                },
                'videos': [],
                'metadata': self.metadata
            }
        }

        # Add video file references
        for i, video in enumerate(self.videos, 1):
            video_filename = f"{video.video_id}.yaml"

            video_entry = {
                'file': video_filename,
                'priority': i
            }

            # Add overrides if video has custom settings
            overrides = {}
            if video.accent_color:
                overrides['accent_color'] = video.accent_color
            if video.voice:
                overrides['voice'] = video.voice
            if video.target_duration:
                overrides['target_duration'] = video.target_duration

            if overrides:
                video_entry['overrides'] = overrides

            set_config['set']['videos'].append(video_entry)

        # Save set_config.yaml
        config_file = output_path / 'set_config.yaml'
        with open(config_file, 'w') as f:
            yaml.dump(set_config, f, default_flow_style=False, sort_keys=False)

        print(f"✓ Created: {config_file}")

        # Save individual video YAML files
        for video in self.videos:
            video_file = output_path / f"{video.video_id}.yaml"

            with open(video_file, 'w') as f:
                yaml.dump(video.to_dict(), f, default_flow_style=False, sort_keys=False)

            print(f"✓ Created: {video_file}")

        print(f"\n✓ Set exported to: {output_path}")
        print(f"  Videos: {len(self.videos)}")
        print(f"\nNext steps:")
        print(f"  python generate_video_set.py {output_path}")

        return output_path

    async def generate_set(self, skip_export: bool = False):
        """
        Generate set directly without YAML export.

        This converts to UnifiedVideo objects and generates directly.
        """
        from generate_video_set import VideoSet

        # Export to temp location
        if not skip_export:
            temp_dir = f"../sets/.temp_{self.set_id}"
            self.export_to_yaml(temp_dir)
        else:
            temp_dir = f"../sets/{self.set_id}"

        # Use standard VideoSet generator
        video_set = VideoSet(temp_dir)
        videos, output_dirs = await video_set.generate_set()

        print(f"\n✓ Set generation complete: {self.set_name}")

        return videos, output_dirs


# Convenience builders for common patterns
class TutorialSeriesBuilder(VideoSetBuilder):
    """Pre-configured builder for tutorial series"""

    def __init__(self, set_id: str, set_name: str, **kwargs):
        super().__init__(
            set_id=set_id,
            set_name=set_name,
            defaults={
                'accent_color': 'blue',
                'voice': 'male',
                'target_duration': 60,
                'min_scene_duration': 3.0,
                'max_scene_duration': 15.0
            },
            naming={
                'prefix': 'tutorial',
                'use_numbers': True,
                'separator': '-'
            },
            **kwargs
        )


class MarketingSeriesBuilder(VideoSetBuilder):
    """Pre-configured builder for marketing videos"""

    def __init__(self, set_id: str, set_name: str, **kwargs):
        super().__init__(
            set_id=set_id,
            set_name=set_name,
            defaults={
                'accent_color': 'purple',
                'voice': 'female_friendly',
                'target_duration': 30,
                'min_scene_duration': 2.5,
                'max_scene_duration': 10.0
            },
            naming={
                'prefix': 'demo',
                'use_numbers': False,
                'separator': '_'
            },
            **kwargs
        )


# Example usage
async def example_tutorial_series():
    """Example: Create tutorial series programmatically"""

    # Create builder
    builder = TutorialSeriesBuilder(
        set_id="python_basics_programmatic",
        set_name="Python Basics (Programmatic)",
        description="Tutorial series created with Python code"
    )

    # Add video 1
    builder.add_video(
        video_id="introduction",
        title="Introduction",
        description="Series overview",
        scenes=[
            builder.create_title_scene(
                title="Python Basics",
                subtitle="Introduction",
                narration="Python basics. Your complete introduction to programming."
            ),
            builder.create_list_scene(
                header="What You'll Learn",
                description="Course Overview",
                items=[
                    ("Variables", "Store data"),
                    ("Functions", "Reusable code"),
                    ("Classes", "Object-oriented programming")
                ]
            ),
            builder.create_outro_scene(
                main_text="Let's Begin",
                sub_text="Next: Variables"
            )
        ]
    )

    # Add video 2
    builder.add_video(
        video_id="variables",
        title="Variables",
        description="Learn about variables",
        scenes=[
            builder.create_title_scene(
                title="Variables",
                subtitle="Storing Data"
            ),
            builder.create_command_scene(
                header="Creating Variables",
                description="Basic Syntax",
                commands=[
                    "# Create variables",
                    "name = 'Alice'",
                    "age = 30",
                    "print(f'{name} is {age}')"
                ],
                narration="Create variables with simple assignment. Use print to display values."
            ),
            builder.create_outro_scene(
                main_text="Great Job!",
                sub_text="Next: Functions"
            )
        ]
    )

    # Export to YAML (for standard pipeline)
    builder.export_to_yaml("../sets/python_basics_programmatic")

    # Or generate directly
    # await builder.generate_set()


async def example_marketing_campaign():
    """Example: Create marketing videos programmatically"""

    builder = MarketingSeriesBuilder(
        set_id="product_launch_q1",
        set_name="Product Launch Q1",
        metadata={
            'campaign': 'Q1 2024',
            'author': 'Marketing Team'
        }
    )

    # Generate videos in a loop
    features = [
        ("Fast Performance", "10x faster than competitors"),
        ("Easy Setup", "Ready in 60 seconds"),
        ("Great Support", "24/7 availability")
    ]

    for i, (feature, description) in enumerate(features):
        feature_id = feature.lower().replace(' ', '_')

        builder.add_video(
            video_id=feature_id,
            title=feature,
            description=f"Highlight: {description}",
            scenes=[
                builder.create_title_scene(
                    title=feature,
                    subtitle=description
                ),
                builder.create_outro_scene(
                    main_text="Try It Free",
                    sub_text="No credit card needed"
                )
            ]
        )

    builder.export_to_yaml("../sets/product_launch_q1")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Python set builder examples')
    parser.add_argument('--example', choices=['tutorial', 'marketing', 'both'], default='both')

    args = parser.parse_args()

    if args.example in ['tutorial', 'both']:
        print("Creating tutorial series example...")
        asyncio.run(example_tutorial_series())

    if args.example in ['marketing', 'both']:
        print("\nCreating marketing campaign example...")
        asyncio.run(example_marketing_campaign())

    print("\n✓ Examples created!")
    print("\nGenerate them with:")
    print("  python generate_all_sets.py")
