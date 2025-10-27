"""
Template-Based Video Generation
================================
Create videos using templates and the programmatic builder system.

This script integrates:
- Template builders (python_set_builder, multilingual_builder)
- Modern pipeline architecture
- Scene type templates
- Programmatic video generation

Usage:
    # Use built-in template
    python create_from_template.py --template tutorial

    # Create from custom Python script
    python create_from_template.py --script my_template.py

    # Interactive template builder
    python create_from_template.py --interactive
"""

import sys
import argparse
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any
import logging

# Setup logging
logger = logging.getLogger(__name__)


# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from scripts.python_set_builder import VideoSetBuilder, SceneConfig, VideoConfig
from scripts.multilingual_builder import MultilingualVideoBuilder
from video_gen.pipeline.complete_pipeline import create_complete_pipeline
from video_gen.shared.models import InputConfig


class TemplateVideoGenerator:
    """Generate videos using templates and builders"""

    def __init__(self):
        self.pipeline = create_complete_pipeline()
        self.builders = {
            'tutorial': self.build_tutorial_template,
            'course': self.build_course_template,
            'demo': self.build_demo_template,
            'multilingual': self.build_multilingual_template,
        }

    def build_tutorial_template(self) -> VideoSetBuilder:
        """Build a tutorial series template"""
        builder = VideoSetBuilder(
            set_id="tutorial_series",
            set_name="Tutorial Series",
            description="Educational tutorial series",
            defaults={
                'accent_color': 'blue',
                'voice': 'male',
                'target_duration': 120
            }
        )

        # Create helper for common scene types
        def create_title_scene(title: str, subtitle: str = "") -> SceneConfig:
            return SceneConfig(
                scene_type='title',
                visual_content={'title': title, 'subtitle': subtitle},
                narration=f"{title}. {subtitle}" if subtitle else title,
                min_duration=3.0,
                max_duration=6.0
            )

        def create_list_scene(header: str, items: list, narration: str) -> SceneConfig:
            return SceneConfig(
                scene_type='list',
                visual_content={'header': header, 'items': items},
                narration=narration,
                min_duration=8.0,
                max_duration=15.0
            )

        def create_outro_scene(main_text: str, sub_text: str = "") -> SceneConfig:
            return SceneConfig(
                scene_type='outro',
                visual_content={'main_text': main_text, 'sub_text': sub_text},
                narration=f"{main_text}. {sub_text}" if sub_text else main_text,
                min_duration=3.0,
                max_duration=6.0
            )

        # Video 1: Introduction
        builder.add_video(
            video_id="intro",
            title="Tutorial Introduction",
            description="Introduction to the tutorial series",
            scenes=[
                create_title_scene("Welcome", "Tutorial Series"),
                create_list_scene(
                    "What You'll Learn",
                    [
                        ("Core Concepts", "Foundation knowledge"),
                        ("Practical Examples", "Real-world applications"),
                        ("Best Practices", "Industry standards")
                    ],
                    "In this tutorial series, you will learn core concepts, see practical examples, and discover best practices."
                ),
                create_outro_scene("Let's Begin", "Start with Lesson 1")
            ]
        )

        # Video 2: Core Concepts
        builder.add_video(
            video_id="concepts",
            title="Core Concepts",
            description="Understanding the fundamentals",
            scenes=[
                create_title_scene("Core Concepts", "The Fundamentals"),
                create_list_scene(
                    "Key Topics",
                    [
                        ("Architecture", "System design"),
                        ("Components", "Building blocks"),
                        ("Workflows", "Process flows")
                    ],
                    "We'll cover architecture, components, and workflows that form the foundation of the system."
                ),
                create_outro_scene("Next Up", "Practical Examples")
            ]
        )

        # Video 3: Practical Examples
        builder.add_video(
            video_id="examples",
            title="Practical Examples",
            description="Real-world implementations",
            scenes=[
                create_title_scene("Practical Examples", "Real-World Use Cases"),
                create_list_scene(
                    "Examples",
                    [
                        ("Example 1", "Basic implementation"),
                        ("Example 2", "Advanced usage"),
                        ("Example 3", "Complex scenario")
                    ],
                    "Let's look at three practical examples, from basic to complex implementations."
                ),
                create_outro_scene("Tutorial Complete", "Happy learning!")
            ]
        )

        return builder

    def build_course_template(self) -> VideoSetBuilder:
        """Build a course template with multiple lessons"""
        builder = VideoSetBuilder(
            set_id="course",
            set_name="Complete Course",
            description="10-lesson educational course",
            defaults={
                'accent_color': 'purple',
                'voice': 'female',
                'target_duration': 180
            }
        )

        lessons = [
            ("Introduction", "Course overview and objectives"),
            ("Lesson 1", "Getting started with the basics"),
            ("Lesson 2", "Understanding core principles"),
            ("Lesson 3", "Practical application"),
            ("Lesson 4", "Advanced techniques"),
            ("Lesson 5", "Problem solving"),
            ("Lesson 6", "Best practices"),
            ("Lesson 7", "Common pitfalls"),
            ("Lesson 8", "Real-world projects"),
            ("Conclusion", "Summary and next steps")
        ]

        for i, (title, description) in enumerate(lessons):
            builder.add_video(
                video_id=f"lesson_{i:02d}",
                title=title,
                description=description,
                scenes=[
                    SceneConfig(
                        scene_type='learning_objectives',
                        visual_content={
                            'header': 'Learning Objectives',
                            'objectives': [
                                f"Understand {title.lower()}",
                                "Apply concepts practically",
                                "Master the fundamentals"
                            ]
                        },
                        narration=f"In this lesson on {title.lower()}, we'll {description.lower()}.",
                        min_duration=5.0,
                        max_duration=10.0
                    )
                ]
            )

        return builder

    def build_demo_template(self) -> VideoSetBuilder:
        """Build a quick demo template"""
        builder = VideoSetBuilder(
            set_id="demo",
            set_name="Quick Demo",
            description="30-second product demo",
            defaults={
                'accent_color': 'cyan',
                'voice': 'male_warm',
                'target_duration': 30
            }
        )

        builder.add_video(
            video_id="demo",
            title="Product Demo",
            description="Quick product demonstration",
            scenes=[
                SceneConfig(
                    scene_type='title',
                    visual_content={'title': 'Product Demo', 'subtitle': 'See it in action'},
                    narration="Welcome to our product demo. See how it works in action.",
                    min_duration=3.0,
                    max_duration=5.0
                ),
                SceneConfig(
                    scene_type='command',
                    visual_content={
                        'header': 'Quick Setup',
                        'subheader': 'Get started in seconds',
                        'commands': ['$ install product', '$ run demo', '$ view results']
                    },
                    narration="Install, run, and view results. It's that simple.",
                    min_duration=8.0,
                    max_duration=12.0
                ),
                SceneConfig(
                    scene_type='outro',
                    visual_content={'main_text': 'Try it today', 'sub_text': 'Free trial available'},
                    narration="Try it today with our free trial.",
                    min_duration=3.0,
                    max_duration=5.0
                )
            ]
        )

        return builder

    def build_multilingual_template(self) -> MultilingualVideoBuilder:
        """Build a multilingual template"""
        builder = MultilingualVideoBuilder(
            set_id="global_campaign",
            set_name="Global Marketing Campaign",
            source_language="en",
            target_languages=["en", "es", "fr", "de", "ja"]
        )

        # Create base video structure
        base_scenes = [
            {
                'type': 'title',
                'title': 'Global Product Launch',
                'subtitle': 'Now Available Worldwide',
                'narration': 'Introducing our new product, now available worldwide.',
                'min_duration': 3.0,
                'max_duration': 6.0
            },
            {
                'type': 'list',
                'header': 'Key Features',
                'items': [
                    ('Fast', 'Lightning speed performance'),
                    ('Secure', 'Enterprise-grade security'),
                    ('Global', 'Available in 50+ countries')
                ],
                'narration': 'Fast, secure, and available globally. Our product delivers on all fronts.',
                'min_duration': 8.0,
                'max_duration': 12.0
            }
        ]

        for i, lang in enumerate(builder.target_languages):
            builder.add_video(
                video_id=f"campaign_{lang}",
                title=f"Global Launch - {lang.upper()}",
                language=lang,
                scenes=base_scenes,
                voice=builder.get_voice_for_language(lang)
            )

        return builder

    async def generate_from_template(self, template_name: str, output_dir: Optional[Path] = None):
        """Generate video from template"""

        if template_name not in self.builders:
            logger.error(f"❌ Unknown template: {template_name}")
            logger.info(f"Available templates: {', '.join(self.builders.keys())}")
            return False

        logger.info(f"🔨 Building template: {template_name}")
        builder = self.builders[template_name]()

        # Export to YAML first
        yaml_dir = project_root / "sets" / builder.set_id
        yaml_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"📝 Exporting to YAML: {yaml_dir}")
        builder.export_to_yaml(str(yaml_dir))

        # Create input config for pipeline
        input_config = InputConfig(
            input_type='programmatic',
            source=str(yaml_dir),
            output_dir=output_dir
        )

        # Execute pipeline
        logger.info(f"\n🚀 Starting video generation pipeline...")
        result = await self.pipeline.execute(input_config)

        if result.success:
            logger.info(f"\n✅ Success! Video generated:")
            logger.info(f"   📹 {result.video_path}")
            return True
        else:
            logger.error(f"\n❌ Pipeline failed:")
            for error in result.errors:
                logger.error(f"   - {error}")
            return False

    async def generate_from_script(self, script_path: Path):
        """Generate video from custom Python script"""
        logger.info(f"📜 Loading custom template: {script_path}")

        # Import the script module
        import importlib.util
        spec = importlib.util.spec_from_file_location("custom_template", script_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Look for builder instance
        if hasattr(module, 'builder'):
            builder = module.builder

            # Export and generate
            yaml_dir = project_root / "sets" / builder.set_id
            yaml_dir.mkdir(parents=True, exist_ok=True)
            builder.export_to_yaml(str(yaml_dir))

            input_config = InputConfig(
                input_type='programmatic',
                source=str(yaml_dir)
            )

            result = await self.pipeline.execute(input_config)
            return result.success
        else:
            logger.error("❌ Script must define a 'builder' variable")
            return False


def main():
    parser = argparse.ArgumentParser(
        description='Generate videos using templates and programmatic builders',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--template',
                       choices=['tutorial', 'course', 'demo', 'multilingual'],
                       help='Use built-in template')
    parser.add_argument('--script',
                       type=Path,
                       help='Path to custom Python template script')
    parser.add_argument('--output-dir',
                       type=Path,
                       help='Custom output directory')
    parser.add_argument('--list', action='store_true',
                       help='List available templates')

    args = parser.parse_args()

    generator = TemplateVideoGenerator()

    if args.list:
        logger.info("\nAvailable Templates:")
        logger.info("=" * 50)
        for name in generator.builders.keys():
            logger.info(f"  • {name}")
        logger.info()
        return

    if not args.template and not args.script:
        parser.error("Either --template or --script is required")

    # Run generation
    if args.template:
        success = asyncio.run(
            generator.generate_from_template(args.template, args.output_dir)
        )
    else:
        success = asyncio.run(
            generator.generate_from_script(args.script)
        )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
