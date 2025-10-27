"""Narration script generator.

This module generates narration scripts for video scenes, converting
structured content into engaging spoken narratives.
"""

from typing import List, Dict, Any, Optional

from ..shared.models import SceneConfig as Scene


class NarrationGenerator:
    """Generator for video narration scripts.

    This class converts structured scene content into narration scripts
    suitable for text-to-speech generation.
    """

    def __init__(self, language: str = "en", style: str = "professional"):
        """Initialize the narration generator.

        Args:
            language: Target language code
            style: Narration style (professional, casual, educational, etc.)
        """
        self.language = language
        self.style = style

    async def generate_script(
        self,
        scenes: List[Scene],
        **kwargs
    ) -> Dict[str, Any]:
        """Generate narration script for scenes.

        This method generates complete narration scripts for a list of scenes,
        analyzing visual content and creating appropriate voice-over text.

        Args:
            scenes: List of scenes to generate narration for
            **kwargs: Additional generation parameters
                - enhance_with_ai: Use AI enhancement (default: False)
                - enhancer: AIScriptEnhancer instance (if enhance_with_ai=True)
                - video_title: Video title for context
                - video_description: Video description for context

        Returns:
            Complete narration script dictionary with:
                - scenes: List of scene narrations
                - metadata: Script metadata (word count, duration estimates, etc.)
                - language: Target language
                - style: Applied style
        """
        # Extract options
        enhance_with_ai = kwargs.get('enhance_with_ai', False)
        enhancer = kwargs.get('enhancer')
        video_title = kwargs.get('video_title', '')
        video_description = kwargs.get('video_description', '')

        # Generate narration for each scene
        scene_narrations = []
        total_words = 0

        for i, scene in enumerate(scenes):
            # Generate or use existing narration
            if scene.narration:
                narration = scene.narration
            else:
                narration = await self.generate_scene_narration(
                    scene,
                    scene_position=i,
                    total_scenes=len(scenes),
                    video_title=video_title
                )

            # Apply style if specified
            if self.style != "professional":  # Don't transform default style
                narration = await self.apply_style(narration, self.style)

            # Enhance with AI if requested
            if enhance_with_ai and enhancer:
                try:
                    narration = await enhancer.enhance_script(
                        narration,
                        scene_type=scene.scene_type,
                        context={
                            'scene_position': i,
                            'total_scenes': len(scenes),
                            'video_title': video_title,
                            'video_description': video_description
                        }
                    )
                except Exception as e:
                    # If enhancement fails, use original
                    pass

            # Count words
            word_count = len(narration.split())
            total_words += word_count

            scene_narrations.append({
                'scene_id': scene.scene_id,
                'scene_type': scene.scene_type,
                'narration': narration,
                'word_count': word_count,
                'estimated_duration': word_count / 2.5  # Rough estimate: 150 words/min = 2.5 words/sec
            })

        # Calculate metadata
        estimated_duration = total_words / 2.5  # seconds
        estimated_duration_formatted = f"{int(estimated_duration // 60)}:{int(estimated_duration % 60):02d}"

        return {
            'scenes': scene_narrations,
            'metadata': {
                'total_scenes': len(scenes),
                'total_words': total_words,
                'estimated_duration_seconds': estimated_duration,
                'estimated_duration_formatted': estimated_duration_formatted,
                'language': self.language,
                'style': self.style,
                'enhanced_with_ai': enhance_with_ai
            },
            'language': self.language,
            'style': self.style
        }

    async def generate(
        self,
        scene: Scene,
        **kwargs
    ) -> str:
        """Generate narration for a scene (alias for generate_scene_narration).

        Args:
            scene: Scene to generate narration for
            **kwargs: Additional parameters

        Returns:
            Narration text
        """
        # Use existing narration from scene if available
        if scene.narration:
            return scene.narration

        # Otherwise generate basic narration from visual content
        if scene.scene_type == "title":
            title = scene.visual_content.get('title', 'Video Title')
            return f"Welcome to {title}"
        elif scene.scene_type == "outro":
            return scene.visual_content.get('main_text', 'Thank you for watching!')
        elif scene.scene_type == "list":
            header = scene.visual_content.get('header', 'Key Points')
            return f"Here are the key points about {header}"
        elif scene.scene_type == "command":
            header = scene.visual_content.get('header', 'Commands')
            return f"Let's look at {header}"
        else:
            return f"This is the {scene.scene_type} scene"

    async def generate_scene_narration(
        self,
        scene: Scene,
        **kwargs
    ) -> str:
        """Generate narration for a single scene.

        Args:
            scene: Scene to generate narration for
            **kwargs: Additional parameters
                - scene_position: Position in video (0-indexed)
                - total_scenes: Total number of scenes
                - video_title: Video title for context

        Returns:
            Narration text
        """
        # Use existing narration if available
        if scene.narration:
            return scene.narration

        # Otherwise generate based on scene type and visual content
        scene_position = kwargs.get('scene_position', 0)
        total_scenes = kwargs.get('total_scenes', 1)
        video_title = kwargs.get('video_title', 'this video')

        # Generate scene-specific narration
        if scene.scene_type == "title":
            title = scene.visual_content.get('title', video_title)
            subtitle = scene.visual_content.get('subtitle', '')

            if scene_position == 0:
                # Opening scene
                if subtitle:
                    return f"Welcome to {title}: {subtitle}. Let's get started."
                else:
                    return f"Welcome to {title}. In this video, we'll explore key concepts."
            else:
                return f"{title}. {subtitle if subtitle else ''}"

        elif scene.scene_type == "outro":
            main_text = scene.visual_content.get('main_text', 'Thank you for watching')
            sub_text = scene.visual_content.get('sub_text', '')

            if scene_position == total_scenes - 1:
                # Final scene
                if sub_text:
                    return f"{main_text}. {sub_text}. Thanks for watching!"
                else:
                    return f"{main_text}. If you found this helpful, check out our other resources. Thanks for watching!"
            else:
                return f"{main_text}. {sub_text if sub_text else ''}"

        elif scene.scene_type == "list":
            header = scene.visual_content.get('header', 'Key Points')
            items = scene.visual_content.get('items', [])

            if items:
                items_preview = f"We have {len(items)} key points to cover"
            else:
                items_preview = "We have several important points"

            return f"Let's look at {header}. {items_preview}."

        elif scene.scene_type == "command":
            header = scene.visual_content.get('header', 'Commands')
            commands = scene.visual_content.get('commands', [])

            if commands:
                return f"Here's how to {header.lower()}. We'll run {len(commands)} commands to get set up."
            else:
                return f"Now let's look at {header}. Follow along with these steps."

        elif scene.scene_type == "code_comparison":
            return "Let's compare the before and after. Notice the key differences in the implementation."

        elif scene.scene_type == "quiz":
            return "Time for a quick knowledge check. Think about what we've covered so far."

        elif scene.scene_type == "problem":
            return "Here's the problem we need to solve. Let's break it down step by step."

        elif scene.scene_type == "solution":
            return "And here's the solution. Notice how we apply the concepts we discussed earlier."

        elif scene.scene_type == "checkpoint":
            progress = int((scene_position / total_scenes) * 100)
            return f"Great progress! We're about {progress}% through. Let's review what we've learned."

        elif scene.scene_type == "exercise":
            return "Now it's your turn to practice. Try this exercise to reinforce what you've learned."

        elif scene.scene_type == "learning_objectives":
            return "By the end of this video, you'll understand these key concepts. Let's dive in."

        elif scene.scene_type == "quote":
            return "Here's an important insight to remember. Keep this in mind as we continue."

        else:
            # Generic fallback
            return f"In this section, we'll cover {scene.scene_type.replace('_', ' ')}."

    async def apply_style(
        self,
        text: str,
        style: Optional[str] = None
    ) -> str:
        """Apply narration style to text.

        Available styles:
        - professional: Formal, authoritative tone
        - casual: Friendly, conversational tone
        - educational: Clear, pedagogical approach
        - enthusiastic: Energetic, engaging tone
        - technical: Precise, detailed technical language
        - storytelling: Narrative, engaging style

        Args:
            text: Original narration text
            style: Style to apply (uses self.style if not specified)
                Options: "professional", "casual", "educational", "enthusiastic",
                         "technical", "storytelling"

        Returns:
            Styled narration text
        """
        target_style = style or self.style

        # Style mappings with characteristics
        style_characteristics = {
            'professional': {
                'tone': 'Formal and authoritative',
                'vocabulary': 'Precise technical terms',
                'sentence_structure': 'Well-structured, complete sentences',
                'example': 'clear, authoritative explanations'
            },
            'casual': {
                'tone': 'Friendly and conversational',
                'vocabulary': 'Everyday language, minimal jargon',
                'sentence_structure': 'Shorter, more natural sentences',
                'example': 'talking to a friend over coffee'
            },
            'educational': {
                'tone': 'Clear and pedagogical',
                'vocabulary': 'Accessible with definitions',
                'sentence_structure': 'Logical progression with explanations',
                'example': 'a patient teacher explaining concepts'
            },
            'enthusiastic': {
                'tone': 'Energetic and engaging',
                'vocabulary': 'Dynamic action words',
                'sentence_structure': 'Varied pacing, exclamatory phrases',
                'example': 'an excited expert sharing discoveries'
            },
            'technical': {
                'tone': 'Precise and detailed',
                'vocabulary': 'Specific technical terminology',
                'sentence_structure': 'Detailed, information-dense',
                'example': 'a technical specification document'
            },
            'storytelling': {
                'tone': 'Narrative and engaging',
                'vocabulary': 'Vivid, descriptive language',
                'sentence_structure': 'Story arc with tension and resolution',
                'example': 'telling an engaging story'
            }
        }

        # If style not in map, return original
        if target_style not in style_characteristics:
            return text

        # Get style characteristics
        characteristics = style_characteristics[target_style]

        # Apply style transformation (simple rule-based approach)
        styled_text = text

        # Apply basic style transformations based on characteristics
        if target_style == 'casual':
            # Make more conversational
            styled_text = styled_text.replace('utilize', 'use')
            styled_text = styled_text.replace('implement', 'set up')
            styled_text = styled_text.replace('demonstrate', 'show')

        elif target_style == 'enthusiastic':
            # Add more dynamic language
            if not styled_text.endswith('!') and len(styled_text) < 100:
                styled_text = styled_text.rstrip('.') + '!'

        elif target_style == 'technical':
            # Keep as-is (already technical)
            pass

        # For more sophisticated styling, could use AI enhancement
        # For now, return the styled text
        return styled_text
