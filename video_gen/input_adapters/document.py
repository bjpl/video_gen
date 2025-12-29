"""Document input adapter for PDF, DOCX, and text files.

This adapter processes document files and extracts structured content for
video generation with AI-enhanced slide content.
"""

from pathlib import Path
from typing import Any, List, Optional, Dict
import re
import logging

from .base import InputAdapter, InputAdapterResult
from .content_splitter import ContentSection
from ..shared.models import VideoSet, SceneConfig
from ..script_generator.ai_enhancer import AIScriptEnhancer

# Import refactored modules
from .document_parsers import (
    parse_markdown_structure,
    clean_markdown_formatting,
    is_metadata_line
)
from .document_ai import DocumentAIEnhancer
from .document_utils import read_document_content, validate_file_path


# Export refactored functions for backward compatibility
__all__ = [
    'DocumentAdapter',
    'parse_markdown_structure',
    'clean_markdown_formatting',
    'is_metadata_line',
    'read_document_content',
    'validate_file_path',
    'DocumentAIEnhancer'
]


class DocumentAdapter(InputAdapter):
    """Adapter for document files (PDF, DOCX, TXT, Markdown).

    This adapter reads document files, extracts text and structure, and
    converts them into VideoSet objects for video generation with AI-enhanced
    slide content and narration.

    Features:
    - Intelligent content splitting for multi-video generation (works with ANY file type)
    - AI-powered narration generation
    - Multiple splitting strategies (auto, AI, headers, paragraphs, etc.)
    """

    def __init__(self, test_mode: bool = False, use_ai: bool = True, ai_api_key: Optional[str] = None):
        """Initialize the document adapter.

        Args:
            test_mode: If True, bypass security checks for testing purposes.
                      This allows reading files outside the project directory.
            use_ai: If True, use AI enhancement for slide content and narration.
            ai_api_key: Optional Anthropic API key for AI enhancement.
        """
        super().__init__(
            name="document",
            description="Processes PDF, DOCX, TXT, and Markdown files with AI enhancement"
        )

        # Set up logger
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        self.supported_formats = {".pdf", ".docx", ".txt", ".md"}
        self.test_mode = test_mode
        self.use_ai = use_ai

        # Initialize AI enhancer if requested
        self.ai_enhancer: Optional[AIScriptEnhancer] = None
        if use_ai:
            try:
                self.ai_enhancer = AIScriptEnhancer(api_key=ai_api_key)
                self.logger.info("AI enhancement enabled for slide content")
            except Exception as e:
                self.logger.warning(f"AI enhancement initialization failed: {e}")
                self.use_ai = False

        # Always initialize AI helper (it handles disabled state internally)
        self.ai_helper = DocumentAIEnhancer(ai_enhancer=self.ai_enhancer, use_ai=self.use_ai)

        # Initialize intelligent content splitter
        try:
            from .content_splitter import ContentSplitter
            self.content_splitter = ContentSplitter(
                ai_api_key=ai_api_key,
                use_ai=use_ai
            )
            self.logger.info("Intelligent content splitter initialized")
        except Exception as e:
            self.logger.warning(f"Content splitter initialization failed: {e}")
            self.content_splitter = None

    # ======================================================================
    # BACKWARD COMPATIBILITY: Delegation methods for refactored functions
    # These methods delegate to the standalone functions in document_parsers.py
    # to maintain API compatibility with existing tests and code.
    # ======================================================================

    def _parse_markdown_structure(self, content: str) -> Dict[str, Any]:
        """Parse markdown content into structured sections.

        BACKWARD COMPATIBILITY: Delegates to parse_markdown_structure().

        Args:
            content: Raw markdown content

        Returns:
            Dictionary with 'sections' key containing parsed structure
        """
        return parse_markdown_structure(content)

    def _clean_markdown_formatting(self, text: str) -> str:
        """Remove markdown formatting from text.

        BACKWARD COMPATIBILITY: Delegates to clean_markdown_formatting().

        Args:
            text: Text with markdown formatting

        Returns:
            Clean text without markdown formatting
        """
        return clean_markdown_formatting(text)

    def _is_metadata_line(self, line: str) -> bool:
        """Check if a line contains metadata.

        BACKWARD COMPATIBILITY: Delegates to is_metadata_line().

        Args:
            line: Line to check

        Returns:
            True if line is metadata, False otherwise
        """
        return is_metadata_line(line)

    async def adapt(self, source: Any, **kwargs) -> InputAdapterResult:
        """Adapt a document file to VideoSet structure.

        Args:
            source: Path to document file or URL
            **kwargs: Additional parameters including:
                - video_count: Number of videos to create (default 1)
                - split_strategy: Strategy to use (auto, ai, headers, etc.)
                - accent_color, voice: Visual/audio settings

        Returns:
            InputAdapterResult with VideoSet
        """
        try:
            # Read document content (file or URL) - using refactored utility
            project_root = Path(__file__).parent.parent.parent.resolve()
            content = await read_document_content(
                source=source,
                test_mode=self.test_mode,
                project_root=project_root
            )

            if not content:
                return InputAdapterResult(
                    success=False,
                    error=f"Failed to read document: {source}"
                )

            # Get splitting parameters
            video_count = kwargs.get('video_count', 1)
            split_strategy = kwargs.get('split_strategy', 'auto')
            enable_ai_splitting = kwargs.get('enable_ai_splitting', True)

            # 🚀 NEW PATH: Use intelligent content splitter for multi-video
            if video_count > 1 and self.content_splitter:
                self.logger.info(f"Using intelligent splitter: {video_count} videos, strategy={split_strategy}")

                from .content_splitter import SplitStrategy

                # Split content intelligently
                split_result = await self.content_splitter.split(
                    content=content,
                    num_sections=video_count,
                    strategy=SplitStrategy(split_strategy) if split_strategy != 'auto' else SplitStrategy.AUTO,
                    **kwargs
                )

                # Create video set from intelligently split sections
                video_set = await self._create_video_set_from_sections(
                    sections=split_result.sections,
                    source=source,
                    split_metadata=split_result.metadata,
                    **kwargs
                )

                return InputAdapterResult(
                    success=True,
                    video_set=video_set,
                    metadata={
                        "source": str(source),
                        "split_strategy": split_result.strategy_used.value,
                        "split_confidence": split_result.confidence,
                        "videos_generated": len(video_set.videos),
                        **split_result.metadata
                    }
                )

            # 📊 OLD PATH: Use traditional markdown structure parsing (single video or fallback)
            else:
                self.logger.info("Using traditional markdown structure parsing")

                # Parse markdown structure - using refactored parser
                structure = parse_markdown_structure(content)

                # Generate video set from structure (with AI enhancement)
                video_set = await self._create_video_set_from_structure(
                    structure,
                    source,
                    **kwargs
                )

                return InputAdapterResult(
                    success=True,
                    video_set=video_set,
                    metadata={
                        "source": str(source),
                        "sections_found": len(structure.get('sections', [])),
                        "videos_generated": len(video_set.videos)
                    }
                )

        except Exception as e:
            return InputAdapterResult(
                success=False,
                error=f"Document adaptation failed: {str(e)}"
            )

    async def _create_video_set_from_structure(self, structure: dict, source: Any, **kwargs) -> VideoSet:
        """Create VideoSet from parsed structure with AI enhancement.

        Enhanced to support:
        - Multiple videos split by ## headings (level 2)
        - Tables rendered as comparison scenes
        - Better scene distribution
        - Max scenes per video configuration
        - AI-enhanced slide content and narration
        """
        import re
        from ..shared.models import VideoSet, VideoConfig

        # Generate set ID
        if isinstance(source, str) and source.startswith('http'):
            set_id = re.sub(r'[^a-z0-9_-]', '_', Path(source).stem.lower())
        else:
            set_id = re.sub(r'[^a-z0-9_-]', '_', Path(source).stem.lower())

        set_name = structure.get('title', 'Document Video')
        accent_color = kwargs.get('accent_color', 'blue')
        voice = kwargs.get('voice', 'male')
        max_scenes_per_video = kwargs.get('max_scenes_per_video', 50)  # Increased to 50 for comprehensive single videos
        split_by_h2 = kwargs.get('split_by_h2', False)  # Default: create ONE comprehensive video with all sections
        video_count = kwargs.get('video_count', None)  # User-specified number of videos (optional)

        # Group sections by level 2 headings if split_by_h2 is enabled OR if video_count > 1
        video_groups = []
        should_split = (split_by_h2 or (video_count and video_count > 1)) and any(s.get('level') == 2 for s in structure['sections'])

        if should_split:
            current_group = []
            current_h2 = None

            for section in structure['sections']:
                if section.get('level') == 2:
                    if current_group:
                        video_groups.append({
                            'title': current_h2,
                            'sections': current_group
                        })
                    current_h2 = section['heading']
                    current_group = [section]
                else:
                    if current_group or current_h2:
                        current_group.append(section)

            if current_group:
                video_groups.append({
                    'title': current_h2,
                    'sections': current_group
                })

            # If user specified exact video count AND split_by_h2 is False, merge groups to match
            # When split_by_h2=True, always create one video per H2 section (ignore video_count)
            if not split_by_h2 and video_count and len(video_groups) > video_count:
                # Merge excess groups into video_count groups
                groups_per_video = len(video_groups) // video_count
                merged_groups = []
                for i in range(0, len(video_groups), groups_per_video):
                    chunk = video_groups[i:i + groups_per_video]
                    merged_sections = []
                    titles = []
                    for grp in chunk:
                        merged_sections.extend(grp['sections'])
                        titles.append(grp['title'])
                    merged_groups.append({
                        'title': ' + '.join(titles[:2]) if len(titles) > 1 else titles[0],
                        'sections': merged_sections
                    })
                video_groups = merged_groups[:video_count]
        else:
            # Single video with all sections
            video_groups = [{
                'title': set_name,
                'sections': structure['sections']
            }]

        # Create videos from groups
        videos = []
        for group_idx, group in enumerate(video_groups):
            video_id = f"{set_id}_video_{group_idx}" if len(video_groups) > 1 else f"{set_id}_main"
            video_title = group['title'] if len(video_groups) > 1 else set_name

            scenes = await self._create_scenes_from_sections(
                sections=group['sections'],
                video_id=video_id,
                title=structure['title'],
                subtitle=group['title'],
                voice=voice,
                max_scenes=max_scenes_per_video
            )

            if scenes:  # Only add video if it has scenes
                video = VideoConfig(
                    video_id=video_id,
                    title=video_title,
                    description=f"Generated from {source}",
                    scenes=scenes,
                    accent_color=accent_color
                )
                videos.append(video)

        # Return video set
        # Store custom options in metadata for backward compatibility with config.defaults
        return VideoSet(
            set_id=set_id,
            name=set_name,
            description=f"Videos generated from document: {source}",
            videos=videos,
            metadata={
                "source": str(source),
                "video_count": len(videos),
                "total_sections": len(structure['sections']),
                # Store custom options for config.defaults backward compat
                "accent_color": accent_color,
                "voice": voice
            }
        )

    async def _create_video_set_from_sections(
        self,
        sections: List[ContentSection],
        source: Any,
        split_metadata: Dict[str, Any],
        **kwargs
    ) -> VideoSet:
        """Create VideoSet from ContentSection objects (intelligent splitter output).

        This is the NEW path for AI-powered multi-video generation.
        Sections already have AI-generated narration from the ContentSplitter.

        Args:
            sections: List of ContentSection objects from ContentSplitter
            source: Original document source
            split_metadata: Metadata from splitting process
            **kwargs: accent_color, voice, etc.

        Returns:
            VideoSet with one video per section
        """
        from ..shared.models import VideoSet, VideoConfig, SceneConfig
        import re

        # Generate set ID from source
        if isinstance(source, str) and source.startswith('http'):
            set_id = re.sub(r'[^a-z0-9_-]', '_', Path(source).stem.lower())
        else:
            set_id = re.sub(r'[^a-z0-9_-]', '_', Path(source).stem.lower())

        accent_color = kwargs.get('accent_color', 'blue')
        voice = kwargs.get('voice', 'male')

        # Create one video per section
        videos = []
        for idx, section in enumerate(sections):
            video_id = f"{set_id}_part_{idx + 1}"

            # Create scenes for this video
            scenes = []

            # 1. Title scene (using section title)
            title_narration = section.narration_hook or f"Welcome to {section.title}"

            scenes.append(SceneConfig(
                scene_id=f"{video_id}_title",
                scene_type="title",
                narration=title_narration,
                visual_content={
                    'title': section.title,
                    'subtitle': f"Part {idx + 1} of {len(sections)}"
                },
                voice=voice
            ))

            # 2. Main content scene (using AI-generated narration!)
            # The narration was already generated by ContentSplitter._generate_narration_for_sections
            main_narration = section.narration or section.content[:500]

            scenes.append(SceneConfig(
                scene_id=f"{video_id}_content",
                scene_type="info",  # Info card scene
                narration=main_narration,  # ✨ AI-generated narration!
                visual_content={
                    'header': section.title,
                    'description': section.key_takeaway or section.content[:200],
                    'content': section.content[:300]
                },
                voice=voice
            ))

            # 3. Outro scene (with takeaway if available)
            outro_text = section.key_takeaway or "Thanks for watching!"
            outro_narration = f"{outro_text} Continue to the next part to learn more."

            scenes.append(SceneConfig(
                scene_id=f"{video_id}_outro",
                scene_type="outro",
                narration=outro_narration,
                visual_content={
                    'main_text': 'Key Takeaway',
                    'sub_text': section.key_takeaway or 'Continue Learning'
                },
                voice=voice
            ))

            # Create video config
            video = VideoConfig(
                video_id=video_id,
                title=section.title,
                description=f"Part {idx + 1}: {section.title}",
                scenes=scenes,
                accent_color=accent_color
            )
            videos.append(video)

        # Return video set
        return VideoSet(
            set_id=set_id,
            name=f"{sections[0].title} (Video Series)" if sections else "Video Series",
            description=f"Videos generated from document: {source} using {split_metadata.get('ai_model', 'intelligent splitter')}",
            videos=videos,
            metadata={
                "source": str(source),
                "video_count": len(videos),
                "split_strategy": split_metadata.get('ai_model', 'unknown'),
                "ai_narration_generated": split_metadata.get('narration_generated', False),
                "accent_color": accent_color,
                "voice": voice
            }
        )

    async def _create_scenes_from_sections(
        self,
        sections: List[dict],
        video_id: str,
        title: str,
        subtitle: str,
        voice: str,
        max_scenes: int = 8
    ) -> List['SceneConfig']:
        """Create scenes from a list of sections with AI-enhanced content."""
        from ..shared.models import SceneConfig

        scenes = []
        total_scenes = min(len(sections) + 2, max_scenes)  # +2 for title and outro

        # Title scene with AI enhancement
        title_text = await self.ai_helper.enhance_slide_content(
            title,
            context_type="title",
            scene_position=0,
            total_scenes=total_scenes
        )
        subtitle_text = await self.ai_helper.enhance_slide_content(
            subtitle or 'Complete Guide',
            context_type="subtitle",
            scene_position=0,
            total_scenes=total_scenes
        )
        title_narration = await self.ai_helper.enhance_narration(
            f"Welcome to {subtitle or title}",
            scene_type="title",
            scene_data={'title': title_text, 'subtitle': subtitle_text},
            scene_position=0,
            total_scenes=total_scenes
        )

        scenes.append(SceneConfig(
            scene_id=f"{video_id}_title",
            scene_type="title",
            narration=title_narration,
            visual_content={
                'title': title_text,
                'subtitle': subtitle_text
            },
            voice=voice
        ))

        # Convert sections to scenes (limit by max_scenes - 2 for title and outro)
        content_scenes = max_scenes - 2
        for i, section in enumerate(sections[:content_scenes]):
            scene_position = i + 1  # +1 because title is scene 0
            heading = section['heading']
            has_code = len(section.get('code_blocks', [])) > 0
            has_lists = len(section.get('lists', [])) > 0
            has_tables = len(section.get('tables', [])) > 0

            if has_tables:
                # Convert table to list scene with AI enhancement
                table = section['tables'][0]  # Use first table
                if len(table) >= 2:  # Need at least header and one row
                    # Format table rows as "label: value" items
                    items = []
                    for row in table[1:5]:  # Skip header, take up to 4 rows
                        if row:
                            if len(row) > 1:
                                item = f"{row[0]}: {' | '.join(row[1:])}"
                            else:
                                item = row[0]
                            # Clean markdown formatting
                            # Use refactored clean_markdown_formatting
                            item = clean_markdown_formatting(item)
                            items.append(item)

                    # AI enhance visual content
                    enhanced_header = await self.ai_helper.enhance_slide_content(
                        heading, "header", scene_position, total_scenes
                    )
                    enhanced_desc = await self.ai_helper.enhance_slide_content(
                        section['text'][:100] if section['text'] else 'Key comparisons',
                        "description", scene_position, total_scenes
                    )
                    enhanced_narration = await self.ai_helper.enhance_narration(
                        f"Here's a comparison of {heading.lower()}",
                        "list",
                        {'header': enhanced_header, 'items': items},
                        scene_position,
                        total_scenes
                    )

                    scenes.append(SceneConfig(
                        scene_id=f"{video_id}_list_{i}",
                        scene_type="list",
                        narration=enhanced_narration,
                        visual_content={
                            'header': enhanced_header,
                            'description': enhanced_desc,
                            'items': items
                        },
                        voice=voice
                    ))

            elif has_code:
                # Command scene with AI enhancement
                commands = []
                for block in section['code_blocks']:
                    for line in block.split('\n')[:6]:
                        if line.strip() and not line.strip().startswith('#'):
                            commands.append(line.strip())

                # AI enhance visual content (clean metadata first)
                section_text = section['text'] if section['text'] else ''
                section_text = re.sub(r'\*?Generated:.*\*?', '', section_text, flags=re.IGNORECASE)
                section_text = re.sub(r'^[-*_]{3,}$', '', section_text, flags=re.MULTILINE)
                section_text = section_text.strip()

                enhanced_header = await self.ai_helper.enhance_slide_content(
                    heading, "header", scene_position, total_scenes
                )
                enhanced_desc = await self.ai_helper.enhance_slide_content(
                    section_text[:100],
                    "description", scene_position, total_scenes
                )
                enhanced_narration = await self.ai_helper.enhance_narration(
                    f"Here's how to {heading.lower()}",
                    "command",
                    {'header': enhanced_header, 'commands': commands},
                    scene_position,
                    total_scenes
                )

                scenes.append(SceneConfig(
                    scene_id=f"{video_id}_command_{i}",
                    scene_type="command",
                    narration=enhanced_narration,
                    visual_content={
                        'header': enhanced_header,
                        'description': enhanced_desc,
                        'commands': commands[:6]
                    },
                    voice=voice
                ))

            elif has_lists:
                # List scene with AI enhancement
                items = []
                for lst in section['lists']:
                    # Flatten nested lists
                    for item in lst:
                        if isinstance(item, dict) and 'text' in item:
                            clean_item = item['text']
                        else:
                            clean_item = str(item)

                        # Clean markdown formatting - use refactored function
                        clean_item = clean_markdown_formatting(clean_item)

                        # CRITICAL: Remove metadata patterns from items - use refactored function
                        # Skip items that are just metadata
                        if is_metadata_line(clean_item):
                            continue  # Skip this item entirely

                        # Only add non-empty, non-metadata items
                        if clean_item.strip():
                            items.append(clean_item)

                # Create narration that describes the list content
                items_preview = items[:3] if len(items) > 3 else items
                narration = f"This section covers {heading.lower()}: {', '.join(items_preview)}"
                if len(items) > 3:
                    narration += f", and {len(items) - 3} more topics"

                # AI enhance visual content (clean metadata first)
                section_text = section['text'] if section['text'] else ''
                section_text = re.sub(r'\*?Generated:.*\*?', '', section_text, flags=re.IGNORECASE)
                section_text = re.sub(r'^[-*_]{3,}$', '', section_text, flags=re.MULTILINE)
                section_text = section_text.strip()

                enhanced_header = await self.ai_helper.enhance_slide_content(
                    heading, "header", scene_position, total_scenes
                )
                enhanced_desc = await self.ai_helper.enhance_slide_content(
                    section_text[:100],
                    "description", scene_position, total_scenes
                )
                enhanced_narration = await self.ai_helper.enhance_narration(
                    narration,
                    "list",
                    {'header': enhanced_header, 'items': items[:5]},
                    scene_position,
                    total_scenes
                )

                scenes.append(SceneConfig(
                    scene_id=f"{video_id}_list_{i}",
                    scene_type="list",
                    narration=enhanced_narration,
                    visual_content={
                        'header': enhanced_header,
                        'description': enhanced_desc,
                        'items': items[:5]  # Limit to 5 items
                    },
                    voice=voice
                ))

            elif section['text']:
                # Text to list scene with AI enhancement
                # First, remove metadata from section text
                section_text = section['text']
                section_text = re.sub(r'\*?Generated:.*\*?', '', section_text, flags=re.IGNORECASE)
                section_text = re.sub(r'^[-*_]{3,}$', '', section_text, flags=re.MULTILINE)
                section_text = section_text.strip()

                sentences = [s.strip() for s in section_text.split('.') if s.strip()]
                # Clean markdown from sentences
                clean_sentences = []
                for sent in sentences:
                    # Skip metadata sentences - use refactored function
                    if is_metadata_line(sent):
                        continue

                    # Clean markdown - use refactored function
                    clean = clean_markdown_formatting(sent)

                    if clean.strip():  # Only add non-empty sentences
                        clean_sentences.append(clean)

                # AI enhance visual content
                enhanced_header = await self.ai_helper.enhance_slide_content(
                    heading, "header", scene_position, total_scenes
                )
                enhanced_desc = await self.ai_helper.enhance_slide_content(
                    clean_sentences[0] if clean_sentences else '',
                    "description", scene_position, total_scenes
                )
                text_items = clean_sentences[1:4] if len(clean_sentences) > 1 else [section['text'][:100]]
                enhanced_narration = await self.ai_helper.enhance_narration(
                    f"About {heading.lower()}",
                    "list",
                    {'header': enhanced_header, 'items': text_items},
                    scene_position,
                    total_scenes
                )

                scenes.append(SceneConfig(
                    scene_id=f"{video_id}_list_{i}",
                    scene_type="list",
                    narration=enhanced_narration,
                    visual_content={
                        'header': enhanced_header,
                        'description': enhanced_desc,
                        'items': text_items
                    },
                    voice=voice
                ))

        # Outro scene with AI enhancement
        outro_main = await self.ai_helper.enhance_slide_content(
            'Learn More',
            context_type="outro_main",
            scene_position=len(scenes),
            total_scenes=total_scenes
        )
        outro_sub = await self.ai_helper.enhance_slide_content(
            'See Full Documentation',
            context_type="outro_sub",
            scene_position=len(scenes),
            total_scenes=total_scenes
        )
        outro_narration = await self.ai_helper.enhance_narration(
            "Thanks for watching! Check out the documentation for more details.",
            scene_type="outro",
            scene_data={'main_text': outro_main, 'sub_text': outro_sub},
            scene_position=len(scenes),
            total_scenes=total_scenes
        )

        scenes.append(SceneConfig(
            scene_id=f"{video_id}_outro",
            scene_type="outro",
            narration=outro_narration,
            visual_content={
                'main_text': outro_main,
                'sub_text': outro_sub
            },
            voice=voice
        ))

        return scenes

    async def validate_source(self, source: Any) -> bool:
        """Validate document file.

        Args:
            source: Path to document file

        Returns:
            True if valid, False otherwise
        """
        return validate_file_path(source, self.supported_formats)

    def supports_format(self, format_type: str) -> bool:
        """Check if format is supported.

        Args:
            format_type: File extension (e.g., ".pdf")

        Returns:
            True if supported
        """
        return format_type.lower() in self.supported_formats

    # Backward compatibility methods for tests
    async def _read_document_content(self, source: Any) -> str:
        """Backward compatibility wrapper for read_document_content."""
        project_root = Path(__file__).parent.parent.parent.resolve()
        return await read_document_content(
            source=source,
            test_mode=self.test_mode,
            project_root=project_root
        )

    def _parse_markdown_structure(self, content: str) -> dict:
        """Backward compatibility wrapper for parse_markdown_structure."""
        return parse_markdown_structure(content)

    async def _enhance_slide_content(
        self,
        content: str,
        context_type: str,
        scene_position: int = 0,
        total_scenes: int = 1
    ) -> str:
        """Backward compatibility wrapper for ai_helper.enhance_slide_content."""
        return await self.ai_helper.enhance_slide_content(
            content, context_type, scene_position, total_scenes
        )

    async def _enhance_narration(
        self,
        narration: str,
        scene_type: str,
        scene_data: dict,
        scene_position: int = 0,
        total_scenes: int = 1
    ) -> str:
        """Backward compatibility wrapper for ai_helper.enhance_narration."""
        return await self.ai_helper.enhance_narration(
            narration, scene_type, scene_data, scene_position, total_scenes
        )
