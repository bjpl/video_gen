"""Document input adapter for PDF, DOCX, and text files.

This adapter processes document files and extracts structured content for
video generation.
"""

from pathlib import Path
from typing import Any, List

from .base import InputAdapter, InputAdapterResult
from ..shared.models import VideoSet, SceneConfig


class DocumentAdapter(InputAdapter):
import re  # For markdown cleaning
    """Adapter for document files (PDF, DOCX, TXT, Markdown).

    This adapter reads document files, extracts text and structure, and
    converts them into VideoSet objects for video generation.
    """

    def __init__(self):
        """Initialize the document adapter."""
        super().__init__(
            name="document",
            description="Processes PDF, DOCX, TXT, and Markdown files"
        )
        self.supported_formats = {".pdf", ".docx", ".txt", ".md"}

    async def adapt(self, source: Any, **kwargs) -> InputAdapterResult:
        """Adapt a document file to VideoSet structure.

        Args:
            source: Path to document file or URL
            **kwargs: Additional parameters (accent_color, voice, etc.)

        Returns:
            InputAdapterResult with VideoSet
        """
        try:
            # Read document content (file or URL)
            content = await self._read_document_content(source)

            if not content:
                return InputAdapterResult(
                    success=False,
                    error=f"Failed to read document: {source}"
                )

            # Parse markdown structure
            structure = self._parse_markdown_structure(content)

            # Generate video set from structure
            video_set = self._create_video_set_from_structure(
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

    async def _read_document_content(self, source: Any) -> str:
        """Read document from file or URL."""
        # Clean the source path - strip quotes and whitespace
        source_str = str(source).strip().strip('"').strip("'")

        # Check if URL
        if source_str.startswith('http://') or source_str.startswith('https://'):
            # Try to import requests
            try:
                import requests
                # Convert GitHub URLs to raw
                url = source_str
                if 'github.com' in url and '/blob/' in url:
                    url = url.replace('github.com', 'raw.githubusercontent.com')
                    url = url.replace('/blob/', '/')

                response = requests.get(url, timeout=10)
                response.raise_for_status()
                return response.text
            except ImportError:
                raise Exception("requests library required for URL fetching. Install: pip install requests")
            except Exception as e:
                raise Exception(f"Failed to fetch URL: {e}")
        else:
            # Read from file
            file_path = Path(source_str)

            # If path is relative, resolve from project root (not module directory)
            if not file_path.is_absolute():
                # Get project root (2 levels up from this file)
                project_root = Path(__file__).parent.parent.parent
                file_path = project_root / file_path

            if not file_path.exists():
                raise Exception(f"File not found: {file_path}")

            return file_path.read_text(encoding='utf-8')

    def _parse_markdown_structure(self, content: str) -> dict:
        """Parse markdown content into structured format.

        Enhanced with support for:
        - Nested lists (up to 3 levels)
        - Tables (basic markdown tables)
        - Better handling of malformed markdown
        - Link extraction
        """
        import re

        lines = content.split('\n')
        structure = {
            'title': '',
            'sections': [],
            'tables': []
        }

        current_section = None
        in_code_block = False
        code_lines = []
        current_list = []
        list_depth = 0
        current_text = []
        in_table = False
        table_rows = []

        def save_current_list():
            """Helper to save accumulated list items."""
            nonlocal current_list, current_section
            if current_list and current_section:
                current_section.setdefault('lists', []).append(current_list)
                current_list = []

        def save_current_section():
            """Helper to save current section."""
            nonlocal current_section, current_text, current_list
            if current_section:
                current_section['text'] = '\n'.join(current_text).strip()
                save_current_list()
                structure['sections'].append(current_section)
                current_text = []

        for line in lines:
            # Code block detection
            if line.strip().startswith('```'):
                if in_code_block:
                    # End code block
                    if current_section:
                        current_section.setdefault('code_blocks', []).append('\n'.join(code_lines))
                    code_lines = []
                    in_code_block = False
                else:
                    in_code_block = True
                    save_current_list()  # Save any pending list
                continue

            if in_code_block:
                code_lines.append(line)
                continue

            # Table detection (basic markdown tables)
            if re.match(r'^\s*\|.*\|\s*$', line):
                if not in_table:
                    in_table = True
                    save_current_list()
                # Parse table row
                cells = [cell.strip() for cell in line.strip('|').split('|')]
                # Skip separator rows (like |---|---|)
                if not all(re.match(r'^:?-+:?$', cell) for cell in cells):
                    table_rows.append(cells)
                continue
            elif in_table:
                # End of table
                if current_section and table_rows:
                    current_section.setdefault('tables', []).append(table_rows)
                table_rows = []
                in_table = False

            # Heading detection
            if match := re.match(r'^(#{1,6})\s+(.+)$', line):
                save_current_section()

                level = len(match.group(1))
                heading = match.group(2).strip()

                # Remove markdown links from heading
                heading = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', heading)

                if level == 1 and not structure['title']:
                    structure['title'] = heading
                else:
                    current_section = {
                        'heading': heading,
                        'level': level,
                        'text': '',
                        'code_blocks': [],
                        'lists': [],
                        'tables': [],
                        'links': []
                    }
                continue

            # Nested list detection (up to 3 levels)
            if match := re.match(r'^([\s]*)[-*+]\s+(.+)$', line):
                indent = len(match.group(1))
                item_text = match.group(2).strip()

                # Extract links from list items
                if current_section:
                    links = re.findall(r'\[([^\]]+)\]\(([^\)]+)\)', item_text)
                    for link_text, link_url in links:
                        current_section['links'].append({'text': link_text, 'url': link_url})

                # Determine nesting level (0, 2, 4 spaces = levels 0, 1, 2)
                depth = min(indent // 2, 2)

                # Create nested structure if needed
                if depth > list_depth:
                    # Starting nested list
                    if current_list:
                        nested_item = {'text': current_list[-1], 'children': [item_text]}
                        current_list[-1] = nested_item
                    else:
                        current_list.append(item_text)
                elif depth < list_depth:
                    # Ending nested list
                    current_list.append(item_text)
                else:
                    current_list.append(item_text)

                list_depth = depth
                continue

            # Numbered list (with nesting support)
            if match := re.match(r'^([\s]*)\d+\.\s+(.+)$', line):
                indent = len(match.group(1))
                item_text = match.group(2).strip()

                # Extract links
                if current_section:
                    links = re.findall(r'\[([^\]]+)\]\(([^\)]+)\)', item_text)
                    for link_text, link_url in links:
                        current_section['links'].append({'text': link_text, 'url': link_url})

                current_list.append(item_text)
                continue

            # Regular text
            if line.strip():
                # Extract links from regular text
                if current_section:
                    links = re.findall(r'\[([^\]]+)\]\(([^\)]+)\)', line)
                    for link_text, link_url in links:
                        current_section['links'].append({'text': link_text, 'url': link_url})

                current_text.append(line.strip())
            elif current_list:
                save_current_list()
                list_depth = 0

        # Save final section
        save_current_section()

        # Handle edge case: if no sections but have title, create one section
        if not structure['sections'] and structure['title']:
            structure['sections'].append({
                'heading': 'Overview',
                'level': 2,
                'text': 'Content from ' + structure['title'],
                'code_blocks': [],
                'lists': [],
                'tables': [],
                'links': []
            })

        return structure

    def _create_video_set_from_structure(self, structure: dict, source: Any, **kwargs) -> VideoSet:
        """Create VideoSet from parsed structure.

        Enhanced to support:
        - Multiple videos split by ## headings (level 2)
        - Tables rendered as comparison scenes
        - Better scene distribution
        - Max scenes per video configuration
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
        max_scenes_per_video = kwargs.get('max_scenes_per_video', 20)  # Increased from 8 to 20 for comprehensive videos
        split_by_h2 = kwargs.get('split_by_h2', True)  # Split by H2 headings by default to create multiple videos
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

            scenes = self._create_scenes_from_sections(
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
        return VideoSet(
            set_id=set_id,
            name=set_name,
            description=f"Videos generated from document: {source}",
            videos=videos,
            metadata={
                "source": str(source),
                "video_count": len(videos),
                "total_sections": len(structure['sections'])
            }
        )

    def _create_scenes_from_sections(
        self,
        sections: List[dict],
        video_id: str,
        title: str,
        subtitle: str,
        voice: str,
        max_scenes: int = 8
    ) -> List['SceneConfig']:
        """Create scenes from a list of sections."""
        from ..shared.models import SceneConfig

        scenes = []

        # Title scene
        scenes.append(SceneConfig(
            scene_id=f"{video_id}_title",
            scene_type="title",
            narration=f"Welcome to {subtitle or title}",
            visual_content={
                'title': title,
                'subtitle': subtitle or 'Complete Guide'
            },
            voice=voice
        ))

        # Convert sections to scenes (limit by max_scenes - 2 for title and outro)
        content_scenes = max_scenes - 2
        for i, section in enumerate(sections[:content_scenes]):
            heading = section['heading']
            has_code = len(section.get('code_blocks', [])) > 0
            has_lists = len(section.get('lists', [])) > 0
            has_tables = len(section.get('tables', [])) > 0

            if has_tables:
                # Convert table to list scene (comparison not supported in template renderer)
                table = section['tables'][0]  # Use first table
                if len(table) >= 2:  # Need at least header and one row
                    # Format table rows as "label: value" items
                    items = []
                    for row in table[1:5]:  # Skip header, take up to 4 rows
                        if row:
                            if len(row) > 1:
                                items.append(f"{row[0]}: {' | '.join(row[1:])}")
                            else:
                                items.append(row[0])

                    scenes.append(SceneConfig(
                        scene_id=f"{video_id}_list_{i}",
                        scene_type="list",
                        narration=f"Here's a comparison of {heading.lower()}",
                        visual_content={
                            'header': heading,
                            'description': section['text'][:100] if section['text'] else 'Key comparisons',
                            'items': items
                        },
                        voice=voice
                    ))

            elif has_code:
                # Command scene
                commands = []
                for block in section['code_blocks']:
                    for line in block.split('\n')[:6]:
                        if line.strip() and not line.strip().startswith('#'):
                            commands.append(line.strip())

                scenes.append(SceneConfig(
                    scene_id=f"{video_id}_command_{i}",
                    scene_type="command",
                    narration=f"Here's how to {heading.lower()}",
                    visual_content={
                        'header': heading,
                        'description': section['text'][:100] if section['text'] else '',
                        'commands': commands[:6]
                    },
                    voice=voice
                ))

            elif has_lists:
                # List scene
                items = []
                for lst in section['lists']:
                    # Flatten nested lists
                    for item in lst:
                        if isinstance(item, dict) and 'text' in item:
                            clean_item = item['text']
                        else:
                            clean_item = str(item)

                        # Clean markdown formatting
                        clean_item = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', clean_item)  # [text](url) → text
                        clean_item = re.sub(r'\*\*([^*]+)\*\*', r'\1', clean_item)  # **bold** → text
                        clean_item = re.sub(r'\*([^*]+)\*', r'\1', clean_item)  # *italic* → text
                        clean_item = re.sub(r'`([^`]+)`', r'\1', clean_item)  # `code` → code
                        items.append(clean_item)

                # Create narration that describes the list content
                items_preview = items[:3] if len(items) > 3 else items
                narration = f"This section covers {heading.lower()}: {', '.join(items_preview)}"
                if len(items) > 3:
                    narration += f", and {len(items) - 3} more topics"

                scenes.append(SceneConfig(
                    scene_id=f"{video_id}_list_{i}",
                    scene_type="list",
                    narration=narration,
                    visual_content={
                        'header': heading,
                        'description': section['text'][:100] if section['text'] else '',
                        'items': items[:5]  # Limit to 5 items
                    },
                    voice=voice
                ))

            elif section['text']:
                # Text to list scene
                sentences = [s.strip() for s in section['text'].split('.') if s.strip()]
                scenes.append(SceneConfig(
                    scene_id=f"{video_id}_list_{i}",
                    scene_type="list",
                    narration=f"About {heading.lower()}",
                    visual_content={
                        'header': heading,
                        'description': sentences[0] if sentences else '',
                        'items': sentences[1:4] if len(sentences) > 1 else [section['text'][:100]]
                    },
                    voice=voice
                ))

        # Outro scene
        scenes.append(SceneConfig(
            scene_id=f"{video_id}_outro",
            scene_type="outro",
            narration="Thanks for watching! Check out the documentation for more details.",
            visual_content={
                'main_text': 'Learn More',
                'sub_text': 'See Full Documentation'
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
        if not isinstance(source, (str, Path)):
            return False

        file_path = Path(source)
        return (
            file_path.exists()
            and file_path.is_file()
            and file_path.suffix.lower() in self.supported_formats
        )

    def supports_format(self, format_type: str) -> bool:
        """Check if format is supported.

        Args:
            format_type: File extension (e.g., ".pdf")

        Returns:
            True if supported
        """
        return format_type.lower() in self.supported_formats
